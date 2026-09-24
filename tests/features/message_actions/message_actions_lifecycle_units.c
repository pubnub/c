/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file message_actions_lifecycle_units.c
 * @brief Use-after-free / lifetime proofs for borrowed timetoken
 *        pointers on the message-actions add/remove paths.
 *
 * The add and remove wire builders copy caller-owned timetoken
 * strings into the request scratch buffer instead of storing the
 * borrowed pointer directly. These tests prove the copy happens by
 * freeing the caller's string immediately after the API call returns
 * and then driving the request through the pending-queue round-trip
 * (enqueue -> promote -> dispatch). Reading the promoted request's
 * path segments must observe the copied value, never freed memory.
 *
 * Under AddressSanitizer a regression (raw borrowed pointer) surfaces
 * as a heap-use-after-free at the point the promoted request is
 * inspected; without ASan it surfaces as a value mismatch.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "providers/provider_internal.h"

/* Configured in-flight capacity plus overflow headroom; derived from
 * the config macro so it tracks every profile. */
#define MAX_TRACKED_SLOTS (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 2)

/** @brief Per-send capture recorded by the chain transport. */
typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static int            s_in_flight;
static send_capture_t s_captures[MAX_TRACKED_SLOTS];
static int            s_fake_handle_storage[MAX_TRACKED_SLOTS];

static void reset_chain(void)
{
    s_send_count = 0;
    s_in_flight  = 0;
    memset(s_captures, 0, sizeof(s_captures));
}

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_TRACKED_SLOTS) {
        return NULL;
    }
    s_captures[s_send_count].request  = request;
    s_captures[s_send_count].response = response;
    s_send_count++;
    s_in_flight++;
    return (pubnub_transport_handle_t*)&s_fake_handle_storage[s_send_count - 1];
}

static int chain_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void chain_cancel(pubnub_transport_provider_t* self,
                         pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_transport_provider_t s_chain_transport = {
    .send              = chain_send,
    .poll              = chain_poll,
    .cancel            = chain_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

/** @brief Minimal success body for a message-actions add/remove. */
static const uint8_t k_ok_body[] =
    "{\"status\":200,\"data\":{\"type\":\"reaction\",\"value\":\"v\","
    "\"uuid\":\"u\",\"actionTimetoken\":\"1\",\"messageTimetoken\":\"2\"}}";

static void chain_complete_ok(int index)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = k_ok_body;
    resp->body_len    = sizeof(k_ok_body) - 1;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;

    /* Strip thread primitives so no background thread races the test's
     * manual completion; pubnub_process() drives ticks synchronously. */
    static pubnub_platform_provider_t s_no_thread_platform;
    pubnub_platform_provider_t*       base = pn_platform_default();
    if (NULL != base) {
        s_no_thread_platform               = *base;
        s_no_thread_platform.thread_create = NULL;
        s_no_thread_platform.thread_join   = NULL;
        cfg.platform                       = &s_no_thread_platform;
    }

    return cfg;
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * @brief Return the path segment that immediately follows the first
 *        segment equal to @p label, or a zero view when not found.
 */
static pubnub_string_view_t segment_after(const pubnub_http_request_t* req,
                                          const char*                  label,
                                          size_t label_len)
{
    pubnub_string_view_t empty = {NULL, 0};
    unsigned int         i;

    for (i = 0; i + 1 < req->path_segment_count; ++i) {
        const pubnub_string_view_t* seg = &req->path_segments[i];
        if (label_len == seg->len && 0 == memcmp(seg->ptr, label, label_len)) {
            return req->path_segments[i + 1];
        }
    }
    return empty;
}

/**
 * @brief Fill every pool slot with in-flight add-message-action calls
 *        using static (non-heap) arguments.
 *
 * The chain transport never completes anything, so each successful
 * call leaves a slot IN_FLIGHT, driving the next request into the
 * pending queue.
 */
static uint16_t fill_pool(pubnub_context_t* ctx, pubnub_future_t* fill)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    uint16_t           i;
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    assert_true(capacity >= 2);
    assert_true((int)(capacity + 1) <= MAX_TRACKED_SLOTS);

    for (i = 0; i < capacity; ++i) {
        pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
        opts.channel           = "fill-ch";
        opts.message_timetoken = "1";
        opts.type              = "reaction";
        opts.value             = "\"v\"";
        fill[i]                = pubnub_add_message_action(ctx, &opts);
        assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fill[i]));
    }
    assert_int_equal(s_send_count, capacity);
    return capacity;
}

/** @brief Complete + release the fill slots and drain the context. */
static void drain_fill(pubnub_context_t* ctx,
                       pubnub_future_t*  fill,
                       uint16_t          first,
                       uint16_t          capacity)
{
    uint16_t i;
    for (i = first; i < capacity; ++i) {
        chain_complete_ok((int)i);
    }
    (void)pubnub_process(ctx);
    for (i = first; i < capacity; ++i) {
        assert_true(pubnub_future_is_ready(fill[i]));
        pubnub_future_release(fill[i]);
    }
}

/**
 * @brief The add path copies the caller's message timetoken into
 *        scratch: freeing it before dispatch is safe across the
 *        pending-queue round-trip.
 */
static void add_timetoken_survives_free_through_pending_queue(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    const uint16_t  capacity = fill_pool(ctx, fill);

    /* Heap-allocate a 17-digit timetoken and hand it to the API. */
    char* tt = strdup("16912345678901234");
    assert_non_null(tt);

    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = "params-ch";
    opts.message_timetoken                = tt;
    opts.type                             = "reaction";
    opts.value                            = "\"v\"";
    pubnub_future_t overflow = pubnub_add_message_action(ctx, &opts);

    /* Free the caller's string now, before the queued request runs.
     * With the borrowed-pointer bug this would leave a dangling ptr. */
    free(tt);

    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(overflow));
    assert_true(overflow.slot_id >= capacity);
    assert_int_equal(s_send_count, capacity);

    /* Free one slot so the pending entry promotes and dispatches. */
    chain_complete_ok(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fill[0]));
    pubnub_future_release(fill[0]);
    (void)pubnub_process(ctx);
    assert_int_equal(s_send_count, capacity + 1);

    /* Inspect the promoted request: the timetoken segment must equal
     * the freed string's value (proving the scratch copy survived). */
    pubnub_http_request_t* promoted = s_captures[capacity].request;
    assert_non_null(promoted);
    pubnub_string_view_t mtt = segment_after(promoted, "message", 7);
    assert_int_equal(mtt.len, 17);
    assert_memory_equal(mtt.ptr, "16912345678901234", 17);

    chain_complete_ok(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    pubnub_future_release(overflow);

    drain_fill(ctx, fill, 1, capacity);
    pubnub_destroy(ctx);
}

/**
 * @brief The remove path copies both message and action timetokens
 *        into scratch and both survive a free before dispatch.
 */
static void remove_timetokens_survive_free_through_pending_queue(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    const uint16_t  capacity = fill_pool(ctx, fill);

    char* mtt = strdup("16900000000000001");
    char* att = strdup("16900000000000002");
    assert_non_null(mtt);
    assert_non_null(att);

    pubnub_remove_message_action_opts_t opts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;
    opts.channel             = "params-ch";
    opts.message_timetoken   = mtt;
    opts.action_timetoken    = att;
    pubnub_future_t overflow = pubnub_remove_message_action(ctx, &opts);

    free(mtt);
    free(att);

    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(overflow));
    assert_true(overflow.slot_id >= capacity);

    chain_complete_ok(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fill[0]));
    pubnub_future_release(fill[0]);
    (void)pubnub_process(ctx);
    assert_int_equal(s_send_count, capacity + 1);

    pubnub_http_request_t* promoted = s_captures[capacity].request;
    assert_non_null(promoted);
    pubnub_string_view_t got_mtt = segment_after(promoted, "message", 7);
    pubnub_string_view_t got_att = segment_after(promoted, "action", 6);
    assert_int_equal(got_mtt.len, 17);
    assert_memory_equal(got_mtt.ptr, "16900000000000001", 17);
    assert_int_equal(got_att.len, 17);
    assert_memory_equal(got_att.ptr, "16900000000000002", 17);

    chain_complete_ok(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    pubnub_future_release(overflow);

    drain_fill(ctx, fill, 1, capacity);
    pubnub_destroy(ctx);
}

/** @brief A non-digit timetoken is rejected before dispatch. */
static void add_rejects_non_digit_timetoken(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = "ch";
    opts.message_timetoken                = "16abc";
    opts.type                             = "reaction";
    opts.value                            = "\"v\"";
    pubnub_future_t fut = pubnub_add_message_action(ctx, &opts);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_future_status(fut));
    assert_int_equal(s_send_count, 0);
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/** @brief A timetoken longer than 19 digits is rejected. */
static void add_rejects_overlong_timetoken(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = "ch";
    opts.message_timetoken                = "12345678901234567890"; /* 20 */
    opts.type                             = "reaction";
    opts.value                            = "\"v\"";
    pubnub_future_t fut = pubnub_add_message_action(ctx, &opts);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_future_status(fut));
    assert_int_equal(s_send_count, 0);
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/** @brief A non-digit action timetoken is rejected on the remove path. */
static void remove_rejects_non_digit_action_timetoken(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_remove_message_action_opts_t opts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;
    opts.channel           = "ch";
    opts.message_timetoken = "16900000000000001";
    opts.action_timetoken  = "not-a-token";
    pubnub_future_t fut    = pubnub_remove_message_action(ctx, &opts);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_future_status(fut));
    assert_int_equal(s_send_count, 0);
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

#if PUBNUB_CFG_NO_HEAP
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif /* PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(add_timetoken_survives_free_through_pending_queue),
        cmocka_unit_test(remove_timetokens_survive_free_through_pending_queue),
        cmocka_unit_test(add_rejects_non_digit_timetoken),
        cmocka_unit_test(add_rejects_overlong_timetoken),
        cmocka_unit_test(remove_rejects_non_digit_action_timetoken),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

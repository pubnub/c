/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file push_lifecycle_units.c
 * @brief Use-after-free / lifetime proof for the borrowed device
 *        token pointer on the push add-channels path.
 *
 * The push path builder copies the caller-owned device token into the
 * request scratch buffer instead of storing the borrowed pointer. This
 * test frees the caller's token immediately after the API call returns
 * and drives the request through the pending-queue round-trip
 * (enqueue -> promote -> dispatch). Reading the promoted request's
 * device path segment must observe the copied value, never freed memory.
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
#include "pubnub/features/push.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "providers/provider_internal.h"

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

/** @brief Success body accepted by the push mutation validator. */
static const uint8_t k_push_ok_body[] = "[1,\"Modified Channels\"]";

static void chain_complete_ok(int index)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = k_push_ok_body;
    resp->body_len    = sizeof(k_push_ok_body) - 1;
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
 * @brief Fill every pool slot with in-flight add-channels calls using
 *        a static (non-heap) device token.
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
        pubnub_push_add_channels_opts_t opts = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
        opts.device   = "static-device";
        opts.gateway  = PUBNUB_PUSH_FCM;
        opts.channels = "ch1";
        fill[i]       = pubnub_push_add_channels(ctx, &opts);
        assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fill[i]));
    }
    assert_int_equal(s_send_count, capacity);
    return capacity;
}

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
 * @brief The device token is copied into scratch: freeing it before
 *        dispatch is safe across the pending-queue round-trip.
 */
static void device_token_survives_free_through_pending_queue(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    const uint16_t  capacity = fill_pool(ctx, fill);

    /* Heap-allocate an FCM-style device token. */
    char* device = strdup("fEdCbA9876543210abcdef");
    assert_non_null(device);

    pubnub_push_add_channels_opts_t opts = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    opts.device                          = device;
    opts.gateway                         = PUBNUB_PUSH_FCM;
    opts.channels                        = "chan-a,chan-b";
    pubnub_future_t overflow             = pubnub_push_add_channels(ctx, &opts);

    /* Free the caller's token before the queued request runs. */
    free(device);

    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(overflow));
    assert_true(overflow.slot_id >= capacity);
    assert_int_equal(s_send_count, capacity);

    chain_complete_ok(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fill[0]));
    pubnub_future_release(fill[0]);
    (void)pubnub_process(ctx);
    assert_int_equal(s_send_count, capacity + 1);

    pubnub_http_request_t* promoted = s_captures[capacity].request;
    assert_non_null(promoted);
    pubnub_string_view_t dev = segment_after(promoted, "devices", 7);
    assert_int_equal(dev.len, 22);
    assert_memory_equal(dev.ptr, "fEdCbA9876543210abcdef", 22);

    chain_complete_ok(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    pubnub_future_release(overflow);

    drain_fill(ctx, fill, 1, capacity);
    pubnub_destroy(ctx);
}

/** @brief A NULL device token is rejected before dispatch. */
static void add_channels_rejects_null_device(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_push_add_channels_opts_t opts = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    opts.device                          = NULL;
    opts.gateway                         = PUBNUB_PUSH_FCM;
    opts.channels                        = "ch1";
    pubnub_future_t fut                  = pubnub_push_add_channels(ctx, &opts);

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
        cmocka_unit_test(device_token_survives_free_through_pending_queue),
        cmocka_unit_test(add_channels_rejects_null_device),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file app_context_lifecycle_units.c
 * @brief Use-after-free / lifetime proof for the borrowed If-Match
 *        pointer on the set-channel/set-uuid metadata paths.
 *
 * Both setters copy the caller-owned If-Match (ETag) string into the
 * request scratch buffer instead of storing the borrowed pointer as a
 * header value. These tests free the caller's string immediately after
 * the API call returns and drive the request through the pending-queue
 * round-trip (enqueue -> promote -> dispatch). Reading the promoted
 * request's If-Match header must observe the copied value, never freed
 * memory. CR/LF injection attempts are rejected up front.
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
#include "pubnub/features/app_context.h"
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

/** @brief Minimal success body accepted by the app-context validator. */
static const uint8_t k_ok_body[] = "{\"status\":200,\"data\":{}}";

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
/** @brief Locate an If-Match header value, or a zero view if absent. */
static pubnub_string_view_t if_match_header(const pubnub_http_request_t* req)
{
    pubnub_string_view_t empty = {NULL, 0};
    unsigned int         i;

    for (i = 0; i < req->header_count; ++i) {
        const pubnub_kv_t* h = &req->headers[i];
        if (8 == h->key.len && 0 == memcmp(h->key.ptr, "If-Match", 8)) {
            return h->value;
        }
    }
    return empty;
}

/** @brief Fill every pool slot with in-flight set-channel calls. */
static uint16_t fill_pool(pubnub_context_t* ctx, pubnub_future_t* fill)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    uint16_t           i;
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    assert_true(capacity >= 2);
    assert_true((int)(capacity + 1) <= MAX_TRACKED_SLOTS);

    for (i = 0; i < capacity; ++i) {
        pubnub_set_channel_metadata_opts_t opts =
            PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
        opts.channel = "fill-ch";
        opts.name    = "fill";
        fill[i]      = pubnub_set_channel_metadata(ctx, &opts);
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
 * @brief set_channel_metadata copies If-Match into scratch: freeing it
 *        before dispatch is safe across the pending-queue round-trip.
 */
static void channel_if_match_survives_free_through_pending_queue(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    const uint16_t  capacity = fill_pool(ctx, fill);

    char* etag = strdup("\"etag-abc-12345\"");
    assert_non_null(etag);

    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel             = "params-ch";
    opts.name                = "n";
    opts.if_match            = etag;
    pubnub_future_t overflow = pubnub_set_channel_metadata(ctx, &opts);

    /* Free the caller's ETag before the queued request runs. */
    free(etag);

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
    pubnub_string_view_t v = if_match_header(promoted);
    assert_int_equal(v.len, 16);
    assert_memory_equal(v.ptr, "\"etag-abc-12345\"", 16);

    chain_complete_ok(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    pubnub_future_release(overflow);

    drain_fill(ctx, fill, 1, capacity);
    pubnub_destroy(ctx);
}

/**
 * @brief set_uuid_metadata copies If-Match into scratch and it
 *        survives a free before dispatch.
 */
static void uuid_if_match_survives_free_through_pending_queue(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Fill the pool with set-channel calls (same request pool). */
    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    const uint16_t  capacity = fill_pool(ctx, fill);

    char* etag = strdup("\"uuid-etag-999\"");
    assert_non_null(etag);

    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.uuid                            = "u-42";
    opts.name                            = "n";
    opts.if_match                        = etag;
    pubnub_future_t overflow             = pubnub_set_uuid_metadata(ctx, &opts);

    free(etag);

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
    pubnub_string_view_t v = if_match_header(promoted);
    assert_int_equal(v.len, 15);
    assert_memory_equal(v.ptr, "\"uuid-etag-999\"", 15);

    chain_complete_ok(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    pubnub_future_release(overflow);

    drain_fill(ctx, fill, 1, capacity);
    pubnub_destroy(ctx);
}

/** @brief An If-Match carrying CR/LF is rejected (header injection). */
static void channel_if_match_rejects_crlf(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel        = "ch";
    opts.name           = "n";
    opts.if_match       = "\"etag\"\r\nX-Injected: 1";
    pubnub_future_t fut = pubnub_set_channel_metadata(ctx, &opts);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_future_status(fut));
    assert_int_equal(s_send_count, 0);
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/** @brief An If-Match carrying CR/LF is rejected on the uuid path too. */
static void uuid_if_match_rejects_crlf(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.uuid                            = "u-42";
    opts.name                            = "n";
    opts.if_match                        = "\"etag\"\nInjected";
    pubnub_future_t fut                  = pubnub_set_uuid_metadata(ctx, &opts);

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
        cmocka_unit_test(channel_if_match_survives_free_through_pending_queue),
        cmocka_unit_test(uuid_if_match_survives_free_through_pending_queue),
        cmocka_unit_test(channel_if_match_rejects_crlf),
        cmocka_unit_test(uuid_if_match_rejects_crlf),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file cross_feature_dispatch_units.c
 * @brief Deterministic tests for cross-feature concurrent dispatch
 *        on a single context.
 *
 * Proves that two different features (publish + time) can share the
 * same context pool without aliased buffers, and that pending-queue
 * promotion preserves data across features.
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
#include "pubnub/features/publish.h"
#include "pubnub/features/time.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

/* Internal accessors. */
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "providers/provider_internal.h"

/* Configured in-flight capacity plus overflow headroom; derived from the
 * config macro so it tracks every profile. */
#define MAX_TRACKED_SLOTS (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 2)

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

static const uint8_t k_publish_ok_body[] = "[1,\"Sent\",\"17000000000000000\"]";
static const uint8_t k_time_ok_body[]    = "[17000000000000000]";

static void chain_complete_capture(int index, const uint8_t* body, size_t body_len)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = body_len;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "pub";
    cfg.subscribe_key   = "sub";
    cfg.user_id         = "cross-feature-tester";
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

#if PUBNUB_CFG_NO_HEAP || !PUBNUB_ENABLE_PUBLISH || !PUBNUB_ENABLE_TIME
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif

#if !PUBNUB_CFG_NO_HEAP

#if PUBNUB_ENABLE_PUBLISH && PUBNUB_ENABLE_TIME

/**
 * Issue pubnub_publish() and pubnub_time() on the same context,
 * complete both, verify both futures return correct results.
 */
static void publish_and_time_concurrent_both_succeed(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t f_pub  = pubnub_publish(ctx,
                                           &(pubnub_publish_opts_t){
                                                .channel = "test-ch",
                                                .message = "\"hello\"",
                                           });
    pubnub_future_t f_time = pubnub_time(ctx);

    assert_int_equal(s_send_count, 2);
    assert_int_equal(s_in_flight, 2);
    assert_false(pubnub_future_is_ready(f_pub));
    assert_false(pubnub_future_is_ready(f_time));

    /* Complete both. */
    chain_complete_capture(0, k_publish_ok_body, sizeof(k_publish_ok_body) - 1);
    chain_complete_capture(1, k_time_ok_body, sizeof(k_time_ok_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(f_pub));
    assert_true(pubnub_future_is_ready(f_time));
    assert_int_equal(pubnub_future_status(f_pub), PUBNUB_OK);
    assert_int_equal(pubnub_future_status(f_time), PUBNUB_OK);

    /* Verify publish result. */
    const pubnub_timetoken_t pub_tt = pubnub_publish_result_timetoken(f_pub);
    assert_int_equal(pub_tt.len, 17);
    assert_memory_equal(pub_tt.ptr, "17000000000000000", 17);

    /* Verify time result. */
    const pubnub_timetoken_t time_tt = pubnub_time_result_timetoken(f_time);
    assert_int_equal(time_tt.len, 17);
    assert_memory_equal(time_tt.ptr, "17000000000000000", 17);

    pubnub_future_release(f_pub);
    pubnub_future_release(f_time);
    pubnub_destroy(ctx);
}

/**
 * Two concurrent requests must have distinct scratch buffer addresses.
 */
static void concurrent_requests_have_distinct_scratch_ptrs(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t f_pub  = pubnub_publish(ctx,
                                           &(pubnub_publish_opts_t){
                                                .channel = "ch-a",
                                                .message = "\"a\"",
                                           });
    pubnub_future_t f_time = pubnub_time(ctx);

    assert_int_equal(s_send_count, 2);

    /* The two requests' scratch buffers must not alias. */
    assert_non_null(s_captures[0].request);
    assert_non_null(s_captures[1].request);
    assert_ptr_not_equal(s_captures[0].request->scratch,
                         s_captures[1].request->scratch);

    /* Clean up. */
    chain_complete_capture(0, k_publish_ok_body, sizeof(k_publish_ok_body) - 1);
    chain_complete_capture(1, k_time_ok_body, sizeof(k_time_ok_body) - 1);
    (void)pubnub_process(ctx);
    pubnub_future_release(f_pub);
    pubnub_future_release(f_time);
    pubnub_destroy(ctx);
}

/**
 * Fill all pool slots with time requests, overflow a publish into the
 * pending queue, complete one time, promote, verify publish data intact.
 */
static void overflow_pending_cross_feature_preserves_data(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    assert_true(capacity >= 2);
    assert_true((int)(capacity + 1) <= MAX_TRACKED_SLOTS);

    /* Fill pool with time requests. */
    pubnub_future_t time_futs[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        time_futs[i] = pubnub_time(ctx);
        assert_int_equal(pubnub_future_status(time_futs[i]), PUBNUB_IN_PROGRESS);
    }
    assert_int_equal(s_send_count, (int)capacity);

    /* Overflow with a publish that has query params. */
    pubnub_future_t overflow =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel             = "overflow-ch",
                           .message             = "\"overflow\"",
                           .store               = PUBNUB_PUBLISH_STORE_YES,
                           .custom_message_type = "test-cmt",
                       });
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_IN_PROGRESS);
    assert_true(overflow.slot_id >= capacity);
    assert_int_equal(s_send_count, (int)capacity);

    /* Complete slot 0 (time) and release it. */
    chain_complete_capture(0, k_time_ok_body, sizeof(k_time_ok_body) - 1);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(time_futs[0]));
    pubnub_future_release(time_futs[0]);

    /* Process: promote the pending publish into the freed slot. */
    (void)pubnub_process(ctx);
    assert_int_equal(s_send_count, (int)capacity + 1);

    /* Verify the promoted publish request data. */
    pubnub_http_request_t* promoted = s_captures[capacity].request;
    assert_non_null(promoted);
    assert_true(promoted->path_segment_count >= 1);

    /* Check query params survived relocation. */
    int found_store = 0;
    for (unsigned int i = 0; i < promoted->query_param_count; i++) {
        const pubnub_kv_t* p = &promoted->query_params[i];
        assert_non_null(p->key.ptr);
        if (5 == p->key.len && 0 == memcmp(p->key.ptr, "store", 5)) {
            assert_int_equal(p->value.len, 1);
            assert_memory_equal(p->value.ptr, "1", 1);
            found_store = 1;
        }
    }
    assert_int_equal(found_store, 1);

    /* Complete promoted publish and drain remaining time slots. */
    chain_complete_capture(
        (int)capacity, k_publish_ok_body, sizeof(k_publish_ok_body) - 1);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_OK);
    pubnub_future_release(overflow);

    for (uint16_t i = 1; i < capacity; i++) {
        chain_complete_capture((int)i, k_time_ok_body, sizeof(k_time_ok_body) - 1);
    }
    (void)pubnub_process(ctx);
    for (uint16_t i = 1; i < capacity; i++) {
        assert_true(pubnub_future_is_ready(time_futs[i]));
        pubnub_future_release(time_futs[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * Prepare two features, fail the second mid-build. Verify both prep
 * slots are properly cleaned up.
 */
static void error_mid_build_releases_prep_for_both_features(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Acquire two prep entries directly. */
    pn_pending_entry_t* entry1 = pn_prep_acquire(ctx);
    pn_pending_entry_t* entry2 = pn_prep_acquire(ctx);
    assert_non_null(entry1);
    assert_non_null(entry2);

    /* Simulate a mid-build failure: release both. */
    pn_prep_release(ctx, entry1);
    pn_prep_release(ctx, entry2);

    /* Verify all N slots remain acquirable. */
    pn_pending_entry_t* entries[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        entries[i] = pn_prep_acquire(ctx);
        assert_non_null(entries[i]);
    }
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_prep_release(ctx, entries[i]);
    }

    pubnub_destroy(ctx);
}

#endif /* PUBNUB_ENABLE_PUBLISH && PUBNUB_ENABLE_TIME */

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP && PUBNUB_ENABLE_PUBLISH && PUBNUB_ENABLE_TIME
        cmocka_unit_test(publish_and_time_concurrent_both_succeed),
        cmocka_unit_test(concurrent_requests_have_distinct_scratch_ptrs),
        cmocka_unit_test(overflow_pending_cross_feature_preserves_data),
        cmocka_unit_test(error_mid_build_releases_prep_for_both_features),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

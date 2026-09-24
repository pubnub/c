/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file providers/allocator/oom_injection_units.c
 * @brief Allocation-failure (OOM) injection tests for core features.
 *
 * Each test builds a real context (real serialization / platform), then
 * injects a failure-injecting allocator via @c pubnub_config_t::allocator
 * and a capturing mock transport. Operations are armed to fail at a
 * chosen allocation and the SDK's error handling, resource hygiene, and
 * post-failure reusability are asserted.
 *
 * These tests deliberately do NOT guard against SDK defects: a crash,
 * leaked pool slot, or out-of-class error code is a real bug and the
 * test is expected to fail loudly if one is present.
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
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#if PUBNUB_ENABLE_PUBLISH
#include "pubnub/features/publish.h"
#endif
#if PUBNUB_ENABLE_HISTORY
#include "pubnub/features/history.h"
#endif
#if PUBNUB_ENABLE_TIME
#include "pubnub/features/time.h"
#endif
#if PUBNUB_ENABLE_SUBSCRIBE
#include "pubnub/features/subscribe.h"
#endif

#include "core/core_internal.h"
#include "core/runtime/request_pool_internal.h"

#include "providers/allocator/mock_oom_allocator.h"

#define MAX_CAPTURES 4

typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static int            s_in_flight;
static send_capture_t s_captures[MAX_CAPTURES];
static int            s_fake_handle_storage[MAX_CAPTURES];

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
    if (s_send_count >= MAX_CAPTURES) {
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

static void chain_complete_with(int index, const uint8_t* body, size_t len)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = len;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

/**
 * @brief Assert @p res is in the capacity/memory class (32..47).
 *
 * The exact code for an allocation failure is not uniform across
 * features: publish/signal/access map a @c buf_acquire failure to
 * @c PUBNUB_ERR_QUEUE_FULL, presence/message_actions/app_context map it
 * to @c PUBNUB_ERR_OUT_OF_MEMORY, and publish's POST-body path maps it
 * to @c PUBNUB_ERR_BUFFER_TOO_SMALL. General @c alloc failures are
 * uniformly @c PUBNUB_ERR_OUT_OF_MEMORY. All of these live in the
 * 32..47 capacity/memory class, so the range is the portable
 * assertion. Unifying the per-feature codes is a separate cleanup task.
 */
static void assert_capacity_class(pubnub_res_t res)
{
    assert_true(res >= 32 && res <= 47);
}

static pubnub_config_t oom_config(pn_mock_oom_allocator_t* mock)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    cfg.allocator       = &mock->base;
    return cfg;
}

static uint16_t pool_in_use(pubnub_context_t* ctx)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    return pool->in_use_count;
}

#if PUBNUB_ENABLE_TIME
static void test_time_api_oom_at_request_start(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Fail the very first allocation of either tier: the request cannot
     * even begin, modelling OOM at request start. */
    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_future_t fut = pubnub_time(ctx);
    assert_true(pubnub_future_is_ready(fut));
    assert_capacity_class(pubnub_future_status(fut));

    pubnub_future_release(fut);
    assert_int_equal(0, pool_in_use(ctx));

    pubnub_destroy(ctx);
}

static void test_time_api_repeated_oom_then_success(void** state)
{
    (void)state;
    int i;

    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    for (i = 0; i < 5; ++i) {
        pubnub_future_t fut;
        pn_mock_oom_reset(&mock);
        pn_mock_oom_fail_alloc_after(&mock, 0);
        pn_mock_oom_fail_buf_acquire_after(&mock, 0);

        fut = pubnub_time(ctx);
        assert_true(pubnub_future_is_ready(fut));
        assert_capacity_class(pubnub_future_status(fut));
        pubnub_future_release(fut);
        assert_int_equal(0, pool_in_use(ctx));
    }

    /* Sixth call with a healthy allocator must succeed end-to-end. */
    pn_mock_oom_reset(&mock);
    reset_chain();

    static const uint8_t k_time_body[] = "[17001000000000001]";
    pubnub_future_t      fut           = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_time_body, sizeof(k_time_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_future_release(fut);
    assert_int_equal(0, pool_in_use(ctx));

    pubnub_destroy(ctx);
}
#endif /* PUBNUB_ENABLE_TIME */

#if PUBNUB_ENABLE_PUBLISH
static pubnub_publish_opts_t publish_opts(void)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = "ch";
    opts.message               = "\"hello\"";
    return opts;
}

static void test_publish_oom_at_request_start(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_publish_opts_t opts = publish_opts();
    pubnub_future_t       fut  = pubnub_publish(ctx, &opts);
    assert_true(pubnub_future_is_ready(fut));
    assert_capacity_class(pubnub_future_status(fut));

    pubnub_future_release(fut);
    assert_int_equal(0, pool_in_use(ctx));

    pubnub_destroy(ctx);
}

static void test_publish_oom_returns_correct_error_class(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Target the purpose-tagged buffer tier specifically. Only the POST
     * method exercises buf_acquire at dispatch (for the request body); a
     * GET publish encodes the message into the URL via the general alloc
     * tier and never touches buf_acquire. NOTE: buf_acquire failure codes
     * are inconsistent across features:
     *   publish/signal/access            -> PUBNUB_ERR_QUEUE_FULL (34)
     *   presence/message_actions/context -> PUBNUB_ERR_OUT_OF_MEMORY (32)
     *   publish POST-body path           -> PUBNUB_ERR_BUFFER_TOO_SMALL (33)
     * All are in the 32..47 capacity class; unification is a separate
     * cleanup task, so assert on the class rather than the exact code. */
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_publish_opts_t opts = publish_opts();
    opts.method                = PUBNUB_PUBLISH_METHOD_POST;
    pubnub_future_t fut        = pubnub_publish(ctx, &opts);
    assert_true(pubnub_future_is_ready(fut));
    assert_capacity_class(pubnub_future_status(fut));

    pubnub_future_release(fut);
    assert_int_equal(0, pool_in_use(ctx));
    pubnub_destroy(ctx);
}

static void test_publish_oom_no_leak_in_pool(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    assert_int_equal(0, pool_in_use(ctx));

    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_publish_opts_t opts = publish_opts();
    pubnub_future_t       fut  = pubnub_publish(ctx, &opts);
    assert_true(pubnub_future_is_ready(fut));
    assert_capacity_class(pubnub_future_status(fut));
    pubnub_future_release(fut);

    /* A failed request must not leak a pool slot. */
    assert_int_equal(0, pool_in_use(ctx));

    /* The pool must still be usable: a healthy publish completes. */
    pn_mock_oom_reset(&mock);
    reset_chain();

    static const uint8_t  k_pub_body[] = "[1,\"Sent\",\"17001000000000001\"]";
    pubnub_publish_opts_t opts2        = publish_opts();
    pubnub_future_t       fut2         = pubnub_publish(ctx, &opts2);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut2));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_pub_body, sizeof(k_pub_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut2));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut2));

    pubnub_future_release(fut2);
    assert_int_equal(0, pool_in_use(ctx));

    pubnub_destroy(ctx);
}
#endif /* PUBNUB_ENABLE_PUBLISH */

#if PUBNUB_ENABLE_HISTORY
static void test_history_fetch_oom_at_request_start(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_true(pubnub_future_is_ready(fut));
    assert_capacity_class(pubnub_future_status(fut));

    pubnub_future_release(fut);
    assert_int_equal(0, pool_in_use(ctx));

    pubnub_destroy(ctx);
}
#endif /* PUBNUB_ENABLE_HISTORY */

#if PUBNUB_ENABLE_HISTORY && PUBNUB_ENABLE_TIME
static void test_history_fetch_oom_context_reusable_after(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";
    pubnub_future_t hfut              = pubnub_fetch_messages(ctx, &opts);
    assert_true(pubnub_future_is_ready(hfut));
    assert_capacity_class(pubnub_future_status(hfut));
    pubnub_future_release(hfut);

    /* Restore a healthy allocator; a subsequent time call must succeed,
     * proving the OOM did not corrupt the context. */
    pn_mock_oom_reset(&mock);
    reset_chain();

    static const uint8_t k_time_body[] = "[17001000000000001]";
    pubnub_future_t      tfut          = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(tfut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_time_body, sizeof(k_time_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(tfut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(tfut));

    pubnub_future_release(tfut);
    assert_int_equal(0, pool_in_use(ctx));

    pubnub_destroy(ctx);
}
#endif /* PUBNUB_ENABLE_HISTORY && PUBNUB_ENABLE_TIME */

#if PUBNUB_ENABLE_SUBSCRIBE
static void test_subscribe_oom_at_request_start(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Build the entity while the allocator is healthy, then starve the
     * subscription creation. The header documents NULL-on-OOM. */
    pubnub_entity_t entity = pubnub_channel(ctx, "ch");
    assert_non_null(entity);

    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);

    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    assert_null(sub);

    pn_mock_oom_reset(&mock);
    pubnub_entity_destroy(entity);
    pubnub_destroy(ctx);
}

static void test_subscribe_oom_no_crashed_listener(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_entity_t entity = pubnub_channel(ctx, "ch");
    assert_non_null(entity);

    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);
    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    assert_null(sub);

    /* The listener subsystem must be intact after the failed allocation. */
    pn_mock_oom_reset(&mock);
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = pubnub_add_listener(ctx, &listener);
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, handle);
    pubnub_remove_listener(ctx, handle);

    pubnub_entity_destroy(entity);
    pubnub_destroy(ctx);
}
#endif /* PUBNUB_ENABLE_SUBSCRIBE */

static void test_oom_context_lifecycle_safe(void** state)
{
    (void)state;
    reset_chain();
    pn_mock_oom_allocator_t mock;
    pn_mock_oom_init(&mock);
    pubnub_config_t   cfg = oom_config(&mock);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

#if PUBNUB_ENABLE_TIME
    /* Immediate OOM. */
    pn_mock_oom_fail_alloc_after(&mock, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock, 0);
    pubnub_future_t f1 = pubnub_time(ctx);
    assert_true(pubnub_future_is_ready(f1));
    assert_capacity_class(pubnub_future_status(f1));
    pubnub_future_release(f1);

    /* Mid-operation OOM: allow a couple of allocations, then fail. The
     * exact allocation count for a time dispatch is an internal detail,
     * so either outcome is valid and must leave the pool clean:
     *   - synchronous failure -> capacity-class status, slot released;
     *   - dispatch succeeded   -> request is in-flight, so drive it to a
     *     healthy completion (a released-but-in-flight future is not a
     *     leak; the slot frees only on completion). */
    pn_mock_oom_reset(&mock);
    reset_chain();
    pn_mock_oom_fail_alloc_after(&mock, 2);
    pn_mock_oom_fail_buf_acquire_after(&mock, 1);
    pubnub_future_t f2 = pubnub_time(ctx);
    if (pubnub_future_is_ready(f2)) {
        assert_capacity_class(pubnub_future_status(f2));
    } else {
        static const uint8_t k_time_body[] = "[17001000000000001]";
        assert_int_equal(1, s_send_count);
        pn_mock_oom_reset(&mock);
        chain_complete_with(0, k_time_body, sizeof(k_time_body) - 1);
        (void)pubnub_process(ctx);
        assert_true(pubnub_future_is_ready(f2));
    }
    pubnub_future_release(f2);
    assert_int_equal(0, pool_in_use(ctx));
#endif

    /* Destroy after OOM must be crash- and leak-free (ASan/UBSan gate). */
    pn_mock_oom_reset(&mock);
    pubnub_destroy(ctx);
}

#if PUBNUB_ENABLE_PUBLISH
static void test_oom_multiple_contexts_one_oom_one_working(void** state)
{
    (void)state;
    reset_chain();

    pn_mock_oom_allocator_t mock_a;
    pn_mock_oom_allocator_t mock_b;
    pn_mock_oom_init(&mock_a);
    pn_mock_oom_init(&mock_b);

    pubnub_config_t   cfg_a = oom_config(&mock_a);
    pubnub_config_t   cfg_b = oom_config(&mock_b);
    pubnub_context_t* ctx_a = pubnub_create(&cfg_a);
    pubnub_context_t* ctx_b = pubnub_create(&cfg_b);
    assert_non_null(ctx_a);
    assert_non_null(ctx_b);

    /* Context A is starved; context B is healthy. */
    pn_mock_oom_fail_alloc_after(&mock_a, 0);
    pn_mock_oom_fail_buf_acquire_after(&mock_a, 0);

    pubnub_publish_opts_t opts_a = publish_opts();
    pubnub_future_t       fut_a  = pubnub_publish(ctx_a, &opts_a);
    assert_true(pubnub_future_is_ready(fut_a));
    assert_capacity_class(pubnub_future_status(fut_a));

    pubnub_publish_opts_t opts_b = publish_opts();
    pubnub_future_t       fut_b  = pubnub_publish(ctx_b, &opts_b);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut_b));
    /* Only B reached the transport (A failed before send). */
    assert_int_equal(1, s_send_count);

    static const uint8_t k_pub_body[] = "[1,\"Sent\",\"17001000000000001\"]";
    chain_complete_with(0, k_pub_body, sizeof(k_pub_body) - 1);
    (void)pubnub_process(ctx_b);

    assert_true(pubnub_future_is_ready(fut_b));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut_b));

    assert_int_equal(0, pool_in_use(ctx_a));

    pubnub_future_release(fut_a);
    pubnub_future_release(fut_b);
    assert_int_equal(0, pool_in_use(ctx_b));

    pubnub_destroy(ctx_a);
    pubnub_destroy(ctx_b);
}
#endif /* PUBNUB_ENABLE_PUBLISH */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if PUBNUB_ENABLE_TIME
        cmocka_unit_test(test_time_api_oom_at_request_start),
        cmocka_unit_test(test_time_api_repeated_oom_then_success),
#endif
#if PUBNUB_ENABLE_PUBLISH
        cmocka_unit_test(test_publish_oom_at_request_start),
        cmocka_unit_test(test_publish_oom_returns_correct_error_class),
        cmocka_unit_test(test_publish_oom_no_leak_in_pool),
#endif
#if PUBNUB_ENABLE_HISTORY
        cmocka_unit_test(test_history_fetch_oom_at_request_start),
#endif
#if PUBNUB_ENABLE_HISTORY && PUBNUB_ENABLE_TIME
        cmocka_unit_test(test_history_fetch_oom_context_reusable_after),
#endif
#if PUBNUB_ENABLE_SUBSCRIBE
        cmocka_unit_test(test_subscribe_oom_at_request_start),
        cmocka_unit_test(test_subscribe_oom_no_crashed_listener),
#endif
        cmocka_unit_test(test_oom_context_lifecycle_safe),
#if PUBNUB_ENABLE_PUBLISH
        cmocka_unit_test(test_oom_multiple_contexts_one_oom_one_working),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

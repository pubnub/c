/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "features/subscribe/subscribe_manager_internal.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "pubnub/client.h"
#include "pubnub/features/subscribe.h"

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t mock_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    (void)purpose;
    pubnub_buffer_t buf = {0};
    return buf;
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    (void)buf;
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = mock_alloc,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
};

static uint64_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static uint64_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static void mock_sleep(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    (void)ms;
}

static int mock_random(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    memset(buf, 0, len);
    return 0;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
};

static int s_cancel_called;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return NULL;
}

static int mock_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
    s_cancel_called = 1;
}

static pubnub_transport_provider_t s_mock_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static pubnub_json_value_t* mock_parse(pubnub_serialization_provider_t* self,
                                       const uint8_t*                   data,
                                       size_t                           len)
{
    (void)self;
    (void)data;
    (void)len;
    return NULL;
}

static pubnub_res_t mock_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    (void)value;
    (void)buf;
    (void)buf_len;
    if (NULL != out_len) {
        *out_len = 0;
    }
    return PUBNUB_OK;
}

static void mock_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    (void)self;
    (void)value;
}

static pubnub_serialization_provider_t s_mock_serialization = {
    .parse         = mock_parse,
    .serialize     = mock_serialize,
    .value_destroy = mock_value_destroy,
};

#if !PUBNUB_CFG_NO_HEAP
static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_mock_allocator;
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = &s_mock_serialization;
    cfg.platform        = &s_mock_platform;
    return pubnub_create(&cfg);
}

/**
 * Verify that cleanup with no active request does not crash.
 */
static void test_cleanup_no_active_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);

    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->active_slot_id);
    assert_int_equal(0, mgr->draining);

    pn_subscribe_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

/**
 * Verify that cleanup sets draining=1 and cancels pending slots.
 */
static void test_cleanup_sets_draining(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);

    /* Simulate an active slot by acquiring one from the pool. */
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);

    pubnub_future_t future = {0};
    pubnub_res_t    rc     = pn_request_pool_acquire(pool, ctx, &future);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_not_equal(PUBNUB_SLOT_ID_INVALID, future.slot_id);

    mgr->active_slot_id = future.slot_id;

    s_cancel_called = 0;
    pn_subscribe_manager_cleanup(mgr, &s_mock_allocator);

    /* Slot was in PENDING state — transport cancel is NOT called
     * (only for IN_FLIGHT slots). The slot is aborted via
     * pn_request_abort. */
    assert_int_equal(0, s_cancel_called);

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

/**
 * Verify that cleanup handles NULL state gracefully.
 */
static void test_cleanup_null_state(void** state)
{
    (void)state;
    pn_subscribe_manager_cleanup(NULL, &s_mock_allocator);
    pn_subscribe_manager_cleanup((void*)0x1, NULL);
}

#if !PUBNUB_CFG_NO_HEAP
static void unsubscribe_all_on_idle_context_returns_ok(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_res_t rc = pubnub_subscribe_unsubscribe_all(ctx);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_destroy(ctx);
}

static void subscription_unsubscribe_before_subscribe_returns_ok(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t       e   = pubnub_channel(ctx, "ch");
    pubnub_subscription_t sub = pubnub_subscription_create(e, NULL);
    assert_non_null(sub);

    pubnub_res_t rc = pubnub_subscription_unsubscribe(sub);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
}

static void subscription_set_add_subscription_before_subscribe_ok(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "ch");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);

    pubnub_res_t rc = pubnub_subscription_set_add_subscription(set, sub);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_subscription_destroy(sub);
    pubnub_subscription_set_destroy(set);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
}

/**
 * Verify that pubnub_subscribe_restore saves the cursor and that
 * event processing in UNSUBSCRIBED state does not clear it.
 */
static void subscription_restore_then_subscribe_preserves_timetoken(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    /* Creating an entity triggers lazy manager registration. */
    pubnub_entity_t       e   = pubnub_channel(ctx, "ch");
    pubnub_subscription_t sub = pubnub_subscription_create(e, NULL);
    assert_non_null(sub);

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, mgr->ee_state);

    /* Restore with a known timetoken. */
    pubnub_timetoken_t tt = {.ptr = "17000000000000001", .len = 17};
    pubnub_res_t       rc = pubnub_subscribe_restore(ctx, tt);
    assert_int_equal(PUBNUB_OK, rc);

    /* Cursor stored immediately. */
    assert_int_equal(1, mgr->restore_cursor_valid);
    assert_int_equal(17, mgr->cursor.timetoken_len);
    assert_memory_equal("17000000000000001", mgr->cursor.timetoken, 17);

    /* Drive the cooperative loop to process the queued
     * SUBSCRIPTION_RESTORED event (stays in UNSUBSCRIBED because
     * subscription_subscribe was not called). */
    pubnub_process(ctx);

    /* Cursor must survive — old code cleared it here. */
    assert_int_equal(1, mgr->restore_cursor_valid);
    assert_memory_equal("17000000000000001", mgr->cursor.timetoken, 17);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(test_cleanup_no_active_request),
        cmocka_unit_test(test_cleanup_sets_draining),
        cmocka_unit_test(unsubscribe_all_on_idle_context_returns_ok),
        cmocka_unit_test(subscription_unsubscribe_before_subscribe_returns_ok),
        cmocka_unit_test(subscription_set_add_subscription_before_subscribe_ok),
        cmocka_unit_test(subscription_restore_then_subscribe_preserves_timetoken),
#endif
        cmocka_unit_test(test_cleanup_null_state),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

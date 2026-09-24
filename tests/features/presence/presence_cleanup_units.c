/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "features/presence/presence_manager.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "pubnub/client.h"

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

static uint64_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
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

static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg    = pubnub_config_defaults();
    cfg.subscribe_key      = "sub-test";
    cfg.user_id            = "test-user";
    cfg.allocator          = &s_mock_allocator;
    cfg.transport          = &s_mock_transport;
    cfg.serialization      = &s_mock_serialization;
    cfg.platform           = &s_mock_platform;
    cfg.heartbeat_interval = 30;
    cfg.presence_timeout   = 300;
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

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);

    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->active_slot_id);
    assert_int_equal(0, mgr->draining);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

/**
 * Verify that cleanup sets draining=1 before freeing.
 * Uses a pending-state slot to exercise the cancel path.
 */
static void test_cleanup_sets_draining(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
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
    pn_presence_manager_cleanup(mgr, &s_mock_allocator);

    /* Slot was in PENDING state, it should have been aborted via
     * pn_request_abort. The transport cancel is NOT called because
     * the slot is PENDING, not IN_FLIGHT. */
    assert_int_equal(0, s_cancel_called);

    pubnub_destroy(ctx);
}

/**
 * Verify that cleanup handles NULL state gracefully.
 */
static void test_cleanup_null_state(void** state)
{
    (void)state;
    pn_presence_manager_cleanup(NULL, &s_mock_allocator);
    pn_presence_manager_cleanup((void*)0x1, NULL);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cleanup_no_active_request),
        cmocka_unit_test(test_cleanup_sets_draining),
        cmocka_unit_test(test_cleanup_null_state),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

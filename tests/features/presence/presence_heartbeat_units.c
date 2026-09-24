/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "features/presence/presence_effects.h"
#include "features/presence/presence_internal.h"
#include "pubnub/client.h"

/* ------------------------------------------------------------------
 * Mock providers — minimal set for pubnub_create()
 * ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

static pubnub_context_t* create_ctx_with_presence(uint32_t heartbeat_interval,
                                                  uint32_t presence_timeout)
{
    pubnub_config_t cfg    = pubnub_config_defaults();
    cfg.subscribe_key      = "sub-test";
    cfg.user_id            = "test-user";
    cfg.allocator          = &s_mock_allocator;
    cfg.transport          = &s_mock_transport;
    cfg.serialization      = &s_mock_serialization;
    cfg.platform           = &s_mock_platform;
    cfg.heartbeat_interval = heartbeat_interval;
    cfg.presence_timeout   = presence_timeout;
    return pubnub_create(&cfg);
}

/* ------------------------------------------------------------------
 * Heartbeat interval computation tests (via pn_presence_manager_create)
 * ------------------------------------------------------------------ */

static void test_both_zero_interval_disabled(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx_with_presence(0, 0);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(0, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

static void test_explicit_interval_takes_precedence(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx_with_presence(30, 0);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(30000, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

static void test_interval_zero_disabled_with_timeout_300(void** state)
{
    (void)state;
    /* interval=0 is an explicit opt-out; presence_timeout does not
     * derive an interval, so heartbeat stays disabled. */
    pubnub_context_t* ctx = create_ctx_with_presence(0, 300);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(0, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

static void test_interval_zero_disabled_with_timeout_20(void** state)
{
    (void)state;
    /* interval=0 opt-out holds regardless of presence_timeout magnitude. */
    pubnub_context_t* ctx = create_ctx_with_presence(0, 20);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(0, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

static void test_interval_zero_disabled_with_timeout_2(void** state)
{
    (void)state;
    /* Small presence_timeout still does not enable heartbeat. */
    pubnub_context_t* ctx = create_ctx_with_presence(0, 2);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(0, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

static void test_interval_zero_disabled_with_timeout_1(void** state)
{
    (void)state;
    /* Minimum presence_timeout still does not enable heartbeat. */
    pubnub_context_t* ctx = create_ctx_with_presence(0, 1);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(0, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

static void test_explicit_interval_overrides_timeout(void** state)
{
    (void)state;
    /* heartbeat_interval=5 takes precedence over presence_timeout=300 */
    pubnub_context_t* ctx = create_ctx_with_presence(5, 300);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(5000, mgr->heartbeat_interval_ms);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

/* ------------------------------------------------------------------
 * Heartbeat notification config caching tests
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * Heartbeat state tracking tests
 * ------------------------------------------------------------------ */

static void test_joined_transitions_to_heartbeating(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_JOINED};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[0].type);
}

/* ------------------------------------------------------------------
 * Null-safety tests
 * ------------------------------------------------------------------ */

static void test_manager_create_null_ctx(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr =
        pn_presence_manager_create(NULL, &s_mock_allocator);
    assert_null(mgr);
}

static void test_manager_create_null_allocator(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx_with_presence(0, 0);
    assert_non_null(ctx);

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, NULL);
    assert_null(mgr);

    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_both_zero_interval_disabled),
        cmocka_unit_test(test_explicit_interval_takes_precedence),
        cmocka_unit_test(test_interval_zero_disabled_with_timeout_300),
        cmocka_unit_test(test_interval_zero_disabled_with_timeout_20),
        cmocka_unit_test(test_interval_zero_disabled_with_timeout_2),
        cmocka_unit_test(test_interval_zero_disabled_with_timeout_1),
        cmocka_unit_test(test_explicit_interval_overrides_timeout),
        cmocka_unit_test(test_manager_create_null_ctx),
        cmocka_unit_test(test_manager_create_null_allocator),
        cmocka_unit_test(test_joined_transitions_to_heartbeating),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

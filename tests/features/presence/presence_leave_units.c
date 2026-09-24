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
#include "core/pn_string.h"
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

static int s_leave_send_count;
static int s_leave_fake_handle;

static pubnub_transport_handle_t* counting_send(pubnub_transport_provider_t* self,
                                                pubnub_http_request_t*  req,
                                                pubnub_http_response_t* resp)
{
    (void)self;
    (void)req;
    (void)resp;
    s_leave_send_count++;
    return (pubnub_transport_handle_t*)&s_leave_fake_handle;
}

static pubnub_transport_provider_t s_counting_transport = {
    .send              = counting_send,
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
 * Test helpers
 * ------------------------------------------------------------------ */

static pubnub_context_t* s_ctx;

static int group_setup(void** state)
{
    (void)state;
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_mock_allocator;
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = &s_mock_serialization;
    cfg.platform        = &s_mock_platform;
    s_ctx               = pubnub_create(&cfg);
    assert_non_null(s_ctx);
    return 0;
}

static int group_teardown(void** state)
{
    (void)state;
    if (NULL != s_ctx) {
        pubnub_destroy(s_ctx);
        s_ctx = NULL;
    }
    return 0;
}

static pn_presence_manager_t* create_mgr(void)
{
    pn_presence_manager_t* mgr =
        pn_presence_manager_create(s_ctx, &s_mock_allocator);
    assert_non_null(mgr);
    return mgr;
}

/* ------------------------------------------------------------------
 * pn_presence_left tests
 * ------------------------------------------------------------------ */

static void test_left_populates_leave_channels_buf(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    pn_presence_left(mgr, "ch2,ch3", "", "ch1", "", 0);

    assert_string_equal("ch1", mgr->leave_channels);
    assert_string_equal("ch2,ch3", mgr->channels);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_populates_leave_groups_buf(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    pn_presence_left(mgr, "", "grp-remain", "", "grp-gone", 0);

    assert_string_equal("grp-gone", mgr->leave_groups);
    assert_string_equal("grp-remain", mgr->groups);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_updates_remaining_channels(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    /* Manually populate active state (bypasses EE dispatch). */
    mgr->channels = pn_strdup("ch1,ch2,ch3", &s_mock_allocator);

    /* Now leave ch2 — remaining is ch1,ch3. */
    pn_presence_left(mgr, "ch1,ch3", "", "ch2", "", 0);

    assert_string_equal("ch1,ch3", mgr->channels);
    assert_string_equal("ch2", mgr->leave_channels);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_with_empty_removed_sets(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    pn_presence_left(mgr, "ch1", "", "", "", 0);

    /* Empty string input produces NULL (pn_strdup returns NULL for ""). */
    assert_null(mgr->leave_channels);
    assert_string_equal("ch1", mgr->channels);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_null_mgr_is_noop(void** state)
{
    (void)state;
    /* Must not crash. */
    pn_presence_left(NULL, "ch1", "", "ch2", "", 0);
}

/* ------------------------------------------------------------------
 * pn_presence_left_all tests
 * ------------------------------------------------------------------ */

static void test_left_all_moves_channels_to_leave_buf(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    /* Manually populate active state (bypasses EE dispatch). */
    mgr->channels = pn_strdup("ch1,ch2,ch3", &s_mock_allocator);

    pn_presence_left_all(mgr);

    assert_string_equal("ch1,ch2,ch3", mgr->leave_channels);
    assert_null(mgr->channels);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_all_moves_groups_to_leave_buf(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    /* Manually populate active state (bypasses EE dispatch). */
    mgr->groups = pn_strdup("grp1,grp2", &s_mock_allocator);

    pn_presence_left_all(mgr);

    assert_string_equal("grp1,grp2", mgr->leave_groups);
    assert_null(mgr->groups);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_all_clears_active_state(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    /* Manually populate active state (bypasses EE dispatch). */
    mgr->channels = pn_strdup("ch1", &s_mock_allocator);
    mgr->groups   = pn_strdup("grp1", &s_mock_allocator);

    pn_presence_left_all(mgr);

    assert_null(mgr->channels);
    assert_null(mgr->groups);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_all_when_already_empty(void** state)
{
    (void)state;
    pn_presence_manager_t* mgr = create_mgr();

    /* No channels joined; leave_all should leave everything NULL. */
    pn_presence_left_all(mgr);

    assert_null(mgr->leave_channels);
    assert_null(mgr->leave_groups);
    assert_null(mgr->channels);
    assert_null(mgr->groups);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_left_all_null_mgr_is_noop(void** state)
{
    (void)state;
    /* Must not crash. */
    pn_presence_left_all(NULL);
}

/* ------------------------------------------------------------------
 * NULL safety for pn_presence_joined (no EE dispatch)
 * ------------------------------------------------------------------ */

static void test_joined_null_mgr_is_noop(void** state)
{
    (void)state;
    /* Must not crash. */
    pn_presence_joined(NULL, "ch1", "");
}

static void test_suppress_leave_events_prevents_dispatch(void** state)
{
    (void)state;
    pubnub_config_t        cfg = pubnub_config_defaults();
    pubnub_context_t*      ctx;
    pn_presence_manager_t* mgr;

    cfg.subscribe_key         = "sub-test";
    cfg.user_id               = "test-user";
    cfg.allocator             = &s_mock_allocator;
    cfg.transport             = &s_counting_transport;
    cfg.serialization         = &s_mock_serialization;
    cfg.platform              = &s_mock_platform;
    cfg.suppress_leave_events = 1;

    ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(1, mgr->suppress_leave);

    /* Put EE into an active state so LEFT produces a LEAVE effect. */
    mgr->ee_state = PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN;

    s_leave_send_count = 0;

    /* Populate leave_channels and push LEFT event into the queue. */
    pn_presence_left(mgr, "", "", "ch1", "", 1);

    /* Tick drains the event queue: EE transitions COOLDOWN->INACTIVE
     * with CANCEL_HEARTBEAT + CANCEL_WAIT + LEAVE effects.
     * dispatch_leave sees suppress_leave=1 and returns immediately. */
    pn_presence_feature_tick(mgr);

    assert_int_equal(0, s_leave_send_count);

    /* Destroy context first: deinit cancels in-flight slots and fires
     * callbacks while mgr is still alive. Then free the manager. */
    pubnub_destroy(ctx);
    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

static void test_no_suppress_leave_events_allows_dispatch(void** state)
{
    (void)state;
    pubnub_config_t        cfg = pubnub_config_defaults();
    pubnub_context_t*      ctx;
    pn_presence_manager_t* mgr;

    cfg.subscribe_key         = "sub-test";
    cfg.user_id               = "test-user";
    cfg.allocator             = &s_mock_allocator;
    cfg.transport             = &s_counting_transport;
    cfg.serialization         = &s_mock_serialization;
    cfg.platform              = &s_mock_platform;
    cfg.suppress_leave_events = 0;

    ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    assert_int_equal(0, mgr->suppress_leave);

    /* Put EE into an active state so LEFT produces a LEAVE effect. */
    mgr->ee_state = PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN;

    s_leave_send_count = 0;

    /* Populate leave_channels and push LEFT event into the queue. */
    pn_presence_left(mgr, "", "", "ch1", "", 1);

    /* Tick drains the event queue: EE transitions COOLDOWN->INACTIVE
     * with CANCEL_HEARTBEAT + CANCEL_WAIT + LEAVE effects.
     * dispatch_leave proceeds and submits the HTTP request. */
    pn_presence_feature_tick(mgr);

    assert_true(0 < s_leave_send_count);

    pubnub_destroy(ctx);
    pn_presence_manager_cleanup(mgr, &s_mock_allocator);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* pn_presence_left */
        cmocka_unit_test(test_left_populates_leave_channels_buf),
        cmocka_unit_test(test_left_populates_leave_groups_buf),
        cmocka_unit_test(test_left_updates_remaining_channels),
        cmocka_unit_test(test_left_with_empty_removed_sets),
        cmocka_unit_test(test_left_null_mgr_is_noop),
        /* pn_presence_left_all */
        cmocka_unit_test(test_left_all_moves_channels_to_leave_buf),
        cmocka_unit_test(test_left_all_moves_groups_to_leave_buf),
        cmocka_unit_test(test_left_all_clears_active_state),
        cmocka_unit_test(test_left_all_when_already_empty),
        cmocka_unit_test(test_left_all_null_mgr_is_noop),
        /* NULL safety */
        cmocka_unit_test(test_joined_null_mgr_is_noop),
        /* suppress_leave_events dispatch gating */
        cmocka_unit_test(test_suppress_leave_events_prevents_dispatch),
        cmocka_unit_test(test_no_suppress_leave_events_allows_dispatch),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

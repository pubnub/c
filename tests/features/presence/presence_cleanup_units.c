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

static int                        s_cancel_called;
static pubnub_transport_handle_t* s_last_cancel_handle;
static pubnub_context_t*          s_probe_ctx;
static uint16_t                   s_probe_slot_id;
static int                        s_slot_ready_at_cancel;
static int                        s_send_returns_handle;
static char                       s_send_handle_backing;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return s_send_returns_handle ? (pubnub_transport_handle_t*)&s_send_handle_backing
                                 : NULL;
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
    s_cancel_called      = 1;
    s_last_cancel_handle = handle;
    if (NULL != s_probe_ctx && PUBNUB_SLOT_ID_INVALID != s_probe_slot_id) {
        pn_request_t* probe = pn_request_pool_get(
            pn_context_request_pool(s_probe_ctx), s_probe_slot_id);

        s_slot_ready_at_cancel =
            (NULL != probe && pn_request_is_ready(probe)) ? 1 : 0;
    }
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

/** Holds a pool slot in a terminal state so the pool can be filled. */
static uint16_t hold_slot(pubnub_context_t* ctx)
{
    pn_request_pool_t* pool   = pn_context_request_pool(ctx);
    pubnub_future_t    future = {0};
    pn_request_t*      slot;

    assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &future));
    slot        = pn_request_pool_get(pool, future.slot_id);
    slot->state = PN_REQUEST_COMPLETE;
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);
    return future.slot_id;
}

static pubnub_future_t enqueue_pending(pubnub_context_t* ctx, uint8_t feature_id)
{
    pn_pending_entry_t* entry = pn_prep_acquire(ctx);

    assert_non_null(entry);
    assert_int_equal(
        PUBNUB_OK,
        pn_pending_entry_init(
            entry, feature_id, NULL, NULL, NULL, PUBNUB_HTTP_GET, ctx, 0));
    return pn_dispatch_or_enqueue(ctx, entry);
}

/**
 * Cleanup aborts the promoted pool slot of a heartbeat whose pending id is
 * stale, and leaves an unrelated queued request alone.
 */
static void test_cleanup_aborts_promoted_pending_heartbeat(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);
    s_send_returns_handle = 1;
    s_cancel_called       = 0;

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    uint16_t            holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t            i;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        holders[i] = hold_slot(ctx);
    }
    pubnub_future_t beat = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_PRESENCE);
    pubnub_future_t other = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_PUBLISH);
    assert_true(beat.slot_id >= pn_context_pool_capacity(ctx));
    assert_int_equal(2, pn_pending_queue_count(queue));

    mgr->active_slot_id         = beat.slot_id;
    mgr->active_slot_generation = beat.generation;

    pn_request_pool_lock(pool);
    pn_request_pool_release(pool, holders[0]);
    pn_request_pool_unlock(pool);
    (void)pn_process_tick(ctx, 0);
    assert_int_equal(1, pn_pending_queue_count(queue));

    pn_pending_ref_t ref;
    pn_request_pool_lock(pool);
    ref = pn_context_pending_resolve_locked(ctx, beat.slot_id, beat.generation);
    pn_request_pool_unlock(pool);
    assert_int_equal(PN_PENDING_REF_REAL, ref.kind);
    assert_int_equal(PN_REQUEST_IN_FLIGHT,
                     pn_request_pool_get(pool, ref.real_slot)->state);

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);

    assert_int_equal(1, s_cancel_called);
    assert_true(pn_request_is_idle(pn_request_pool_get(pool, ref.real_slot)));
    assert_int_equal(1, pn_pending_queue_count(queue));
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(other));

    pubnub_destroy(ctx);
    s_send_returns_handle = 0;
}

/**
 * Cleanup cancels the transport handle of a completed heartbeat while its slot
 * is still ready, and only then releases the slot.
 */
static void test_cleanup_cancels_terminal_handle_before_release(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    s_cancel_called        = 0;
    s_last_cancel_handle   = NULL;
    s_slot_ready_at_cancel = -1;

    pn_presence_manager_t* mgr = pn_presence_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    uint16_t           sid  = hold_slot(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, sid);

    slot->transport_handle = (pubnub_transport_handle_t*)&sentinel;
    mgr->active_slot_id    = sid;
    s_probe_ctx            = ctx;
    s_probe_slot_id        = sid;

    pn_presence_manager_cleanup(mgr, &s_mock_allocator);

    assert_int_equal(1, s_cancel_called);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    assert_int_equal(1, s_slot_ready_at_cancel);
    assert_true(pn_request_is_idle(slot));
    assert_null(slot->transport_handle);

    s_probe_ctx     = NULL;
    s_probe_slot_id = PUBNUB_SLOT_ID_INVALID;
    pubnub_destroy(ctx);
    assert_int_equal(1, s_cancel_called);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cleanup_no_active_request),
        cmocka_unit_test(test_cleanup_sets_draining),
        cmocka_unit_test(test_cleanup_null_state),
        cmocka_unit_test(test_cleanup_aborts_promoted_pending_heartbeat),
        cmocka_unit_test(test_cleanup_cancels_terminal_handle_before_release),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

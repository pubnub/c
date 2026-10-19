/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_slot_release_units.c
 * @brief White-box tests for subscribe slot-release ordering.
 *
 * The transport cancel must run before the pool slot is released: release
 * bumps the slot generation the retry middleware matches its handle by.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/types_fwd.h"

/* White-box interposition: give the dispatch path a channel to subscribe to
 * without building a subscription registry. */
#define pn_subscribe_build_channel_string_alloc test_build_channel_string

/* White-box: pull the static effect implementations into this TU. */
#include "features/subscribe/subscribe_effects.c"

char* test_build_channel_string(const pn_subscribe_manager_t* mgr,
                                pubnub_allocator_provider_t*  alloc)
{
    char* out = (char*)alloc->alloc(alloc, 5U, 1U);

    (void)mgr;
    if (NULL != out) {
        memcpy(out, "test", 5U);
    }
    return out;
}

#include "pubnub/client.h"

#include "support/test_allocator.h"

extern pubnub_serialization_provider_t* pn_serialization_default(void);

#if !PUBNUB_CFG_NO_HEAP

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

/* Recording transport: cancel() captures the handle it received and,
 * when armed, snapshots whether the probed pool slot was still ready
 * (not yet released) at the moment cancel ran. */
static int                        s_cancel_count;
static pubnub_transport_handle_t* s_last_cancel_handle;
static pubnub_transport_handle_t* s_sentinel_handle;
static int                        s_saw_sentinel_cancel;
static pubnub_context_t*          s_probe_ctx;
static uint16_t                   s_probe_slot_id;
static int                        s_slot_ready_at_cancel;
static int                        s_send_returns_handle;
static int                        s_send_calls;
static uint16_t                   s_send_probe_slot;
static int                        s_cancel_seen_at_send;
static int                        s_in_use_at_send;
static char                       s_send_handle_backing;

static void reset_mock_state(void)
{
    s_send_returns_handle  = 0;
    s_send_calls           = 0;
    s_send_probe_slot      = PUBNUB_SLOT_ID_INVALID;
    s_cancel_seen_at_send  = -1;
    s_in_use_at_send       = -1;
    s_cancel_count         = 0;
    s_last_cancel_handle   = NULL;
    s_sentinel_handle      = NULL;
    s_saw_sentinel_cancel  = 0;
    s_probe_ctx            = NULL;
    s_probe_slot_id        = PUBNUB_SLOT_ID_INVALID;
    s_slot_ready_at_cancel = -1;
}

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    s_send_calls++;
    if (PUBNUB_SLOT_ID_INVALID != s_send_probe_slot && NULL != s_probe_ctx) {
        s_cancel_seen_at_send = s_saw_sentinel_cancel;
        s_in_use_at_send = (int)pn_context_request_pool(s_probe_ctx)->in_use_count;
    }
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
    s_cancel_count++;
    s_last_cancel_handle = handle;
    if (NULL != s_sentinel_handle && handle == s_sentinel_handle) {
        s_saw_sentinel_cancel = 1;
    }
    if (NULL != s_probe_ctx && PUBNUB_SLOT_ID_INVALID != s_probe_slot_id) {
        pn_request_pool_t* pool = pn_context_request_pool(s_probe_ctx);
        pn_request_t*      slot = pn_request_pool_get(pool, s_probe_slot_id);
        s_slot_ready_at_cancel =
            (NULL != slot && pn_request_is_ready(slot)) ? 1 : 0;
    }
}

static pubnub_transport_provider_t s_mock_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = pn_test_allocator();
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = pn_serialization_default();
    cfg.platform        = &s_mock_platform;
    return pubnub_create(&cfg);
}

/* Acquire a real pool slot and force it to a ready COMPLETE state with a
 * detachable transport handle, mimicking a completed long-poll. */
static uint16_t attach_ready_slot(pubnub_context_t*          ctx,
                                  pubnub_transport_handle_t* handle)
{
    pn_request_pool_t* pool   = pn_context_request_pool(ctx);
    pubnub_future_t    future = {0};
    pn_request_t*      slot;
    pubnub_res_t       rc;

    assert_non_null(pool);
    rc = pn_request_pool_acquire(pool, ctx, &future);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_not_equal(PUBNUB_SLOT_ID_INVALID, future.slot_id);

    slot = pn_request_pool_get(pool, future.slot_id);
    assert_non_null(slot);
    slot->state            = PN_REQUEST_COMPLETE;
    slot->transport_handle = handle;
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);

    return future.slot_id;
}

/*
 * Part 1 smoking gun: cancel_active_request must invoke the transport
 * cancel while the slot is still ready (pre-release). Before the fix the
 * slot was released first, so the slot read as idle at cancel time and
 * the retry middleware's pointer+generation lookup would miss.
 */
static void cancel_active_request_cancels_before_release(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    mgr->active_slot_id = sid;

    s_probe_ctx     = ctx;
    s_probe_slot_id = sid;

    cancel_active_request(mgr);

    assert_int_equal(1, s_cancel_count);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    /* The core assertion: slot was still ready when cancel ran. */
    assert_int_equal(1, s_slot_ready_at_cancel);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, sid);
    assert_true(pn_request_is_idle(slot));

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/**
 * A re-dispatch cancels and releases the completed old long-poll before
 * sending the successor, so the transport can reuse its keep-alive connection.
 */
static void redispatch_reaps_before_send(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();
    s_send_returns_handle = 1;

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    pn_request_pool_t* pool            = pn_context_request_pool(ctx);
    uint16_t           baseline_in_use = pool->in_use_count;
    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    mgr->active_slot_id = sid;
    s_sentinel_handle   = (pubnub_transport_handle_t*)&sentinel;
    s_probe_ctx         = ctx;
    s_probe_slot_id     = sid;
    s_send_probe_slot   = sid;

    dispatch_subscribe_request(mgr, 1 /* handshake */);

    assert_int_equal(1, s_send_calls);
    assert_int_equal(1, s_saw_sentinel_cancel);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    assert_int_equal(1, s_slot_ready_at_cancel);
    assert_int_equal(1, s_cancel_seen_at_send);
    assert_int_equal((int)baseline_in_use + 1, s_in_use_at_send);
    assert_int_equal(baseline_in_use + 1, pool->in_use_count);
    assert_int_not_equal(PUBNUB_SLOT_ID_INVALID, mgr->active_slot_id);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/**
 * Teardown cancels a completed long-poll's transport handle while its slot is
 * still ready, then releases the slot.
 */
static void manager_cleanup_cancels_terminal_handle_before_release(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    mgr->active_slot_id = sid;
    s_probe_ctx         = ctx;
    s_probe_slot_id     = sid;

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());

    assert_int_equal(1, s_cancel_count);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    assert_int_equal(1, s_slot_ready_at_cancel);
    assert_true(pn_request_is_idle(
        pn_request_pool_get(pn_context_request_pool(ctx), sid)));

    s_probe_ctx = NULL;
    pubnub_destroy(ctx);
    assert_int_equal(1, s_cancel_count);
}

/* Context helper: a live handle is cancelled once, while the slot is still
 * ready, and only then is the slot released. */
static void context_release_cancels_handle_then_releases(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    pn_request_t* slot = pn_request_pool_get(pn_context_request_pool(ctx), sid);
    uint16_t      gen  = slot->generation;

    s_probe_ctx     = ctx;
    s_probe_slot_id = sid;

    pn_context_release_terminal_slot(ctx, sid, gen);

    assert_int_equal(1, s_cancel_count);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    assert_int_equal(1, s_slot_ready_at_cancel);
    assert_true(pn_request_is_idle(slot));
    assert_null(slot->transport_handle);

    s_probe_ctx = NULL;
    pubnub_destroy(ctx);
    assert_int_equal(1, s_cancel_count);
}

static void context_release_without_handle_just_releases(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    uint16_t      sid  = attach_ready_slot(ctx, NULL);
    pn_request_t* slot = pn_request_pool_get(pn_context_request_pool(ctx), sid);

    pn_context_release_terminal_slot(ctx, sid, PN_GENERATION_ANY);

    assert_int_equal(0, s_cancel_count);
    assert_true(pn_request_is_idle(slot));

    pubnub_destroy(ctx);
}

static void context_release_with_stale_generation_is_a_noop(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    pn_request_t* slot = pn_request_pool_get(pn_context_request_pool(ctx), sid);

    pn_context_release_terminal_slot(ctx, sid, (uint16_t)(slot->generation + 1U));

    assert_int_equal(0, s_cancel_count);
    assert_false(pn_request_is_idle(slot));
    assert_ptr_equal((void*)&sentinel, (void*)slot->transport_handle);

    /* Out-of-range and NULL inputs are ignored. */
    pn_context_release_terminal_slot(ctx, UINT16_MAX - 1U, PN_GENERATION_ANY);
    pn_context_release_terminal_slot(NULL, sid, PN_GENERATION_ANY);
    pn_context_cancel_slot_transport(NULL, sid);
    assert_int_equal(0, s_cancel_count);

    pn_context_release_terminal_slot(ctx, sid, PN_GENERATION_ANY);
    assert_int_equal(1, s_cancel_count);
    pubnub_destroy(ctx);
}

/* The cancel-only variant clears the handle and leaves the slot allocated. */
static void context_cancel_slot_transport_keeps_slot(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    pn_request_t* slot = pn_request_pool_get(pn_context_request_pool(ctx), sid);

    pn_context_cancel_slot_transport(ctx, sid);
    pn_context_cancel_slot_transport(ctx, sid);

    assert_int_equal(1, s_cancel_count);
    assert_null(slot->transport_handle);
    assert_false(pn_request_is_idle(slot));

    pubnub_destroy(ctx);
}

/* Dispatches a queued request for the given feature; the pool must be full. */
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
 * Teardown aborts the promoted pool slot of a subscribe request whose pending
 * id is stale, and leaves the unrelated queued request alone.
 */
static void cancel_active_request_aborts_promoted_pending_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();
    s_send_returns_handle = 1;

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);
    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    uint16_t            holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t            i;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        holders[i] = attach_ready_slot(ctx, NULL);
    }

    pubnub_future_t sub = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_SUBSCRIBE);
    pubnub_future_t other = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_PUBLISH);
    assert_int_equal(PUBNUB_IN_PROGRESS, sub.status);
    assert_int_equal(PUBNUB_IN_PROGRESS, other.status);
    assert_true(sub.slot_id >= pn_context_pool_capacity(ctx));
    assert_int_equal(2, pn_pending_queue_count(queue));

    mgr->active_slot_id         = sub.slot_id;
    mgr->active_slot_generation = sub.generation;

    /* Freeing one slot promotes the subscribe request; the other stays queued. */
    pn_request_pool_lock(pool);
    pn_request_pool_release(pool, holders[0]);
    pn_request_pool_unlock(pool);
    (void)pn_process_tick(ctx, 0);
    assert_int_equal(1, pn_pending_queue_count(queue));

    pn_pending_ref_t ref;
    pn_request_pool_lock(pool);
    ref = pn_context_pending_resolve_locked(ctx, sub.slot_id, sub.generation);
    pn_request_pool_unlock(pool);
    assert_int_equal(PN_PENDING_REF_REAL, ref.kind);
    assert_int_equal(PN_REQUEST_IN_FLIGHT,
                     pn_request_pool_get(pool, ref.real_slot)->state);

    cancel_active_request(mgr);

    assert_int_equal(1, s_cancel_count);
    assert_true(pn_request_is_idle(pn_request_pool_get(pool, ref.real_slot)));
    assert_int_equal(1, pn_pending_queue_count(queue));
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(other));

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * Cleanup of a manager whose active request still waits in the queue must
 * drop exactly that request.
 */
static void cleanup_cancels_queued_active_request_only(void** state)
{
    (void)state;
    if (PUBNUB_CFG_MAX_PENDING_REQUESTS < 3) {
        skip();
    }
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        (void)attach_ready_slot(ctx, NULL);
    }
    pubnub_future_t first = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_PUBLISH);
    pubnub_future_t sub = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_SUBSCRIBE);
    pubnub_future_t last = enqueue_pending(ctx, (uint8_t)PUBNUB_FEATURE_PUBLISH);

    mgr->active_slot_id         = sub.slot_id;
    mgr->active_slot_generation = sub.generation;
    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());

    /* The middle request is gone; its neighbours are still queued and
     * addressable. */
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(first));
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(last));
    assert_int_not_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(sub));

    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
#if !PUBNUB_CFG_NO_HEAP
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(cancel_active_request_cancels_before_release),
        cmocka_unit_test(redispatch_reaps_before_send),
        cmocka_unit_test(cancel_active_request_aborts_promoted_pending_request),
        cmocka_unit_test(cleanup_cancels_queued_active_request_only),
        cmocka_unit_test(manager_cleanup_cancels_terminal_handle_before_release),
        cmocka_unit_test(context_release_cancels_handle_then_releases),
        cmocka_unit_test(context_release_without_handle_just_releases),
        cmocka_unit_test(context_release_with_stale_generation_is_a_noop),
        cmocka_unit_test(context_cancel_slot_transport_keeps_slot),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
#else
    return 0;
#endif
}

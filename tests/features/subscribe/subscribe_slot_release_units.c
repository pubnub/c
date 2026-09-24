/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_slot_release_units.c
 * @brief White-box unit tests for the subscribe slot-release ordering fix.
 *
 * Includes subscribe_effects.c directly to reach cancel_active_request,
 * dispatch_subscribe_request (parked-drain path), and the manager
 * lifecycle. These tests pin the ordering invariant behind the arena
 * RX-buffer exhaustion regression: the transport cancel for a stale
 * long-poll handle must run BEFORE the owning pool slot is released,
 * because pn_request_pool_release bumps the slot generation and the
 * retry middleware matches its tracked inner handle by pointer AND
 * generation. Releasing first strands the inner handle (and its rx_buf)
 * because the post-release generation no longer matches.
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

/* White-box interposition: dispatch_subscribe_request's reap epilogue
 * branches on pn_context_has_bg_thread, but a live bg-thread handle cannot be
 * set on an opaque context. Redirect that one call site to a test flag so both
 * the bg-mode park and the cooperative inline-reap paths are reachable. */
static int s_force_bg_thread;

static int test_ctx_has_bg_thread(const pubnub_context_t* ctx)
{
    (void)ctx;
    return s_force_bg_thread;
}

#define pn_context_has_bg_thread test_ctx_has_bg_thread

/* White-box: pull the static effect implementations into this TU. */
#include "features/subscribe/subscribe_effects.c"

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

static void reset_mock_state(void)
{
    s_cancel_count         = 0;
    s_last_cancel_handle   = NULL;
    s_sentinel_handle      = NULL;
    s_saw_sentinel_cancel  = 0;
    s_probe_ctx            = NULL;
    s_probe_slot_id        = PUBNUB_SLOT_ID_INVALID;
    s_slot_ready_at_cancel = -1;
    s_force_bg_thread      = 0;
}

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

/*
 * Manager construction must seed prev_reap_slot_id to the INVALID
 * sentinel — memset zeroes the field but 0 is a valid slot id.
 */
static void create_initializes_prev_reap_slot_invalid(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->prev_reap_slot_id);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * Part 4: context teardown while a bg-thread deferral is parked must
 * cancel the parked handle AND release the parked slot (no slot leak).
 */
static void cleanup_drains_parked_handle_and_slot(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    pn_request_pool_t* pool   = pn_context_request_pool(ctx);
    pubnub_future_t    future = {0};
    assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &future));
    uint16_t sid           = future.slot_id;
    uint16_t before_in_use = pool->in_use_count;

    s_sentinel_handle      = (pubnub_transport_handle_t*)&sentinel;
    mgr->prev_reap_handle  = s_sentinel_handle;
    mgr->prev_reap_slot_id = sid;

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());

    assert_int_equal(1, s_saw_sentinel_cancel);
    pn_request_t* slot = pn_request_pool_get(pool, sid);
    assert_true(pn_request_is_idle(slot));
    assert_int_equal(before_in_use - 1, pool->in_use_count);

    pubnub_destroy(ctx);
}

/*
 * Edge case exercised by the fix: a parked slot with NO handle (handle
 * was already NULL when detached) must still be released on teardown —
 * the slot release is gated on the slot id, not on the handle.
 */
static void cleanup_releases_parked_slot_without_handle(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    pn_request_pool_t* pool   = pn_context_request_pool(ctx);
    pubnub_future_t    future = {0};
    assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &future));
    uint16_t sid = future.slot_id;

    mgr->prev_reap_handle  = NULL;
    mgr->prev_reap_slot_id = sid;

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());

    assert_int_equal(0, s_cancel_count);
    pn_request_t* slot = pn_request_pool_get(pool, sid);
    assert_true(pn_request_is_idle(slot));

    pubnub_destroy(ctx);
}

/*
 * Part 2 (bg-thread deferral drain): the next re-dispatch must drain a
 * parked handle+slot at entry — cancel the handle and release the slot,
 * then clear both fields. dispatch bails out afterwards (no channels),
 * but the entry drain runs unconditionally.
 */
static void redispatch_drains_parked_handle_and_slot(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    pn_request_pool_t* pool   = pn_context_request_pool(ctx);
    pubnub_future_t    future = {0};
    assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &future));
    uint16_t sid = future.slot_id;

    s_sentinel_handle      = (pubnub_transport_handle_t*)&sentinel;
    mgr->prev_reap_handle  = s_sentinel_handle;
    mgr->prev_reap_slot_id = sid;

    dispatch_subscribe_request(mgr, 1 /* handshake */);

    assert_int_equal(1, s_saw_sentinel_cancel);
    assert_null(mgr->prev_reap_handle);
    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->prev_reap_slot_id);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * End-to-end park→drain (bg-thread mode). Cycle 1 runs the reap epilogue
 * with a completed prior long-poll in active_slot_id: the handle is
 * detached and, because bg-thread mode is forced, BOTH handle and slot are
 * parked (no cancel yet, slot generation intact). Cycle 2 drains at entry:
 * cancel runs on the real inner handle BEFORE the slot is released, then
 * both prev_reap fields clear and the slot returns to the pool.
 *
 * With no channels registered, each dispatch bails at build_wire_inputs
 * (INVALID_ARGUMENT) before acquiring a new slot — so the detach/park and
 * entry-drain run deterministically without a live transport send.
 */
static void redispatch_bg_mode_parks_then_drains(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();
    s_force_bg_thread = 1;

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    pn_request_pool_t* pool            = pn_context_request_pool(ctx);
    uint16_t           baseline_in_use = pool->in_use_count;
    uint16_t sid = attach_ready_slot(ctx, (pubnub_transport_handle_t*)&sentinel);
    mgr->active_slot_id = sid;
    s_sentinel_handle   = (pubnub_transport_handle_t*)&sentinel;

    /* Cycle 1: detach + park (bg-thread mode defers the cancel). */
    dispatch_subscribe_request(mgr, 1 /* handshake */);

    assert_int_equal(0, s_cancel_count);
    assert_ptr_equal((void*)&sentinel, (void*)mgr->prev_reap_handle);
    assert_int_equal(sid, mgr->prev_reap_slot_id);
    pn_request_t* parked = pn_request_pool_get(pool, sid);
    assert_true(pn_request_is_ready(parked));
    assert_int_equal(baseline_in_use + 1, pool->in_use_count);

    /* Cycle 2: entry drain cancels the parked handle before releasing. */
    s_probe_ctx     = ctx;
    s_probe_slot_id = sid;

    dispatch_subscribe_request(mgr, 0 /* receive */);

    assert_int_equal(1, s_saw_sentinel_cancel);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    assert_int_equal(1, s_slot_ready_at_cancel);
    assert_null(mgr->prev_reap_handle);
    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->prev_reap_slot_id);
    assert_int_equal(baseline_in_use, pool->in_use_count);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * Cooperative-mode variant: no parking. The reap epilogue cancels the
 * detached handle and releases the slot inline within the same dispatch
 * call. Cancel still precedes the slot release (generation intact).
 */
static void redispatch_cooperative_reaps_inline(void** state)
{
    (void)state;
    int               sentinel = 0;
    pubnub_context_t* ctx      = create_ctx();
    assert_non_null(ctx);
    reset_mock_state();
    s_force_bg_thread = 0;

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

    dispatch_subscribe_request(mgr, 1 /* handshake */);

    assert_int_equal(1, s_saw_sentinel_cancel);
    assert_ptr_equal((void*)&sentinel, (void*)s_last_cancel_handle);
    assert_int_equal(1, s_slot_ready_at_cancel);
    assert_null(mgr->prev_reap_handle);
    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->prev_reap_slot_id);
    assert_int_equal(baseline_in_use, pool->in_use_count);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
#if !PUBNUB_CFG_NO_HEAP
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(cancel_active_request_cancels_before_release),
        cmocka_unit_test(create_initializes_prev_reap_slot_invalid),
        cmocka_unit_test(cleanup_drains_parked_handle_and_slot),
        cmocka_unit_test(cleanup_releases_parked_slot_without_handle),
        cmocka_unit_test(redispatch_drains_parked_handle_and_slot),
        cmocka_unit_test(redispatch_bg_mode_parks_then_drains),
        cmocka_unit_test(redispatch_cooperative_reaps_inline),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
#else
    return 0;
#endif
}

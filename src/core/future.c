/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file future.c
 * @brief Public query/consumption API for pubnub_future_t handles.
 *
 * Lives in the core library (not runtime) because the queries need
 * to traverse pubnub_context_t via pn_context_request_pool() to find
 * the slot the future refers to.
 *
 * Pending-range futures (slot_id >= pool capacity) are resolved through
 * pn_context_pending_resolve_locked(): the future's generation is the
 * identity epoch of its pending-slot-map entry, and a promoted request is
 * followed to its pool slot and that slot's generation. A recycled entry or
 * slot resolves to "stale" rather than to another request's state.
 */

#include "pubnub/future.h"

#include "core_internal.h"
#include "pn_lock.h"
#include "runtime/pending_queue_internal.h"
#include "runtime/pipeline_internal.h"
#include "runtime/request_internal.h"
#include "runtime/request_pool_internal.h"

#include <stddef.h>

/**
 * @brief Resolve a future to a pool slot, a queued entry, or a terminal
 *        marker. Takes the context lock only for pending-range ids.
 *
 * The lock is dropped before the caller inspects the slot, so direct and
 * promoted futures are validated against the returned generation.
 */
static pn_pending_ref_t future_resolve(pubnub_future_t future)
{
    pn_pending_ref_t   ref  = {PN_PENDING_REF_STALE, 0, 0, 0, NULL};
    pn_request_pool_t* pool = pn_context_request_pool(future.ctx);

    if (NULL == pool) {
        return ref;
    }
    if (future.slot_id < pool->capacity) {
        ref.kind            = PN_PENDING_REF_REAL;
        ref.real_slot       = future.slot_id;
        ref.real_generation = future.generation;
        return ref;
    }

    pn_request_pool_lock(pool);
    ref = pn_context_pending_resolve_locked(
        future.ctx, future.slot_id, future.generation);
    pn_request_pool_unlock(pool);
    return ref;
}

bool pubnub_future_is_ready(pubnub_future_t future)
{
    pn_request_pool_t* pool;
    pn_pending_ref_t   ref;
    pn_request_t*      slot;

    if (NULL == future.ctx) {
        return true;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return true;
    }

    pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return true;
    }

    ref = future_resolve(future);
    if (PN_PENDING_REF_QUEUED == ref.kind) {
        return false;
    }
    if (PN_PENDING_REF_REAL != ref.kind) {
        return true;
    }

    slot = pn_request_pool_get(pool, ref.real_slot);
    if (NULL == slot || ref.real_generation != slot->generation) {
        return true;
    }

    return pn_request_is_ready(slot) != 0;
}

pubnub_res_t pubnub_future_status(pubnub_future_t future)
{
    pn_request_pool_t* pool;
    pn_pending_ref_t   ref;
    pn_request_t*      slot;

    if (NULL == future.ctx || PUBNUB_IN_PROGRESS != future.status) {
        return future.status;
    }

    pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    ref = future_resolve(future);
    if (PN_PENDING_REF_CANCELLED == ref.kind) {
        return PUBNUB_ERR_CANCELLED;
    }
    if (PN_PENDING_REF_QUEUED == ref.kind) {
        return PUBNUB_IN_PROGRESS;
    }
    if (PN_PENDING_REF_REAL != ref.kind) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    slot = pn_request_pool_get(pool, ref.real_slot);
    if (NULL == slot || ref.real_generation != slot->generation) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (!pn_request_is_ready(slot)) {
        return PUBNUB_IN_PROGRESS;
    }

    return slot->result;
}

void pubnub_future_release(pubnub_future_t future)
{
    pn_pending_cancel_data_t     cancel_data = {0};
    pn_request_pool_t*           pool;
    pn_request_t*                slot;
    pubnub_transport_handle_t*   handle = NULL;
    pubnub_transport_provider_t* chain_head;
    uint16_t                     real_slot;
    uint16_t                     real_generation;

    if (NULL == future.ctx) {
        return;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return;
    }

    pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return;
    }

    /* Id resolution, pending-queue cancellation and the slot-state decision
     * share one critical section: a promotion between them could move the
     * request to a pool slot and invalidate the queue position. */
    pn_request_pool_lock(pool);
    if (future.slot_id < pool->capacity) {
        real_slot       = future.slot_id;
        real_generation = future.generation;
    } else {
        /* Callbacks are extracted under the lock and fired outside it so
         * they may re-enter the SDK. */
        pn_pending_ref_t ref = pn_context_pending_cancel_locked(
            future.ctx, future.slot_id, future.generation, 1, &cancel_data);

        if (PN_PENDING_REF_REMOVED == ref.kind) {
            pn_request_pool_unlock(pool);
            pn_pending_cancel_data_run(&cancel_data);
            return;
        }
        if (PN_PENDING_REF_REAL != ref.kind) {
            pn_request_pool_unlock(pool);
            return;
        }
        real_slot       = ref.real_slot;
        real_generation = ref.real_generation;
    }

    slot = pn_request_pool_get(pool, real_slot);
    if (NULL == slot || real_generation != slot->generation) {
        pn_request_pool_unlock(pool);
        return;
    }
    if (PN_REQUEST_COMPLETING == slot->state || PN_REQUEST_IN_FLIGHT == slot->state) {
        /* Transport handle is still live (IN_FLIGHT) or callback
         * delivery is in progress (COMPLETING); defer the release
         * until the process tick routes completion. */
        slot->release_deferred = 1;
        pn_request_pool_unlock(pool);
        return;
    }

    /* Terminal slot. A successful response keeps transport_handle live
     * because response->body aliases its rx buffer. The transport is not
     * thread-safe, so when another thread owns it the slot is handed to
     * pn_process_tick, which cancels and reclaims it. The generation is not
     * bumped: retry and compression middleware look the slot up by pointer
     * and generation. */
    handle = slot->transport_handle;
    if (NULL != handle) {
        if (0 == pn_context_transport_claim_locked(future.ctx)) {
            slot->release_deferred = 1;
            pn_request_pool_unlock(pool);
            pn_context_wake(future.ctx);
            return;
        }
        slot->transport_handle = NULL;
        pn_request_pool_unlock(pool);

        /* Cancel OUTSIDE the lock: it may call the allocator or fire
         * callbacks. The claim keeps pn_process_tick out of the transport
         * meanwhile. */
        chain_head = pn_context_pipeline_chain_head(future.ctx);
        if (NULL != chain_head && NULL != chain_head->cancel) {
            chain_head->cancel(chain_head, handle);
        }

        pn_request_pool_lock(pool);
        pn_context_transport_unclaim_locked(future.ctx);
        /* A concurrent release of the same future may have reclaimed (and
         * re-acquired) the slot while the cancel ran; only release our own
         * generation. */
        if (real_generation == slot->generation) {
            pn_request_pool_release(pool, real_slot);
        }
        pn_request_pool_unlock(pool);
        return;
    }

    if (slot->release_deferred) {
        /* The tick owns the handle and reclaims the slot itself. Releasing
         * here would bump the generation the middleware's cancel lookup uses. */
        pn_request_pool_unlock(pool);
        return;
    }
    pn_request_pool_release(pool, real_slot);
    pn_request_pool_unlock(pool);
}

pubnub_res_t pubnub_future_cancel(pubnub_future_t future)
{
    pn_pending_cancel_data_t cancel_data = {0};
    pn_request_pool_t*       pool        = NULL;
    pn_request_t*            slot        = NULL;
    uint16_t                 real_slot;
    uint16_t                 real_generation;

    if (NULL == future.ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return PUBNUB_IN_PROGRESS;
    }

    pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Records intent only; pn_process_tick performs the transport cancel
     * and terminal transition. Id resolution, queue cancellation and the
     * flag share one critical section so a promotion cannot slip between. */
    pn_request_pool_lock(pool);
    if (future.slot_id < pool->capacity) {
        real_slot       = future.slot_id;
        real_generation = future.generation;
    } else {
        /* Callbacks fire outside the lock, as in pubnub_future_release. */
        pn_pending_ref_t ref = pn_context_pending_cancel_locked(
            future.ctx, future.slot_id, future.generation, 0, &cancel_data);

        if (PN_PENDING_REF_REMOVED == ref.kind) {
            pn_request_pool_unlock(pool);
            pn_pending_cancel_data_run(&cancel_data);
            return PUBNUB_OK;
        }
        if (PN_PENDING_REF_REAL != ref.kind) {
            pn_request_pool_unlock(pool);
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        real_slot       = ref.real_slot;
        real_generation = ref.real_generation;
    }

    slot = pn_request_pool_get(pool, real_slot);
    if (NULL == slot || real_generation != slot->generation) {
        pn_request_pool_unlock(pool);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (PN_REQUEST_PENDING != slot->state && PN_REQUEST_IN_FLIGHT != slot->state) {
        /* Terminal, completing, or idle: nothing live to cancel. */
        pn_request_pool_unlock(pool);
        return PUBNUB_IN_PROGRESS;
    }
    slot->cancel_requested = 1;
    pn_request_pool_unlock(pool);

    /* Break the owning thread out of a blocking poll so the cancel is
     * serviced promptly rather than at the next poll timeout. */
    pn_context_wake(future.ctx);

    return PUBNUB_OK;
}

/**
 * @brief Internal adapter: bridges pubnub_async_cb_t to pn_request_cb_t.
 *
 * Stored as the slot's on_complete when pubnub_async registers a
 * callback on a live (non-ready) slot. user_data carries the
 * pubnub_context_t pointer set during pubnub_async registration.
 */
static void async_trampoline(pn_request_t* request, pubnub_res_t status, void* user_data)
{
    if (NULL == request || NULL == request->async_cb) {
        return;
    }

    pubnub_context_t* ctx = (pubnub_context_t*)user_data;

    pubnub_future_t fut = {
        .ctx        = ctx,
        .slot_id    = request->slot_id,
        .generation = request->generation,
        .status     = PUBNUB_IN_PROGRESS,
    };

    pubnub_async_cb_t cb   = request->async_cb;
    void*             udat = request->async_cb_user_data;

    /* Clear so the callback is not invoked twice. */
    request->async_cb           = NULL;
    request->async_cb_user_data = NULL;

    cb(fut, status, udat);
}

pubnub_res_t pubnub_await(pubnub_future_t future)
{
    if (NULL == future.ctx) {
        return future.status;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return future.status;
    }

    pubnub_context_t*           ctx      = future.ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);

    /* pubnub_await never starts a background thread — that is the
     * exclusive responsibility of pubnub_async. Starting a thread here
     * would permanently change context semantics (disabling
     * pubnub_process) as an invisible side effect of await.
     *
     * Two modes of operation:
     * 1. Background thread already running (started by prior
     *    pubnub_async): poll is_ready with short sleeps.
     * 2. No background thread: drive pubnub_process cooperatively. */
    if (PUBNUB_CFG_THREAD_SAFETY && pn_context_has_bg_thread(ctx)) {
        while (!pubnub_future_is_ready(future)) {
            if (NULL != platform && NULL != platform->sleep_ms) {
                platform->sleep_ms(platform, 10);
            }
        }
        return pubnub_future_status(future);
    }

    /* Cooperative fallback: blocking poll until socket data arrives. */
    while (!pubnub_future_is_ready(future)) {
        if (PUBNUB_CFG_THREAD_SAFETY && pn_context_has_bg_thread(ctx)) {
            if (NULL != platform && NULL != platform->sleep_ms) {
                platform->sleep_ms(platform, 10);
            }
            continue;
        }
        pubnub_res_t tick_rc = pn_process_tick(ctx, PUBNUB_CFG_MAX_POLL_MS);
        if (PUBNUB_IN_PROGRESS == tick_rc && NULL != platform
            && NULL != platform->sleep_ms) {
            platform->sleep_ms(platform, 5);
        }
    }

    return pubnub_future_status(future);
}

pubnub_res_t pubnub_async(pubnub_future_t   future,
                          pubnub_async_cb_t callback,
                          void*             user_data)
{
    if (NULL == callback) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == future.ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        callback(future, future.status, user_data);
        return PUBNUB_OK;
    }

    /* Lazily start the background processing thread so callbacks fire
     * without the user needing a manual pubnub_process loop. Non-fatal
     * if threads are unavailable - callback will fire when the user
     * calls pubnub_process manually (cooperative fallback). */
    (void)pn_context_start_bg_thread(future.ctx);

    pn_request_pool_t*          pool     = pn_context_request_pool(future.ctx);
    pubnub_platform_provider_t* platform = pn_context_platform(future.ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(future.ctx);

    if (NULL == pool) {
        callback(future, PUBNUB_ERR_NOT_INITIALIZED, user_data);
        return PUBNUB_OK;
    }

    /* Acquire context lock before touching pending entries or slot
     * state. Prevents race with pn_process_promote_pending which
     * dequeues and promotes entries under the same lock. */
    pn_ctx_lock(platform, lock);

    /* Resolve under the lock — the request may be promoted at any time
     * outside it. */
    pn_pending_ref_t ref = pn_context_pending_resolve_locked(
        future.ctx, future.slot_id, future.generation);

    if (PN_PENDING_REF_CANCELLED == ref.kind) {
        pn_ctx_unlock(platform, lock);
        callback(future, PUBNUB_ERR_CANCELLED, user_data);
        return PUBNUB_OK;
    }

    if (PN_PENDING_REF_QUEUED == ref.kind) {
        /* Still in pending queue. Store callback on the entry. */
        ref.entry->async_cb           = callback;
        ref.entry->async_cb_user_data = user_data;
        ref.entry->on_complete        = async_trampoline;
        ref.entry->user_data          = future.ctx;

        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK;
    }

    if (PN_PENDING_REF_REAL != ref.kind) {
        pn_ctx_unlock(platform, lock);
        callback(future, PUBNUB_ERR_INVALID_ARGUMENT, user_data);
        return PUBNUB_OK;
    }

    /* Real slot path (either direct or post-promotion). */
    pn_request_t* slot = pn_request_pool_get(pool, ref.real_slot);
    if (NULL == slot || ref.real_generation != slot->generation) {
        pn_ctx_unlock(platform, lock);
        callback(future, PUBNUB_ERR_INVALID_ARGUMENT, user_data);
        return PUBNUB_OK;
    }

    if (pn_request_is_ready(slot)) {
        pubnub_res_t result = slot->result;
        pn_ctx_unlock(platform, lock);
        callback(future, result, user_data);
        return PUBNUB_OK;
    }

    slot->async_cb           = callback;
    slot->async_cb_user_data = user_data;
    slot->on_complete        = async_trampoline;
    slot->user_data          = future.ctx;

    pn_ctx_unlock(platform, lock);
    return PUBNUB_OK;
}

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
 * Pending-range futures (slot_id >= pool capacity) are resolved via
 * the context's pending_slot_map. Before promotion the map entry is
 * PUBNUB_SLOT_ID_INVALID (not ready); after promotion it holds the
 * real slot_id. Cancelled pending entries use PN_SLOT_ID_CANCELLED
 * so accessors can report terminal state without the entry itself.
 */

#include "pubnub/future.h"

#include "core_internal.h"
#include "pn_lock.h"
#include "runtime/pending_queue_internal.h"
#include "runtime/pipeline_internal.h"
#include "runtime/request_internal.h"
#include "runtime/request_pool_internal.h"

#include <stddef.h>

/** @brief Map sentinel for cancelled pending entries. Distinct from
 *  PUBNUB_SLOT_ID_INVALID ("not yet promoted") so accessors report
 *  the future as terminal (is_ready = true, status = CANCELLED). */
#define PN_SLOT_ID_CANCELLED ((uint16_t)(UINT16_MAX - 1))

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + PUBNUB_CFG_MAX_PENDING_REQUESTS
                         < (UINT16_MAX - 1),
                     "pool + pending capacity must not reach sentinel values");

/** @brief Non-zero if the future originated from the pending range
 *  (slot_id >= pool capacity). Pending-range futures are validated
 *  by map-entry invalidation, not by generation counters. */
static int pn_future_is_pending_range(pubnub_future_t future)
{
    uint16_t capacity = pn_context_pool_capacity(future.ctx);
    return 0 != capacity && future.slot_id >= capacity;
}

/** @brief Non-zero if the future's generation matches the slot's current
 *  generation. Always returns 1 (valid) for pending-range futures
 *  because they rely on map invalidation for ABA protection instead. */
static int pn_future_generation_valid(pubnub_future_t future, const pn_request_t* slot)
{
    if (NULL == slot) {
        return 0;
    }
    if (pn_future_is_pending_range(future)) {
        return 1;
    }
    return future.generation == slot->generation;
}

/**
 * @brief Resolve a pending-range future to the real slot_id, or
 *        PUBNUB_SLOT_ID_INVALID if not yet promoted.
 */
static uint16_t resolve_pending_slot(pubnub_future_t future)
{
    uint16_t capacity = pn_context_pool_capacity(future.ctx);
    if (0 == capacity || future.slot_id < capacity) {
        return future.slot_id;
    }

    uint16_t  pending_idx = (uint16_t)(future.slot_id - capacity);
    uint16_t* map         = pn_context_pending_slot_map(future.ctx);
    if (NULL == map) {
        return PUBNUB_SLOT_ID_INVALID;
    }

    return map[pending_idx];
}

bool pubnub_future_is_ready(pubnub_future_t future)
{
    if (NULL == future.ctx) {
        return true;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return true;
    }

    uint16_t real_slot = resolve_pending_slot(future);
    if (PN_SLOT_ID_CANCELLED == real_slot) {
        return true;
    }
    if (PUBNUB_SLOT_ID_INVALID == real_slot) {
        return false;
    }

    pn_request_pool_t* pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return true;
    }

    pn_request_t* slot = pn_request_pool_get(pool, real_slot);
    if (NULL == slot) {
        return true;
    }

    if (!pn_future_generation_valid(future, slot)) {
        return true;
    }

    return pn_request_is_ready(slot) != 0;
}

pubnub_res_t pubnub_future_status(pubnub_future_t future)
{
    if (NULL == future.ctx || PUBNUB_IN_PROGRESS != future.status) {
        return future.status;
    }

    uint16_t real_slot = resolve_pending_slot(future);
    if (PN_SLOT_ID_CANCELLED == real_slot) {
        return PUBNUB_ERR_CANCELLED;
    }
    if (PUBNUB_SLOT_ID_INVALID == real_slot) {
        return PUBNUB_IN_PROGRESS;
    }

    pn_request_pool_t* pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    pn_request_t* slot = pn_request_pool_get(pool, real_slot);
    if (NULL == slot) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (!pn_future_generation_valid(future, slot)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (!pn_request_is_ready(slot)) {
        return PUBNUB_IN_PROGRESS;
    }

    return slot->result;
}

void pubnub_future_release(pubnub_future_t future)
{
    if (NULL == future.ctx) {
        return;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return;
    }

    uint16_t capacity = pn_context_pool_capacity(future.ctx);
    uint16_t real_slot;

    if (0 != capacity && future.slot_id >= capacity) {
        uint16_t  pending_idx = (uint16_t)(future.slot_id - capacity);
        uint16_t* map         = pn_context_pending_slot_map(future.ctx);
        if (NULL == map) {
            return;
        }

        real_slot = map[pending_idx];
        if (PN_SLOT_ID_CANCELLED == real_slot) {
            /* Already cancelled — just clear the map entry. */
            map[pending_idx] = PUBNUB_SLOT_ID_INVALID;
            return;
        }
        if (PUBNUB_SLOT_ID_INVALID == real_slot) {
            /* Not yet promoted - cancel the pending entry.
             * cancel_at takes a logical index (0 = oldest from head);
             * convert physical pending_idx to logical. Extract
             * callbacks via out_data so they fire outside the lock
             * (prevents deadlock on non-reentrant mutexes). */
            pn_pending_queue_t* queue = pn_context_pending_queue(future.ctx);
            pn_request_pool_t*  pool  = pn_context_request_pool(future.ctx);
            if (NULL != queue && NULL != pool) {
                pn_pending_cancel_data_t cancel_data = {0};
                cancel_data.async_cb_future          = future;
                uint16_t logical =
                    (uint16_t)((pending_idx - queue->head + queue->capacity)
                               % queue->capacity);
                pn_request_pool_lock(pool);
                pn_pending_queue_cancel_at(queue, logical, &cancel_data);
                pn_request_pool_unlock(pool);
                pn_pending_cancel_data_run(&cancel_data);
            }
            map[pending_idx] = PUBNUB_SLOT_ID_INVALID;
            return;
        }

        /* Clear the map entry after promotion. */
        map[pending_idx] = PUBNUB_SLOT_ID_INVALID;
    } else {
        real_slot = future.slot_id;
    }

    pn_request_pool_t* pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return;
    }

    pn_request_pool_lock(pool);
    pn_request_t* slot = pn_request_pool_get(pool, real_slot);
    if (NULL != slot && !pn_future_generation_valid(future, slot)) {
        pn_request_pool_unlock(pool);
        return;
    }
    if (NULL != slot
        && (PN_REQUEST_COMPLETING == slot->state
            || PN_REQUEST_IN_FLIGHT == slot->state)) {
        /* Transport handle is still live (IN_FLIGHT) or callback
         * delivery is in progress (COMPLETING); defer the release
         * until the process tick routes completion. */
        slot->release_deferred = 1;
        pn_request_pool_unlock(pool);
        return;
    }

    /* Terminal slot. On the success path pn_request_on_success_impl keeps
     * transport_handle live so response->body (which aliases the transport
     * rx buffer the handle owns) stays valid until this release. Snapshot
     * and clear the handle under the lock, then cancel it OUTSIDE the lock:
     * the transport cancel frees rx_buf and may invoke callbacks / allocator
     * release, neither of which may run while the pool lock is held.
     * Mirrors pn_request_abort's snapshot / unlock / cancel sequence. */
    pubnub_transport_handle_t* handle = NULL;
    if (NULL != slot) {
        handle                 = slot->transport_handle;
        slot->transport_handle = NULL;
    }
    pn_request_pool_unlock(pool);

    if (NULL != handle) {
        pubnub_transport_provider_t* chain_head =
            pn_context_pipeline_chain_head(future.ctx);
        if (NULL != chain_head && NULL != chain_head->cancel) {
            chain_head->cancel(chain_head, handle);
        }
    }

    pn_request_pool_lock(pool);
    pn_request_pool_release(pool, real_slot);
    pn_request_pool_unlock(pool);
}

pubnub_res_t pubnub_future_cancel(pubnub_future_t future)
{
    pn_request_pool_t*          pool     = NULL;
    pubnub_platform_provider_t* platform = NULL;
    pubnub_lock_t*              lock     = NULL;
    pn_request_t*               slot     = NULL;
    uint16_t                    real_slot;

    if (NULL == future.ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (PUBNUB_IN_PROGRESS != future.status) {
        return PUBNUB_IN_PROGRESS;
    }

    real_slot = resolve_pending_slot(future);
    if (PUBNUB_SLOT_ID_INVALID == real_slot) {
        /* Still in the pending queue — extract and cancel the entry,
         * then fire its async_cb with PUBNUB_ERR_CANCELLED outside
         * the lock (same pattern as pubnub_future_release). */
        uint16_t capacity = pn_context_pool_capacity(future.ctx);
        if (0 == capacity) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        uint16_t            pending_idx = (uint16_t)(future.slot_id - capacity);
        pn_pending_queue_t* queue       = pn_context_pending_queue(future.ctx);
        pool                            = pn_context_request_pool(future.ctx);
        if (NULL == queue || NULL == pool) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        pn_pending_cancel_data_t cancel_data = {0};
        cancel_data.async_cb_future          = future;
        uint16_t logical = (uint16_t)((pending_idx - queue->head + queue->capacity)
                                      % queue->capacity);
        pn_request_pool_lock(pool);
        pubnub_res_t rc_q =
            pn_pending_queue_cancel_at(queue, logical, &cancel_data);
        pn_request_pool_unlock(pool);
        if (PUBNUB_OK != rc_q) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        uint16_t* map = pn_context_pending_slot_map(future.ctx);
        if (NULL != map) {
            map[pending_idx] = PN_SLOT_ID_CANCELLED;
        }
        pn_pending_cancel_data_run(&cancel_data);
        return PUBNUB_OK;
    }

    pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    platform = pn_context_platform(future.ctx);
    lock     = pn_context_mutex_mem(future.ctx);

    /* Record intent only; the poll-owning thread runs the transport
     * cancel and terminal transition in pn_process_tick (see cancel_requested). */
    pn_ctx_lock(platform, lock);
    slot = pn_request_pool_get(pool, real_slot);
    if (NULL == slot || !pn_future_generation_valid(future, slot)) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (PN_REQUEST_PENDING != slot->state && PN_REQUEST_IN_FLIGHT != slot->state) {
        /* Terminal, completing, or idle: nothing live to cancel. */
        pn_ctx_unlock(platform, lock);
        return PUBNUB_IN_PROGRESS;
    }
    slot->cancel_requested = 1;
    pn_ctx_unlock(platform, lock);

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

    /* Re-resolve under lock — entry may have been promoted between
     * the initial check and lock acquisition. */
    uint16_t real_slot = resolve_pending_slot(future);

    if (PN_SLOT_ID_CANCELLED == real_slot) {
        pn_ctx_unlock(platform, lock);
        callback(future, PUBNUB_ERR_CANCELLED, user_data);
        return PUBNUB_OK;
    }

    if (PUBNUB_SLOT_ID_INVALID == real_slot) {
        /* Still in pending queue. Store callback on the entry. */
        uint16_t            capacity = pn_context_pool_capacity(future.ctx);
        pn_pending_queue_t* queue    = pn_context_pending_queue(future.ctx);
        if (NULL == queue || NULL == queue->entries) {
            pn_ctx_unlock(platform, lock);
            callback(future, PUBNUB_ERR_NOT_INITIALIZED, user_data);
            return PUBNUB_OK;
        }

        uint16_t pending_idx = (uint16_t)(future.slot_id - capacity);
        if (pending_idx >= queue->capacity) {
            pn_ctx_unlock(platform, lock);
            callback(future, PUBNUB_ERR_INVALID_ARGUMENT, user_data);
            return PUBNUB_OK;
        }

        pn_pending_entry_t* entry = &queue->entries[pending_idx];
        if (!entry->occupied) {
            pn_ctx_unlock(platform, lock);
            callback(future, PUBNUB_ERR_CANCELLED, user_data);
            return PUBNUB_OK;
        }

        entry->async_cb           = callback;
        entry->async_cb_user_data = user_data;
        entry->on_complete        = async_trampoline;
        entry->user_data          = future.ctx;

        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK;
    }

    /* Real slot path (either direct or post-promotion). */
    pn_request_t* slot = pn_request_pool_get(pool, real_slot);
    if (NULL == slot || !pn_future_generation_valid(future, slot)) {
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

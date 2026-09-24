/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_effects.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_effects.c requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "presence_event_queue.h"
#include "presence_internal.h"
#include "presence_manager.h"
#include "presence_wire_internal.h"

#include "core/core_internal.h"
#include "core/pn_lock.h"
#include "core/pn_string.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/pending_queue_internal.h"
#include "core/runtime/pipeline_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#include "pubnub/capabilities.h"
#include "pubnub/providers/transport.h"

#include <string.h>

/* Forward declarations. */
static void execute_single_effect(pn_presence_manager_t*         mgr,
                                  const pn_presence_ee_effect_t* effect);
static void execute_effects(pn_presence_manager_t*                    mgr,
                            const pn_presence_ee_transition_result_t* result);
static void dispatch_heartbeat(pn_presence_manager_t* mgr);
static void dispatch_leave(pn_presence_manager_t* mgr, uint8_t leave_all);

/**
 * @brief Duplicate a non-empty string, returning NULL for NULL or "".
 *
 * Normalizes both NULL and empty-string inputs to NULL so that pointer
 * NULL checks replace the previous '\0'-first-byte checks throughout.
 */
static char* dup_nonempty(const char* src, pubnub_allocator_provider_t* alloc)
{
    if (NULL == src || '\0' == src[0]) {
        return NULL;
    }
    return pn_strdup(src, alloc);
}

/**
 * @brief Release a terminal pool slot, cancelling its transport handle first.
 *
 * `pn_request_pool_release` calls `pn_request_reset` (memset), which wipes
 * `transport_handle` without freeing the underlying transport object
 * (e.g. `pn_curl_request_t` + RX buffer). The handle must be snapshotted,
 * the slot released, and `cancel()` called on the handle afterwards — the
 * same ordering used by `pn_request_abort` and the `pubnub_deinit` loop.
 */
static void release_slot_and_cancel_transport(pn_presence_manager_t* mgr,
                                              pn_request_pool_t*     pool,
                                              uint16_t               slot_id,
                                              pn_request_t*          slot)
{
    pubnub_transport_handle_t*   th = slot->transport_handle;
    pubnub_transport_provider_t* transport;

    slot->transport_handle = NULL;
    pn_request_pool_lock(pool);
    pn_request_pool_release(pool, slot_id);
    pn_request_pool_unlock(pool);

    if (NULL != th) {
        transport = pn_context_pipeline_chain_head(mgr->ctx);
        if (NULL != transport && NULL != transport->cancel) {
            transport->cancel(transport, th);
        }
    }
}

/**
 * @brief Cancel the in-flight or pending heartbeat request if one exists.
 *
 * Handles two cases based on whether the slot_id is in the real pool
 * range (< capacity) or the pending-queue range (>= capacity).
 */
static void cancel_active_heartbeat(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t* platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(mgr->ctx);
    uint16_t                    claimed_slot;
    pn_request_pool_t*          pool;
    uint16_t                    capacity;
    pn_request_t*               slot;

    /* Atomic claim: read + clear active_slot_id under lock. */
    pn_ctx_lock(platform, lock);
    claimed_slot        = mgr->active_slot_id;
    mgr->active_slot_id = PUBNUB_SLOT_ID_INVALID;
    pn_ctx_unlock(platform, lock);

    if (PUBNUB_SLOT_ID_INVALID == claimed_slot) {
        return;
    }

    pool = pn_context_request_pool(mgr->ctx);
    if (NULL == pool) {
        return;
    }

    capacity = pn_context_pool_capacity(mgr->ctx);

    if (claimed_slot >= capacity) {
        /* Pending-range: try to cancel in the pending queue. Convert
         * the physical circular-buffer index to a logical offset from
         * head — cancel_at expects logical (0 = oldest). */
        pn_pending_queue_t* queue = pn_context_pending_queue(mgr->ctx);
        uint16_t            pending_idx;
        if (NULL == queue) {
            return;
        }

        pending_idx = (uint16_t)(claimed_slot - capacity);
        {
            uint16_t logical =
                (uint16_t)((pending_idx - queue->head + queue->capacity)
                           % queue->capacity);
            pn_pending_cancel_data_t cancel_data = {0};
            pubnub_res_t             cancel_rc;

            cancel_data.async_cb_future.ctx     = mgr->ctx;
            cancel_data.async_cb_future.slot_id = claimed_slot;
            cancel_data.async_cb_future.status  = PUBNUB_IN_PROGRESS;
            pn_request_pool_lock(pool);
            cancel_rc = pn_pending_queue_cancel_at(queue, logical, &cancel_data);
            pn_request_pool_unlock(pool);
            if (PUBNUB_OK == cancel_rc) {
                pn_pending_cancel_data_run(&cancel_data);
                return;
            }
        }

        /* Entry was already promoted to a real pool slot. Resolve
         * the real slot ID via the pending-slot map and fall through
         * to the real-slot cancel path below. */
        {
            const uint16_t* slot_map = pn_context_pending_slot_map(mgr->ctx);
            if (NULL == slot_map || pending_idx >= PUBNUB_CFG_MAX_PENDING_REQUESTS) {
                return;
            }
            claimed_slot = slot_map[pending_idx];
            if (claimed_slot >= capacity) {
                return;
            }
        }
    }

    /* Real pool slot. */
    slot = pn_request_pool_get(pool, claimed_slot);
    if (NULL == slot) {
        return;
    }

    if (!pn_request_is_terminal(slot) && !pn_request_is_idle(slot)) {
        pn_request_abort(
            mgr->ctx, claimed_slot, PN_GENERATION_ANY, PUBNUB_ERR_CANCELLED, 0);
    }

    if (pn_request_is_terminal(slot)) {
        release_slot_and_cancel_transport(mgr, pool, claimed_slot, slot);
    }
}

/**
 * @brief Cancel the cooldown wait timer.
 */
static void cancel_wait_timer(pn_presence_manager_t* mgr)
{
    if (NULL != mgr->wait_timer) {
        pn_timer_list_remove(&mgr->timers, mgr->wait_timer);
        mgr->wait_timer = NULL;
    }
}

/**
 * @brief Callback invoked when the heartbeat HTTP response arrives.
 *
 * Pushes the result as a HEARTBEAT_SUCCESS or HEARTBEAT_FAILURE event
 * into the deferred queue. The next feature tick drains the queue and
 * executes effects — this ensures the slot has fully transitioned to a
 * terminal state before any effect tries to release it.
 */
static void pn_presence_on_complete(pn_request_t* request,
                                    pubnub_res_t  status,
                                    void*         user_data)
{
    pn_presence_manager_t*      mgr = (pn_presence_manager_t*)user_data;
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
    pn_presence_ee_event_t      event;

    if (NULL == mgr) {
        return;
    }

    if (mgr->draining) {
        return;
    }

    if (PUBNUB_ERR_CANCELLED == status) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    memset(&event, 0, sizeof(event));
    event.type = (PUBNUB_OK == status) ? PN_PRES_EVENT_HEARTBEAT_SUCCESS
                                       : PN_PRES_EVENT_HEARTBEAT_FAILURE;

    /* After pending-queue promotion the real pool slot ID may differ
     * from the ID stored at dispatch time. Reconcile so the next
     * heartbeat dispatch can release the correct slot. Skip when
     * the slot was already cleared by cancel_active_heartbeat. */
    pn_ctx_lock(platform, lock);
    if (PUBNUB_SLOT_ID_INVALID != mgr->active_slot_id) {
        mgr->active_slot_id = request->slot_id;
    }
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);
}

/**
 * @brief Callback for fire-and-forget leave requests.
 *
 * Always releases the pool slot regardless of outcome. Logs a
 * warning on failure since leaves are best-effort with no retry.
 */
static void on_leave_complete(pn_request_t* request, pubnub_res_t status, void* user_data)
{
    pn_presence_manager_t* mgr = (pn_presence_manager_t*)user_data;
    pn_request_pool_t*     pool;

    if (PUBNUB_OK != status && PUBNUB_ERR_CANCELLED != status && NULL != mgr) {
        PN_LOG_WARN(mgr->ctx,
                    "presence leave completed with error (status=%d)",
                    (int)status);
    }

    if (NULL == mgr) {
        return;
    }

    pool = pn_context_request_pool(mgr->ctx);
    if (NULL != pool) {
        release_slot_and_cancel_transport(mgr, pool, request->slot_id, request);
    }
}

/** @brief Release the active slot if it has reached a terminal state. */
static void release_terminal_active_slot(pn_presence_manager_t* mgr)
{
    pn_request_pool_t* pool;
    uint16_t           cap;
    pn_request_t*      old;

    if (PUBNUB_SLOT_ID_INVALID == mgr->active_slot_id) {
        return;
    }

    pool = pn_context_request_pool(mgr->ctx);
    if (NULL != pool) {
        cap = pn_context_pool_capacity(mgr->ctx);
        if (mgr->active_slot_id < cap) {
            old = pn_request_pool_get(pool, mgr->active_slot_id);
            if (NULL != old && pn_request_is_terminal(old)) {
                release_slot_and_cancel_transport(
                    mgr, pool, mgr->active_slot_id, old);
            }
        }
    }
    mgr->active_slot_id = PUBNUB_SLOT_ID_INVALID;
}

/**
 * @brief Dispatch a heartbeat HTTP request via the pending queue path.
 *
 * Snapshots channel/group strings under lock, encodes outside the lock,
 * and attaches the encoded strings as dispatch state for the request
 * lifetime. Uses pn_dispatch_or_enqueue so that pool exhaustion enqueues
 * the request instead of triggering a permanent EE failure.
 */
static void dispatch_heartbeat(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t*   platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*                lock     = pn_context_mutex_mem(mgr->ctx);
    pubnub_allocator_provider_t*  alloc    = pn_context_allocator(mgr->ctx);
    char*                         raw_channels;
    char*                         raw_groups;
    const pubnub_config_t*        config;
    char*                         encoded_channels;
    char*                         encoded_groups = NULL;
    pn_presence_dispatch_state_t* ds;
    pn_pending_entry_t*           entry = NULL;
    pubnub_res_t                  rc;
    pn_presence_wire_inputs_t     inputs;
    pubnub_future_t               future;

    if (NULL == alloc) {
        return;
    }

    /* Snapshot channels/groups under lock (bounded O(N) strdup). */
    pn_ctx_lock(platform, lock);
    raw_channels = pn_strdup(mgr->channels, alloc);
    raw_groups   = pn_strdup(mgr->groups, alloc);
    pn_ctx_unlock(platform, lock);

    if (NULL == raw_channels) {
        pn_strfree(raw_groups, alloc);
        return;
    }

    config = pn_context_config(mgr->ctx);
    if (NULL == config) {
        pn_strfree(raw_channels, alloc);
        pn_strfree(raw_groups, alloc);
        return;
    }

    /* Release previous slot if it reached a terminal state. */
    release_terminal_active_slot(mgr);

    /* Encode channels outside the lock. */
    encoded_channels = pn_url_encode_alloc_n((const uint8_t*)raw_channels,
                                             strlen(raw_channels),
                                             alloc,
                                             PN_ENCODE_KEEP_COMMAS);
    pn_strfree(raw_channels, alloc);
    if (NULL == encoded_channels) {
        pn_strfree(raw_groups, alloc);
        mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
        return;
    }

    /* Encode groups (nullable). */
    if (NULL != raw_groups) {
        encoded_groups = pn_url_encode_alloc_n((const uint8_t*)raw_groups,
                                               strlen(raw_groups),
                                               alloc,
                                               PN_ENCODE_KEEP_COMMAS);
        pn_strfree(raw_groups, alloc);
        if (NULL == encoded_groups) {
            PN_FREE(alloc, encoded_channels);
            mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
            return;
        }
    }

    /* Allocate dispatch state (takes ownership of encoded strings on
     * success; frees them on failure). */
    ds = pn_channel_dispatch_state_create(encoded_channels, encoded_groups, alloc);
    if (NULL == ds) {
        mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
        return;
    }

    /* Acquire a prep-pool entry for building the heartbeat request. */
    entry = pn_prep_acquire(mgr->ctx);
    if (NULL == entry) {
        pn_channel_dispatch_state_cleanup(ds, alloc);
        mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
        return;
    }

    rc = pn_pending_entry_init(entry,
                               (uint8_t)PUBNUB_FEATURE_PRESENCE,
                               ds,
                               pn_channel_dispatch_state_cleanup,
                               NULL,
                               PUBNUB_HTTP_GET,
                               config,
                               0);
    if (PUBNUB_OK != rc) {
        pn_prep_release(mgr->ctx, entry);
        pn_channel_dispatch_state_cleanup(ds, alloc);
        mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
        return;
    }

    memset(&inputs, 0, sizeof(inputs));
    inputs.subscribe_key  = config->subscribe_key;
    inputs.channels       = encoded_channels;
    inputs.channel_groups = encoded_groups;
    inputs.heartbeat_sec  = mgr->presence_timeout_sec;
    inputs.timeout_ms     = config->transaction_timeout_ms;

    rc = pn_presence_build_heartbeat(&entry->http_request, &inputs);
    if (PUBNUB_OK != rc) {
        pn_prep_release(mgr->ctx, entry);
        pn_channel_dispatch_state_cleanup(ds, alloc);
        mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
        return;
    }

    entry->on_complete = pn_presence_on_complete;
    entry->user_data   = mgr;

    future = pn_dispatch_or_enqueue(mgr->ctx, entry);

    if (PUBNUB_IN_PROGRESS != future.status) {
        /* Dispatch already released the prep entry and cleaned up
         * state on drop. */
        mgr->cascaded_event = PN_PRES_EVENT_HEARTBEAT_FAILURE;
        return;
    }

    pn_ctx_lock(platform, lock);
    mgr->active_slot_id = future.slot_id;
    pn_ctx_unlock(platform, lock);
}

/**
 * @brief Dispatch a leave HTTP request (fire-and-forget).
 *
 * Snapshots leave_channels/leave_groups under lock, encodes outside,
 * and dispatches with a dispatch state owning the encoded strings.
 * If suppress_leave is set, this is a no-op.
 */
static void dispatch_leave(pn_presence_manager_t* mgr, uint8_t leave_all)
{
    pubnub_platform_provider_t*   platform;
    pubnub_lock_t*                lock;
    pubnub_allocator_provider_t*  alloc;
    char*                         raw_channels;
    char*                         raw_groups;
    const pubnub_config_t*        config;
    char*                         encoded_channels;
    char*                         encoded_groups = NULL;
    pn_presence_dispatch_state_t* ds;
    pn_pending_entry_t*           entry = NULL;
    pubnub_res_t                  rc;
    pn_presence_wire_inputs_t     inputs;
    pubnub_future_t               future;

    (void)leave_all;

    if (mgr->suppress_leave) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);
    alloc    = pn_context_allocator(mgr->ctx);

    if (NULL == alloc) {
        return;
    }

    /* Snapshot leave channels/groups under lock. */
    pn_ctx_lock(platform, lock);
    raw_channels = pn_strdup(mgr->leave_channels, alloc);
    raw_groups   = pn_strdup(mgr->leave_groups, alloc);
    pn_ctx_unlock(platform, lock);

    if (NULL == raw_channels) {
        pn_strfree(raw_groups, alloc);
        return;
    }

    config = pn_context_config(mgr->ctx);
    if (NULL == config) {
        pn_strfree(raw_channels, alloc);
        pn_strfree(raw_groups, alloc);
        return;
    }

    /* Encode channels outside the lock. */
    encoded_channels = pn_url_encode_alloc_n((const uint8_t*)raw_channels,
                                             strlen(raw_channels),
                                             alloc,
                                             PN_ENCODE_KEEP_COMMAS);
    pn_strfree(raw_channels, alloc);
    if (NULL == encoded_channels) {
        pn_strfree(raw_groups, alloc);
        return;
    }

    /* Encode groups (nullable). */
    if (NULL != raw_groups) {
        encoded_groups = pn_url_encode_alloc_n((const uint8_t*)raw_groups,
                                               strlen(raw_groups),
                                               alloc,
                                               PN_ENCODE_KEEP_COMMAS);
        pn_strfree(raw_groups, alloc);
        if (NULL == encoded_groups) {
            PN_FREE(alloc, encoded_channels);
            return;
        }
    }

    /* Allocate dispatch state (takes ownership of encoded strings on
     * success; frees them on failure). */
    ds = pn_channel_dispatch_state_create(encoded_channels, encoded_groups, alloc);
    if (NULL == ds) {
        return;
    }

    /* Acquire a prep-pool entry for building the leave request. */
    entry = pn_prep_acquire(mgr->ctx);
    if (NULL == entry) {
        pn_channel_dispatch_state_cleanup(ds, alloc);
        return;
    }

    rc = pn_pending_entry_init(entry,
                               (uint8_t)PUBNUB_FEATURE_PRESENCE,
                               ds,
                               pn_channel_dispatch_state_cleanup,
                               NULL,
                               PUBNUB_HTTP_GET,
                               config,
                               0);
    if (PUBNUB_OK != rc) {
        pn_prep_release(mgr->ctx, entry);
        pn_channel_dispatch_state_cleanup(ds, alloc);
        return;
    }

    memset(&inputs, 0, sizeof(inputs));
    inputs.subscribe_key  = config->subscribe_key;
    inputs.channels       = encoded_channels;
    inputs.channel_groups = encoded_groups;
    inputs.heartbeat_sec  = 0;
    inputs.timeout_ms     = config->transaction_timeout_ms;

    rc = pn_presence_build_leave(&entry->http_request, &inputs);
    if (PUBNUB_OK != rc) {
        pn_prep_release(mgr->ctx, entry);
        pn_channel_dispatch_state_cleanup(ds, alloc);
        return;
    }

    entry->on_complete = on_leave_complete;
    entry->user_data   = mgr;

    /* Best-effort: silently ignore if both pool and queue are full.
     * Dispatch releases the prep entry and cleans up state on drop. */
    future = pn_dispatch_or_enqueue(mgr->ctx, entry);
    (void)future;
}

/**
 * @brief Timer callback: cooldown expired, push TIMES_UP event.
 *
 * Pushes the event into the deferred queue. The same tick that fired
 * the timer will drain the queue immediately after this returns.
 */
static void pn_presence_wait_expired(void* cb_data)
{
    pn_presence_manager_t*      mgr = (pn_presence_manager_t*)cb_data;
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
    pn_presence_ee_event_t      event;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    mgr->wait_timer = NULL;

    memset(&event, 0, sizeof(event));
    event.type = PN_PRES_EVENT_TIMES_UP;

    pn_ctx_lock(platform, lock);
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);
}

/**
 * @brief Start the cooldown wait timer.
 */
static void start_wait_timer(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t* platform;

    if (0 == mgr->heartbeat_interval_ms) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    if (NULL == platform) {
        return;
    }

    /* Cancel existing timer if somehow leftover. */
    cancel_wait_timer(mgr);

    mgr->wait_timer =
        pn_timer_list_add(&mgr->timers,
                          (pubnub_milliseconds_t)mgr->heartbeat_interval_ms,
                          pn_presence_wait_expired,
                          mgr,
                          platform);
}

/**
 * @brief Execute a single non-dispatch effect.
 *
 * Handles cancel, wait, and emit effects. HEARTBEAT and LEAVE are
 * handled at the loop level in execute_effects() to keep dispatch
 * functions out of the call chain (avoids structural recursion flagged
 * by misc-no-recursion).
 */
static void execute_single_effect(pn_presence_manager_t*         mgr,
                                  const pn_presence_ee_effect_t* effect)
{
    if (NULL == mgr || NULL == effect) {
        return;
    }

    switch (effect->type) {
    case PN_PRES_EE_EFFECT_WAIT: start_wait_timer(mgr); break;
    case PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT:
        cancel_active_heartbeat(mgr);
        break;
    case PN_PRES_EE_EFFECT_CANCEL_WAIT: cancel_wait_timer(mgr); break;
    default:
        /* NONE — no-op.
         * HEARTBEAT and LEAVE — handled at the caller loop level
         * to avoid structural recursion. */
        break;
    }
}

/**
 * @brief Execute effects iteratively, draining cascaded events.
 *
 * Cancels run first (CANCEL_HEARTBEAT, CANCEL_WAIT), then actions.
 * Dispatch effects (HEARTBEAT, LEAVE) are called directly at this
 * level — NOT through execute_single_effect — so there is no
 * structural recursion. If a dispatch sets mgr->cascaded_event, the
 * loop re-enters the EE and processes the resulting effects before
 * returning.
 */
static void execute_effects(pn_presence_manager_t*                    mgr,
                            const pn_presence_ee_transition_result_t* result)
{
    pubnub_platform_provider_t* platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(mgr->ctx);

    pn_presence_ee_transition_result_t current = *result;

    for (;;) {
        uint8_t                i;
        pn_presence_ee_event_t cascade_evt;

        /* Cancel effects first (CANCEL_HEARTBEAT, CANCEL_WAIT). */
        for (i = 0; i < current.effect_count; i++) {
            pn_presence_ee_effect_type_t t = current.effects[i].type;
            if (PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT == t
                || PN_PRES_EE_EFFECT_CANCEL_WAIT == t) {
                execute_single_effect(mgr, &current.effects[i]);
            }
        }

        /* Action effects in order. */
        for (i = 0; i < current.effect_count; i++) {
            switch (current.effects[i].type) {
            case PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT:
            case PN_PRES_EE_EFFECT_CANCEL_WAIT: break;
            case PN_PRES_EE_EFFECT_HEARTBEAT: dispatch_heartbeat(mgr); break;
            case PN_PRES_EE_EFFECT_LEAVE:
                dispatch_leave(mgr, current.effects[i].leave_all);
                break;
            default: execute_single_effect(mgr, &current.effects[i]); break;
            }
        }

        /* Check for cascaded event from dispatch failure. */
        if (PN_PRES_EVENT_NONE == mgr->cascaded_event) {
            break;
        }

        memset(&cascade_evt, 0, sizeof(cascade_evt));
        cascade_evt.type    = mgr->cascaded_event;
        mgr->cascaded_event = PN_PRES_EVENT_NONE;

        pn_ctx_lock(platform, lock);
        current       = pn_presence_ee_transition(mgr->ee_state, &cascade_evt);
        mgr->ee_state = current.new_state;
        pn_ctx_unlock(platform, lock);

        if (0 == current.effect_count) {
            break;
        }
    }
}

/**
 * @brief Drive the presence EE with an event and execute effects.
 */
static void drive_ee(pn_presence_manager_t* mgr, const pn_presence_ee_event_t* event)
{
    pubnub_platform_provider_t*        platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*                     lock = pn_context_mutex_mem(mgr->ctx);
    pn_presence_ee_transition_result_t result;

    pn_ctx_lock(platform, lock);
    result        = pn_presence_ee_transition(mgr->ee_state, event);
    mgr->ee_state = result.new_state;
    pn_ctx_unlock(platform, lock);

    if (result.effect_count > 0) {
        execute_effects(mgr, &result);
    }
}

void pn_presence_joined(pn_presence_manager_t* mgr,
                        const char*            channels,
                        const char*            groups)
{
    pubnub_platform_provider_t*  platform;
    pubnub_lock_t*               lock;
    pubnub_allocator_provider_t* alloc;
    pn_presence_ee_event_t       event;

    if (NULL == mgr) {
        return;
    }

    /* The initial /heartbeat always fires on join to announce the client
     * to PubNub, regardless of heartbeat_interval. The interval only
     * governs the recurring wait timer: when heartbeat_interval == 0 the
     * initial heartbeat still fires but no recurring timer starts (see
     * start_wait_timer, which returns early for a zero interval); when
     * heartbeat_interval > 0 the initial heartbeat is followed by a
     * recurring timer at that interval. */
    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);
    alloc    = pn_context_allocator(mgr->ctx);

    memset(&event, 0, sizeof(event));
    event.type = PN_PRES_EVENT_JOINED;

    /* Replace channel/group strings and enqueue event under lock.
     * The bg thread tick will dequeue and call drive_ee. */
    pn_ctx_lock(platform, lock);
    pn_strfree(mgr->channels, alloc);
    mgr->channels = dup_nonempty(channels, alloc);
    pn_strfree(mgr->groups, alloc);
    mgr->groups = dup_nonempty(groups, alloc);
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);

    pn_context_wake_bg_thread(mgr->ctx);
}

void pn_presence_left(pn_presence_manager_t* mgr,
                      const char*            remaining_channels,
                      const char*            remaining_groups,
                      const char*            removed_channels,
                      const char*            removed_groups,
                      uint8_t                subscriptions_empty)
{
    pubnub_platform_provider_t*  platform;
    pubnub_lock_t*               lock;
    pubnub_allocator_provider_t* alloc;
    pn_presence_ee_event_t       event;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);
    alloc    = pn_context_allocator(mgr->ctx);

    memset(&event, 0, sizeof(event));
    event.type                = PN_PRES_EVENT_LEFT;
    event.subscriptions_empty = subscriptions_empty;

    /* Update channel strings and enqueue event under lock.
     * The bg thread tick will dequeue and call drive_ee. */
    pn_ctx_lock(platform, lock);
    pn_strfree(mgr->leave_channels, alloc);
    mgr->leave_channels = dup_nonempty(removed_channels, alloc);
    pn_strfree(mgr->leave_groups, alloc);
    mgr->leave_groups = dup_nonempty(removed_groups, alloc);
    pn_strfree(mgr->channels, alloc);
    mgr->channels = dup_nonempty(remaining_channels, alloc);
    pn_strfree(mgr->groups, alloc);
    mgr->groups = dup_nonempty(remaining_groups, alloc);
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);

    pn_context_wake_bg_thread(mgr->ctx);
}

void pn_presence_left_all(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t*  platform;
    pubnub_lock_t*               lock;
    pubnub_allocator_provider_t* alloc;
    pn_presence_ee_event_t       event;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);
    alloc    = pn_context_allocator(mgr->ctx);

    memset(&event, 0, sizeof(event));
    event.type = PN_PRES_EVENT_LEFT_ALL;

    /* Swap active->leave pointers and enqueue event under lock.
     * The bg thread tick will dequeue and call drive_ee. */
    pn_ctx_lock(platform, lock);
    pn_strfree(mgr->leave_channels, alloc);
    mgr->leave_channels = mgr->channels;
    mgr->channels       = NULL;
    pn_strfree(mgr->leave_groups, alloc);
    mgr->leave_groups = mgr->groups;
    mgr->groups       = NULL;
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);

    pn_context_wake_bg_thread(mgr->ctx);
}

void pn_presence_disconnect(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
    pn_presence_ee_event_t      event;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    memset(&event, 0, sizeof(event));
    event.type = PN_PRES_EVENT_DISCONNECT;

    pn_ctx_lock(platform, lock);
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);

    pn_context_wake_bg_thread(mgr->ctx);
}

void pn_presence_reconnect(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
    pn_presence_ee_event_t      event;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    memset(&event, 0, sizeof(event));
    event.type = PN_PRES_EVENT_RECONNECT;

    pn_ctx_lock(platform, lock);
    pn_presence_event_queue_push(&mgr->event_queue, &event);
    pn_ctx_unlock(platform, lock);

    pn_context_wake_bg_thread(mgr->ctx);
}

/**
 * @brief Process one tick of the presence event engine.
 *
 * Fires expired timers (which may push events into the queue), then
 * drains the event queue through drive_ee which transitions the state
 * machine and executes any resulting effects. All effects run
 * exclusively from this tick (bg thread) to avoid data races on
 * mgr->active_slot_id and request pool slots.
 */
static void pn_presence_tick(pn_presence_manager_t* mgr)
{
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    /* Fire expired timers — may push TIMES_UP into queue. */
    pn_timer_list_fire_expired(&mgr->timers, platform);

    /* Drain event queue through the state machine. */
    for (;;) {
        pn_presence_ee_event_t event;

        pn_ctx_lock(platform, lock);
        if (!pn_presence_event_queue_pop(&mgr->event_queue, &event)) {
            pn_ctx_unlock(platform, lock);
            break;
        }
        pn_ctx_unlock(platform, lock);

        drive_ee(mgr, &event);
    }
}

int pn_presence_feature_tick(void* state)
{
    pn_presence_manager_t* mgr = (pn_presence_manager_t*)state;
    if (NULL == mgr) {
        return 0;
    }

    /* Active when either the EE is in a non-idle state or events are
     * pending in the queue (e.g., a callback pushed an event between
     * ticks while the EE was still in INACTIVE from a cold start).
     * Lockless read: benign TOCTOU - worst case skips one tick. */
    if (PN_PRESENCE_STATE_HEARTBEAT_INACTIVE == mgr->ee_state
        && !pn_presence_event_queue_has_events(&mgr->event_queue)) {
        return 0;
    }

    pn_presence_tick(mgr);
    return 1;
}

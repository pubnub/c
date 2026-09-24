/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "subscribe_effects.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_effects.c requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "subscribe_event_queue.h"
#include "subscribe_manager_internal.h"
#include "subscribe_wire_internal.h"

#include "core/core_internal.h"
#include "core/pn_lock.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/pending_queue_internal.h"
#include "core/runtime/pipeline_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#include "pubnub/providers/transport.h"

#include <string.h>

#if PUBNUB_CFG_LOG_LEVEL_COMPILED || (PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0)
/** @brief Human-readable name for an EE state (debug logging). */
static const char* pn_sub_state_str(pn_subscribe_ee_state_t s)
{
    switch (s) {
    case PN_SUBSCRIBE_STATE_UNSUBSCRIBED: return "UNSUBSCRIBED";
    case PN_SUBSCRIBE_STATE_HANDSHAKING: return "HANDSHAKING";
    case PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
    case PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED: return "HANDSHAKE_STOPPED";
    case PN_SUBSCRIBE_STATE_RECEIVING: return "RECEIVING";
    case PN_SUBSCRIBE_STATE_RECEIVE_FAILED: return "RECEIVE_FAILED";
    case PN_SUBSCRIBE_STATE_RECEIVE_STOPPED: return "RECEIVE_STOPPED";
    default: return "?";
    }
}

/** @brief Human-readable name for an EE event type (debug logging). */
static const char* pn_sub_event_str(pn_subscribe_ee_event_type_t e)
{
    switch (e) {
    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: return "SUBSCRIPTION_CHANGED";
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED: return "SUBSCRIPTION_RESTORED";
    case PN_SUB_EVENT_HANDSHAKE_SUCCESS: return "HANDSHAKE_SUCCESS";
    case PN_SUB_EVENT_HANDSHAKE_FAILURE: return "HANDSHAKE_FAILURE";
    case PN_SUB_EVENT_RECEIVE_SUCCESS: return "RECEIVE_SUCCESS";
    case PN_SUB_EVENT_RECEIVE_FAILURE: return "RECEIVE_FAILURE";
    case PN_SUB_EVENT_DISCONNECT: return "DISCONNECT";
    case PN_SUB_EVENT_RECONNECT: return "RECONNECT";
    case PN_SUB_EVENT_UNSUBSCRIBE_ALL: return "UNSUBSCRIBE_ALL";
    default: return "?";
    }
}

/** @brief Human-readable name for an EE effect type (trace logging). */
static const char* pn_sub_effect_str(pn_subscribe_ee_effect_type_t t)
{
    switch (t) {
    case PN_SUB_EE_EFFECT_NONE: return "NONE";
    case PN_SUB_EE_EFFECT_HANDSHAKE: return "HANDSHAKE";
    case PN_SUB_EE_EFFECT_RECEIVE_MESSAGES: return "RECEIVE_MESSAGES";
    case PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE: return "CANCEL_HANDSHAKE";
    case PN_SUB_EE_EFFECT_CANCEL_RECEIVE: return "CANCEL_RECEIVE";
    case PN_SUB_EE_EFFECT_EMIT_STATUS: return "EMIT_STATUS";
    case PN_SUB_EE_EFFECT_EMIT_MESSAGES: return "EMIT_MESSAGES";
    default: return "?";
    }
}

/** @brief Human-readable name for an EE status category (trace logging). */
static const char* pn_sub_status_str(pn_subscribe_ee_status_t s)
{
    switch (s) {
    case PN_SUB_EE_STATUS_CONNECTED: return "CONNECTED";
    case PN_SUB_EE_STATUS_DISCONNECTED: return "DISCONNECTED";
    case PN_SUB_EE_STATUS_DISCONNECTED_UNEXPECTEDLY:
        return "DISCONNECTED_UNEXPECTEDLY";
    case PN_SUB_EE_STATUS_CONNECTION_ERROR: return "CONNECTION_ERROR";
    case PN_SUB_EE_STATUS_SUBSCRIPTION_CHANGED: return "SUBSCRIPTION_CHANGED";
    default: return "?";
    }
}
#endif /* PUBNUB_CFG_LOG_LEVEL_COMPILED || MAX_LOG_MESSAGE_SIZE > 0 */

#if PUBNUB_ENABLE_CRYPTO
/* Forward declaration — avoids cross-feature include coupling.
 * The definition lives in src/features/crypto/crypto_api.c. */
pubnub_res_t pn_crypto_module_decrypt_from_base64(pubnub_crypto_module_t* module,
                                                  const char* base64,
                                                  size_t      base64_len,
                                                  uint8_t**   output,
                                                  size_t*     output_len,
                                                  pubnub_allocator_provider_t* alloc);
#endif

/**
 * @brief Build wire inputs and dispatch state from the manager's
 *        current channel registry and context configuration.
 *
 * Allocates encoded channel/channel-group strings via the allocator
 * and wraps them in a dispatch state struct. The caller attaches the
 * dispatch state to the pending entry so the strings remain valid
 * through transport dispatch and are freed on slot release.
 *
 * @param mgr       Subscribe manager (non-NULL).
 * @param out       Wire inputs struct to fill (output).
 * @param out_state Receives the allocated dispatch state on success
 *                  (caller must attach to entry or free on failure).
 * @return PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t build_wire_inputs(pn_subscribe_manager_t*         mgr,
                                      pn_subscribe_wire_inputs_t*     out,
                                      pn_subscribe_dispatch_state_t** out_state)
{
    const pubnub_config_t*         config = pn_context_config(mgr->ctx);
    pubnub_allocator_provider_t*   alloc;
    char*                          raw_channels;
    char*                          raw_groups;
    char*                          encoded_channels = NULL;
    char*                          encoded_groups   = NULL;
    pn_subscribe_dispatch_state_t* ds;

    if (NULL == config) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    alloc = pn_context_allocator(mgr->ctx);
    if (NULL == alloc) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    /* Build raw channel string (unencoded). */
    raw_channels = pn_subscribe_build_channel_string_alloc(mgr, alloc);

    /* Build raw channel-group string (unencoded, may be NULL). */
    raw_groups = pn_subscribe_build_channel_group_string_alloc(mgr, alloc);

    /* If no channels AND no groups, nothing to subscribe to. */
    if (NULL == raw_channels && NULL == raw_groups) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Encode channels. If raw_channels is NULL (only groups), use
     * "," placeholder per PubNub protocol. */
    if (NULL != raw_channels) {
        encoded_channels = pn_url_encode_alloc_n((const uint8_t*)raw_channels,
                                                 strlen(raw_channels),
                                                 alloc,
                                                 PN_ENCODE_KEEP_COMMAS);
        PN_FREE(alloc, raw_channels);
        if (NULL == encoded_channels) {
            if (NULL != raw_groups) {
                PN_FREE(alloc, raw_groups);
            }
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    } else {
        /* Allocate a "," placeholder. */
        encoded_channels = (char*)PN_ALLOC(alloc, 2, 1);
        if (NULL == encoded_channels) {
            if (NULL != raw_groups) {
                PN_FREE(alloc, raw_groups);
            }
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        encoded_channels[0] = ',';
        encoded_channels[1] = '\0';
    }

    /* Encode channel-groups (if present). */
    if (NULL != raw_groups) {
        encoded_groups = pn_url_encode_alloc_n((const uint8_t*)raw_groups,
                                               strlen(raw_groups),
                                               alloc,
                                               PN_ENCODE_KEEP_COMMAS);
        PN_FREE(alloc, raw_groups);
        if (NULL == encoded_groups) {
            PN_FREE(alloc, encoded_channels);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    }

    /* Allocate the dispatch state struct (takes ownership of both
     * encoded strings on success; frees them on failure). */
    ds = pn_channel_dispatch_state_create(encoded_channels, encoded_groups, alloc);
    if (NULL == ds) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Populate wire inputs — views point into dispatch-state-owned
     * buffers, valid until the dispatch state is cleaned up. */
    out->channels       = encoded_channels;
    out->channel_groups = encoded_groups;
    out->subscribe_key  = config->subscribe_key;
    out->filter_expr    = config->filter_expression;
    out->heartbeat_sec  = config->presence_timeout;
    out->timeout_ms     = config->non_transaction_timeout_ms;

    *out_state = ds;
    return PUBNUB_OK;
}

/**
 * @brief Parse and apply cursor from a successful subscribe response.
 *
 * Extracts the cursor (timetoken + region) from the response body and
 * updates mgr->cursor under the context lock. Frees the parsed tree.
 *
 * @retval 1 A valid cursor (non-empty timetoken) was parsed and applied.
 * @retval 0 The body was empty, unparsable, or carried no usable cursor
 *           (for example a bare `{}` handshake reply).
 */
static int apply_response_cursor(pn_subscribe_manager_t*     mgr,
                                 const pn_request_t*         request,
                                 pubnub_platform_provider_t* platform,
                                 pubnub_lock_t*              lock)
{
    pubnub_serialization_provider_t* serial;
    pn_subscribe_parsed_response_t   parsed;
    pubnub_res_t                     prc;
    int                              applied = 0;

    if (NULL == request || 0 == request->http_response.body_len) {
        return 0;
    }

    serial = pn_context_serialization(mgr->ctx);
    if (NULL == serial) {
        return 0;
    }

    memset(&parsed, 0, sizeof(parsed));
    prc = pn_subscribe_parse_response(serial,
                                      request->http_response.body,
                                      request->http_response.body_len,
                                      &parsed);
    if (PUBNUB_OK == prc && 0 != parsed.cursor.timetoken_len) {
        pn_ctx_lock(platform, lock);
        if (mgr->restore_cursor_valid) {
            /* Restore path: keep the user-supplied timetoken, adopt the
             * region from the handshake response for server affinity. */
            mgr->cursor.region        = parsed.cursor.region;
            mgr->restore_cursor_valid = 0;
        } else {
            mgr->cursor = parsed.cursor;
        }
        pn_ctx_unlock(platform, lock);
        applied = 1;
    }

    if (NULL != parsed._tree) {
        serial->value_destroy(serial, parsed._tree);
    }

    return applied;
}

/**
 * @brief Push an event, surfacing a warning and error status on overflow.
 *
 * Acquires the context lock only for the bounded push, then (outside the
 * lock) logs a warning and emits a CONNECTION_ERROR status carrying
 * PUBNUB_ERR_QUEUE_FULL when the fixed-capacity queue was full and the
 * event was dropped. Emitting the status outside the lock keeps listener
 * callbacks off the lock-held path.
 *
 * @param mgr   Manager (non-NULL).
 * @param event Event to enqueue (copied).
 */
static void pn_subscribe_push_event_or_report(pn_subscribe_manager_t* mgr,
                                              const pn_subscribe_ee_event_t* event)
{
    pubnub_platform_provider_t* platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(mgr->ctx);
    pn_subscribe_ee_effect_t    overflow;
    int                         pushed;

    pn_ctx_lock(platform, lock);
    pushed = pn_subscribe_event_queue_push(&mgr->event_queue, event);
    pn_ctx_unlock(platform, lock);
    if (pushed) {
        return;
    }

    PN_LOG_WARN(mgr->ctx,
                "[sub EE] event queue full (cap %d): event dropped",
                (int)PUBNUB_CFG_SUBSCRIBE_EVENT_QUEUE_SIZE);

    memset(&overflow, 0, sizeof(overflow));
    overflow.type   = PN_SUB_EE_EFFECT_EMIT_STATUS;
    overflow.status = PN_SUB_EE_STATUS_CONNECTION_ERROR;
    overflow.reason = PUBNUB_ERR_QUEUE_FULL;
    pn_subscribe_emit_status(mgr, &overflow);
}

/**
 * @brief Internal completion callback for subscribe requests.
 *
 * Maps the transport result into an event engine event and pushes it
 * into the manager's event queue for processing on the next tick.
 *
 * Called from pn_request_deliver_notification() which runs OUTSIDE the
 * context lock. We acquire the lock around event queue access and
 * cursor/state reads.
 */
static void pn_subscribe_on_complete(pn_request_t* request,
                                     pubnub_res_t  status,
                                     void*         user_data)
{
    pn_subscribe_manager_t*     mgr = (pn_subscribe_manager_t*)user_data;
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
    pn_subscribe_ee_event_t     event;
    int                         is_handshake;

    if (NULL == mgr) {
        return;
    }

    if (mgr->draining) {
        return;
    }

    /* Cancelled requests do not generate events — the cancel
     * effect already drives state via DISCONNECT or channel
     * change events. */
    if (PUBNUB_ERR_CANCELLED == status) {
        (void)request;
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    memset(&event, 0, sizeof(event));

    /* Read the EE state under lock to decide event type. */
    pn_ctx_lock(platform, lock);
    is_handshake = (PN_SUBSCRIBE_STATE_HANDSHAKING == mgr->ee_state);
    pn_ctx_unlock(platform, lock);

    if (PUBNUB_OK == status) {
        event.type = is_handshake ? PN_SUB_EVENT_HANDSHAKE_SUCCESS
                                  : PN_SUB_EVENT_RECEIVE_SUCCESS;
        /* Handshake success has no EMIT_MESSAGES effect, so the cursor
         * must be extracted here. For receive success, emit_messages
         * updates the cursor before RECEIVE_MESSAGES dispatches. */
        if (is_handshake && !apply_response_cursor(mgr, request, platform, lock)) {
            /* A bare `{}` or otherwise cursorless handshake reply must
             * not report CONNECTED: with no timetoken the receive loop
             * would stall forever. Convert it to a handshake failure so
             * the EE moves to HANDSHAKE_FAILED and reconnects. */
            event.type           = PN_SUB_EVENT_HANDSHAKE_FAILURE;
            event.failure_reason = PUBNUB_ERR_SERIALIZATION;
            if (NULL != request) {
                event.http_status_code =
                    (uint16_t)request->http_response.status_code;
            }
        }
    } else {
        event.type           = is_handshake ? PN_SUB_EVENT_HANDSHAKE_FAILURE
                                            : PN_SUB_EVENT_RECEIVE_FAILURE;
        event.failure_reason = status;
        if (NULL != request) {
            event.http_status_code = (uint16_t)request->http_response.status_code;
        }
    }

    pn_subscribe_push_event_or_report(mgr, &event);
}

/**
 * @brief Cancel a detached previous-request transport handle.
 *
 * Runs the transport chain-head cancel outside any pool lock (cancel may
 * call the allocator or fire callbacks). On the curl transport this
 * releases the prior request's rx_buf, freeing an arena slot; on the
 * socket transport a stale generation makes the cancel a bounded no-op,
 * preserving the reused keep-alive connection.
 *
 * @param mgr    Manager (non-NULL).
 * @param handle Detached handle to cancel; NULL is a no-op.
 */
/** @brief Push a handshake or receive failure event. */
static void push_dispatch_failure_event(pn_subscribe_manager_t* mgr, int is_handshake)
{
    pn_subscribe_ee_event_t evt;

    memset(&evt, 0, sizeof(evt));
    evt.type = is_handshake ? PN_SUB_EVENT_HANDSHAKE_FAILURE
                            : PN_SUB_EVENT_RECEIVE_FAILURE;
    pn_subscribe_push_event_or_report(mgr, &evt);
}

static void reap_prev_transport_handle(pn_subscribe_manager_t*    mgr,
                                       pubnub_transport_handle_t* handle)
{
    pubnub_transport_provider_t* head;

    if (NULL == handle) {
        return;
    }

    head = pn_context_pipeline_chain_head(mgr->ctx);
    if (NULL != head && NULL != head->cancel) {
        head->cancel(head, handle);
    }
}

/** @brief Cancel handle then release slot — cancel must precede release so
 *  the retry middleware finds the slot via its still-valid generation. */
static void reap_handle_and_slot(pn_subscribe_manager_t*    mgr,
                                 pubnub_transport_handle_t* handle,
                                 uint16_t                   slot_id)
{
    pn_request_pool_t* pool = pn_context_request_pool(mgr->ctx);

    reap_prev_transport_handle(mgr, handle);
    if (NULL != pool && PUBNUB_SLOT_ID_INVALID != slot_id
        && slot_id < pn_context_pool_capacity(mgr->ctx)) {
        pn_request_pool_lock(pool);
        pn_request_pool_release(pool, slot_id);
        pn_request_pool_unlock(pool);
    }
}

/**
 * @brief Build and dispatch a subscribe request via the pending queue path.
 *
 * Called from effect execution (outside the context lock). Uses
 * pn_dispatch_or_enqueue so pool exhaustion enqueues rather than
 * triggering an immediate EE failure. Only synthesizes a failure
 * event when both pool and pending queue are full.
 *
 * @param mgr          Manager (non-NULL).
 * @param is_handshake 1 for handshake (tt=0), 0 for receive with cursor.
 */
static void dispatch_subscribe_request(pn_subscribe_manager_t* mgr, int is_handshake)
{
    pn_request_pool_t*             pool     = pn_context_request_pool(mgr->ctx);
    pubnub_platform_provider_t*    platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*                 lock     = pn_context_mutex_mem(mgr->ctx);
    pn_subscribe_wire_inputs_t     inputs;
    pn_subscribe_dispatch_state_t* dispatch_state = NULL;
    const pubnub_config_t*         config         = NULL;
    pn_pending_entry_t*            entry          = NULL;
    pubnub_transport_handle_t*     stale_handle   = NULL;
    pn_subscribe_cursor_t          cursor_copy;
    pubnub_future_t                future;
    uint16_t                       prev_slot;
    uint16_t                       stale_slot = PUBNUB_SLOT_ID_INVALID;
    pubnub_res_t                   rc;

    /* Drain handle+slot deferred from bg-thread mode: by now socket_send has
     * bumped the generation (stale → no-op); curl: frees rx_buf one cycle late.
     * Cancel first (generation intact → retry frees inner handle), then release
     * the parked slot. Handle drains even when pool is NULL; slot needs pool. */
    if (NULL != mgr->prev_reap_handle
        || PUBNUB_SLOT_ID_INVALID != mgr->prev_reap_slot_id) {
        reap_handle_and_slot(mgr, mgr->prev_reap_handle, mgr->prev_reap_slot_id);
        mgr->prev_reap_handle  = NULL;
        mgr->prev_reap_slot_id = PUBNUB_SLOT_ID_INVALID;
    }

    if (NULL == pool) {
        return;
    }

    /* Release previous slot if still held — atomic claim. */
    pn_ctx_lock(platform, lock);
    prev_slot           = mgr->active_slot_id;
    mgr->active_slot_id = PUBNUB_SLOT_ID_INVALID;
    pn_ctx_unlock(platform, lock);

    if (PUBNUB_SLOT_ID_INVALID != prev_slot) {
        const uint16_t cap = pn_context_pool_capacity(mgr->ctx);
        if (prev_slot < cap) {
            pn_request_t* old = pn_request_pool_get(pool, prev_slot);
            if (NULL != old && pn_request_is_ready(old)) {
                /* Detach handle; defer BOTH cancel and slot release until after
                 * socket_send bumps the connection generation (keep-alive) and
                 * the retry lookup can still match the pre-release generation. */
                pn_request_pool_lock(pool);
                stale_handle          = old->transport_handle;
                old->transport_handle = NULL;
                pn_request_pool_unlock(pool);
                stale_slot = prev_slot;
            }
        }
    }

    /* Build wire inputs under lock (reads channel registry) and
     * allocate the dispatch state with encoded strings.
     * Allocator calls under lock are acceptable: supported allocators
     * (stdlib, arena bump) are O(1) non-blocking, and the registry
     * must be stable across the two-pass compute+write sequence. */
    memset(&inputs, 0, sizeof(inputs));

    pn_ctx_lock(platform, lock);
    rc = build_wire_inputs(mgr, &inputs, &dispatch_state);
    pn_ctx_unlock(platform, lock);

    if (PUBNUB_OK != rc) {
        goto reap;
    }

    /* Set the host from context config. */
    config = pn_context_config(mgr->ctx);
    if (NULL == config) {
        goto reap;
    }

    /* Acquire a prep-pool entry for the subscribe HTTP request. */
    entry = pn_prep_acquire(mgr->ctx);
    if (NULL == entry) {
        goto reap;
    }

    rc = pn_request_set_host(&entry->http_request, config->origin);
    if (PUBNUB_OK != rc) {
        goto reap;
    }

    /* Build the HTTP request via wire layer (pure computation). */
    pn_ctx_lock(platform, lock);
    cursor_copy = mgr->cursor;
    if (!is_handshake) {
        /* For a receive dispatch that follows SUBSCRIPTION_RESTORED
         * directly (RECEIVING → RECEIVING path), the restored timetoken
         * is already in mgr->cursor.  Clear the flag so a future
         * handshake triggered by an unrelated event does not
         * accidentally suppress its own cursor. */
        mgr->restore_cursor_valid = 0;
    }
    pn_ctx_unlock(platform, lock);

    if (is_handshake) {
        rc = pn_subscribe_build_handshake(&entry->http_request, &inputs);
    } else {
        rc = pn_subscribe_build_receive(&entry->http_request, &inputs, &cursor_copy);
    }

    if (PUBNUB_OK != rc) {
        goto reap;
    }

    entry->feature_id            = (uint8_t)PUBNUB_FEATURE_SUBSCRIBE;
    entry->response_validator    = pn_subscribe_response_validator;
    entry->on_complete           = pn_subscribe_on_complete;
    entry->user_data             = mgr;
    entry->feature_state         = dispatch_state;
    entry->feature_state_cleanup = pn_channel_dispatch_state_cleanup;

    future = pn_dispatch_or_enqueue(mgr->ctx, entry);

    /* Dispatch consumed the prep entry and took ownership of the dispatch
     * state (cleaning both up on the drop path). The reap epilogue must
     * not double-free them. */
    entry          = NULL;
    dispatch_state = NULL;

    if (PUBNUB_IN_PROGRESS != future.status) {
        /* Both pool and pending queue are full or context not
         * initialized — push a failure event. */
        push_dispatch_failure_event(mgr, is_handshake);
        goto reap;
    }

    pn_ctx_lock(platform, lock);
    mgr->active_slot_id = future.slot_id;
    pn_ctx_unlock(platform, lock);

reap:
    /* Single cleanup epilogue reached by every exit after the previous
     * slot was released. */
    if (NULL != entry) {
        pn_prep_release(mgr->ctx, entry);
    }
    if (NULL != dispatch_state) {
        pn_channel_dispatch_state_cleanup(dispatch_state,
                                          pn_context_allocator(mgr->ctx));
    }

    /* Subscribe transiently holds two pool slots (1 parked + 1 active) across
     * the send→reap window, so concurrent non-subscribe requests may briefly
     * hit backpressure (fits within MAX_IN_FLIGHT=2). */
    if (NULL != stale_handle || PUBNUB_SLOT_ID_INVALID != stale_slot) {
        if (pn_context_has_bg_thread(mgr->ctx)) {
            /* Bg-thread: socket_send hasn't run yet — cancelling now would
             * match the live generation and tear down keep-alive. Defer both. */
            mgr->prev_reap_handle  = stale_handle;
            mgr->prev_reap_slot_id = stale_slot;
        } else {
            /* Cooperative: socket_send already ran, generation bumped — cancel
             * first (retry frees inner handle; socket gen stale → no-op). */
            reap_handle_and_slot(mgr, stale_handle, stale_slot);
        }
    }
}

/**
 * @brief Cancel the in-flight or pending subscribe request if one exists.
 *
 * Uses atomic-claim pattern: reads and clears active_slot_id in one
 * critical section, then operates on the claimed slot outside the
 * lock. Handles two cases: real pool slots (< capacity) and pending-
 * range slots (>= capacity).
 *
 * Idempotent: no-op when no request is active.
 */
static void cancel_active_request(pn_subscribe_manager_t* mgr)
{
    pubnub_platform_provider_t* platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(mgr->ctx);
    uint16_t                    slot_id;

    /* Atomic claim: read + clear in one critical section. Once
     * cleared, no concurrent path can observe the stale value. */
    pn_ctx_lock(platform, lock);
    slot_id             = mgr->active_slot_id;
    mgr->active_slot_id = PUBNUB_SLOT_ID_INVALID;
    pn_ctx_unlock(platform, lock);

    if (PUBNUB_SLOT_ID_INVALID == slot_id) {
        return;
    }

    pn_request_pool_t* pool = pn_context_request_pool(mgr->ctx);
    if (NULL == pool) {
        return;
    }

    const uint16_t capacity = pn_context_pool_capacity(mgr->ctx);

    if (slot_id >= capacity) {
        /* Pending-range: cancel in the pending queue. Convert the
         * physical circular-buffer index to a logical offset from
         * head — cancel_at expects logical (0 = oldest). Fire
         * callbacks outside the lock to prevent deadlock. */
        pn_pending_queue_t* queue = pn_context_pending_queue(mgr->ctx);
        if (NULL != queue) {
            uint16_t pending_idx = (uint16_t)(slot_id - capacity);
            uint16_t logical =
                (uint16_t)((pending_idx - queue->head + queue->capacity)
                           % queue->capacity);
            pn_pending_cancel_data_t cancel_data = {0};
            cancel_data.async_cb_future.ctx      = mgr->ctx;
            cancel_data.async_cb_future.slot_id  = slot_id;
            cancel_data.async_cb_future.status   = PUBNUB_IN_PROGRESS;
            pn_request_pool_lock(pool);
            (void)pn_pending_queue_cancel_at(queue, logical, &cancel_data);
            pn_request_pool_unlock(pool);
            pn_pending_cancel_data_run(&cancel_data);
        }
        return;
    }

    /* Real pool slot. */
    pn_request_t* slot = pn_request_pool_get(pool, slot_id);
    if (NULL == slot) {
        return;
    }

    if (PN_REQUEST_PENDING == slot->state || PN_REQUEST_IN_FLIGHT == slot->state) {
        pn_request_abort(
            mgr->ctx, slot_id, PN_GENERATION_ANY, PUBNUB_ERR_CANCELLED, 1);
    }

    /* pn_request_is_ready covers both COMPLETE and COMPLETING: the atomic
     * readiness gate is set before deliver_notification fires on_complete,
     * so the slot may still be COMPLETING inside the callback chain. */
    if (pn_request_is_ready(slot)) {
        pubnub_transport_handle_t*   stale_handle;
        pubnub_transport_provider_t* head;
        pn_request_pool_lock(pool);
        stale_handle           = slot->transport_handle;
        slot->transport_handle = NULL;
        pn_request_pool_unlock(pool);
        /* Cancel before release: pn_request_pool_release bumps the slot
         * generation, which makes the retry middleware's pointer+generation
         * lookup miss and skip freeing the tracked inner handle (rx_buf). */
        head = pn_context_pipeline_chain_head(mgr->ctx);
        if (NULL != stale_handle && NULL != head && NULL != head->cancel) {
            head->cancel(head, stale_handle);
        }
        pn_request_pool_lock(pool);
        pn_request_pool_release(pool, slot_id);
        pn_request_pool_unlock(pool);
    }
}

/**
 * @brief Decrypt and dispatch a single message to listeners.
 *
 * @param mgr          Subscribe manager.
 * @param entry        Parsed dispatch entry.
 * @param serial       Serialization provider.
 * @param crypto_mod   Crypto module (may be NULL).
 * @param crypto_alloc Allocator for decryption (may be NULL).
 */
static void dispatch_single_message(pn_subscribe_manager_t*          mgr,
                                    pn_subscribe_dispatch_entry_t*   entry,
                                    pubnub_serialization_provider_t* serial,
                                    pubnub_crypto_module_t*          crypto_mod,
                                    pubnub_allocator_provider_t* crypto_alloc)
{
    pubnub_json_value_t* decrypted_tree = NULL;

#if PUBNUB_ENABLE_CRYPTO
    /* Attempt decryption for regular messages and file events with
     * string payloads. Encrypted content is base64 in the "d" field.
     * On failure: pass-through unchanged (JS SDK behavior). */
    if (NULL != crypto_mod && NULL != crypto_alloc
        && (PUBNUB_SUBSCRIBE_MESSAGE == entry->event.type
            || PUBNUB_SUBSCRIBE_FILE == entry->event.type)
        && NULL != entry->event.payload && NULL != serial && NULL != serial->value_type
        && NULL != serial->value_as_string && NULL != serial->parse
        && PUBNUB_JSON_STRING == serial->value_type(entry->event.payload)) {
        size_t      cipher_len = 0;
        const char* cipher_ptr =
            serial->value_as_string(entry->event.payload, &cipher_len);
        if (NULL != cipher_ptr && cipher_len > 2) {
            uint8_t*     dec_buf = NULL;
            size_t       dec_len = 0;
            pubnub_res_t dec_rc  = pn_crypto_module_decrypt_from_base64(
                crypto_mod, cipher_ptr, cipher_len, &dec_buf, &dec_len, crypto_alloc);
            if (PUBNUB_OK == dec_rc && NULL != dec_buf && dec_len > 0) {
                decrypted_tree = serial->parse(serial, dec_buf, dec_len);
                PN_FREE(crypto_alloc, dec_buf);
                if (NULL != decrypted_tree) {
                    entry->event.payload = decrypted_tree;
                }
            } else if (NULL != dec_buf) {
                PN_FREE(crypto_alloc, dec_buf);
            }
        }
    }
#else
    (void)crypto_mod;
    (void)crypto_alloc;
#endif

    pn_subscribe_emit_message(mgr, entry);

    if (NULL != decrypted_tree) {
        serial->value_destroy(serial, decrypted_tree);
    }
}

/** @brief Parse a small unsigned integer from raw bytes following "r":. */
static uint32_t pn_subscribe_parse_region(const uint8_t* scan, size_t avail)
{
    size_t i;
    for (i = 0; i + 3 < avail && i < 32; i++) {
        if ('"' == scan[i] && 'r' == scan[i + 1] && '"' == scan[i + 2]
            && ':' == scan[i + 3]) {
            size_t   j   = i + 4;
            uint32_t val = 0;
            while (j < avail && '0' <= scan[j] && scan[j] <= '9') {
                val = val * 10 + (uint32_t)(scan[j] - '0');
                j++;
            }
            return val;
        }
    }
    return 0;
}

/**
 * @brief Extract the subscribe cursor from a raw response body without
 *        allocating memory.
 *
 * Used as a fallback when the full jsmn parse fails (e.g., Zone B OOM).
 * Scans the raw bytes for the pattern "t":{"t":"<17-digit-timetoken>"
 * which is always present in a PubNub subscribe v2 response envelope.
 * Zero allocations — safe to call when the arena is completely
 * exhausted.
 *
 * @note Relies on the PubNub subscribe V2 wire format placing the cursor
 *       object ("t":{}) before the messages array ("m":[]) in the
 *       response body. The first match is treated as the envelope cursor,
 *       not a user-payload pattern.
 *
 * @param body     Raw HTTP response body (borrowed, may not be
 *                 NUL-terminated).
 * @param body_len Body length in bytes.
 * @param out      Cursor to populate on success (non-NULL).
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERIALIZATION if the
 *         pattern is not found or the timetoken is malformed.
 */
static pubnub_res_t pn_subscribe_extract_cursor_raw(const uint8_t* body,
                                                    size_t         body_len,
                                                    pn_subscribe_cursor_t* out)
{
    /* Needle: "t":{"t":" — marks the cursor object in the envelope. */
    static const char needle[]   = "\"t\":{\"t\":\"";
    const size_t      needle_len = sizeof(needle) - 1; /* 10 bytes */
    const uint8_t*    pos;
    const uint8_t*    end;

    if (NULL == body || 0 == body_len || NULL == out) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Minimum viable response: needle + 17-digit tt + closing quote. */
    if (body_len < needle_len + 17 + 1) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Linear scan for the needle byte pattern. */
    pos = body;
    end = body + body_len - (needle_len + 17);

    while (pos <= end) {
        const uint8_t* candidate;
        size_t         remaining;

        candidate =
            (const uint8_t*)memchr(pos, '"', (size_t)(body + body_len - pos));
        if (NULL == candidate) {
            return PUBNUB_ERR_SERIALIZATION;
        }

        remaining = (size_t)(body + body_len - candidate);
        if (remaining < needle_len + 17 + 1) {
            return PUBNUB_ERR_SERIALIZATION;
        }

        if (0 == memcmp(candidate, needle, needle_len)) {
            /* Found the pattern — extract up to 19 digits. */
            const uint8_t* tt_start = candidate + needle_len;
            size_t         tt_avail = (size_t)(body + body_len - tt_start);
            size_t         tt_len   = 0;
            const uint8_t* r_scan;
            size_t         r_avail;

            while (tt_len < 19 && tt_len < tt_avail && '0' <= tt_start[tt_len]
                   && tt_start[tt_len] <= '9') {
                tt_len++;
            }

            /* PubNub timetokens are exactly 17 decimal digits. */
            if (17 != tt_len) {
                return PUBNUB_ERR_SERIALIZATION;
            }

            /* Verify the closing quote follows the digits. */
            if (tt_len >= tt_avail || '"' != tt_start[tt_len]) {
                return PUBNUB_ERR_SERIALIZATION;
            }

            /* Copy timetoken into output. */
            memcpy(out->timetoken, tt_start, 17);
            out->timetoken[17] = '\0';
            out->timetoken_len = 17;

            /* Extract region integer from the bytes after the timetoken. */
            r_scan      = tt_start + 17 + 1; /* past '"' */
            r_avail     = (size_t)(body + body_len - r_scan);
            out->region = pn_subscribe_parse_region(r_scan, r_avail);

            return PUBNUB_OK;
        }

        /* Advance past this '"' and continue scanning. */
        pos = candidate + 1;
    }

    return PUBNUB_ERR_SERIALIZATION;
}

/**
 * @brief Process messages from the completed subscribe response.
 *
 * Parses the response body, updates the cursor, and dispatches each
 * message to registered listeners. Parsing and listener dispatch
 * happen outside the context lock; only cursor update and slot_id
 * read require the lock.
 */
static void emit_messages(pn_subscribe_manager_t* mgr)
{
    pubnub_platform_provider_t*      platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*                   lock     = pn_context_mutex_mem(mgr->ctx);
    pubnub_serialization_provider_t* serial   = NULL;
    pubnub_crypto_module_t*          crypto_mod   = NULL;
    pubnub_allocator_provider_t*     crypto_alloc = NULL;
    pn_subscribe_parsed_response_t   parsed       = {0};
    pn_request_pool_t*               pool         = NULL;
    pn_request_t*                    slot         = NULL;
    uint16_t                         slot_id;
    pubnub_res_t                     rc;

    pn_ctx_lock(platform, lock);
    slot_id = mgr->active_slot_id;
    pn_ctx_unlock(platform, lock);

    if (PUBNUB_SLOT_ID_INVALID == slot_id) {
        return;
    }

    pool = pn_context_request_pool(mgr->ctx);
    if (NULL == pool) {
        return;
    }

    slot = pn_request_pool_get(pool, slot_id);
    if (NULL == slot) {
        return;
    }

    /* Only process if the slot has completed successfully. */
    if (!pn_request_is_ready(slot)) {
        return;
    }
    if (NULL == slot->http_response.body || 0 == slot->http_response.body_len) {
        return;
    }

    /* Parse response body outside the lock (serialization provider). */
    serial = pn_context_serialization(mgr->ctx);
    if (NULL == serial) {
        return;
    }

    rc = pn_subscribe_parse_response(
        serial, slot->http_response.body, slot->http_response.body_len, &parsed);

    if (PUBNUB_OK != rc) {
        /* Full parse failed (likely Zone B OOM). Attempt zero-alloc
         * cursor extraction to advance past this batch. */
        pn_subscribe_cursor_t fallback_cursor;
        memset(&fallback_cursor, 0, sizeof(fallback_cursor));
        if (PUBNUB_OK
            == pn_subscribe_extract_cursor_raw(slot->http_response.body,
                                               slot->http_response.body_len,
                                               &fallback_cursor)) {
            PN_LOG_ERROR_ENTRY(
                mgr->ctx,
                (int)PUBNUB_ERR_SERIALIZATION,
                "subscribe batch dropped: parse OOM, cursor advanced",
                NULL);
            pn_ctx_lock(platform, lock);
            mgr->cursor = fallback_cursor;
            pn_ctx_unlock(platform, lock);
        } else {
            /* Even raw cursor extraction failed — push failure event
             * so the EE transitions to RECEIVE_FAILED and breaks the
             * stale-cursor loop via reconnect (tt=0). */
            pn_subscribe_ee_event_t fail_evt;
            PN_LOG_ERROR_ENTRY(
                mgr->ctx,
                (int)PUBNUB_ERR_SERIALIZATION,
                "subscribe parse failed, cursor extraction also failed",
                NULL);
            memset(&fail_evt, 0, sizeof(fail_evt));
            fail_evt.type           = PN_SUB_EVENT_RECEIVE_FAILURE;
            fail_evt.failure_reason = PUBNUB_ERR_SERIALIZATION;
            pn_subscribe_push_event_or_report(mgr, &fail_evt);
        }
        return;
    }

    /* Update cursor under lock for the next request cycle. */
    pn_ctx_lock(platform, lock);
    mgr->cursor = parsed.cursor;
    pn_ctx_unlock(platform, lock);

    /* Resolve crypto module once for the entire batch. */
    if (PUBNUB_ENABLE_CRYPTO) {
        crypto_mod = pn_context_crypto_module(mgr->ctx);
        if (NULL != crypto_mod) {
            crypto_alloc = pn_context_allocator(mgr->ctx);
        }
    }

    /* Dispatch messages to all registered listeners (outside lock). */
    {
        uint16_t i;
        for (i = 0; i < parsed.message_count; i++) {
            dispatch_single_message(
                mgr, &parsed.messages[i], serial, crypto_mod, crypto_alloc);
        }
    }

    /* Destroy the parsed tree — string views are now invalid. */
    if (NULL != parsed._tree) {
        serial->value_destroy(serial, parsed._tree);
    }
}

void pn_subscribe_execute_effect(pn_subscribe_manager_t*         mgr,
                                 const pn_subscribe_ee_effect_t* effect)
{
    if (NULL == mgr || NULL == effect) {
        return;
    }

    if (PN_SUB_EE_EFFECT_EMIT_STATUS == effect->type) {
        PN_LOG_TRACE(mgr->ctx,
                     "[sub EE] effect: %s (%s)",
                     pn_sub_effect_str(effect->type),
                     pn_sub_status_str(effect->status));
    } else {
        PN_LOG_TRACE(
            mgr->ctx, "[sub EE] effect: %s", pn_sub_effect_str(effect->type));
    }

    switch (effect->type) {
    case PN_SUB_EE_EFFECT_NONE: break;

    case PN_SUB_EE_EFFECT_HANDSHAKE: dispatch_subscribe_request(mgr, 1); break;

    case PN_SUB_EE_EFFECT_RECEIVE_MESSAGES:
        dispatch_subscribe_request(mgr, 0);
        break;

    case PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE:
    case PN_SUB_EE_EFFECT_CANCEL_RECEIVE: cancel_active_request(mgr); break;

    case PN_SUB_EE_EFFECT_EMIT_STATUS:
        pn_subscribe_emit_status(mgr, effect);
        break;

    case PN_SUB_EE_EFFECT_EMIT_MESSAGES: emit_messages(mgr); break;
    }
}

void pn_subscribe_execute_effects(pn_subscribe_manager_t* mgr,
                                  const pn_subscribe_ee_transition_result_t* result)
{
    uint8_t i;

    if (NULL == mgr || NULL == result) {
        return;
    }

    /* Execute EMIT_MESSAGES first — response data must be consumed
     * while the slot is still valid (before cancel releases it). */
    for (i = 0; i < result->effect_count; i++) {
        if (PN_SUB_EE_EFFECT_EMIT_MESSAGES == result->effects[i].type) {
            pn_subscribe_execute_effect(mgr, &result->effects[i]);
        }
    }

    /* Execute cancel effects to release the old slot before
     * dispatching a new request. */
    for (i = 0; i < result->effect_count; i++) {
        pn_subscribe_ee_effect_type_t t = result->effects[i].type;
        if (PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE == t
            || PN_SUB_EE_EFFECT_CANCEL_RECEIVE == t) {
            pn_subscribe_execute_effect(mgr, &result->effects[i]);
        }
    }

    /* Execute remaining effects in order. */
    for (i = 0; i < result->effect_count; i++) {
        pn_subscribe_ee_effect_type_t t = result->effects[i].type;
        if (PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE == t
            || PN_SUB_EE_EFFECT_CANCEL_RECEIVE == t
            || PN_SUB_EE_EFFECT_EMIT_MESSAGES == t) {
            continue; /* Already executed above. */
        }
        pn_subscribe_execute_effect(mgr, &result->effects[i]);
    }
}

void pn_subscribe_tick(pn_subscribe_manager_t* mgr)
{
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;

    if (NULL == mgr) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock     = pn_context_mutex_mem(mgr->ctx);

    /* Drain event queue through the state machine one event at a time.
     * Pop + transition + state update under lock; effect execution
     * outside lock (effects do transport I/O and invoke callbacks).
     * Double-release is prevented by the atomic-claim pattern on
     * active_slot_id: cancel_active_request reads-and-clears it under
     * lock, so only one consumer ever acts on a given slot_id. */
    for (;;) {
        pn_subscribe_ee_event_t             event;
        pn_subscribe_ee_transition_result_t result;
        pn_subscribe_ee_state_t             prev_state;

        pn_ctx_lock(platform, lock);
        if (!pn_subscribe_event_queue_pop(&mgr->event_queue, &event)) {
            pn_ctx_unlock(platform, lock);
            break;
        }

        /* Discard stale SUBSCRIPTION_CHANGED / SUBSCRIPTION_RESTORED
         * events. When multiple subscription mutations happen before
         * the EE drains the queue, only the latest matters — earlier
         * events would produce the same channel set and cause
         * redundant cancel+redispatch cycles. Signed difference
         * handles uint32_t wraparound via two's complement.
         *
         * Exception: never discard events with subscriptions_empty=1.
         * These represent "all subscriptions removed" and must always
         * drive the EE through UNSUBSCRIBED so that a subsequent
         * subscribe triggers a fresh handshake and CONNECTED status. */
        if ((PN_SUB_EVENT_SUBSCRIPTION_CHANGED == event.type
             || PN_SUB_EVENT_SUBSCRIPTION_RESTORED == event.type)
            && !event.subscriptions_empty
            && (int32_t)(event.generation - mgr->subscription_generation) < 0) {
            pn_ctx_unlock(platform, lock);
            continue;
        }

        /* Transition is pure computation: O(1), no I/O. */
        prev_state = mgr->ee_state;
        result     = pn_subscribe_ee_transition(mgr->ee_state, &event);

        /* Apply state transition. */
        mgr->ee_state = result.new_state;

        /* Update public connection state to reflect the new EE state. */
        switch (mgr->ee_state) {
        case PN_SUBSCRIBE_STATE_UNSUBSCRIBED:
            mgr->connection_state = PUBNUB_SUBSCRIBE_IDLE;
            /* restore_cursor_valid intentionally NOT cleared here — a saved
             * restore cursor must survive the UNSUBSCRIBED state so that
             * restore() → subscribe() → reconnect() delivers the correct
             * timetoken. The flag is consumed at dispatch (receive path) or
             * apply_response_cursor (handshake path). */
            break;
        case PN_SUBSCRIBE_STATE_HANDSHAKING:
            mgr->connection_state = PUBNUB_SUBSCRIBE_CONNECTING;
            break;
        case PN_SUBSCRIBE_STATE_RECEIVING:
            mgr->connection_state = PUBNUB_SUBSCRIBE_CONNECTED;
            break;
        case PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED:
        case PN_SUBSCRIBE_STATE_RECEIVE_FAILED:
            mgr->connection_state = PUBNUB_SUBSCRIBE_RECONNECTING;
            break;
        case PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED:
        case PN_SUBSCRIBE_STATE_RECEIVE_STOPPED:
            mgr->connection_state = PUBNUB_SUBSCRIBE_DISCONNECTED;
            break;
        }

        pn_ctx_unlock(platform, lock);

        /* Log after unlock — logger is a provider, must not be called
         * under the context lock. All three args are stack-local. */
        PN_LOG_DEBUG(mgr->ctx,
                     "[sub EE] %s + %s -> %s",
                     pn_sub_state_str(prev_state),
                     pn_sub_event_str(event.type),
                     pn_sub_state_str(result.new_state));
        (void)prev_state;

        /* Execute side-effects OUTSIDE the lock — effects perform
         * transport I/O, cancel operations, and invoke listener
         * callbacks which must not be called under lock. */
        if (result.effect_count > 0) {
            pn_subscribe_execute_effects(mgr, &result);
        }
    }
}

int pn_subscribe_feature_tick(void* state)
{
    pn_subscribe_manager_t* mgr = (pn_subscribe_manager_t*)state;
    if (NULL == mgr) {
        return 0;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(mgr->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(mgr->ctx);

    /* Check if there is work to do (under lock for consistent read). */
    pn_ctx_lock(platform, lock);
    int idle = (PN_SUBSCRIBE_STATE_UNSUBSCRIBED == mgr->ee_state
                && !pn_subscribe_event_queue_has_events(&mgr->event_queue));
    pn_ctx_unlock(platform, lock);

    if (idle) {
        return 0;
    }

    pn_subscribe_tick(mgr);

    /* Return whether the subscribe EE is still active. */
    pn_ctx_lock(platform, lock);
    int active = (PN_SUBSCRIBE_STATE_UNSUBSCRIBED != mgr->ee_state);
    pn_ctx_unlock(platform, lock);

    return active;
}

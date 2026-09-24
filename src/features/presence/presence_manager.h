/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_MANAGER_H
#define PN_PRESENCE_MANAGER_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_manager.h requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "presence_event_queue.h"
#include "presence_internal.h"
#include "core/protocol_common/pn_channel_dispatch_state.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/types_fwd.h"
#include "core/runtime/timer_list_internal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Maximum timer entries for the presence event engine.
 *
 * Sized for: 1 heartbeat cooldown timer + 1 headroom.
 */
#ifndef PUBNUB_CFG_PRESENCE_MAX_TIMERS
#define PUBNUB_CFG_PRESENCE_MAX_TIMERS 2
#endif

/**
 * @brief Presence manager: per-context feature state for presence.
 *
 * Owns the heartbeat event engine state, timer infrastructure, and
 * cached channel/group strings. Allocated lazily on first
 * pn_presence_api_joined() call.
 */
typedef struct pn_presence_manager {
    /** Current heartbeat event engine state. */
    pn_presence_ee_state_t ee_state;

    /** Fixed-capacity storage for the timer list. */
    pn_timer_entry_t timer_entries[PUBNUB_CFG_PRESENCE_MAX_TIMERS];
    /** Timer list managing heartbeat/wait scheduling. */
    pn_timer_list_t timers;
    /** Handle for the active wait (cooldown) timer, or invalid. */
    pn_timer_handle_t wait_timer;

    /** Deferred event queue: callbacks push events here, tick drains. */
    pn_presence_event_queue_t event_queue;

    /** Slot ID of the in-flight heartbeat request.
     *  PUBNUB_SLOT_ID_INVALID when no request is active. */
    uint16_t active_slot_id;

    /** Currently tracked channels (comma-separated, allocator-owned).
     *  NULL when no channels are active. Overwritten on JOINED,
     *  modified on LEFT. */
    char* channels;

    /** Currently tracked channel groups (comma-separated, allocator-owned).
     *  NULL when no groups are active. */
    char* groups;

    /** Channels to leave (comma-separated, allocator-owned).
     *  Populated before firing LEFT/LEFT_ALL event; consumed by
     *  dispatch_leave. NULL when empty. */
    char* leave_channels;

    /** Channel groups to leave (allocator-owned). Same lifecycle
     *  as leave_channels. */
    char* leave_groups;

    /** Heartbeat interval in milliseconds (computed from config). */
    uint32_t heartbeat_interval_ms;

    /** Presence timeout in seconds (for the heartbeat query param). */
    uint32_t presence_timeout_sec;

    /** 1 = suppress leave requests on unsubscribe. */
    uint8_t suppress_leave;

    /** Cascaded event from a dispatch-failure path. When non-NONE, the
     *  iterative effect loop re-enters the EE with this event instead
     *  of recursing through execute_single_effect. */
    pn_presence_ee_event_type_t cascaded_event;

    /** 1 = context is being destroyed; callbacks must no-op. */
    uint8_t draining;

    /** Owning context (borrowed). */
    pubnub_context_t* ctx;
} pn_presence_manager_t;

/**
 * @brief Per-dispatch state holding pre-encoded channel/group strings.
 *
 * Attached to the pending entry as feature_state so the strings remain
 * valid through dispatch and are freed on slot release.
 */
typedef pn_channel_dispatch_state_t pn_presence_dispatch_state_t;

/**
 * @brief Allocate and initialize the presence manager for a context.
 *
 * Uses the context's allocator. The caller must register the returned
 * manager in the feature registry via pn_context_set_feature_state()
 * with cleanup = pn_presence_manager_cleanup.
 *
 * @param ctx   Context (non-NULL, initialized). Stored as back-pointer.
 * @param alloc Allocator for the manager struct.
 * @return Allocated manager on success, or NULL on allocation failure.
 */
pn_presence_manager_t* pn_presence_manager_create(pubnub_context_t* ctx,
                                                  pubnub_allocator_provider_t* alloc);

/**
 * @brief Feature registry cleanup callback for presence.
 *
 * Conforms to pn_feature_cleanup_fn_t. Frees the manager struct.
 *
 * @param state Manager pointer (cast from void*).
 * @param alloc Allocator for deallocation.
 */
void pn_presence_manager_cleanup(void* state, pubnub_allocator_provider_t* alloc);

/**
 * @brief Feature-registry tick adaptor for presence.
 *
 * Conforms to pn_feature_tick_fn_t. Sweeps timers and processes
 * effects. Returns non-zero when the presence EE is active.
 *
 * @param state Presence manager (cast from void*).
 * @return Non-zero if the presence EE is active, 0 if idle.
 */
int pn_presence_feature_tick(void* state);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PRESENCE_MANAGER_H */

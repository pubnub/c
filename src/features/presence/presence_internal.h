/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_INTERNAL_H
#define PN_PRESENCE_INTERNAL_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_internal.h requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "pubnub/error.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Presence heartbeat event engine states. */
typedef enum pn_presence_ee_state {
    /** No heartbeat activity; presence engine idle. */
    PN_PRESENCE_STATE_HEARTBEAT_INACTIVE = 0,
    /** Heartbeat HTTP request in flight. */
    PN_PRESENCE_STATE_HEARTBEATING,
    /** Waiting for the next heartbeat interval (cooldown timer). */
    PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN,
    /** Last heartbeat failed; awaiting channel change or reconnect. */
    PN_PRESENCE_STATE_HEARTBEAT_FAILED,
    /** Heartbeat paused by explicit disconnect. */
    PN_PRESENCE_STATE_HEARTBEAT_STOPPED
} pn_presence_ee_state_t;

/** @brief Events that drive the presence heartbeat event engine. */
typedef enum pn_presence_ee_event_type {
    /** No event (sentinel for cascaded_event field). */
    PN_PRES_EVENT_NONE = 0,
    /** Channels added to the presence set. */
    PN_PRES_EVENT_JOINED,
    /** Channels removed from the presence set. */
    PN_PRES_EVENT_LEFT,
    /** All channels removed at once. */
    PN_PRES_EVENT_LEFT_ALL,
    /** User explicitly disconnected. */
    PN_PRES_EVENT_DISCONNECT,
    /** User explicitly reconnects from stopped/failed state. */
    PN_PRES_EVENT_RECONNECT,
    /** Heartbeat HTTP request succeeded. */
    PN_PRES_EVENT_HEARTBEAT_SUCCESS,
    /** Heartbeat HTTP request failed. */
    PN_PRES_EVENT_HEARTBEAT_FAILURE,
    /** Cooldown timer expired (time to heartbeat again). */
    PN_PRES_EVENT_TIMES_UP
} pn_presence_ee_event_type_t;

/** @brief Side-effects produced by a presence state transition. */
typedef enum pn_presence_ee_effect_type {
    /** No effect (sentinel/padding). */
    PN_PRES_EE_EFFECT_NONE = 0,
    /** Issue a heartbeat HTTP request. */
    PN_PRES_EE_EFFECT_HEARTBEAT,
    /** Issue a leave HTTP request. */
    PN_PRES_EE_EFFECT_LEAVE,
    /** Start the cooldown wait timer. */
    PN_PRES_EE_EFFECT_WAIT,
    /** Cancel the in-flight heartbeat request. */
    PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT,
    /** Cancel the running cooldown timer. */
    PN_PRES_EE_EFFECT_CANCEL_WAIT
} pn_presence_ee_effect_type_t;

/** @brief Maximum effects a single presence transition may emit. */
#define PN_PRESENCE_MAX_EFFECTS 4

/**
 * @brief Default presence timeout when the user does not configure one.
 *
 * Matches the server-side default expiry window used by JS/Kotlin/Swift
 * SDKs. Sent as the @c ?heartbeat= parameter on subscription-list
 * changes so the server registers the UUID for presence tracking.
 */
#define PN_PRESENCE_DEFAULT_TIMEOUT_SEC 300U

/**
 * @brief Input event for the presence state machine.
 *
 * @c subscriptions_empty is meaningful for LEFT events (1 = the channel
 * set is now empty after the removal).
 */
typedef struct pn_presence_ee_event {
    pn_presence_ee_event_type_t type;
    uint8_t                     subscriptions_empty;
} pn_presence_ee_event_t;

/**
 * @brief A single effect descriptor produced by a presence transition.
 *
 * For LEAVE effects, @c leave_all indicates whether the leave targets
 * all channels (1) or only the delta channel set (0).
 */
typedef struct pn_presence_ee_effect {
    pn_presence_ee_effect_type_t type;
    uint8_t                      leave_all;
} pn_presence_ee_effect_t;

/**
 * @brief Complete result of a presence state-machine transition.
 *
 * Pure value - no heap allocation, no pointers. The caller reads
 * @c new_state and iterates @c effects[0..effect_count-1].
 */
typedef struct pn_presence_ee_transition_result {
    pn_presence_ee_state_t  new_state;
    pn_presence_ee_effect_t effects[PN_PRESENCE_MAX_EFFECTS];
    uint8_t                 effect_count;
} pn_presence_ee_transition_result_t;

/**
 * @brief Compute the next state and effects for the presence engine.
 *
 * Pure function with no side effects. Reads @p current_state and
 * @p event, returns the transition result. Never allocates, never
 * touches external state.
 *
 * @param current_state Present state of the presence event engine.
 * @param event         Incoming event descriptor (non-NULL).
 *
 * @return Transition result containing the new state and an ordered
 *         list of effects to execute.
 */
pn_presence_ee_transition_result_t
pn_presence_ee_transition(pn_presence_ee_state_t        current_state,
                          const pn_presence_ee_event_t* event);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PRESENCE_INTERNAL_H */

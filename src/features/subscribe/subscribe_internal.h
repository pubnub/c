/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_SUBSCRIBE_INTERNAL_H
#define PN_SUBSCRIBE_INTERNAL_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_internal.h requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "pubnub/error.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Subscribe event engine states. */
typedef enum pn_subscribe_ee_state {
    /** No active subscription; idle. */
    PN_SUBSCRIBE_STATE_UNSUBSCRIBED = 0,
    /** Initial handshake request in flight. */
    PN_SUBSCRIBE_STATE_HANDSHAKING,
    /** Handshake failed; awaiting RECONNECT or channel change. */
    PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED,
    /** Handshake cancelled by DISCONNECT; awaiting RECONNECT. */
    PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED,
    /** Long-poll receive loop active. */
    PN_SUBSCRIBE_STATE_RECEIVING,
    /** Receive failed; awaiting RECONNECT or channel change. */
    PN_SUBSCRIBE_STATE_RECEIVE_FAILED,
    /** Receive cancelled by DISCONNECT; awaiting RECONNECT. */
    PN_SUBSCRIBE_STATE_RECEIVE_STOPPED
} pn_subscribe_ee_state_t;

/** @brief Events that drive the subscribe event engine. */
typedef enum pn_subscribe_ee_event_type {
    /** Channel/group set mutated (add or remove). */
    PN_SUB_EVENT_SUBSCRIPTION_CHANGED = 0,
    /** Subscription restored with a known cursor. */
    PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
    /** Handshake HTTP request completed successfully. */
    PN_SUB_EVENT_HANDSHAKE_SUCCESS,
    /** Handshake HTTP request failed. */
    PN_SUB_EVENT_HANDSHAKE_FAILURE,
    /** Long-poll receive returned new messages. */
    PN_SUB_EVENT_RECEIVE_SUCCESS,
    /** Long-poll receive request failed. */
    PN_SUB_EVENT_RECEIVE_FAILURE,
    /** User explicitly disconnected. */
    PN_SUB_EVENT_DISCONNECT,
    /** User explicitly reconnects from a stopped/failed state. */
    PN_SUB_EVENT_RECONNECT,
    /** All channels/groups removed — terminate. */
    PN_SUB_EVENT_UNSUBSCRIBE_ALL
} pn_subscribe_ee_event_type_t;

/** @brief Side-effects produced by a state transition. */
typedef enum pn_subscribe_ee_effect_type {
    /** No effect (sentinel/padding). */
    PN_SUB_EE_EFFECT_NONE = 0,
    /** Issue a handshake HTTP request. */
    PN_SUB_EE_EFFECT_HANDSHAKE,
    /** Issue a long-poll receive HTTP request. */
    PN_SUB_EE_EFFECT_RECEIVE_MESSAGES,
    /** Cancel the in-flight handshake request. Idempotent: the effect
     *  executor must treat this as a no-op when the transport handle
     *  has already completed or was never issued. */
    PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE,
    /** Cancel the in-flight receive request. Idempotent: same no-op
     *  contract as CANCEL_HANDSHAKE. */
    PN_SUB_EE_EFFECT_CANCEL_RECEIVE,
    /** Emit a subscribe status event to listeners. */
    PN_SUB_EE_EFFECT_EMIT_STATUS,
    /** Emit received messages to listeners. */
    PN_SUB_EE_EFFECT_EMIT_MESSAGES
} pn_subscribe_ee_effect_type_t;

/** @brief Status categories delivered via EMIT_STATUS effects. */
typedef enum pn_subscribe_ee_status {
    /** Handshake succeeded on first attempt. */
    PN_SUB_EE_STATUS_CONNECTED = 0,
    /** User-initiated disconnect. */
    PN_SUB_EE_STATUS_DISCONNECTED,
    /** Connection lost without user intent. */
    PN_SUB_EE_STATUS_DISCONNECTED_UNEXPECTEDLY,
    /** Handshake attempt failed (network/server). */
    PN_SUB_EE_STATUS_CONNECTION_ERROR,
    /** Channel set changed while actively receiving. */
    PN_SUB_EE_STATUS_SUBSCRIPTION_CHANGED
} pn_subscribe_ee_status_t;

/** @brief Maximum effects a single transition may emit. */
#define PN_SUBSCRIBE_MAX_EFFECTS 4

/**
 * @brief A single effect descriptor produced by a transition.
 *
 * For @ref PN_SUB_EE_EFFECT_EMIT_STATUS the @c status field carries the
 * specific category; @c reason and @c http_status_code carry error
 * detail (zero for non-error statuses).
 */
typedef struct pn_subscribe_ee_effect {
    pn_subscribe_ee_effect_type_t type;
    pn_subscribe_ee_status_t      status;
    pubnub_res_t                  reason;
    uint16_t                      http_status_code;
} pn_subscribe_ee_effect_t;

/**
 * @brief Complete result of a state-machine transition.
 *
 * Pure value — no heap allocation, no pointers. The caller reads
 * @c new_state and iterates @c effects[0..effect_count-1].
 */
typedef struct pn_subscribe_ee_transition_result {
    pn_subscribe_ee_state_t  new_state;
    pn_subscribe_ee_effect_t effects[PN_SUBSCRIBE_MAX_EFFECTS];
    uint8_t                  effect_count;
} pn_subscribe_ee_transition_result_t;

/**
 * @brief Input event for the subscribe state machine.
 *
 * @c subscriptions_empty is meaningful only for SUBSCRIPTION_CHANGED and
 * SUBSCRIPTION_RESTORED events (1 = the channel/group set is now
 * empty after the change). @c failure_reason and @c http_status_code
 * are populated for HANDSHAKE_FAILURE / RECEIVE_FAILURE events.
 *
 * @c generation is meaningful for SUBSCRIPTION_CHANGED and
 * SUBSCRIPTION_RESTORED events: it carries the subscription mutation
 * counter at the time the event was enqueued so the EE can discard
 * stale events superseded by a later mutation.
 */
typedef struct pn_subscribe_ee_event {
    pn_subscribe_ee_event_type_t type;
    uint8_t                      subscriptions_empty;
    pubnub_res_t                 failure_reason;
    uint16_t                     http_status_code;
    uint32_t                     generation;
} pn_subscribe_ee_event_t;

/**
 * @brief Compute the next state and effects for the subscribe engine.
 *
 * Pure function with no side effects. Reads @p current_state and
 * @p event, returns the transition result. Never allocates, never
 * touches external state.
 *
 * @param current_state Present state of the event engine.
 * @param event         Incoming event descriptor (non-NULL).
 *
 * @return Transition result containing the new state and an ordered
 *         list of effects to execute.
 */
pn_subscribe_ee_transition_result_t
pn_subscribe_ee_transition(pn_subscribe_ee_state_t        current_state,
                           const pn_subscribe_ee_event_t* event);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_SUBSCRIBE_INTERNAL_H */

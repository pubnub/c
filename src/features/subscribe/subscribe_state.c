/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "subscribe_internal.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_state.c requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include <stddef.h>

/**
 * @brief Return a no-op transition (stay in current state, zero effects).
 */
static pn_subscribe_ee_transition_result_t pn_no_transition(pn_subscribe_ee_state_t state)
{
    pn_subscribe_ee_transition_result_t r = {0};
    r.new_state                           = state;
    r.effect_count                        = 0;
    return r;
}

/**
 * @brief Append an effect to a transition result being built.
 *
 * Caller must ensure effect_count < PN_SUBSCRIBE_MAX_EFFECTS.
 */
static void pn_add_effect(pn_subscribe_ee_transition_result_t* r,
                          pn_subscribe_ee_effect_type_t        type,
                          pn_subscribe_ee_status_t             status)
{
    r->effects[r->effect_count].type             = type;
    r->effects[r->effect_count].status           = status;
    r->effects[r->effect_count].reason           = PUBNUB_OK;
    r->effects[r->effect_count].http_status_code = 0;
    r->effect_count++;
}

/**
 * @brief Append an EMIT_STATUS effect carrying error detail.
 */
static void pn_add_status_effect(pn_subscribe_ee_transition_result_t* r,
                                 pn_subscribe_ee_status_t             status,
                                 pubnub_res_t                         reason,
                                 uint16_t http_status_code)
{
    r->effects[r->effect_count].type             = PN_SUB_EE_EFFECT_EMIT_STATUS;
    r->effects[r->effect_count].status           = status;
    r->effects[r->effect_count].reason           = reason;
    r->effects[r->effect_count].http_status_code = http_status_code;
    r->effect_count++;
}

/**
 * @brief Handle SUBSCRIPTION_CHANGED / SUBSCRIPTION_RESTORED when
 *        not in an active managed-effect state (no cancel needed).
 *
 * Non-empty → target_state with HANDSHAKE; empty → UNSUBSCRIBED.
 */
static pn_subscribe_ee_transition_result_t
pn_sub_changed_no_cancel(pn_subscribe_ee_state_t target_if_nonempty,
                         uint8_t                 subscriptions_empty)
{
    pn_subscribe_ee_transition_result_t r = {0};

    if (subscriptions_empty) {
        r.new_state    = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
        r.effect_count = 0;
        return r;
    }

    r.new_state = target_if_nonempty;
    pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
    return r;
}

static pn_subscribe_ee_transition_result_t
pn_transition_unsubscribed(const pn_subscribe_ee_event_t* event)
{
    switch (event->type) {
    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: {
        if (event->subscriptions_empty) {
            return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);
        }
        pn_subscribe_ee_transition_result_t r = {0};
        r.new_state                           = PN_SUBSCRIBE_STATE_HANDSHAKING;
        pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;
    }
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        return pn_sub_changed_no_cancel(PN_SUBSCRIBE_STATE_HANDSHAKING,
                                        event->subscriptions_empty);

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);
    }
}

static pn_subscribe_ee_transition_result_t
pn_transition_handshaking(const pn_subscribe_ee_event_t* event)
{
    pn_subscribe_ee_transition_result_t r = {0};

    switch (event->type) {
    case PN_SUB_EVENT_HANDSHAKE_SUCCESS:
        r.new_state = PN_SUBSCRIBE_STATE_RECEIVING;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(&r, PN_SUB_EE_EFFECT_EMIT_STATUS, PN_SUB_EE_STATUS_CONNECTED);
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, (pn_subscribe_ee_status_t)0);
        return r;

    case PN_SUB_EVENT_HANDSHAKE_FAILURE:
        r.new_state = PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        pn_add_status_effect(&r,
                             PN_SUB_EE_STATUS_CONNECTION_ERROR,
                             event->failure_reason,
                             event->http_status_code);
        return r;

    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: /* falls through */
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        if (event->subscriptions_empty) {
            r.new_state = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
            pn_add_effect(&r,
                          PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE,
                          (pn_subscribe_ee_status_t)0);
            return r;
        }
        r.new_state = PN_SUBSCRIBE_STATE_HANDSHAKING;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;

    case PN_SUB_EVENT_DISCONNECT:
        r.new_state = PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;

    case PN_SUB_EVENT_UNSUBSCRIBE_ALL:
        r.new_state = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_HANDSHAKING);
    }
}

static pn_subscribe_ee_transition_result_t
pn_transition_handshake_failed(const pn_subscribe_ee_event_t* event)
{
    switch (event->type) {
    case PN_SUB_EVENT_RECONNECT: {
        pn_subscribe_ee_transition_result_t r = {0};
        r.new_state                           = PN_SUBSCRIBE_STATE_HANDSHAKING;
        pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;
    }
    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: /* falls through */
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        return pn_sub_changed_no_cancel(PN_SUBSCRIBE_STATE_HANDSHAKING,
                                        event->subscriptions_empty);

    case PN_SUB_EVENT_UNSUBSCRIBE_ALL:
        return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED);
    }
}

static pn_subscribe_ee_transition_result_t
pn_transition_handshake_stopped(const pn_subscribe_ee_event_t* event)
{
    switch (event->type) {
    case PN_SUB_EVENT_RECONNECT: {
        pn_subscribe_ee_transition_result_t r = {0};
        r.new_state                           = PN_SUBSCRIBE_STATE_HANDSHAKING;
        pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;
    }
    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: /* fall through */
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        if (event->subscriptions_empty) {
            return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);
        }
        return pn_no_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED);

    case PN_SUB_EVENT_UNSUBSCRIBE_ALL:
        return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED);
    }
}

static pn_subscribe_ee_transition_result_t
pn_transition_receiving(const pn_subscribe_ee_event_t* event)
{
    pn_subscribe_ee_transition_result_t r = {0};

    switch (event->type) {
    case PN_SUB_EVENT_RECEIVE_SUCCESS:
        r.new_state = PN_SUBSCRIBE_STATE_RECEIVING;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_EMIT_MESSAGES, (pn_subscribe_ee_status_t)0);
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, (pn_subscribe_ee_status_t)0);
        return r;

    case PN_SUB_EVENT_RECEIVE_FAILURE:
        r.new_state = PN_SUBSCRIBE_STATE_RECEIVE_FAILED;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
        pn_add_status_effect(&r,
                             PN_SUB_EE_STATUS_DISCONNECTED_UNEXPECTEDLY,
                             event->failure_reason,
                             event->http_status_code);
        return r;

    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED:
        if (event->subscriptions_empty) {
            r.new_state = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
            pn_add_effect(
                &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
            pn_add_effect(
                &r, PN_SUB_EE_EFFECT_EMIT_STATUS, PN_SUB_EE_STATUS_DISCONNECTED);
            return r;
        }
        r.new_state = PN_SUBSCRIBE_STATE_RECEIVING;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(&r,
                      PN_SUB_EE_EFFECT_EMIT_STATUS,
                      PN_SUB_EE_STATUS_SUBSCRIPTION_CHANGED);
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, (pn_subscribe_ee_status_t)0);
        return r;

    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        if (event->subscriptions_empty) {
            r.new_state = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
            pn_add_effect(
                &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
            pn_add_effect(
                &r, PN_SUB_EE_EFFECT_EMIT_STATUS, PN_SUB_EE_STATUS_DISCONNECTED);
            return r;
        }
        /* Connection is already established — restart receive directly
         * with the restored cursor; no re-handshake needed. */
        r.new_state = PN_SUBSCRIBE_STATE_RECEIVING;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(&r, PN_SUB_EE_EFFECT_EMIT_STATUS, PN_SUB_EE_STATUS_CONNECTED);
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, (pn_subscribe_ee_status_t)0);
        return r;

    case PN_SUB_EVENT_DISCONNECT:
        r.new_state = PN_SUBSCRIBE_STATE_RECEIVE_STOPPED;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(&r, PN_SUB_EE_EFFECT_EMIT_STATUS, PN_SUB_EE_STATUS_DISCONNECTED);
        return r;

    case PN_SUB_EVENT_UNSUBSCRIBE_ALL:
        r.new_state = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
        pn_add_effect(
            &r, PN_SUB_EE_EFFECT_CANCEL_RECEIVE, (pn_subscribe_ee_status_t)0);
        pn_add_effect(&r, PN_SUB_EE_EFFECT_EMIT_STATUS, PN_SUB_EE_STATUS_DISCONNECTED);
        return r;

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_RECEIVING);
    }
}

static pn_subscribe_ee_transition_result_t
pn_transition_receive_failed(const pn_subscribe_ee_event_t* event)
{
    switch (event->type) {
    case PN_SUB_EVENT_RECONNECT: {
        pn_subscribe_ee_transition_result_t r = {0};
        r.new_state                           = PN_SUBSCRIBE_STATE_HANDSHAKING;
        pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;
    }
    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: /* fall through */
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        return pn_sub_changed_no_cancel(PN_SUBSCRIBE_STATE_HANDSHAKING,
                                        event->subscriptions_empty);

    case PN_SUB_EVENT_UNSUBSCRIBE_ALL:
        return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_RECEIVE_FAILED);
    }
}

static pn_subscribe_ee_transition_result_t
pn_transition_receive_stopped(const pn_subscribe_ee_event_t* event)
{
    switch (event->type) {
    case PN_SUB_EVENT_RECONNECT: {
        pn_subscribe_ee_transition_result_t r = {0};
        r.new_state                           = PN_SUBSCRIBE_STATE_HANDSHAKING;
        pn_add_effect(&r, PN_SUB_EE_EFFECT_HANDSHAKE, (pn_subscribe_ee_status_t)0);
        return r;
    }
    case PN_SUB_EVENT_SUBSCRIPTION_CHANGED: /* fall through */
    case PN_SUB_EVENT_SUBSCRIPTION_RESTORED:
        if (event->subscriptions_empty) {
            return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);
        }
        return pn_no_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED);

    case PN_SUB_EVENT_UNSUBSCRIBE_ALL:
        return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);

    default: return pn_no_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED);
    }
}

pn_subscribe_ee_transition_result_t
pn_subscribe_ee_transition(pn_subscribe_ee_state_t        current_state,
                           const pn_subscribe_ee_event_t* event)
{
    if (NULL == event) {
        return pn_no_transition(current_state);
    }

    switch (current_state) {
    case PN_SUBSCRIBE_STATE_UNSUBSCRIBED:
        return pn_transition_unsubscribed(event);
    case PN_SUBSCRIBE_STATE_HANDSHAKING:
        return pn_transition_handshaking(event);
    case PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED:
        return pn_transition_handshake_failed(event);
    case PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED:
        return pn_transition_handshake_stopped(event);
    case PN_SUBSCRIBE_STATE_RECEIVING: return pn_transition_receiving(event);
    case PN_SUBSCRIBE_STATE_RECEIVE_FAILED:
        return pn_transition_receive_failed(event);
    case PN_SUBSCRIBE_STATE_RECEIVE_STOPPED:
        return pn_transition_receive_stopped(event);
    default: return pn_no_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED);
    }
}

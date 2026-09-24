/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_internal.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_state.c requires PUBNUB_ENABLE_PRESENCE=ON - this translation " \
    "unit has no meaning without the presence feature."
#endif

#include <stddef.h>

/**
 * @brief Return a no-op transition (stay in current state, zero effects).
 */
static pn_presence_ee_transition_result_t pn_no_transition(pn_presence_ee_state_t state)
{
    pn_presence_ee_transition_result_t r = {0};
    r.new_state                          = state;
    r.effect_count                       = 0;
    return r;
}

/**
 * @brief Append an effect to a transition result being built.
 *
 * Caller must ensure effect_count < PN_PRESENCE_MAX_EFFECTS.
 */
static void pn_add_effect(pn_presence_ee_transition_result_t* r,
                          pn_presence_ee_effect_type_t        type,
                          uint8_t                             leave_all)
{
    r->effects[r->effect_count].type      = type;
    r->effects[r->effect_count].leave_all = leave_all;
    r->effect_count++;
}

static pn_presence_ee_transition_result_t
pn_transition_heartbeat_inactive(const pn_presence_ee_event_t* event)
{
    switch (event->type) {
    case PN_PRES_EVENT_JOINED: {
        pn_presence_ee_transition_result_t r = {0};
        r.new_state                          = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;
    }
    default: return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE);
    }
}

static pn_presence_ee_transition_result_t
pn_transition_heartbeating(const pn_presence_ee_event_t* event)
{
    pn_presence_ee_transition_result_t r = {0};

    switch (event->type) {
    case PN_PRES_EVENT_HEARTBEAT_SUCCESS:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_WAIT, 0);
        return r;

    case PN_PRES_EVENT_JOINED:
        r.new_state = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_LEFT:
        if (event->subscriptions_empty) {
            r.new_state = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
            pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
            pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
            return r;
        }
        /* Remaining channels are still subscribed; the subscribe long-poll's
         * heartbeat= timeout maintains their presence. Let the in-flight
         * heartbeat (if any) complete naturally and keep the cooldown clock
         * undisturbed — only LEAVE the removed channels. */
        r.new_state = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 0);
        return r;

    case PN_PRES_EVENT_LEFT_ALL:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
        return r;

    case PN_PRES_EVENT_HEARTBEAT_FAILURE:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_FAILED;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_DISCONNECT:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_STOPPED;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
        return r;

    default: return pn_no_transition(PN_PRESENCE_STATE_HEARTBEATING);
    }
}

static pn_presence_ee_transition_result_t
pn_transition_heartbeat_cooldown(const pn_presence_ee_event_t* event)
{
    pn_presence_ee_transition_result_t r = {0};

    switch (event->type) {
    case PN_PRES_EVENT_JOINED:
        r.new_state = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_WAIT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_HEARTBEAT_SUCCESS: /* fallthrough */
    case PN_PRES_EVENT_HEARTBEAT_FAILURE:
        /* Out-of-band heartbeat completed: clean up the handle, stay
         * in COOLDOWN (the timer will fire the next regular one). */
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_TIMES_UP:
        r.new_state = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_WAIT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_LEFT:
        if (event->subscriptions_empty) {
            r.new_state = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
            pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
            pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_WAIT, 0);
            pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
            return r;
        }
        /* Same reasoning as HEARTBEATING+LEFT(!empty): cooldown timer keeps
         * counting from its original start — no reset, no presence timeout
         * risk. Only LEAVE the removed channels. */
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 0);
        return r;

    case PN_PRES_EVENT_LEFT_ALL:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_WAIT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
        return r;

    case PN_PRES_EVENT_DISCONNECT:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_STOPPED;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_CANCEL_WAIT, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
        return r;

    default: return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN);
    }
}

static pn_presence_ee_transition_result_t
pn_transition_heartbeat_failed(const pn_presence_ee_event_t* event)
{
    pn_presence_ee_transition_result_t r = {0};

    switch (event->type) {
    case PN_PRES_EVENT_JOINED:
        r.new_state = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_LEFT:
        if (event->subscriptions_empty) {
            r.new_state = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
            pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
            return r;
        }
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 0);
        pn_add_effect(&r, PN_PRES_EE_EFFECT_WAIT, 0);
        return r;

    case PN_PRES_EVENT_LEFT_ALL:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_INACTIVE;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
        return r;

    case PN_PRES_EVENT_RECONNECT:
        r.new_state = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;

    case PN_PRES_EVENT_DISCONNECT:
        r.new_state = PN_PRESENCE_STATE_HEARTBEAT_STOPPED;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_LEAVE, 1);
        return r;

    default: return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED);
    }
}

static pn_presence_ee_transition_result_t
pn_transition_heartbeat_stopped(const pn_presence_ee_event_t* event)
{
    switch (event->type) {
    case PN_PRES_EVENT_JOINED: /* fallthrough */
    case PN_PRES_EVENT_LEFT:
        return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_STOPPED);

    case PN_PRES_EVENT_RECONNECT: {
        pn_presence_ee_transition_result_t r = {0};
        r.new_state                          = PN_PRESENCE_STATE_HEARTBEATING;
        pn_add_effect(&r, PN_PRES_EE_EFFECT_HEARTBEAT, 0);
        return r;
    }

    case PN_PRES_EVENT_LEFT_ALL:
        return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE);

    default: return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_STOPPED);
    }
}

pn_presence_ee_transition_result_t
pn_presence_ee_transition(pn_presence_ee_state_t        current_state,
                          const pn_presence_ee_event_t* event)
{
    if (NULL == event) {
        return pn_no_transition(current_state);
    }

    switch (current_state) {
    case PN_PRESENCE_STATE_HEARTBEAT_INACTIVE:
        return pn_transition_heartbeat_inactive(event);
    case PN_PRESENCE_STATE_HEARTBEATING:
        return pn_transition_heartbeating(event);
    case PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN:
        return pn_transition_heartbeat_cooldown(event);
    case PN_PRESENCE_STATE_HEARTBEAT_FAILED:
        return pn_transition_heartbeat_failed(event);
    case PN_PRESENCE_STATE_HEARTBEAT_STOPPED:
        return pn_transition_heartbeat_stopped(event);
    default: return pn_no_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE);
    }
}

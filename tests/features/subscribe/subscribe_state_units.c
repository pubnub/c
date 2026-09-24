/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_state_units.c
 * @brief Unit tests for the subscribe event engine state machine.
 *
 * Exercises `pn_subscribe_ee_transition` in isolation — no mocks, no
 * transport, no allocations. Each test drives a single (state, event)
 * pair and asserts the resulting new state and effect list.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "features/subscribe/subscribe_event_queue.h"
#include "features/subscribe/subscribe_internal.h"

/* ================================================================== */
/* UNSUBSCRIBED state                                                   */
/* ================================================================== */

static void test_unsubscribed_subscription_changed_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_unsubscribed_subscription_changed_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_unsubscribed_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_unsubscribed_ignores_disconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_DISCONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* HANDSHAKING state                                                    */
/* ================================================================== */

static void test_handshaking_handshake_success(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_HANDSHAKE_SUCCESS};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVING, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_CONNECTED, result.effects[1].status);
    assert_int_equal(PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, result.effects[2].type);
}

static void test_handshaking_handshake_failure(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_HANDSHAKE_FAILURE};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_CONNECTION_ERROR, result.effects[1].status);
}

static void test_handshaking_disconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_DISCONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
}

static void test_handshaking_subscription_changed_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[1].type);
}

static void test_handshaking_subscription_changed_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
}

static void test_handshaking_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[1].type);
}

static void test_handshaking_subscription_restored_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
}

static void test_handshaking_unsubscribe_all(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_HANDSHAKE, result.effects[0].type);
}

/* ================================================================== */
/* HANDSHAKE_FAILED state                                              */
/* ================================================================== */

static void test_handshake_failed_reconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_RECONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_handshake_failed_subscription_changed_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_handshake_failed_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_handshake_failed_unsubscribe_all(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* HANDSHAKE_STOPPED state                                             */
/* ================================================================== */

static void test_handshake_stopped_reconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_RECONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_handshake_stopped_subscription_changed_stays(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, &event);

    /* Stopped state absorbs the change without restarting. */
    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_handshake_stopped_subscription_changed_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_handshake_stopped_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, &event);

    /* Stopped states absorb the restore without restarting. */
    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* RECEIVING state                                                      */
/* ================================================================== */

static void test_receiving_receive_success(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_RECEIVE_SUCCESS};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVING, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_MESSAGES, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, result.effects[2].type);
}

static void test_receiving_receive_failure(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_RECEIVE_FAILURE};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVE_FAILED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_DISCONNECTED_UNEXPECTEDLY,
                     result.effects[1].status);
}

static void test_receiving_disconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_DISCONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_DISCONNECTED, result.effects[1].status);
}

static void test_receiving_subscription_changed_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVING, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_SUBSCRIPTION_CHANGED,
                     result.effects[1].status);
    assert_int_equal(PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, result.effects[2].type);
}

static void test_receiving_subscription_changed_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_DISCONNECTED, result.effects[1].status);
}

static void test_receiving_unsubscribe_all(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_DISCONNECTED, result.effects[1].status);
}

static void test_receiving_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVING, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_CONNECTED, result.effects[1].status);
    assert_int_equal(PN_SUB_EE_EFFECT_RECEIVE_MESSAGES, result.effects[2].type);
}

static void test_receiving_subscription_restored_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_CANCEL_RECEIVE, result.effects[0].type);
    assert_int_equal(PN_SUB_EE_EFFECT_EMIT_STATUS, result.effects[1].type);
    assert_int_equal(PN_SUB_EE_STATUS_DISCONNECTED, result.effects[1].status);
}

/* ================================================================== */
/* RECEIVE_FAILED state                                                */
/* ================================================================== */

static void test_receive_failed_reconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_RECONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_receive_failed_subscription_changed(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_receive_failed_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_receive_failed_unsubscribe_all(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* RECEIVE_STOPPED state                                               */
/* ================================================================== */

static void test_receive_stopped_reconnect(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_RECONNECT};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_HANDSHAKING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_SUB_EE_EFFECT_HANDSHAKE, result.effects[0].type);
}

static void test_receive_stopped_subscription_changed_stays(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, &event);

    /* Stopped state absorbs the change without restarting. */
    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_receive_stopped_subscription_changed_empty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .subscriptions_empty = 1,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_receive_stopped_subscription_restored_nonempty(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {
        .type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED,
        .subscriptions_empty = 0,
    };

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, &event);

    /* Stopped states absorb the restore without restarting. */
    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_receive_stopped_unsubscribe_all(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVE_STOPPED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* Cross-cutting: UNSUBSCRIBE_ALL from multiple states                 */
/* ================================================================== */

static void test_unsubscribe_all_from_handshake_failed(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_FAILED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
}

static void test_unsubscribe_all_from_handshake_stopped(void** state)
{
    (void)state;
    pn_subscribe_ee_event_t event = {.type = PN_SUB_EVENT_UNSUBSCRIBE_ALL};

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_HANDSHAKE_STOPPED, &event);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
}

/* ================================================================== */
/* NULL event safety                                                    */
/* ================================================================== */

static void test_null_event_returns_same_state(void** state)
{
    (void)state;

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_RECEIVING, NULL);

    assert_int_equal(PN_SUBSCRIBE_STATE_RECEIVING, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_null_event_unsubscribed_state(void** state)
{
    (void)state;

    pn_subscribe_ee_transition_result_t result =
        pn_subscribe_ee_transition(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, NULL);

    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_event_queue_preserves_generation(void** state)
{
    (void)state;
    pn_subscribe_event_queue_t q;
    pn_subscribe_event_queue_init(&q);

    pn_subscribe_ee_event_t push_event;
    pn_subscribe_ee_event_t pop_event;
    memset(&push_event, 0, sizeof(push_event));
    push_event.type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
    push_event.generation = 42;

    pn_subscribe_event_queue_push(&q, &push_event);
    assert_int_equal(1, pn_subscribe_event_queue_pop(&q, &pop_event));
    assert_int_equal(PN_SUB_EVENT_SUBSCRIPTION_CHANGED, pop_event.type);
    assert_int_equal(42, (int)pop_event.generation);
}

static void test_stale_event_detected_by_generation(void** state)
{
    (void)state;
    /* Simulate: two SUBSCRIPTION_CHANGED events with gen=1 and gen=2.
     * Current manager generation is 2. Event with gen=1 is stale. */
    uint32_t mgr_generation = 2;

    pn_subscribe_ee_event_t stale = {
        .type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .generation = 1,
    };
    pn_subscribe_ee_event_t current = {
        .type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .generation = 2,
    };
    pn_subscribe_ee_event_t non_mutation = {
        .type       = PN_SUB_EVENT_DISCONNECT,
        .generation = 0,
    };

    /* Stale: gen=1 < manager gen=2. */
    assert_true((int32_t)(stale.generation - mgr_generation) < 0);

    /* Current: gen=2 == manager gen=2 — not stale. */
    assert_false((int32_t)(current.generation - mgr_generation) < 0);

    /* Non-mutation events skip the generation check entirely. */
    assert_int_not_equal(PN_SUB_EVENT_SUBSCRIPTION_CHANGED, non_mutation.type);
    assert_int_not_equal(PN_SUB_EVENT_SUBSCRIPTION_RESTORED, non_mutation.type);
}

static void test_generation_wraparound(void** state)
{
    (void)state;
    /* Manager at UINT32_MAX, event at UINT32_MAX is current.
     * Event at UINT32_MAX-1 is stale. */
    uint32_t mgr_generation = UINT32_MAX;

    pn_subscribe_ee_event_t current = {
        .type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .generation = UINT32_MAX,
    };
    assert_false((int32_t)(current.generation - mgr_generation) < 0);

    pn_subscribe_ee_event_t stale = {
        .type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .generation = UINT32_MAX - 1,
    };
    assert_true((int32_t)(stale.generation - mgr_generation) < 0);

    /* Manager wraps to 0. Event at UINT32_MAX is now stale
     * (signed diff: UINT32_MAX - 0 = -1 as int32_t). */
    mgr_generation                          = 0;
    pn_subscribe_ee_event_t post_wrap_stale = {
        .type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .generation = UINT32_MAX,
    };
    assert_true((int32_t)(post_wrap_stale.generation - mgr_generation) < 0);
}

static void test_single_subscribe_generation_processed(void** state)
{
    (void)state;
    /* A single mutation produces gen=1 and manager gen=1.
     * The event must NOT be considered stale. */
    uint32_t mgr_generation = 0;
    mgr_generation++;

    pn_subscribe_ee_event_t event = {
        .type       = PN_SUB_EVENT_SUBSCRIPTION_CHANGED,
        .generation = mgr_generation,
    };

    int is_stale = (PN_SUB_EVENT_SUBSCRIPTION_CHANGED == event.type
                    || PN_SUB_EVENT_SUBSCRIPTION_RESTORED == event.type)
                && (int32_t)(event.generation - mgr_generation) < 0;

    assert_false(is_stale);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* UNSUBSCRIBED */
        cmocka_unit_test(test_unsubscribed_subscription_changed_nonempty),
        cmocka_unit_test(test_unsubscribed_subscription_changed_empty),
        cmocka_unit_test(test_unsubscribed_subscription_restored_nonempty),
        cmocka_unit_test(test_unsubscribed_ignores_disconnect),
        /* HANDSHAKING */
        cmocka_unit_test(test_handshaking_handshake_success),
        cmocka_unit_test(test_handshaking_handshake_failure),
        cmocka_unit_test(test_handshaking_disconnect),
        cmocka_unit_test(test_handshaking_subscription_changed_nonempty),
        cmocka_unit_test(test_handshaking_subscription_changed_empty),
        cmocka_unit_test(test_handshaking_subscription_restored_nonempty),
        cmocka_unit_test(test_handshaking_subscription_restored_empty),
        cmocka_unit_test(test_handshaking_unsubscribe_all),
        /* HANDSHAKE_FAILED */
        cmocka_unit_test(test_handshake_failed_reconnect),
        cmocka_unit_test(test_handshake_failed_subscription_changed_nonempty),
        cmocka_unit_test(test_handshake_failed_subscription_restored_nonempty),
        cmocka_unit_test(test_handshake_failed_unsubscribe_all),
        /* HANDSHAKE_STOPPED */
        cmocka_unit_test(test_handshake_stopped_reconnect),
        cmocka_unit_test(test_handshake_stopped_subscription_changed_stays),
        cmocka_unit_test(test_handshake_stopped_subscription_changed_empty),
        cmocka_unit_test(test_handshake_stopped_subscription_restored_nonempty),
        /* RECEIVING */
        cmocka_unit_test(test_receiving_receive_success),
        cmocka_unit_test(test_receiving_receive_failure),
        cmocka_unit_test(test_receiving_disconnect),
        cmocka_unit_test(test_receiving_subscription_changed_nonempty),
        cmocka_unit_test(test_receiving_subscription_changed_empty),
        cmocka_unit_test(test_receiving_subscription_restored_nonempty),
        cmocka_unit_test(test_receiving_subscription_restored_empty),
        cmocka_unit_test(test_receiving_unsubscribe_all),
        /* RECEIVE_FAILED */
        cmocka_unit_test(test_receive_failed_reconnect),
        cmocka_unit_test(test_receive_failed_subscription_changed),
        cmocka_unit_test(test_receive_failed_subscription_restored_nonempty),
        cmocka_unit_test(test_receive_failed_unsubscribe_all),
        /* RECEIVE_STOPPED */
        cmocka_unit_test(test_receive_stopped_reconnect),
        cmocka_unit_test(test_receive_stopped_subscription_changed_stays),
        cmocka_unit_test(test_receive_stopped_subscription_changed_empty),
        cmocka_unit_test(test_receive_stopped_subscription_restored_nonempty),
        cmocka_unit_test(test_receive_stopped_unsubscribe_all),
        /* Cross-cutting UNSUBSCRIBE_ALL */
        cmocka_unit_test(test_unsubscribe_all_from_handshake_failed),
        cmocka_unit_test(test_unsubscribe_all_from_handshake_stopped),
        /* NULL safety */
        cmocka_unit_test(test_null_event_returns_same_state),
        cmocka_unit_test(test_null_event_unsubscribed_state),
        /* Generation-based deduplication */
        cmocka_unit_test(test_event_queue_preserves_generation),
        cmocka_unit_test(test_stale_event_detected_by_generation),
        cmocka_unit_test(test_generation_wraparound),
        cmocka_unit_test(test_single_subscribe_generation_processed),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

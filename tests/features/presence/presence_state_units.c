/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file presence_state_units.c
 * @brief Unit tests for the presence heartbeat event engine state machine.
 *
 * Exercises `pn_presence_ee_transition` in isolation — no mocks, no
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

#include "features/presence/presence_internal.h"

/* ================================================================== */
/* HEARTBEAT_INACTIVE state                                            */
/* ================================================================== */

static void test_inactive_joined(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_JOINED};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[0].type);
}

static void test_inactive_ignores_left(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_LEFT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_inactive_ignores_disconnect(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_DISCONNECT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* HEARTBEATING state                                                  */
/* ================================================================== */

static void test_heartbeating_success(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type = PN_PRES_EVENT_HEARTBEAT_SUCCESS,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_WAIT, result.effects[1].type);
}

static void test_heartbeating_failure(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_HEARTBEAT_FAILURE};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_FAILED, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
}

static void test_heartbeating_disconnect(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_DISCONNECT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[1].type);
    assert_int_equal(1, result.effects[1].leave_all);
}

static void test_heartbeating_left_all(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_LEFT_ALL};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[1].type);
    assert_int_equal(1, result.effects[1].leave_all);
}

static void test_heartbeating_left_nonempty(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 0,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[0].type);
    assert_int_equal(0, result.effects[0].leave_all);
}

static void test_heartbeating_left_empty(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 1,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[1].type);
    assert_int_equal(1, result.effects[1].leave_all);
}

static void test_heartbeating_joined(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_JOINED};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[1].type);
}

/* ================================================================== */
/* HEARTBEAT_COOLDOWN state                                            */
/* ================================================================== */

static void test_cooldown_joined(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_JOINED};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_WAIT, result.effects[1].type);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[2].type);
}

static void test_cooldown_heartbeat_success(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_HEARTBEAT_SUCCESS};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    /* Out-of-band success: clean up handle, stay in COOLDOWN. */
    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
}

static void test_cooldown_heartbeat_failure(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_HEARTBEAT_FAILURE};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    /* Out-of-band failure: clean up handle, stay in COOLDOWN. */
    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
}

static void test_cooldown_times_up(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_TIMES_UP};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_WAIT, result.effects[1].type);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[2].type);
}

static void test_cooldown_left_nonempty(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 0,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[0].type);
    assert_int_equal(0, result.effects[0].leave_all);
}

static void test_cooldown_left_empty(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 1,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_WAIT, result.effects[1].type);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[2].type);
    assert_int_equal(1, result.effects[2].leave_all);
}

static void test_cooldown_left_all(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_LEFT_ALL};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_WAIT, result.effects[1].type);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[2].type);
    assert_int_equal(1, result.effects[2].leave_all);
}

static void test_cooldown_disconnect(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_DISCONNECT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, result.new_state);
    assert_int_equal(3, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_HEARTBEAT, result.effects[0].type);
    assert_int_equal(PN_PRES_EE_EFFECT_CANCEL_WAIT, result.effects[1].type);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[2].type);
    assert_int_equal(1, result.effects[2].leave_all);
}

/* ================================================================== */
/* HEARTBEAT_FAILED state                                              */
/* ================================================================== */

static void test_failed_reconnect(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_RECONNECT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[0].type);
}

static void test_failed_joined(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_JOINED};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[0].type);
}

static void test_failed_left_nonempty(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 0,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_COOLDOWN, result.new_state);
    assert_int_equal(2, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[0].type);
    assert_int_equal(0, result.effects[0].leave_all);
    assert_int_equal(PN_PRES_EE_EFFECT_WAIT, result.effects[1].type);
}

static void test_failed_left_empty(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 1,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[0].type);
    assert_int_equal(1, result.effects[0].leave_all);
}

static void test_failed_left_all(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_LEFT_ALL};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[0].type);
    assert_int_equal(1, result.effects[0].leave_all);
}

static void test_failed_disconnect(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_DISCONNECT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_FAILED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_LEAVE, result.effects[0].type);
    assert_int_equal(1, result.effects[0].leave_all);
}

/* ================================================================== */
/* HEARTBEAT_STOPPED state                                             */
/* ================================================================== */

static void test_stopped_reconnect(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_RECONNECT};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(1, result.effect_count);
    assert_int_equal(PN_PRES_EE_EFFECT_HEARTBEAT, result.effects[0].type);
}

static void test_stopped_joined_stays(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_JOINED};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, &event);

    /* Stopped absorbs joins without restarting heartbeat. */
    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_stopped_left_stays(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {
        .type                = PN_PRES_EVENT_LEFT,
        .subscriptions_empty = 0,
    };

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, &event);

    /* Stopped absorbs leaves without restarting heartbeat. */
    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_stopped_left_all_goes_inactive(void** state)
{
    (void)state;
    pn_presence_ee_event_t event = {.type = PN_PRES_EVENT_LEFT_ALL};

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_STOPPED, &event);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */
/* NULL event safety                                                    */
/* ================================================================== */

static void test_null_event_returns_same_state(void** state)
{
    (void)state;

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEATING, NULL);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEATING, result.new_state);
    assert_int_equal(0, result.effect_count);
}

static void test_null_event_inactive_state(void** state)
{
    (void)state;

    pn_presence_ee_transition_result_t result =
        pn_presence_ee_transition(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, NULL);

    assert_int_equal(PN_PRESENCE_STATE_HEARTBEAT_INACTIVE, result.new_state);
    assert_int_equal(0, result.effect_count);
}

/* ================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* HEARTBEAT_INACTIVE */
        cmocka_unit_test(test_inactive_joined),
        cmocka_unit_test(test_inactive_ignores_left),
        cmocka_unit_test(test_inactive_ignores_disconnect),
        /* HEARTBEATING */
        cmocka_unit_test(test_heartbeating_success),
        cmocka_unit_test(test_heartbeating_failure),
        cmocka_unit_test(test_heartbeating_disconnect),
        cmocka_unit_test(test_heartbeating_left_all),
        cmocka_unit_test(test_heartbeating_left_nonempty),
        cmocka_unit_test(test_heartbeating_left_empty),
        cmocka_unit_test(test_heartbeating_joined),
        /* HEARTBEAT_COOLDOWN */
        cmocka_unit_test(test_cooldown_joined),
        cmocka_unit_test(test_cooldown_heartbeat_success),
        cmocka_unit_test(test_cooldown_heartbeat_failure),
        cmocka_unit_test(test_cooldown_times_up),
        cmocka_unit_test(test_cooldown_left_nonempty),
        cmocka_unit_test(test_cooldown_left_empty),
        cmocka_unit_test(test_cooldown_left_all),
        cmocka_unit_test(test_cooldown_disconnect),
        /* HEARTBEAT_FAILED */
        cmocka_unit_test(test_failed_reconnect),
        cmocka_unit_test(test_failed_joined),
        cmocka_unit_test(test_failed_left_nonempty),
        cmocka_unit_test(test_failed_left_empty),
        cmocka_unit_test(test_failed_left_all),
        cmocka_unit_test(test_failed_disconnect),
        /* HEARTBEAT_STOPPED */
        cmocka_unit_test(test_stopped_reconnect),
        cmocka_unit_test(test_stopped_joined_stays),
        cmocka_unit_test(test_stopped_left_stays),
        cmocka_unit_test(test_stopped_left_all_goes_inactive),
        /* NULL safety */
        cmocka_unit_test(test_null_event_returns_same_state),
        cmocka_unit_test(test_null_event_inactive_state),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

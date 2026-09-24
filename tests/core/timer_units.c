/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file timer_units.c
 * @brief Unit tests for the internal deadline timer (pn_timer_t).
 *
 * Uses a mock platform provider with a controllable monotonic clock
 * so all timer behavior can be tested deterministically.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/timer_internal.h"

/* ======================================================================== */
/* Mock platform provider with controllable clock                           */
/* ======================================================================== */

static pubnub_milliseconds_t s_mock_clock_ms = 0;

static pubnub_milliseconds_t mock_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return s_mock_clock_ms;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms = mock_monotonic_ms,
    .sleep_ms     = NULL,
    .random_bytes = NULL,
    .secure_zero  = NULL,
};

static int reset_clock(void** state)
{
    (void)state;
    s_mock_clock_ms = 0;
    return 0;
}

/* ======================================================================== */
/* Tests: pn_timer_start                                                    */
/* ======================================================================== */

static void start_should_capture_current_time(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;

    pn_timer_t sut = pn_timer_start(500, &s_mock_platform);

    assert_int_equal(sut.start_ms, 1000);
    assert_int_equal(sut.duration_ms, 500);
}

static void start_with_zero_duration_should_create_expired_timer(void** state)
{
    (void)state;
    s_mock_clock_ms = 5000;

    pn_timer_t sut = pn_timer_start(0, &s_mock_platform);

    assert_int_equal(sut.start_ms, 5000);
    assert_int_equal(sut.duration_ms, 0);
    assert_true(pn_timer_is_expired(sut, &s_mock_platform));
}

/* ======================================================================== */
/* Tests: pn_timer_is_expired */
/* ======================================================================== */

static void expired_should_return_false_before_deadline(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 1499;

    assert_false(pn_timer_is_expired(sut, &s_mock_platform));
}

static void expired_should_return_true_at_exact_deadline(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 1500;

    assert_true(pn_timer_is_expired(sut, &s_mock_platform));
}

static void expired_should_return_true_past_deadline(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 2000;

    assert_true(pn_timer_is_expired(sut, &s_mock_platform));
}

static void expired_should_return_true_for_zero_initialized_timer(void** state)
{
    (void)state;
    pn_timer_t sut;
    memset(&sut, 0, sizeof(sut));

    assert_true(pn_timer_is_expired(sut, &s_mock_platform));
}

/* ======================================================================== */
/* Tests: pn_timer_remaining_ms                                             */
/* ======================================================================== */

static void remaining_should_return_full_duration_at_start(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 500);
}

static void remaining_should_decrease_over_time(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 1200;

    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 300);
}

static void remaining_should_return_zero_when_expired(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 1500;

    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 0);
}

static void remaining_should_return_zero_past_deadline(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 9999;

    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 0);
}

static void remaining_should_return_zero_for_inactive_timer(void** state)
{
    (void)state;
    pn_timer_t sut;
    memset(&sut, 0, sizeof(sut));

    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 0);
}

/* ======================================================================== */
/* Tests: pn_timer_elapsed_ms                                               */
/* ======================================================================== */

static void elapsed_should_return_zero_at_start(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    assert_int_equal(pn_timer_elapsed_ms(sut, &s_mock_platform), 0);
}

static void elapsed_should_track_time_passage(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 1350;

    assert_int_equal(pn_timer_elapsed_ms(sut, &s_mock_platform), 350);
}

static void elapsed_should_continue_past_deadline(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    s_mock_clock_ms = 3000;

    assert_int_equal(pn_timer_elapsed_ms(sut, &s_mock_platform), 2000);
}

static void elapsed_should_return_zero_for_inactive_timer(void** state)
{
    (void)state;
    pn_timer_t sut;
    memset(&sut, 0, sizeof(sut));

    assert_int_equal(pn_timer_elapsed_ms(sut, &s_mock_platform), 0);
}

/* ======================================================================== */
/* Tests: pn_timer_reset                                                    */
/* ======================================================================== */

static void reset_should_restart_with_same_duration(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);
    s_mock_clock_ms = 1400;

    pn_timer_reset(&sut, &s_mock_platform);

    assert_int_equal(sut.start_ms, 1400);
    assert_int_equal(sut.duration_ms, 500);
    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 500);
    assert_false(pn_timer_is_expired(sut, &s_mock_platform));
}

static void reset_should_revive_expired_timer(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);
    s_mock_clock_ms = 2000;

    pn_timer_reset(&sut, &s_mock_platform);

    assert_false(pn_timer_is_expired(sut, &s_mock_platform));
    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 500);
}

static void reset_on_zero_initialized_timer_should_be_noop(void** state)
{
    (void)state;
    s_mock_clock_ms = 5000;
    pn_timer_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_timer_reset(&sut, &s_mock_platform);

    /* Must remain inactive — no start_ms should have been set. */
    assert_false(pn_timer_is_active(sut));
    assert_int_equal(sut.start_ms, 0);
    assert_int_equal(sut.duration_ms, 0);
}

static void reset_on_stopped_timer_should_be_noop(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);
    pn_timer_stop(&sut);

    s_mock_clock_ms = 5000;
    pn_timer_reset(&sut, &s_mock_platform);

    /* Stopped timer has duration_ms == 0 — reset must be a no-op. */
    assert_false(pn_timer_is_active(sut));
    assert_int_equal(sut.start_ms, 0);
    assert_int_equal(sut.duration_ms, 0);
}

static void reset_null_should_not_crash(void** state)
{
    (void)state;
    s_mock_clock_ms = 5000;

    pn_timer_reset(NULL, &s_mock_platform);
}

/* ======================================================================== */
/* Tests: pn_timer_stop                                                     */
/* ======================================================================== */

static void stop_should_deactivate_running_timer(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    pn_timer_stop(&sut);

    assert_false(pn_timer_is_active(sut));
    assert_true(pn_timer_is_expired(sut, &s_mock_platform));
    assert_int_equal(pn_timer_remaining_ms(sut, &s_mock_platform), 0);
    assert_int_equal(pn_timer_elapsed_ms(sut, &s_mock_platform), 0);
}

static void stop_should_be_safe_on_already_inactive_timer(void** state)
{
    (void)state;
    pn_timer_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_timer_stop(&sut);

    assert_false(pn_timer_is_active(sut));
}

static void stop_null_should_not_crash(void** state)
{
    (void)state;

    pn_timer_stop(NULL);
}

static void stop_should_allow_restart(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;
    pn_timer_t sut  = pn_timer_start(500, &s_mock_platform);

    pn_timer_stop(&sut);
    assert_false(pn_timer_is_active(sut));

    s_mock_clock_ms = 2000;
    sut             = pn_timer_start(300, &s_mock_platform);

    assert_true(pn_timer_is_active(sut));
    assert_int_equal(sut.start_ms, 2000);
    assert_int_equal(sut.duration_ms, 300);
}

/* ======================================================================== */
/* Tests: pn_timer_is_active                                                */
/* ======================================================================== */

static void is_active_should_return_false_for_zero_initialized(void** state)
{
    (void)state;
    pn_timer_t sut;
    memset(&sut, 0, sizeof(sut));

    assert_false(pn_timer_is_active(sut));
}

static void is_active_should_return_true_after_start(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;

    pn_timer_t sut = pn_timer_start(500, &s_mock_platform);

    assert_true(pn_timer_is_active(sut));
}

static void is_active_should_return_true_for_zero_duration_started_timer(void** state)
{
    (void)state;
    s_mock_clock_ms = 1000;

    pn_timer_t sut = pn_timer_start(0, &s_mock_platform);

    /* start_ms != 0, so it's active (even though already expired). */
    assert_true(pn_timer_is_active(sut));
}

/* ======================================================================== */
/* Tests: edge cases                                                        */
/* ======================================================================== */

static void timer_should_work_with_large_duration(void** state)
{
    (void)state;
    s_mock_clock_ms = 100;
    pn_timer_t sut  = pn_timer_start(UINT32_MAX, &s_mock_platform);

    s_mock_clock_ms = 100 + 1000000;

    assert_false(pn_timer_is_expired(sut, &s_mock_platform));
    assert_int_equal(pn_timer_elapsed_ms(sut, &s_mock_platform), 1000000);
}

static void
timer_started_at_clock_zero_with_nonzero_duration_should_be_active(void** state)
{
    (void)state;
    s_mock_clock_ms = 0;

    pn_timer_t sut = pn_timer_start(100, &s_mock_platform);

    /* start_ms == 0 but duration_ms != 0, so it's active. */
    assert_true(pn_timer_is_active(sut));
    assert_false(pn_timer_is_expired(sut, &s_mock_platform));
}

/* ======================================================================== */
/* Test runner                                                              */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* start */
        cmocka_unit_test_setup(start_should_capture_current_time, reset_clock),
        cmocka_unit_test_setup(
            start_with_zero_duration_should_create_expired_timer, reset_clock),

        /* expired */
        cmocka_unit_test_setup(expired_should_return_false_before_deadline,
                               reset_clock),
        cmocka_unit_test_setup(expired_should_return_true_at_exact_deadline,
                               reset_clock),
        cmocka_unit_test_setup(expired_should_return_true_past_deadline, reset_clock),
        cmocka_unit_test_setup(
            expired_should_return_true_for_zero_initialized_timer, reset_clock),

        /* remaining_ms */
        cmocka_unit_test_setup(remaining_should_return_full_duration_at_start,
                               reset_clock),
        cmocka_unit_test_setup(remaining_should_decrease_over_time, reset_clock),
        cmocka_unit_test_setup(remaining_should_return_zero_when_expired, reset_clock),
        cmocka_unit_test_setup(remaining_should_return_zero_past_deadline,
                               reset_clock),
        cmocka_unit_test_setup(remaining_should_return_zero_for_inactive_timer,
                               reset_clock),

        /* elapsed_ms */
        cmocka_unit_test_setup(elapsed_should_return_zero_at_start, reset_clock),
        cmocka_unit_test_setup(elapsed_should_track_time_passage, reset_clock),
        cmocka_unit_test_setup(elapsed_should_continue_past_deadline, reset_clock),
        cmocka_unit_test_setup(elapsed_should_return_zero_for_inactive_timer,
                               reset_clock),

        /* reset */
        cmocka_unit_test_setup(reset_should_restart_with_same_duration, reset_clock),
        cmocka_unit_test_setup(reset_should_revive_expired_timer, reset_clock),
        cmocka_unit_test_setup(reset_on_zero_initialized_timer_should_be_noop,
                               reset_clock),
        cmocka_unit_test_setup(reset_on_stopped_timer_should_be_noop, reset_clock),
        cmocka_unit_test_setup(reset_null_should_not_crash, reset_clock),

        /* stop */
        cmocka_unit_test_setup(stop_should_deactivate_running_timer, reset_clock),
        cmocka_unit_test_setup(stop_should_be_safe_on_already_inactive_timer,
                               reset_clock),
        cmocka_unit_test_setup(stop_null_should_not_crash, reset_clock),
        cmocka_unit_test_setup(stop_should_allow_restart, reset_clock),

        /* is_active */
        cmocka_unit_test_setup(is_active_should_return_false_for_zero_initialized,
                               reset_clock),
        cmocka_unit_test_setup(is_active_should_return_true_after_start, reset_clock),
        cmocka_unit_test_setup(
            is_active_should_return_true_for_zero_duration_started_timer, reset_clock),

        /* edge cases */
        cmocka_unit_test_setup(timer_should_work_with_large_duration, reset_clock),
        cmocka_unit_test_setup(
            timer_started_at_clock_zero_with_nonzero_duration_should_be_active,
            reset_clock),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

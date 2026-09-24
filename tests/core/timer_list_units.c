/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file timer_list_units.c
 * @brief Unit tests for the centralized timer scheduler.
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

#include "core/runtime/timer_list_internal.h"

/* ======================================================================== */
/* Mock platform                                                            */
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

/* ======================================================================== */
/* Callback tracking                                                        */
/* ======================================================================== */

#define MAX_CB_RECORDS 16

static int   s_cb_count;
static void* s_cb_records[MAX_CB_RECORDS];

static void mock_cb(void* cb_data)
{
    if (s_cb_count < MAX_CB_RECORDS) {
        s_cb_records[s_cb_count] = cb_data;
    }
    s_cb_count++;
}

/* Re-arm callback: adds a new timer from within the callback. */
typedef struct rearm_data {
    pn_timer_list_t*            list;
    pubnub_platform_provider_t* platform;
    pubnub_milliseconds_t       delay_ms;
    int                         fire_count;
} rearm_data_t;

static void rearm_cb(void* cb_data)
{
    rearm_data_t* rd = (rearm_data_t*)cb_data;
    rd->fire_count++;
    pn_timer_list_add(rd->list, rd->delay_ms, rearm_cb, rd, rd->platform);
}

/* Cross-cancel callback: removes another timer during fire_expired(). */
typedef struct cancel_other_data {
    pn_timer_list_t*  list;
    pn_timer_handle_t target;
    int               fire_count;
} cancel_other_data_t;

static void cancel_other_cb(void* cb_data)
{
    cancel_other_data_t* d = (cancel_other_data_t*)cb_data;
    d->fire_count++;
    pn_timer_list_remove(d->list, d->target);
}

/* ======================================================================== */
/* Test helpers                                                             */
/* ======================================================================== */

#define TEST_CAPACITY 8

static int reset_globals(void** state)
{
    (void)state;
    s_mock_clock_ms = 0;
    s_cb_count      = 0;
    memset(s_cb_records, 0, sizeof(s_cb_records));
    return 0;
}

/* ======================================================================== */
/* Tests: pn_timer_list_init                                                */
/* ======================================================================== */

static void init_should_set_zero_count(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);

    assert_int_equal(pn_timer_list_count(&sut), 0);
}

/* ======================================================================== */
/* Tests: pn_timer_list_add                                                 */
/* ======================================================================== */

static void add_should_return_handle_and_increment_count(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;

    pn_timer_handle_t handle =
        pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);

    assert_non_null(handle);
    assert_int_equal(pn_timer_list_count(&sut), 1);
}

static void add_should_return_null_when_full(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;

    for (unsigned int i = 0; i < TEST_CAPACITY; i++) {
        assert_non_null(
            pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform));
    }

    pn_timer_handle_t handle =
        pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);

    assert_null(handle);
    assert_int_equal(pn_timer_list_count(&sut), TEST_CAPACITY);
}

static void add_should_reject_null_callback(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);

    pn_timer_handle_t handle =
        pn_timer_list_add(&sut, 500, NULL, NULL, &s_mock_platform);

    assert_null(handle);
    assert_int_equal(pn_timer_list_count(&sut), 0);
}

/* ======================================================================== */
/* Tests: pn_timer_list_remove                                              */
/* ======================================================================== */

static void remove_should_decrement_count(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;
    pn_timer_handle_t handle =
        pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);

    pn_timer_list_remove(&sut, handle);

    assert_int_equal(pn_timer_list_count(&sut), 0);
}

static void remove_null_should_not_crash(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);

    pn_timer_list_remove(&sut, NULL);

    assert_int_equal(pn_timer_list_count(&sut), 0);
}

static void remove_should_prevent_firing(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;
    pn_timer_handle_t handle =
        pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);

    pn_timer_list_remove(&sut, handle);
    s_mock_clock_ms = 700;
    int fired       = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 0);
    assert_int_equal(s_cb_count, 0);
}

static void remove_frees_slot_for_reuse(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;

    pn_timer_handle_t handles[TEST_CAPACITY];
    for (unsigned int i = 0; i < TEST_CAPACITY; i++) {
        handles[i] = pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);
    }
    assert_null(pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform));

    pn_timer_list_remove(&sut, handles[3]);

    pn_timer_handle_t handle =
        pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);

    assert_non_null(handle);
    assert_int_equal(pn_timer_list_count(&sut), TEST_CAPACITY);
}

/* ======================================================================== */
/* Tests: pn_timer_list_fire_expired                                        */
/* ======================================================================== */

static void fire_should_return_zero_when_none_expired(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;
    pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);

    s_mock_clock_ms = 400;
    int fired       = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 0);
    assert_int_equal(s_cb_count, 0);
    assert_int_equal(pn_timer_list_count(&sut), 1);
}

static void fire_should_invoke_callback_and_remove(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    int sentinel    = 42;
    s_mock_clock_ms = 100;
    pn_timer_list_add(&sut, 500, mock_cb, &sentinel, &s_mock_platform);

    s_mock_clock_ms = 600;
    int fired       = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 1);
    assert_int_equal(s_cb_count, 1);
    assert_ptr_equal(s_cb_records[0], &sentinel);
    assert_int_equal(pn_timer_list_count(&sut), 0);
}

static void fire_should_handle_multiple_expired(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    int a = 1, b = 2, c = 3;
    s_mock_clock_ms = 100;
    pn_timer_list_add(&sut, 200, mock_cb, &a, &s_mock_platform);
    pn_timer_list_add(&sut, 300, mock_cb, &b, &s_mock_platform);
    pn_timer_list_add(&sut, 1000, mock_cb, &c, &s_mock_platform);

    s_mock_clock_ms = 500;
    int fired       = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 2);
    assert_int_equal(s_cb_count, 2);
    assert_int_equal(pn_timer_list_count(&sut), 1);
}

static void fire_should_return_zero_for_empty_list(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);

    int fired = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 0);
}

static void fire_should_allow_rearm_from_callback(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    rearm_data_t rd = {
        .list       = &sut,
        .platform   = &s_mock_platform,
        .delay_ms   = 100,
        .fire_count = 0,
    };
    s_mock_clock_ms = 0;
    pn_timer_list_add(&sut, 100, rearm_cb, &rd, &s_mock_platform);

    s_mock_clock_ms = 100;
    int fired       = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 1);
    assert_int_equal(rd.fire_count, 1);
    assert_int_equal(pn_timer_list_count(&sut), 1);

    s_mock_clock_ms = 200;
    fired           = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(fired, 1);
    assert_int_equal(rd.fire_count, 2);
    assert_int_equal(pn_timer_list_count(&sut), 1);
}

static void fire_should_skip_timer_cancelled_by_earlier_callback(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 0;

    cancel_other_data_t cancel_data = {
        .list       = &sut,
        .target     = NULL,
        .fire_count = 0,
    };
    int sentinel_b = 99;

    /* Timer A (slot 0): when fired, cancels timer B. */
    pn_timer_list_add(&sut, 100, cancel_other_cb, &cancel_data, &s_mock_platform);

    /* Timer B (slot 1): should NOT fire because A's callback cancels it. */
    pn_timer_handle_t handle_b =
        pn_timer_list_add(&sut, 100, mock_cb, &sentinel_b, &s_mock_platform);
    cancel_data.target = handle_b;
    assert_int_equal(pn_timer_list_count(&sut), 2);

    s_mock_clock_ms = 100;
    int fired       = pn_timer_list_fire_expired(&sut, &s_mock_platform);

    /* A fired and cancelled B; B should not have fired. */
    assert_int_equal(cancel_data.fire_count, 1);
    assert_int_equal(s_cb_count, 0);
    assert_int_equal(fired, 1);
    assert_int_equal(pn_timer_list_count(&sut), 0);
}

/* ======================================================================== */
/* Tests: pn_timer_list_ms_until_next                                       */
/* ======================================================================== */

static void ms_until_next_should_return_no_active_when_empty(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);

    pubnub_milliseconds_t ms = pn_timer_list_ms_until_next(&sut, &s_mock_platform);

    assert_int_equal(ms, PN_TIMER_LIST_NO_ACTIVE_TIMERS);
}

static void ms_until_next_should_return_remaining_of_soonest(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;
    pn_timer_list_add(&sut, 500, mock_cb, NULL, &s_mock_platform);
    pn_timer_list_add(&sut, 200, mock_cb, NULL, &s_mock_platform);
    pn_timer_list_add(&sut, 800, mock_cb, NULL, &s_mock_platform);

    s_mock_clock_ms = 200;
    pubnub_milliseconds_t ms = pn_timer_list_ms_until_next(&sut, &s_mock_platform);

    assert_int_equal(ms, 100);
}

static void ms_until_next_should_return_zero_when_expired(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 100;
    pn_timer_list_add(&sut, 100, mock_cb, NULL, &s_mock_platform);

    s_mock_clock_ms = 300;
    pubnub_milliseconds_t ms = pn_timer_list_ms_until_next(&sut, &s_mock_platform);

    assert_int_equal(ms, 0);
}

/* ======================================================================== */
/* Tests: pn_timer_list_count                                               */
/* ======================================================================== */

static void count_should_track_adds_and_removes(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 0;

    assert_int_equal(pn_timer_list_count(&sut), 0);

    pn_timer_handle_t handle1 =
        pn_timer_list_add(&sut, 100, mock_cb, NULL, &s_mock_platform);
    pn_timer_handle_t handle2 =
        pn_timer_list_add(&sut, 200, mock_cb, NULL, &s_mock_platform);
    assert_int_equal(pn_timer_list_count(&sut), 2);

    pn_timer_list_remove(&sut, handle1);
    assert_int_equal(pn_timer_list_count(&sut), 1);

    pn_timer_list_remove(&sut, handle2);
    assert_int_equal(pn_timer_list_count(&sut), 0);
}

static void count_should_decrease_after_fire(void** state)
{
    (void)state;
    pn_timer_entry_t entries[TEST_CAPACITY];
    pn_timer_list_t  sut;
    pn_timer_list_init(&sut, entries, TEST_CAPACITY);
    s_mock_clock_ms = 0;
    pn_timer_list_add(&sut, 100, mock_cb, NULL, &s_mock_platform);
    pn_timer_list_add(&sut, 200, mock_cb, NULL, &s_mock_platform);
    assert_int_equal(pn_timer_list_count(&sut), 2);

    s_mock_clock_ms = 150;
    pn_timer_list_fire_expired(&sut, &s_mock_platform);

    assert_int_equal(pn_timer_list_count(&sut), 1);
}

/* ======================================================================== */
/* Test runner                                                              */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* init */
        cmocka_unit_test_setup(init_should_set_zero_count, reset_globals),

        /* add */
        cmocka_unit_test_setup(add_should_return_handle_and_increment_count,
                               reset_globals),
        cmocka_unit_test_setup(add_should_return_null_when_full, reset_globals),
        cmocka_unit_test_setup(add_should_reject_null_callback, reset_globals),

        /* remove */
        cmocka_unit_test_setup(remove_should_decrement_count, reset_globals),
        cmocka_unit_test_setup(remove_null_should_not_crash, reset_globals),
        cmocka_unit_test_setup(remove_should_prevent_firing, reset_globals),
        cmocka_unit_test_setup(remove_frees_slot_for_reuse, reset_globals),

        /* fire_expired */
        cmocka_unit_test_setup(fire_should_return_zero_when_none_expired,
                               reset_globals),
        cmocka_unit_test_setup(fire_should_invoke_callback_and_remove, reset_globals),
        cmocka_unit_test_setup(fire_should_handle_multiple_expired, reset_globals),
        cmocka_unit_test_setup(fire_should_return_zero_for_empty_list, reset_globals),
        cmocka_unit_test_setup(fire_should_allow_rearm_from_callback, reset_globals),
        cmocka_unit_test_setup(
            fire_should_skip_timer_cancelled_by_earlier_callback, reset_globals),

        /* ms_until_next */
        cmocka_unit_test_setup(ms_until_next_should_return_no_active_when_empty,
                               reset_globals),
        cmocka_unit_test_setup(ms_until_next_should_return_remaining_of_soonest,
                               reset_globals),
        cmocka_unit_test_setup(ms_until_next_should_return_zero_when_expired,
                               reset_globals),

        /* count */
        cmocka_unit_test_setup(count_should_track_adds_and_removes, reset_globals),
        cmocka_unit_test_setup(count_should_decrease_after_fire, reset_globals),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

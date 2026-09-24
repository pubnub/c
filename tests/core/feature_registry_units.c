/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file feature_registry_units.c
 * @brief Unit tests for pn_feature_registry: init, register, query,
 *        state retrieval, cleanup, and edge cases.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/pn_feature_registry.h"

/* ======================================================================== */
/* Test fixtures and helpers                                                 */
/* ======================================================================== */

/** Tracks cleanup invocations: order and arguments. */
#define MAX_CLEANUP_CALLS 16

static struct {
    void* state_arg[MAX_CLEANUP_CALLS];
    int   count;
} s_cleanup_log;

static void reset_cleanup_log(void)
{
    memset(&s_cleanup_log, 0, sizeof(s_cleanup_log));
}

static void mock_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    (void)alloc;
    if (s_cleanup_log.count < MAX_CLEANUP_CALLS) {
        s_cleanup_log.state_arg[s_cleanup_log.count] = state;
    }
    s_cleanup_log.count++;
}

static int setup(void** state)
{
    (void)state;
    reset_cleanup_log();
    return 0;
}

/* ======================================================================== */
/* Tests: pn_feature_registry_init                                          */
/* ======================================================================== */

static void test_init_zeroes_active_mask(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    /* Dirty the memory first. */
    memset(&reg, 0xFF, sizeof(reg));
    pn_feature_registry_init(&reg);

    assert_int_equal(0U, reg.active_mask);
}

static void test_init_zeroes_all_slots(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    memset(&reg, 0xFF, sizeof(reg));
    pn_feature_registry_init(&reg);

    for (int i = 0; i < PUBNUB_FEATURE_COUNT; i++) {
        assert_null(reg.slots[i].state);
        assert_null(reg.slots[i].cleanup);
    }
}

static void test_init_null_registry_does_not_crash(void** state)
{
    (void)state;
    /* Must not crash — silent no-op. */
    pn_feature_registry_init(NULL);
}

/* ======================================================================== */
/* Tests: pn_feature_register                                               */
/* ======================================================================== */

static void test_register_sets_active_bit(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_register(&reg, PUBNUB_FEATURE_PUBLISH, NULL, NULL);

    assert_true(0 != (reg.active_mask & (1U << PUBNUB_FEATURE_PUBLISH)));
}

static void test_register_stores_state_pointer(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int dummy = 42;
    pn_feature_register(&reg, PUBNUB_FEATURE_HISTORY, &dummy, NULL);

    assert_ptr_equal(&dummy, reg.slots[PUBNUB_FEATURE_HISTORY].state);
}

static void test_register_stores_cleanup_fn(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_register(&reg, PUBNUB_FEATURE_CRYPTO, NULL, mock_cleanup);

    assert_ptr_equal(mock_cleanup, reg.slots[PUBNUB_FEATURE_CRYPTO].cleanup);
}

static void test_register_multiple_features_independent(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_register(&reg, PUBNUB_FEATURE_PUBLISH, NULL, NULL);
    pn_feature_register(&reg, PUBNUB_FEATURE_SUBSCRIBE, NULL, NULL);
    pn_feature_register(&reg, PUBNUB_FEATURE_CRYPTO, NULL, NULL);

    uint32_t expected = (1U << PUBNUB_FEATURE_PUBLISH)
                      | (1U << PUBNUB_FEATURE_SUBSCRIBE)
                      | (1U << PUBNUB_FEATURE_CRYPTO);
    assert_int_equal(expected, reg.active_mask);
}

static void test_register_null_registry_does_not_crash(void** state)
{
    (void)state;
    pn_feature_register(NULL, PUBNUB_FEATURE_PUBLISH, NULL, NULL);
}

static void test_register_out_of_bounds_is_noop(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_register(&reg, (pubnub_feature_t)99, NULL, NULL);

    assert_int_equal(0U, reg.active_mask);
}

static void test_register_double_registration_overwrites(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int first  = 1;
    int second = 2;

    pn_feature_register(&reg, PUBNUB_FEATURE_PAM, &first, NULL);
    pn_feature_register(&reg, PUBNUB_FEATURE_PAM, &second, mock_cleanup);

    assert_ptr_equal(&second, reg.slots[PUBNUB_FEATURE_PAM].state);
    assert_ptr_equal(mock_cleanup, reg.slots[PUBNUB_FEATURE_PAM].cleanup);
    /* Bit still set (not doubled). */
    assert_int_equal((1U << PUBNUB_FEATURE_PAM), reg.active_mask);
}

/* ======================================================================== */
/* Tests: pn_feature_registry_has                                           */
/* ======================================================================== */

static void test_has_returns_nonzero_for_registered(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_register(&reg, PUBNUB_FEATURE_PRESENCE, NULL, NULL);

    assert_true(0 != pn_feature_registry_has(&reg, PUBNUB_FEATURE_PRESENCE));
}

static void test_has_returns_zero_for_unregistered(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    assert_int_equal(0, pn_feature_registry_has(&reg, PUBNUB_FEATURE_APP_CONTEXT));
}

static void test_has_null_registry_returns_zero(void** state)
{
    (void)state;
    assert_int_equal(0, pn_feature_registry_has(NULL, PUBNUB_FEATURE_PUBLISH));
}

static void test_has_out_of_bounds_returns_zero(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);
    reg.active_mask = 0xFFFFFFFFU; /* All bits set. */

    assert_int_equal(0, pn_feature_registry_has(&reg, (pubnub_feature_t)99));
}

/* ======================================================================== */
/* Tests: pn_feature_registry_state                                         */
/* ======================================================================== */

static void test_state_returns_stored_pointer(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int dummy = 7;
    pn_feature_register(&reg, PUBNUB_FEATURE_FILES, &dummy, NULL);

    assert_ptr_equal(&dummy, pn_feature_registry_state(&reg, PUBNUB_FEATURE_FILES));
}

static void test_state_returns_null_for_unregistered(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    assert_null(pn_feature_registry_state(&reg, PUBNUB_FEATURE_SIGNAL));
}

static void test_state_returns_null_for_null_registry(void** state)
{
    (void)state;
    assert_null(pn_feature_registry_state(NULL, PUBNUB_FEATURE_PUBLISH));
}

static void test_state_returns_null_for_out_of_bounds(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    assert_null(pn_feature_registry_state(&reg, (pubnub_feature_t)99));
}

static void test_state_returns_null_when_registered_with_null(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_register(&reg, PUBNUB_FEATURE_SUBSCRIBE, NULL, mock_cleanup);

    /* Feature IS registered, but state was NULL. */
    assert_null(pn_feature_registry_state(&reg, PUBNUB_FEATURE_SUBSCRIBE));
}

/* ======================================================================== */
/* Tests: pn_feature_registry_cleanup_all                                   */
/* ======================================================================== */

static void test_cleanup_all_invokes_callbacks(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int dummy = 1;
    pn_feature_register(&reg, PUBNUB_FEATURE_PUBLISH, &dummy, mock_cleanup);

    pn_feature_registry_cleanup_all(&reg, NULL);

    assert_int_equal(1, s_cleanup_log.count);
    assert_ptr_equal(&dummy, s_cleanup_log.state_arg[0]);
}

static void test_cleanup_all_reverse_order(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int s0 = 0;
    int s1 = 1;
    int s2 = 2;

    /* Register features 0, 5, 10 (ascending enum values). */
    pn_feature_register(&reg, PUBNUB_FEATURE_PUBLISH, &s0, mock_cleanup);
    pn_feature_register(&reg, PUBNUB_FEATURE_SIGNAL, &s1, mock_cleanup);
    pn_feature_register(&reg, PUBNUB_FEATURE_CRYPTO, &s2, mock_cleanup);

    pn_feature_registry_cleanup_all(&reg, NULL);

    /* Reverse of enum value: CRYPTO(10), SIGNAL(5), PUBLISH(0). */
    assert_int_equal(3, s_cleanup_log.count);
    assert_ptr_equal(&s2, s_cleanup_log.state_arg[0]);
    assert_ptr_equal(&s1, s_cleanup_log.state_arg[1]);
    assert_ptr_equal(&s0, s_cleanup_log.state_arg[2]);
}

static void test_cleanup_all_resets_mask(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int dummy = 0;
    pn_feature_register(&reg, PUBNUB_FEATURE_HISTORY, &dummy, mock_cleanup);
    pn_feature_register(&reg, PUBNUB_FEATURE_PRESENCE, &dummy, mock_cleanup);

    pn_feature_registry_cleanup_all(&reg, NULL);

    assert_int_equal(0U, reg.active_mask);
}

static void test_cleanup_all_clears_slots(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int dummy = 0;
    pn_feature_register(&reg, PUBNUB_FEATURE_APP_CONTEXT, &dummy, mock_cleanup);

    pn_feature_registry_cleanup_all(&reg, NULL);

    assert_null(reg.slots[PUBNUB_FEATURE_APP_CONTEXT].state);
    assert_null(reg.slots[PUBNUB_FEATURE_APP_CONTEXT].cleanup);
}

static void test_cleanup_all_skips_null_state(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    /* cleanup set but state is NULL — callback must NOT fire. */
    pn_feature_register(&reg, PUBNUB_FEATURE_CHANNEL_GROUPS, NULL, mock_cleanup);

    pn_feature_registry_cleanup_all(&reg, NULL);

    assert_int_equal(0, s_cleanup_log.count);
}

static void test_cleanup_all_skips_null_cleanup_fn(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    int dummy = 0;
    /* state set but cleanup is NULL — must not crash. */
    pn_feature_register(&reg, PUBNUB_FEATURE_FILES, &dummy, NULL);

    pn_feature_registry_cleanup_all(&reg, NULL);

    /* No crash, and slot is still cleared. */
    assert_null(reg.slots[PUBNUB_FEATURE_FILES].state);
    assert_int_equal(0U, reg.active_mask);
}

static void test_cleanup_all_null_registry_does_not_crash(void** state)
{
    (void)state;
    pn_feature_registry_cleanup_all(NULL, NULL);
}

static void test_cleanup_all_empty_registry_is_noop(void** state)
{
    (void)state;
    pn_feature_registry_t reg;
    pn_feature_registry_init(&reg);

    pn_feature_registry_cleanup_all(&reg, NULL);

    assert_int_equal(0, s_cleanup_log.count);
    assert_int_equal(0U, reg.active_mask);
}

/* ======================================================================== */
/* Test runner                                                               */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* init */
        cmocka_unit_test(test_init_zeroes_active_mask),
        cmocka_unit_test(test_init_zeroes_all_slots),
        cmocka_unit_test(test_init_null_registry_does_not_crash),

        /* register */
        cmocka_unit_test(test_register_sets_active_bit),
        cmocka_unit_test(test_register_stores_state_pointer),
        cmocka_unit_test(test_register_stores_cleanup_fn),
        cmocka_unit_test(test_register_multiple_features_independent),
        cmocka_unit_test(test_register_null_registry_does_not_crash),
        cmocka_unit_test(test_register_out_of_bounds_is_noop),
        cmocka_unit_test(test_register_double_registration_overwrites),

        /* has */
        cmocka_unit_test(test_has_returns_nonzero_for_registered),
        cmocka_unit_test(test_has_returns_zero_for_unregistered),
        cmocka_unit_test(test_has_null_registry_returns_zero),
        cmocka_unit_test(test_has_out_of_bounds_returns_zero),

        /* state */
        cmocka_unit_test(test_state_returns_stored_pointer),
        cmocka_unit_test(test_state_returns_null_for_unregistered),
        cmocka_unit_test(test_state_returns_null_for_null_registry),
        cmocka_unit_test(test_state_returns_null_for_out_of_bounds),
        cmocka_unit_test(test_state_returns_null_when_registered_with_null),

        /* cleanup_all */
        cmocka_unit_test_setup(test_cleanup_all_invokes_callbacks, setup),
        cmocka_unit_test_setup(test_cleanup_all_reverse_order, setup),
        cmocka_unit_test_setup(test_cleanup_all_resets_mask, setup),
        cmocka_unit_test_setup(test_cleanup_all_clears_slots, setup),
        cmocka_unit_test_setup(test_cleanup_all_skips_null_state, setup),
        cmocka_unit_test_setup(test_cleanup_all_skips_null_cleanup_fn, setup),
        cmocka_unit_test_setup(test_cleanup_all_null_registry_does_not_crash, setup),
        cmocka_unit_test_setup(test_cleanup_all_empty_registry_is_noop, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

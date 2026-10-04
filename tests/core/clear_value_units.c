/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file clear_value_units.c
 * @brief Unit tests for the PUBNUB_CLEAR_VALUE sentinel and PN_IS_CLEAR_VALUE.
 *
 * Verifies the by-address identity contract: PN_IS_CLEAR_VALUE recognises
 * only the marker's own address, never a distinct object that happens to hold
 * identical bytes. The distinct-content case is the anti-folding guard -- if a
 * linker coalesced the marker with an unrelated identical literal, that test
 * would fail.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "pubnub/types.h"

#include "core/clear_value_internal.h"

static void clear_value_should_match_the_marker(void** state)
{
    (void)state;

    assert_true(PN_IS_CLEAR_VALUE(PUBNUB_CLEAR_VALUE));
    assert_true(PN_IS_CLEAR_VALUE(pubnub_clear_value_marker));
}

static void clear_value_should_reject_null(void** state)
{
    (void)state;

    assert_false(PN_IS_CLEAR_VALUE(NULL));
}

static void clear_value_should_reject_identical_content(void** state)
{
    (void)state;

    /* Same bytes as the marker but a distinct object with a distinct address.
     * The marker identity is by address, so this must NOT match even though
     * memcmp over the full object would report equality. */
    const char impostor[] = "\0PN_CLEAR_VALUE";

    assert_int_equal(
        0, memcmp(impostor, pubnub_clear_value_marker, sizeof(impostor)));
    assert_false(PN_IS_CLEAR_VALUE(impostor));
}

static void clear_value_should_reject_empty_literal(void** state)
{
    (void)state;

    const char* empty = "";

    assert_false(PN_IS_CLEAR_VALUE(empty));
}

static void clear_value_marker_address_should_be_stable(void** state)
{
    (void)state;

    const char* first  = PUBNUB_CLEAR_VALUE;
    const char* second = PUBNUB_CLEAR_VALUE;

    assert_ptr_equal(first, second);
    assert_ptr_equal(first, pubnub_clear_value_marker);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(clear_value_should_match_the_marker),
        cmocka_unit_test(clear_value_should_reject_null),
        cmocka_unit_test(clear_value_should_reject_identical_content),
        cmocka_unit_test(clear_value_should_reject_empty_literal),
        cmocka_unit_test(clear_value_marker_address_should_be_stable),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

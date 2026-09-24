/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file compat_static_assert_units.c
 * @brief Smoke test for the @c PUBNUB_STATIC_ASSERT macro.
 *
 * Ensures the macro compiles in every build configuration even when no
 * other translation unit consumes it. The asserts here run at
 * compile time -- if the cascade in @c pubnub/pubnub_compat.h breaks
 * for any toolchain combination, this TU fails to build.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "pubnub/pubnub_compat.h"

/* File-scope: smoke-check that PUBNUB_STATIC_ASSERT works at file scope. */
PUBNUB_STATIC_ASSERT(1 == 1, "compile-time true");
PUBNUB_STATIC_ASSERT(sizeof(int) >= 2, "int is at least 16 bits");

/* File-scope: two adjacent invocations on different lines exercise the
 * __COUNTER__ / __LINE__ uniqueness guarantee in the C99 fallback. */
PUBNUB_STATIC_ASSERT(sizeof(char) == 1, "char is one byte");
PUBNUB_STATIC_ASSERT(0 == 0, "trivially true");

static void compat_static_assert_should_compile_at_function_scope(void** state)
{
    (void)state;

    /* Block scope: the macro must compile inside a function body too. */
    PUBNUB_STATIC_ASSERT(1 != 0, "block-scope assertion");
    PUBNUB_STATIC_ASSERT(
        sizeof(void*) >= sizeof(int),
        "pointer at least as wide as int on supported targets");

    /* Runtime sanity to give cmocka something to assert on. The
     * compile-time work above is what this test really verifies. */
    assert_true(1);
}

static void compat_atomic_uint8_should_store_and_load(void** state)
{
    (void)state;

    PUBNUB_ATOMIC_UINT8 flag = 0;
    assert_int_equal(0, (int)PUBNUB_ATOMIC_LOAD_U8(&flag));

    PUBNUB_ATOMIC_STORE_U8(&flag, 1);
    assert_int_equal(1, (int)PUBNUB_ATOMIC_LOAD_U8(&flag));

    PUBNUB_ATOMIC_STORE_U8(&flag, 0);
    assert_int_equal(0, (int)PUBNUB_ATOMIC_LOAD_U8(&flag));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(compat_static_assert_should_compile_at_function_scope),
        cmocka_unit_test(compat_atomic_uint8_should_store_and_load),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

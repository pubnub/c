/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <inttypes.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/pn_format.h"
#include "pubnub/config.h"

/* ======================================================================== */
/* Tests: basic formatting                                                  */
/* ======================================================================== */

static void basic_string(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "hello %s", "world");

    assert_string_equal(buf, "hello world");
    assert_int_equal(n, 11);
}

static void integer_positive(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "n=%d", 42);

    assert_string_equal(buf, "n=42");
    assert_int_equal(n, 4);
}

static void integer_negative(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%d", -1);

    assert_string_equal(buf, "-1");
    assert_int_equal(n, 2);
}

static void unsigned_zero(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%u", 0u);

    assert_string_equal(buf, "0");
    assert_int_equal(n, 1);
}

static void hex_value(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%x", 255u);

    assert_string_equal(buf, "ff");
    assert_int_equal(n, 2);
}

static void hex_zero(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%x", 0u);

    assert_string_equal(buf, "0");
    assert_int_equal(n, 1);
}

static void literal_percent(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "100%%");

    assert_string_equal(buf, "100%");
    assert_int_equal(n, 4);
}

static void null_string_arg(void** state)
{
    (void)state;
    char buf[64];

    /* Intentional: test pn_snprintf NULL-string handling. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow"
#endif
    int n = pn_snprintf(buf, sizeof(buf), "%s", (const char*)NULL);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    assert_string_equal(buf, "(null)");
    assert_int_equal(n, 6);
}

/* ======================================================================== */
/* Tests: precision string (%.*s)                                           */
/* ======================================================================== */

static void precision_string_basic(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "[%.*s]", 5, "hello world");

    assert_string_equal(buf, "[hello]");
    assert_int_equal(n, 7);
}

static void precision_string_shorter_than_source(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%.*s", 3, "abcdef");

    assert_string_equal(buf, "abc");
    assert_int_equal(n, 3);
}

static void precision_string_longer_than_source(void** state)
{
    (void)state;
    char buf[64];

    /* Precision exceeds string length — stops at NUL. */
    int n = pn_snprintf(buf, sizeof(buf), "%.*s", 100, "hi");

    assert_string_equal(buf, "hi");
    assert_int_equal(n, 2);
}

static void precision_string_zero(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "[%.*s]", 0, "ignored");

    assert_string_equal(buf, "[]");
    assert_int_equal(n, 2);
}

#if PUBNUB_CFG_MINIMAL_FORMATTER
static void precision_string_negative(void** state)
{
    (void)state;
    char buf[64];

    /* Minimal formatter: negative precision treated as 0 — no output. */
    int n = pn_snprintf(buf, sizeof(buf), "[%.*s]", -5, "ignored");

    assert_string_equal(buf, "[]");
    assert_int_equal(n, 2);
}

static void precision_string_null(void** state)
{
    (void)state;
    char buf[64];

    /* Minimal formatter: NULL string emits nothing. */
    int n = pn_snprintf(buf, sizeof(buf), "[%.*s]", 10, (const char*)NULL);

    assert_string_equal(buf, "[]");
    assert_int_equal(n, 2);
}
#endif

static void precision_string_with_other_specifiers(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%s:%.*s:%d", "pre", 4, "longval", 99);

    assert_string_equal(buf, "pre:long:99");
    assert_int_equal(n, 11);
}

/* ======================================================================== */
/* Tests: truncation and edge cases                                         */
/* ======================================================================== */

static void truncation_null_terminates(void** state)
{
    (void)state;
    char buf[6];
    memset(buf, 'X', sizeof(buf));

    int n = pn_snprintf(buf, sizeof(buf), "hello world");

    assert_int_equal(buf[5], '\0');
    assert_true(n > (int)sizeof(buf));
    assert_memory_equal(buf, "hello", 5);
}

static void zero_size_returns_length(void** state)
{
    (void)state;

    int n = pn_snprintf(NULL, 0, "hello");

    assert_int_equal(n, 5);
}

static void multiple_specifiers(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%s=%d", "x", 10);

    assert_string_equal(buf, "x=10");
    assert_int_equal(n, 4);
}

static void int_min_value(void** state)
{
    (void)state;
    char buf[64];
    char expected[64];

    /* Build expected string from known INT_MIN. */
    int          exp_len = 0;
    unsigned int abs_val = 0u - (unsigned int)INT_MIN;

    expected[exp_len++] = '-';
    {
        char         tmp[12];
        int          tlen = 0;
        unsigned int v    = abs_val;
        while (v != 0) {
            tmp[tlen++] = (char)('0' + (int)(v % 10u));
            v /= 10u;
        }
        while (tlen > 0) {
            expected[exp_len++] = tmp[--tlen];
        }
    }
    expected[exp_len] = '\0';

    int n = pn_snprintf(buf, sizeof(buf), "%d", INT_MIN);

    assert_string_equal(buf, expected);
    assert_int_equal(n, exp_len);
}

static void uint_max_value(void** state)
{
    (void)state;
    char buf[64];
    char expected[64];

    /* Build expected string from UINT_MAX. */
    int exp_len = 0;
    {
        char         tmp[12];
        int          tlen = 0;
        unsigned int v    = UINT_MAX;
        while (v != 0) {
            tmp[tlen++] = (char)('0' + (int)(v % 10u));
            v /= 10u;
        }
        while (tlen > 0) {
            expected[exp_len++] = tmp[--tlen];
        }
    }
    expected[exp_len] = '\0';

    int n = pn_snprintf(buf, sizeof(buf), "%u", UINT_MAX);

    assert_string_equal(buf, expected);
    assert_int_equal(n, exp_len);
}

#if PUBNUB_CFG_MINIMAL_FORMATTER
static void unknown_specifier_passthrough(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "%f");

    assert_string_equal(buf, "%f");
    assert_int_equal(n, 2);
}
#endif

/* ======================================================================== */
/* Tests: %llu / %lld (always-on per Round 6 D-2)                           */
/* ======================================================================== */

static void format_should_emit_uint64_max_decimal(void** state)
{
    (void)state;
    char buf[32];

    int n = pn_snprintf(buf, sizeof(buf), "%llu", ULLONG_MAX);

    assert_string_equal(buf, "18446744073709551615");
    assert_int_equal(n, 20);
}

static void format_should_emit_uint64_zero(void** state)
{
    (void)state;
    char buf[32];

    int n = pn_snprintf(buf, sizeof(buf), "%llu", 0ULL);

    assert_string_equal(buf, "0");
    assert_int_equal(n, 1);
}

static void format_should_emit_int64_min_decimal(void** state)
{
    (void)state;
    char buf[32];

    /* LLONG_MIN is the negative-overflow corner case: computing
     * -LLONG_MIN as a signed value is UB. The formatter must compute
     * the magnitude in unsigned domain. */
    int n = pn_snprintf(buf, sizeof(buf), "%lld", LLONG_MIN);

    assert_string_equal(buf, "-9223372036854775808");
    assert_int_equal(n, 20);
}

static void format_should_emit_int64_signed_negative(void** state)
{
    (void)state;
    char buf[32];

    int n = pn_snprintf(buf, sizeof(buf), "%lld", (long long)-42);

    assert_string_equal(buf, "-42");
    assert_int_equal(n, 3);
}

static void format_should_emit_int64_signed_positive(void** state)
{
    (void)state;
    char buf[32];

    int n = pn_snprintf(buf, sizeof(buf), "%lld", (long long)42);

    assert_string_equal(buf, "42");
    assert_int_equal(n, 2);
}

static void format_should_match_priu64_typedef(void** state)
{
    (void)state;
    char           buf_llu[32];
    char           buf_pri[32];
    const uint64_t now_s = 1700000000123ULL;

    int n_llu =
        pn_snprintf(buf_llu, sizeof(buf_llu), "%llu", (unsigned long long)now_s);
    int n_pri = pn_snprintf(buf_pri, sizeof(buf_pri), "%" PRIu64, now_s);

    assert_int_equal(n_llu, n_pri);
    assert_string_equal(buf_llu, buf_pri);
}

/* Regression test for Round 5 PF-R5-2: when %llu is followed by another
 * specifier, the formatter must consume the FULL long-long argument from
 * the va_list. If it incorrectly consumed only `unsigned int`, the
 * trailing %d would print bytes from the high half of the long long. */
static void format_should_consume_full_va_arg_for_ll(void** state)
{
    (void)state;
    char buf[32];

    int n = pn_snprintf(buf, sizeof(buf), "%llu %d", (long long)42, 99);

    assert_string_equal(buf, "42 99");
    assert_int_equal(n, 5);
}

static void empty_format_string(void** state)
{
    (void)state;
    char buf[64];
    buf[0] = 'X';

    /* Intentional: test pn_snprintf empty-format-string handling. */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
#endif
    int n = pn_snprintf(buf, sizeof(buf), "");
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

    assert_string_equal(buf, "");
    assert_int_equal(n, 0);
}

#if PUBNUB_CFG_MINIMAL_FORMATTER
static void trailing_percent(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "end%%");

    assert_string_equal(buf, "end%");
    assert_int_equal(n, 4);
}

static void trailing_percent_bare(void** state)
{
    (void)state;
    char buf[64];

    int n = pn_snprintf(buf, sizeof(buf), "end%");

    assert_string_equal(buf, "end%");
    assert_int_equal(n, 4);
}
#endif

/* ======================================================================== */
/* Test runner                                                              */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(basic_string),
        cmocka_unit_test(integer_positive),
        cmocka_unit_test(integer_negative),
        cmocka_unit_test(unsigned_zero),
        cmocka_unit_test(hex_value),
        cmocka_unit_test(hex_zero),
        cmocka_unit_test(literal_percent),
        cmocka_unit_test(null_string_arg),
        cmocka_unit_test(precision_string_basic),
        cmocka_unit_test(precision_string_shorter_than_source),
        cmocka_unit_test(precision_string_longer_than_source),
        cmocka_unit_test(precision_string_zero),
#if PUBNUB_CFG_MINIMAL_FORMATTER
        cmocka_unit_test(precision_string_negative),
        cmocka_unit_test(precision_string_null),
#endif
        cmocka_unit_test(precision_string_with_other_specifiers),
        cmocka_unit_test(truncation_null_terminates),
        cmocka_unit_test(zero_size_returns_length),
        cmocka_unit_test(multiple_specifiers),
        cmocka_unit_test(int_min_value),
        cmocka_unit_test(uint_max_value),
        cmocka_unit_test(empty_format_string),
#if PUBNUB_CFG_MINIMAL_FORMATTER
        cmocka_unit_test(unknown_specifier_passthrough),
        cmocka_unit_test(trailing_percent),
        cmocka_unit_test(trailing_percent_bare),
#endif
        cmocka_unit_test(format_should_emit_uint64_max_decimal),
        cmocka_unit_test(format_should_emit_uint64_zero),
        cmocka_unit_test(format_should_emit_int64_min_decimal),
        cmocka_unit_test(format_should_emit_int64_signed_negative),
        cmocka_unit_test(format_should_emit_int64_signed_positive),
        cmocka_unit_test(format_should_match_priu64_typedef),
        cmocka_unit_test(format_should_consume_full_va_arg_for_ll),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

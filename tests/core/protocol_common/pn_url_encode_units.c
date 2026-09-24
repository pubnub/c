/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_url_encode_units.c
 * @brief Unit tests for pn_url_encode().
 *
 * The encoder is security-relevant: it is the only barrier between
 * user-controlled strings (auth tokens, user IDs, channel names)
 * and the outbound URL. These tests pin every input-validation
 * branch, the RFC 3986 unreserved-set classification, uppercase
 * hex output, boundary sizing, and non-ASCII byte handling.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/protocol_common/pn_url_encode.h"

/* ======================================================================== */
/* Input validation                                                         */
/* ======================================================================== */

static void encode_should_reject_null_input(void** state)
{
    (void)state;
    char out[8];

    pubnub_res_t rc = pn_url_encode(NULL, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_should_reject_null_output(void** state)
{
    (void)state;

    pubnub_res_t rc = pn_url_encode("abc", NULL, 8, PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_should_reject_zero_size(void** state)
{
    (void)state;
    char out[1];

    pubnub_res_t rc = pn_url_encode("abc", out, 0, PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */
/* Unreserved set (RFC 3986 \u00a72.3) */
/* ======================================================================== */

static void encode_should_pass_unreserved_chars_through(void** state)
{
    (void)state;
    char out[32];

    pubnub_res_t rc = pn_url_encode("Ab1-_.~", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "Ab1-_.~");
}

static void encode_should_accept_empty_input(void** state)
{
    (void)state;
    char out[4] = {'x', 'x', 'x', 'x'};

    pubnub_res_t rc = pn_url_encode("", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out[0], '\0');
}

/* ======================================================================== */
/* Percent-encoding of reserved characters                                  */
/* ======================================================================== */

static void encode_should_percent_encode_reserved_chars(void** state)
{
    (void)state;
    char out[32];

    pubnub_res_t rc = pn_url_encode("a/b+c", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "a%2Fb%2Bc");
}

static void encode_should_use_uppercase_hex(void** state)
{
    (void)state;
    char out[16];

    /* 0xFF is a reserved byte: must encode as uppercase %FF, not %ff. */
    pubnub_res_t rc = pn_url_encode("\xff", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "%FF");
}

static void encode_should_handle_high_bit_bytes(void** state)
{
    (void)state;
    char out[16];
    /* 0xC3 0xBC == "u-umlaut" in UTF-8. */
    const char input[] = {(char)0xC3, (char)0xBC, '\0'};

    pubnub_res_t rc = pn_url_encode(input, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "%C3%BC");
}

/* ======================================================================== */
/* Boundary sizing                                                          */
/* ======================================================================== */

static void encode_should_fail_when_buffer_too_small_for_reserved(void** state)
{
    (void)state;
    char out[3];

    /* "/" needs "%2F\0" = 4 bytes; 3 is not enough. */
    pubnub_res_t rc = pn_url_encode("/", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

static void encode_should_succeed_at_exact_boundary(void** state)
{
    (void)state;
    char out[4];

    pubnub_res_t rc = pn_url_encode("/", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "%2F");
}

static void encode_should_fail_when_buffer_too_small_for_unreserved(void** state)
{
    (void)state;
    char out[3];

    /* "abc" needs "abc\0" = 4 bytes; 3 is not enough. */
    pubnub_res_t rc = pn_url_encode("abc", out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

/* ======================================================================== */
/* Exhaustive byte-table check                                              */
/* ======================================================================== */

static int is_rfc3986_unreserved(int b)
{
    return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
        || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~';
}

static void encode_should_classify_every_byte_per_rfc3986(void** state)
{
    (void)state;
    static const char hex[] = "0123456789ABCDEF";

    /* NUL (0x00) is input terminator for this encoder and cannot be
     * tested through the null-terminated interface. Iterate 1..255. */
    for (int b = 1; b < 256; ++b) {
        char input[2] = {(char)b, '\0'};
        char out[4];

        pubnub_res_t rc = pn_url_encode(input, out, sizeof(out), PN_ENCODE_FULL);
        assert_int_equal(rc, PUBNUB_OK);

        /* '.' is unreserved per RFC 3986 but percent-encoded here to
         * neutralize single-byte "." dot-segments in path components. */
        if (is_rfc3986_unreserved(b) && '.' != b) {
            assert_int_equal((unsigned char)out[0], (unsigned char)b);
            assert_int_equal(out[1], '\0');
        } else {
            char expected[4];
            expected[0] = '%';
            expected[1] = hex[(b >> 4) & 0x0F];
            expected[2] = hex[b & 0x0F];
            expected[3] = '\0';
            assert_string_equal(out, expected);
        }
    }
}

/* ======================================================================== */
/* pn_url_encode_n -- length-aware variant                                  */
/* ======================================================================== */

static void encode_n_should_reject_null_input_nonzero_len(void** state)
{
    (void)state;
    char out[8];

    pubnub_res_t rc = pn_url_encode_n(NULL, 5, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_n_should_accept_null_input_zero_len(void** state)
{
    (void)state;
    char out[4] = {'x', 'x', 'x', 'x'};

    pubnub_res_t rc = pn_url_encode_n(NULL, 0, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out[0], '\0');
}

static void encode_n_should_reject_null_output(void** state)
{
    (void)state;

    pubnub_res_t rc = pn_url_encode_n("abc", 3, NULL, 16, PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_n_should_reject_zero_out_size(void** state)
{
    (void)state;
    char out[1];

    pubnub_res_t rc = pn_url_encode_n("abc", 3, out, 0, PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_n_should_encode_hello_world(void** state)
{
    (void)state;
    char out[32];

    pubnub_res_t rc =
        pn_url_encode_n("hello world", 11, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "hello%20world");
}

static void encode_n_should_encode_embedded_nul(void** state)
{
    (void)state;
    char out[16];
    /* Input: 'a', NUL, 'b' -- three bytes total. */
    const char input[3] = {'a', '\0', 'b'};

    pubnub_res_t rc = pn_url_encode_n(input, 3, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "a%00b");
}

static void encode_n_should_fail_when_buffer_too_small(void** state)
{
    (void)state;
    char out[4];

    /* "a b" needs "a%20b\0" = 6 bytes; 4 is not enough. */
    pubnub_res_t rc = pn_url_encode_n("a b", 3, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

static void encode_n_should_match_nul_terminated_variant(void** state)
{
    (void)state;
    char       out_n[64];
    char       out_z[64];
    const char input[] = "hello/world?foo=bar&baz=qux~test";

    pubnub_res_t rc_z = pn_url_encode(input, out_z, sizeof(out_z), PN_ENCODE_FULL);
    pubnub_res_t rc_n =
        pn_url_encode_n(input, strlen(input), out_n, sizeof(out_n), PN_ENCODE_FULL);

    assert_int_equal(rc_z, PUBNUB_OK);
    assert_int_equal(rc_n, PUBNUB_OK);
    assert_string_equal(out_n, out_z);
}

static void encode_n_should_pass_all_unreserved_through(void** state)
{
    (void)state;
    char out[128];

    /* Build an input with all RFC 3986 unreserved chars. */
    char unreserved[66 + 1]; /* 26+26+10+4 = 66 */
    int  pos = 0;
    for (char c = 'A'; c <= 'Z'; c++) {
        unreserved[pos++] = c;
    }
    for (char c = 'a'; c <= 'z'; c++) {
        unreserved[pos++] = c;
    }
    for (char c = '0'; c <= '9'; c++) {
        unreserved[pos++] = c;
    }
    unreserved[pos++] = '-';
    unreserved[pos++] = '_';
    unreserved[pos++] = '.';
    unreserved[pos++] = '~';
    unreserved[pos]   = '\0';

    pubnub_res_t rc =
        pn_url_encode_n(unreserved, (size_t)pos, out, sizeof(out), PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, unreserved);
}

/* ======================================================================== */
/* Test runner                                                              */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* input validation */
        cmocka_unit_test(encode_should_reject_null_input),
        cmocka_unit_test(encode_should_reject_null_output),
        cmocka_unit_test(encode_should_reject_zero_size),

        /* unreserved set */
        cmocka_unit_test(encode_should_pass_unreserved_chars_through),
        cmocka_unit_test(encode_should_accept_empty_input),

        /* percent-encoding */
        cmocka_unit_test(encode_should_percent_encode_reserved_chars),
        cmocka_unit_test(encode_should_use_uppercase_hex),
        cmocka_unit_test(encode_should_handle_high_bit_bytes),

        /* boundary sizing */
        cmocka_unit_test(encode_should_fail_when_buffer_too_small_for_reserved),
        cmocka_unit_test(encode_should_succeed_at_exact_boundary),
        cmocka_unit_test(encode_should_fail_when_buffer_too_small_for_unreserved),

        /* exhaustive classification */
        cmocka_unit_test(encode_should_classify_every_byte_per_rfc3986),

        /* pn_url_encode_n -- length-aware variant */
        cmocka_unit_test(encode_n_should_reject_null_input_nonzero_len),
        cmocka_unit_test(encode_n_should_accept_null_input_zero_len),
        cmocka_unit_test(encode_n_should_reject_null_output),
        cmocka_unit_test(encode_n_should_reject_zero_out_size),
        cmocka_unit_test(encode_n_should_encode_hello_world),
        cmocka_unit_test(encode_n_should_encode_embedded_nul),
        cmocka_unit_test(encode_n_should_fail_when_buffer_too_small),
        cmocka_unit_test(encode_n_should_match_nul_terminated_variant),
        cmocka_unit_test(encode_n_should_pass_all_unreserved_through),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

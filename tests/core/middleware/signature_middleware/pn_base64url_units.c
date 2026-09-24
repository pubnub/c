/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_base64url_units.c
 * @brief Unit tests for pn_base64url_encoded_len + pn_base64url_encode.
 *
 * The encoder runs on security-sensitive output (HMAC-SHA256 signing
 * bytes); correctness is pinned against RFC 4648 §5 reference vectors
 * plus the signing-specific 32-byte length that matters in practice.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/protocol_common/pn_base64url.h"

/* ======================================================================== */
/* pn_base64url_encoded_len                                                 */
/* ======================================================================== */

static void encoded_len_should_return_zero_for_empty_input(void** state)
{
    (void)state;

    assert_int_equal(pn_base64url_encoded_len(0), 0);
}

static void encoded_len_should_return_two_for_one_byte(void** state)
{
    (void)state;

    assert_int_equal(pn_base64url_encoded_len(1), 2);
}

static void encoded_len_should_return_three_for_two_bytes(void** state)
{
    (void)state;

    assert_int_equal(pn_base64url_encoded_len(2), 3);
}

static void encoded_len_should_return_four_for_three_bytes(void** state)
{
    (void)state;

    assert_int_equal(pn_base64url_encoded_len(3), 4);
}

static void encoded_len_should_return_43_for_32_bytes(void** state)
{
    (void)state;

    /* HMAC-SHA256 output is 32 bytes; base64url (no padding)
     * produces 43 characters. This is the signing hot path. */
    assert_int_equal(pn_base64url_encoded_len(32), 43);
}

/* ======================================================================== */
/* Input validation                                                         */
/* ======================================================================== */

static void encode_should_reject_null_output(void** state)
{
    (void)state;
    const uint8_t input[3] = {'a', 'b', 'c'};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), NULL, 16);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_should_reject_zero_output_size(void** state)
{
    (void)state;
    char          out[8]   = {0};
    const uint8_t input[3] = {'a', 'b', 'c'};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, 0);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

static void encode_should_reject_null_input_with_nonzero_len(void** state)
{
    (void)state;
    char out[8] = {0};

    pubnub_res_t rc = pn_base64url_encode(NULL, 3, out, sizeof(out));

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void encode_should_reject_too_small_output(void** state)
{
    (void)state;
    const uint8_t input[3] = {'a', 'b', 'c'};
    char          out[3]   = {0};

    /* Needs 4 + 1 (NUL) = 5 bytes; only 3 given. */
    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

/* ======================================================================== */
/* Empty input                                                              */
/* ======================================================================== */

static void encode_should_terminate_empty_output(void** state)
{
    (void)state;
    char out[4] = {'x', 'x', 'x', 'x'};

    pubnub_res_t rc = pn_base64url_encode(NULL, 0, out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out[0], '\0');
}

/* ======================================================================== */
/* RFC 4648 §10 test vectors (converted to base64url, no padding)          */
/* ======================================================================== */

static void encode_should_match_rfc4648_f(void** state)
{
    (void)state;
    const uint8_t input[] = {'f'};
    char          out[4]  = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "Zg");
}

static void encode_should_match_rfc4648_fo(void** state)
{
    (void)state;
    const uint8_t input[] = {'f', 'o'};
    char          out[8]  = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "Zm8");
}

static void encode_should_match_rfc4648_foo(void** state)
{
    (void)state;
    const uint8_t input[] = {'f', 'o', 'o'};
    char          out[8]  = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "Zm9v");
}

static void encode_should_match_rfc4648_foobar(void** state)
{
    (void)state;
    const uint8_t input[] = {'f', 'o', 'o', 'b', 'a', 'r'};
    char          out[16] = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "Zm9vYmFy");
}

/* ======================================================================== */
/* URL-safe alphabet (+ -> -, / -> _)                                       */
/* ======================================================================== */

static void encode_should_use_dash_for_byte_62(void** state)
{
    (void)state;
    /* Bytes yielding the 62-index sextet (standard '+', url-safe '-'). */
    const uint8_t input[] = {0xFB, 0xFF, 0xFF};
    char          out[8]  = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "-___");
}

static void encode_should_use_underscore_for_byte_63(void** state)
{
    (void)state;
    /* Forces at least one index 63 (standard '/', url-safe '_'). */
    const uint8_t input[] = {0xFF, 0xFF, 0xFF};
    char          out[8]  = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(out, "____");
}

static void encode_should_never_emit_padding(void** state)
{
    (void)state;
    /* Two bytes force one-byte remainder in the next block -- the
     * classic trigger for base64 `=` padding. We must emit none. */
    const uint8_t input[] = {0x00, 0x00};
    char          out[8]  = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_null(strchr(out, '='));
    assert_string_equal(out, "AAA");
}

/* ======================================================================== */
/* Signing-hot-path: 32-byte HMAC output                                     */
/* ======================================================================== */

static void encode_should_produce_43_chars_for_32_bytes(void** state)
{
    (void)state;
    uint8_t input[32];
    for (size_t i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)i;
    }
    char out[64] = {0};

    pubnub_res_t rc = pn_base64url_encode(input, sizeof(input), out, sizeof(out));

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(strlen(out), 43);
}

/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(encoded_len_should_return_zero_for_empty_input),
        cmocka_unit_test(encoded_len_should_return_two_for_one_byte),
        cmocka_unit_test(encoded_len_should_return_three_for_two_bytes),
        cmocka_unit_test(encoded_len_should_return_four_for_three_bytes),
        cmocka_unit_test(encoded_len_should_return_43_for_32_bytes),
        cmocka_unit_test(encode_should_reject_null_output),
        cmocka_unit_test(encode_should_reject_zero_output_size),
        cmocka_unit_test(encode_should_reject_null_input_with_nonzero_len),
        cmocka_unit_test(encode_should_reject_too_small_output),
        cmocka_unit_test(encode_should_terminate_empty_output),
        cmocka_unit_test(encode_should_match_rfc4648_f),
        cmocka_unit_test(encode_should_match_rfc4648_fo),
        cmocka_unit_test(encode_should_match_rfc4648_foo),
        cmocka_unit_test(encode_should_match_rfc4648_foobar),
        cmocka_unit_test(encode_should_use_dash_for_byte_62),
        cmocka_unit_test(encode_should_use_underscore_for_byte_63),
        cmocka_unit_test(encode_should_never_emit_padding),
        cmocka_unit_test(encode_should_produce_43_chars_for_32_bytes),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/error.h"

/* Internal header under test. */
#include "features/crypto/crypto_header.h"

static void header_parse_valid_acrh(void** state)
{
    (void)state;

    /* Build a valid 26-byte ACRH header:
     *   sentinel PNED (4) + version 1 (1) + identifier ACRH (4)
     *   + metadata_len 16 (1) = 10-byte prefix
     *   + 16 bytes metadata = 26 total header bytes */
    uint8_t input[64];
    memset(input, 0xAA, sizeof(input));

    /* Sentinel */
    input[0] = 0x50; /* P */
    input[1] = 0x4E; /* N */
    input[2] = 0x45; /* E */
    input[3] = 0x44; /* D */
    /* Version */
    input[4] = 0x01;
    /* Identifier "ACRH" */
    input[5] = 0x41; /* A */
    input[6] = 0x43; /* C */
    input[7] = 0x52; /* R */
    input[8] = 0x48; /* H */
    /* Metadata length = 16 (single byte) */
    input[9] = 16;
    /* Metadata (16 bytes of zeros). */
    memset(&input[10], 0, 16);

    pn_crypto_header_t header;
    memset(&header, 0, sizeof(header));

    pubnub_res_t res = pn_crypto_header_parse(input, sizeof(input), &header);
    assert_int_equal(res, PUBNUB_OK);

    assert_int_equal(header.identifier[0], 0x41);
    assert_int_equal(header.identifier[1], 0x43);
    assert_int_equal(header.identifier[2], 0x52);
    assert_int_equal(header.identifier[3], 0x48);
    assert_int_equal(header.metadata_len, 16);
    assert_int_equal(header.header_len, 26);
}

static void header_parse_extended_metadata_length(void** state)
{
    (void)state;

    /* When metadata_len >= 255, encoding uses 0xFF + 2-byte
     * big-endian. Total prefix becomes 12 bytes. */
    size_t metadata_len = 256;
    size_t total_size = 12 + metadata_len + 16; /* prefix + meta + ciphertext */
    uint8_t* input    = (uint8_t*)calloc(1, total_size);
    assert_non_null(input);

    /* Sentinel */
    input[0] = 0x50;
    input[1] = 0x4E;
    input[2] = 0x45;
    input[3] = 0x44;
    /* Version */
    input[4] = 0x01;
    /* Identifier "TEST" */
    input[5] = 'T';
    input[6] = 'E';
    input[7] = 'S';
    input[8] = 'T';
    /* Extended metadata length: marker + big-endian 256 */
    input[9]  = 0xFF;
    input[10] = 0x01; /* 256 >> 8 */
    input[11] = 0x00; /* 256 & 0xFF */

    pn_crypto_header_t header;
    memset(&header, 0, sizeof(header));

    pubnub_res_t res = pn_crypto_header_parse(input, total_size, &header);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(header.metadata_len, 256);
    assert_int_equal(header.header_len, 12 + 256);

    assert_int_equal(header.identifier[0], 'T');
    assert_int_equal(header.identifier[1], 'E');
    assert_int_equal(header.identifier[2], 'S');
    assert_int_equal(header.identifier[3], 'T');

    free(input);
}

static void header_parse_truncated_input(void** state)
{
    (void)state;

    /* Input shorter than PN_CRYPTO_MIN_HEADER (10 bytes). */
    uint8_t input[9] = {0x50, 0x4E, 0x45, 0x44, 0x01, 'A', 'C', 'R', 'H'};

    pn_crypto_header_t header;
    pubnub_res_t res = pn_crypto_header_parse(input, sizeof(input), &header);
    assert_int_equal(res, PUBNUB_ERR_CRYPTO);
}

static void header_parse_unsupported_version(void** state)
{
    (void)state;

    /* Version byte > 1 should fail. */
    uint8_t input[26];
    memset(input, 0, sizeof(input));
    input[0] = 0x50;
    input[1] = 0x4E;
    input[2] = 0x45;
    input[3] = 0x44;
    input[4] = 0x02; /* version 2 -- unsupported */
    input[5] = 'A';
    input[6] = 'C';
    input[7] = 'R';
    input[8] = 'H';
    input[9] = 16;

    pn_crypto_header_t header;
    pubnub_res_t res = pn_crypto_header_parse(input, sizeof(input), &header);
    assert_int_equal(res, PUBNUB_ERR_CRYPTO);
}

static void header_parse_metadata_beyond_input(void** state)
{
    (void)state;

    /* Header claims 300 bytes of metadata but input is only 20 bytes. */
    uint8_t input[20];
    memset(input, 0, sizeof(input));
    input[0]  = 0x50;
    input[1]  = 0x4E;
    input[2]  = 0x45;
    input[3]  = 0x44;
    input[4]  = 0x01;
    input[5]  = 'A';
    input[6]  = 'C';
    input[7]  = 'R';
    input[8]  = 'H';
    input[9]  = 0xFF;
    input[10] = (uint8_t)(300 >> 8);   /* 0x01 */
    input[11] = (uint8_t)(300 & 0xFF); /* 0x2C */

    pn_crypto_header_t header;
    pubnub_res_t res = pn_crypto_header_parse(input, sizeof(input), &header);
    assert_int_equal(res, PUBNUB_ERR_CRYPTO);
}

static void header_is_present_true(void** state)
{
    (void)state;

    uint8_t input[] = {0x50, 0x4E, 0x45, 0x44, 0x01, 0x00};
    int     result  = pn_crypto_header_is_present(input, sizeof(input));
    assert_int_equal(result, 1);
}

static void header_is_present_false(void** state)
{
    (void)state;

    uint8_t input[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00};
    int     result  = pn_crypto_header_is_present(input, sizeof(input));
    assert_int_equal(result, 0);
}

static void header_serialize_roundtrip(void** state)
{
    (void)state;

    const uint8_t identifier[4] = {'A', 'C', 'R', 'H'};
    size_t        metadata_len  = 16;

    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    size_t prefix_written =
        pn_crypto_header_serialize(identifier, metadata_len, buf, sizeof(buf));
    assert_true(prefix_written > 0);

    /* Fill in fake metadata after the prefix so parse sees full header. */
    memset(buf + prefix_written, 0xBB, metadata_len);

    /* Parse back. */
    size_t             total_len = prefix_written + metadata_len;
    pn_crypto_header_t header;
    pubnub_res_t       res = pn_crypto_header_parse(buf, total_len, &header);
    assert_int_equal(res, PUBNUB_OK);

    assert_memory_equal(header.identifier, identifier, 4);
    assert_int_equal(header.metadata_len, metadata_len);
    assert_int_equal(header.header_len, total_len);
}

static void header_size_correct(void** state)
{
    (void)state;

    /* metadata < 255: sentinel(4) + ver(1) + id(4) + len(1) + metadata */
    size_t size_16 = pn_crypto_header_size(16);
    assert_int_equal(size_16, 4 + 1 + 4 + 1 + 16);

    /* metadata == 0 */
    size_t size_0 = pn_crypto_header_size(0);
    assert_int_equal(size_0, 4 + 1 + 4 + 1 + 0);

    /* metadata >= 255: sentinel(4) + ver(1) + id(4) + len(3) + metadata */
    size_t size_255 = pn_crypto_header_size(255);
    assert_int_equal(size_255, 4 + 1 + 4 + 3 + 255);

    size_t size_256 = pn_crypto_header_size(256);
    assert_int_equal(size_256, 4 + 1 + 4 + 3 + 256);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(header_parse_valid_acrh),
        cmocka_unit_test(header_parse_extended_metadata_length),
        cmocka_unit_test(header_parse_truncated_input),
        cmocka_unit_test(header_parse_unsupported_version),
        cmocka_unit_test(header_parse_metadata_beyond_input),
        cmocka_unit_test(header_is_present_true),
        cmocka_unit_test(header_is_present_false),
        cmocka_unit_test(header_serialize_roundtrip),
        cmocka_unit_test(header_size_correct),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

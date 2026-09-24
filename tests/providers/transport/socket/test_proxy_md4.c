/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file test_proxy_md4.c
 * @brief MD4 unit tests with RFC 1320 appendix A.5 test vectors.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "providers/transport/socket/proxy/pn_proxy_md4.h"
#include "providers/transport/socket/proxy/pn_proxy_md4.c"

static void test_md4_empty(void** state)
{
    (void)state;

    const uint8_t expected[] = {
        0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0};
    uint8_t digest[16];

    pn_proxy_md4(NULL, 0, digest);
    assert_memory_equal(expected, digest, 16);
}

static void test_md4_a(void** state)
{
    (void)state;

    const uint8_t expected[] = {
        0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46, 0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24};
    uint8_t digest[16];

    pn_proxy_md4((const uint8_t*)"a", 1, digest);
    assert_memory_equal(expected, digest, 16);
}

static void test_md4_abc(void** state)
{
    (void)state;

    const uint8_t expected[] = {
        0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d};
    uint8_t digest[16];

    pn_proxy_md4((const uint8_t*)"abc", 3, digest);
    assert_memory_equal(expected, digest, 16);
}

static void test_md4_message_digest(void** state)
{
    (void)state;

    const uint8_t expected[] = {
        0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b};
    uint8_t digest[16];

    pn_proxy_md4((const uint8_t*)"message digest", 14, digest);
    assert_memory_equal(expected, digest, 16);
}

static void test_md4_alphabet(void** state)
{
    (void)state;

    const uint8_t expected[] = {
        0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9};
    uint8_t digest[16];

    pn_proxy_md4((const uint8_t*)"abcdefghijklmnopqrstuvwxyz", 26, digest);
    assert_memory_equal(expected, digest, 16);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_md4_empty),
        cmocka_unit_test(test_md4_a),
        cmocka_unit_test(test_md4_abc),
        cmocka_unit_test(test_md4_message_digest),
        cmocka_unit_test(test_md4_alphabet),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

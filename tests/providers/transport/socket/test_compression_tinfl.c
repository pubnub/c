/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file test_compression_tinfl.c
 * @brief Tests for the tinfl decompression backend using pre-baked fixtures.
 *
 * Compiled only when PUBNUB_COMPRESSION_BACKEND_TINFL is defined. Does not
 * depend on system zlib — all test inputs are pre-baked const byte arrays.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

/* Include pn_inflate.c directly with the tinfl backend selected. */
#define PUBNUB_COMPRESSION_BACKEND_TINFL 1
#include "providers/transport/socket/inflate/pn_inflate.c"

#include "test_compression_fixtures.h"

/** Minimal stub allocator — tinfl needs alloc/free for its workspace. */
static void* stub_alloc(struct pubnub_allocator_provider* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void stub_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static struct pubnub_allocator_provider g_alloc = {
    .alloc = stub_alloc,
    .free  = stub_free,
};

/** Decompress FIXTURE_GZIP_HELLO and verify "Hello, World!". */
static void test_tinfl_gzip_hello(void** state)
{
    (void)state;
    uint8_t out[64] = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_gzip(FIXTURE_GZIP_HELLO,
                             FIXTURE_GZIP_HELLO_len,
                             out,
                             sizeof(out),
                             &out_len,
                             &g_alloc,
                             NULL);
    assert_int_equal(rc, 0);
    assert_int_equal((int)out_len, 13);
    assert_memory_equal(out, "Hello, World!", 13);
}

/** Decompress FIXTURE_DEFLATE_HELLO and verify "Hello, World!". */
static void test_tinfl_deflate_hello(void** state)
{
    (void)state;
    uint8_t out[64] = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_deflate(FIXTURE_DEFLATE_HELLO,
                                FIXTURE_DEFLATE_HELLO_len,
                                out,
                                sizeof(out),
                                &out_len,
                                &g_alloc,
                                NULL);
    assert_int_equal(rc, 0);
    assert_int_equal((int)out_len, 13);
    assert_memory_equal(out, "Hello, World!", 13);
}

/** Decompress empty gzip stream: 0 bytes output, returns 0. */
static void test_tinfl_empty_gzip(void** state)
{
    (void)state;
    uint8_t out[8]  = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_gzip(FIXTURE_GZIP_EMPTY,
                             FIXTURE_GZIP_EMPTY_len,
                             out,
                             sizeof(out),
                             &out_len,
                             &g_alloc,
                             NULL);
    assert_int_equal(rc, 0);
    assert_int_equal((int)out_len, 0);
}

/** Output buffer too small (5 bytes for 13-byte output): returns -1. */
static void test_tinfl_output_too_small(void** state)
{
    (void)state;
    uint8_t out[5]  = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_gzip(FIXTURE_GZIP_HELLO,
                             FIXTURE_GZIP_HELLO_len,
                             out,
                             sizeof(out),
                             &out_len,
                             &g_alloc,
                             NULL);
    assert_int_equal(rc, -1);
}

/** Bad magic bytes: returns -2. */
static void test_tinfl_invalid_data(void** state)
{
    (void)state;
    uint8_t out[64] = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_gzip(FIXTURE_GZIP_BAD_MAGIC,
                             FIXTURE_GZIP_BAD_MAGIC_len,
                             out,
                             sizeof(out),
                             &out_len,
                             &g_alloc,
                             NULL);
    assert_int_equal(rc, -2);
}

/** Truncated gzip (missing trailer): returns -2. */
static void test_tinfl_truncated(void** state)
{
    (void)state;
    uint8_t out[64] = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_gzip(FIXTURE_GZIP_TRUNCATED,
                             FIXTURE_GZIP_TRUNCATED_len,
                             out,
                             sizeof(out),
                             &out_len,
                             &g_alloc,
                             NULL);
    assert_int_equal(rc, -2);
}

/** Trailing garbage after a valid complete gzip stream. */
static void test_tinfl_trailing_garbage(void** state)
{
    (void)state;
    uint8_t buf[64] = {0};
    uint8_t out[64] = {0};
    size_t  out_len = 0;
    size_t  i       = 0;
    int     rc      = 0;

    memcpy(buf, FIXTURE_GZIP_HELLO, FIXTURE_GZIP_HELLO_len);
    /* Append junk past the end of the valid gzip member. */
    for (i = 0; i < 8; i++) {
        buf[FIXTURE_GZIP_HELLO_len + i] = (uint8_t)(0xA5 ^ i);
    }
    rc = pn_inflate_gzip(
        buf, FIXTURE_GZIP_HELLO_len + 8, out, sizeof(out), &out_len, &g_alloc, NULL);
    /* The only channel to report appended garbage through this API is
     * the return code, so correct behavior is a non-OK result. */
    /* BUG: trailing bytes after a valid complete gzip stream are not validated
     * and are silently accepted; callers cannot distinguish a clean stream from a stream with appended garbage. */
    assert_int_not_equal(rc, 0);
}

/** Zero-length input: graceful decode error, no crash. */
static void test_tinfl_zero_length_input(void** state)
{
    (void)state;
    uint8_t out[8]  = {0};
    size_t  out_len = 0;
    int     rc      = pn_inflate_gzip(
        FIXTURE_GZIP_HELLO, 0, out, sizeof(out), &out_len, &g_alloc, NULL);
    assert_int_not_equal(rc, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tinfl_gzip_hello),
        cmocka_unit_test(test_tinfl_deflate_hello),
        cmocka_unit_test(test_tinfl_empty_gzip),
        cmocka_unit_test(test_tinfl_output_too_small),
        cmocka_unit_test(test_tinfl_invalid_data),
        cmocka_unit_test(test_tinfl_truncated),
        cmocka_unit_test(test_tinfl_trailing_garbage),
        cmocka_unit_test(test_tinfl_zero_length_input),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <zlib.h>

#include "providers/transport/socket/inflate/pn_inflate.h"

static void test_inflate_gzip(void** state)
{
    (void)state;

    const char* original =
        "Hello, World! This is a test string for compression.";
    size_t original_len = strlen(original);

    uLong    compressed_bound = compressBound(original_len) + 18;
    uint8_t* compressed       = malloc(compressed_bound);
    assert_non_null(compressed);

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in  = (Bytef*)original;
    stream.avail_in = (uInt)original_len;

    int ret = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    assert_int_equal(ret, Z_OK);

    stream.next_out  = compressed;
    stream.avail_out = (uInt)compressed_bound;

    ret = deflate(&stream, Z_FINISH);
    if (Z_STREAM_END != ret) {
        deflateEnd(&stream);
        fail_msg("deflate() returned %d, expected Z_STREAM_END", ret);
    }

    uLong compressed_len = stream.total_out;
    deflateEnd(&stream);

    uint8_t* decompressed = malloc(original_len + 100);
    assert_non_null(decompressed);

    size_t decompressed_len = 0;
    ret                     = pn_inflate_gzip(compressed,
                          compressed_len,
                          decompressed,
                          original_len + 100,
                          &decompressed_len,
                          NULL,
                          NULL);

    assert_int_equal(ret, 0);
    assert_int_equal(decompressed_len, original_len);
    assert_memory_equal(decompressed, original, original_len);

    free(compressed);
    free(decompressed);
}

static void test_inflate_deflate(void** state)
{
    (void)state;

    const char* original     = "Raw deflate test string.";
    size_t      original_len = strlen(original);

    uLong    compressed_bound = compressBound(original_len);
    uint8_t* compressed       = malloc(compressed_bound);
    assert_non_null(compressed);

    z_stream stream;
    stream.zalloc   = Z_NULL;
    stream.zfree    = Z_NULL;
    stream.opaque   = Z_NULL;
    stream.next_in  = (Bytef*)original;
    stream.avail_in = (uInt)original_len;

    int ret = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    assert_int_equal(ret, Z_OK);

    stream.next_out  = compressed;
    stream.avail_out = (uInt)compressed_bound;

    ret = deflate(&stream, Z_FINISH);
    assert_int_equal(ret, Z_STREAM_END);

    uLong compressed_len = stream.total_out;
    deflateEnd(&stream);

    uint8_t* decompressed = malloc(original_len + 100);
    assert_non_null(decompressed);

    size_t decompressed_len = 0;
    ret                     = pn_inflate_deflate(compressed,
                             compressed_len,
                             decompressed,
                             original_len + 100,
                             &decompressed_len,
                             NULL,
                             NULL);

    assert_int_equal(ret, 0);
    assert_int_equal(decompressed_len, original_len);
    assert_memory_equal(decompressed, original, original_len);

    free(compressed);
    free(decompressed);
}

static void test_inflate_gzip_buffer_too_small(void** state)
{
    (void)state;

    const char* original     = "This will not fit.";
    size_t      original_len = strlen(original);

    uLong    compressed_bound = compressBound(original_len) + 18;
    uint8_t* compressed       = malloc(compressed_bound);
    assert_non_null(compressed);

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in  = (Bytef*)original;
    stream.avail_in = (uInt)original_len;

    int ret = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    assert_int_equal(ret, Z_OK);

    stream.next_out  = compressed;
    stream.avail_out = (uInt)compressed_bound;

    ret = deflate(&stream, Z_FINISH);
    if (Z_STREAM_END != ret) {
        deflateEnd(&stream);
        fail_msg("deflate() returned %d, expected Z_STREAM_END", ret);
    }

    uLong compressed_len = stream.total_out;
    deflateEnd(&stream);

    uint8_t small_buffer[5];
    size_t  decompressed_len = 0;

    ret = pn_inflate_gzip(compressed,
                          compressed_len,
                          small_buffer,
                          sizeof(small_buffer),
                          &decompressed_len,
                          NULL,
                          NULL);

    assert_int_equal(ret, -1);

    free(compressed);
}

static void test_inflate_gzip_invalid_data(void** state)
{
    (void)state;

    uint8_t garbage[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    uint8_t output[100];
    size_t  out_len = 0;

    int ret = pn_inflate_gzip(
        garbage, sizeof(garbage), output, sizeof(output), &out_len, NULL, NULL);

    assert_int_equal(ret, -2);
}

static void test_inflate_empty(void** state)
{
    (void)state;

    uint8_t  compressed[100];
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in  = Z_NULL;
    stream.avail_in = 0;

    int ret = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    assert_int_equal(ret, Z_OK);

    stream.next_out  = compressed;
    stream.avail_out = sizeof(compressed);

    ret = deflate(&stream, Z_FINISH);
    if (Z_STREAM_END != ret) {
        deflateEnd(&stream);
        fail_msg("deflate() returned %d, expected Z_STREAM_END", ret);
    }

    uLong compressed_len = stream.total_out;
    deflateEnd(&stream);

    uint8_t output[100];
    size_t  out_len = 0;

    ret = pn_inflate_gzip(
        compressed, compressed_len, output, sizeof(output), &out_len, NULL, NULL);

    assert_int_equal(ret, 0);
    assert_int_equal(out_len, 0);
}

/** Compress a buffer to a gzip stream. Returns gzip length via out_len. */
static size_t gzip_compress(const void* src, size_t src_len, uint8_t* dst, size_t dst_cap)
{
    z_stream stream    = {0};
    uLong    total_out = 0;
    int      ret       = 0;

    stream.next_in  = (Bytef*)src;
    stream.avail_in = (uInt)src_len;
    ret             = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    assert_int_equal(ret, Z_OK);
    stream.next_out  = dst;
    stream.avail_out = (uInt)dst_cap;
    ret              = deflate(&stream, Z_FINISH);
    if (Z_STREAM_END != ret) {
        deflateEnd(&stream);
        fail_msg("deflate() returned %d, expected Z_STREAM_END", ret);
    }
    total_out = stream.total_out;
    deflateEnd(&stream);
    return (size_t)total_out;
}

/** Round-trip a subscribe-style JSON payload through gzip. */
static void test_inflate_gzip_subscribe_payload(void** state)
{
    (void)state;

    const char* original =
        "{\"t\":{\"t\":\"17001234567890123\",\"r\":42},\"m\":["
        "{\"a\":\"1\",\"f\":0,\"i\":\"client-1\",\"p\":{\"t\":"
        "\"17001234567890000\",\"r\":42},\"k\":\"sub-key\",\"c\":"
        "\"my-channel\",\"d\":{\"text\":\"hello world from the "
        "subscribe loop\"}}]}";
    size_t  original_len    = strlen(original);
    uint8_t compressed[512] = {0};
    size_t  compressed_len =
        gzip_compress(original, original_len, compressed, sizeof(compressed));
    uint8_t* decompressed     = malloc(original_len + 64);
    size_t   decompressed_len = 0;
    int      ret              = 0;

    assert_non_null(decompressed);
    ret = pn_inflate_gzip(compressed,
                          compressed_len,
                          decompressed,
                          original_len + 64,
                          &decompressed_len,
                          NULL,
                          NULL);
    assert_int_equal(ret, PN_INFLATE_OK);
    assert_int_equal(decompressed_len, original_len);
    assert_memory_equal(decompressed, original, original_len);
    free(decompressed);
}

/** Truncated gzip stream (cut mid-stream): decode error, not partial. */
static void test_inflate_gzip_truncated(void** state)
{
    (void)state;

    const char* original =
        "A reasonably long payload so the deflate stream has real "
        "compressed content that can be cut mid-stream to force a "
        "decode error rather than a clean end.";
    size_t  original_len    = strlen(original);
    uint8_t compressed[512] = {0};
    size_t  compressed_len =
        gzip_compress(original, original_len, compressed, sizeof(compressed));
    uint8_t output[512] = {0};
    size_t  out_len     = 0;
    int     ret         = 0;

    /* Feed only the first half: the trailer and part of the deflate
     * payload are missing, so decode must fail. */
    ret = pn_inflate_gzip(
        compressed, compressed_len / 2, output, sizeof(output), &out_len, NULL, NULL);
    /* BUG: a truncated/incomplete gzip stream returns PN_INFLATE_ERR_OVERFLOW;
     * the zlib backend maps Z_BUF_ERROR to overflow unconditionally, even when
     * output space remains. Callers cannot distinguish "output buffer too small"
     * (retry with a larger buffer) from "input truncated" (retry is futile) and
     * may grow buffers pointlessly. The correct code for a malformed/incomplete stream is PN_INFLATE_ERR_INVALID. */
    assert_int_equal(ret, PN_INFLATE_ERR_INVALID);
}

/** Trailing garbage after a valid complete gzip stream. */
static void test_inflate_gzip_trailing_garbage(void** state)
{
    (void)state;

    const char* original        = "Hello, World!";
    size_t      original_len    = strlen(original);
    uint8_t     compressed[128] = {0};
    size_t      compressed_len =
        gzip_compress(original, original_len, compressed, sizeof(compressed));
    uint8_t output[64] = {0};
    size_t  out_len    = 0;
    int     ret        = 0;
    size_t  i          = 0;

    /* Append junk past the end of the valid gzip member. */
    for (i = 0; i < 8; i++) {
        compressed[compressed_len + i] = (uint8_t)(0xA5 ^ i);
    }
    ret = pn_inflate_gzip(
        compressed, compressed_len + 8, output, sizeof(output), &out_len, NULL, NULL);
    /* The only channel to report appended garbage through this API is
     * the return code, so correct behavior is a non-OK result. */
    /* BUG: trailing bytes after a valid complete gzip stream are not validated
     * and are silently accepted; callers cannot distinguish a clean stream from a stream with appended garbage. */
    assert_int_not_equal(ret, PN_INFLATE_OK);
}

/** Zero-length input: graceful decode error, no crash. */
static void test_inflate_gzip_zero_length_input(void** state)
{
    (void)state;

    uint8_t input[2]   = {0x1f, 0x8b};
    uint8_t output[16] = {0};
    size_t  out_len    = 0;
    int     ret =
        pn_inflate_gzip(input, 0, output, sizeof(output), &out_len, NULL, NULL);
    assert_int_not_equal(ret, PN_INFLATE_OK);
}

/** Corrupted gzip header byte (valid magic, bad method): decode error. */
static void test_inflate_gzip_corrupt_header(void** state)
{
    (void)state;

    const char* original        = "corrupt me";
    size_t      original_len    = strlen(original);
    uint8_t     compressed[128] = {0};
    size_t      compressed_len =
        gzip_compress(original, original_len, compressed, sizeof(compressed));
    uint8_t output[64] = {0};
    size_t  out_len    = 0;
    int     ret        = 0;

    /* Byte 2 is the compression method (0x08 = deflate). A value the
     * decoder does not understand must be rejected. */
    compressed[2] = 0x09;
    ret           = pn_inflate_gzip(
        compressed, compressed_len, output, sizeof(output), &out_len, NULL, NULL);
    assert_int_equal(ret, PN_INFLATE_ERR_INVALID);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_inflate_gzip),
        cmocka_unit_test(test_inflate_deflate),
        cmocka_unit_test(test_inflate_gzip_buffer_too_small),
        cmocka_unit_test(test_inflate_gzip_invalid_data),
        cmocka_unit_test(test_inflate_empty),
        cmocka_unit_test(test_inflate_gzip_subscribe_payload),
        cmocka_unit_test(test_inflate_gzip_truncated),
        cmocka_unit_test(test_inflate_gzip_trailing_garbage),
        cmocka_unit_test(test_inflate_gzip_zero_length_input),
        cmocka_unit_test(test_inflate_gzip_corrupt_header),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

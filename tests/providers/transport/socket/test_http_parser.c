/**
 * @file test_http_parser.c
 * @brief cmocka tests for HTTP response parser.
 *
 * Copyright PubNub Inc.
 */

#include "http_parser.h"
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

/** Test simple 200 response in one feed. */
static void test_parse_simple_200(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Content-Length: 5\r\n"
                         "\r\n"
                         "hello";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_int_equal(body_len, 5);
    assert_memory_equal(body_start, "hello", 5);
}

/** Test chunked transfer encoding. */
static void test_parse_chunked(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "5\r\n"
                         "hello\r\n"
                         "6\r\n"
                         " world\r\n"
                         "0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_int_equal(body_len, 11);
    assert_memory_equal(body_start, "hello world", 11);
}

/** Test 204 No Content with zero body. */
static void test_parse_no_body_204(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 204 No Content\r\n"
                         "Content-Length: 0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 204);
    assert_int_equal(body_len, 0);
}

/** Test byte-by-byte feeding (simulates FSM accumulated-buffer pattern). */
static void test_parse_byte_by_byte(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* Source data — one byte delivered per tick into an accumulator. */
    static const uint8_t source[] = "HTTP/1.1 200 OK\r\n"
                                    "Content-Length: 3\r\n"
                                    "\r\n"
                                    "abc";
    const size_t         total    = sizeof(source) - 1;

    /* Accumulator mirrors rx_buf: grows by one byte each tick. */
    uint8_t  accum[sizeof(source)] = {0};
    size_t   accum_len             = 0;
    uint16_t status                = 0;

    for (size_t i = 0; i < total; ++i) {
        accum[accum_len++] = source[i];

        size_t                 consumed   = 0;
        const uint8_t*         body_start = NULL;
        size_t                 body_len   = 0;
        pn_http_parse_result_t result     = pn_http_parser_feed(
            &parser, accum, accum_len, &consumed, &status, &body_start, &body_len);

        if (PN_HTTP_PARSE_COMPLETE == result) {
            assert_int_equal(status, 200);
            assert_int_equal((int)body_len, 3);
            assert_memory_equal(body_start, "abc", 3);
            return;
        }
        assert_int_equal(result, PN_HTTP_PARSE_NEED_MORE);
    }

    fail_msg("Expected COMPLETE but got NEED_MORE");
}

/** Test partial header split across feeds (simulates FSM accumulated-buffer pattern). */
static void test_parse_partial_header(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* part1 + part2 concatenated form the full response. */
    static const uint8_t part1[] = "HTTP/1.1 200 OK\r\n"
                                   "Content-Le";
    static const uint8_t part2[] = "ngth: 2\r\n"
                                   "\r\n"
                                   "ok";

    /* Accumulator: first feed part1, then append part2. */
    uint8_t accum[sizeof(part1) + sizeof(part2)] = {0};
    memcpy(accum, part1, sizeof(part1) - 1);
    size_t accum_len = sizeof(part1) - 1;

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, accum, accum_len, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_NEED_MORE);

    /* Append part2 to accumulator and feed the full buffer again. */
    memcpy(accum + accum_len, part2, sizeof(part2) - 1);
    accum_len += sizeof(part2) - 1;

    result = pn_http_parser_feed(
        &parser, accum, accum_len, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_int_equal((int)body_len, 2);
    assert_memory_equal(body_start, "ok", 2);
}

/** Test malformed status line. */
static void test_parse_malformed_status(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "GARBAGE\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_ERROR);
}

/** Test Content-Encoding: gzip flag. */
static void test_parse_gzip_flag(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Content-Encoding: gzip\r\n"
                         "Content-Length: 0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_true(0 != (parser.flags & PN_HTTP_FLAG_GZIP));
}

/** Test Connection: close flag. */
static void test_parse_connection_close(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Connection: close\r\n"
                         "Content-Length: 0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_true(0 != (parser.flags & PN_HTTP_FLAG_CONNECTION_CLOSE));
}

/** Test multiple chunks of different sizes. */
static void test_parse_multiple_chunks(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "3\r\n"
                         "foo\r\n"
                         "7\r\n"
                         "bar baz\r\n"
                         "2\r\n"
                         "!!\r\n"
                         "0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_int_equal(body_len, 12);
    assert_memory_equal(body_start, "foobar baz!!", 12);
}

/** Chunk-size with 9 hex digits must return error (overflow guard). */
static void test_parse_chunk_size_overflow(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* "100000000" is 9 hex digits — overflows uint32_t silently without guard. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "100000000\r\n"
                         "data\r\n"
                         "0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_ERROR);
}

/** Content-Length value 4294967296 (UINT32_MAX + 1) in 10 digits must return error. */
static void test_parse_content_length_uint32_overflow(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* "4294967296" is UINT32_MAX + 1 — 10 digits that silently overflow without guard. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Content-Length: 4294967296\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_ERROR);
}

/** Content-Length with 11 decimal digits must return error (overflow guard). */
static void test_parse_content_length_overflow(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* "42949672950" is 11 digits — overflows uint32_t without guard. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Content-Length: 42949672950\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_ERROR);
}

/** Content-Length 2097152 (2 MB) must parse successfully end-to-end. */
static void test_parse_2mb_content_length(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* Build headers + 2 MB body in a heap buffer. */
    static const char headers[]  = "HTTP/1.1 200 OK\r\n"
                                   "Content-Length: 2097152\r\n"
                                   "\r\n";
    const size_t      header_len = sizeof(headers) - 1;
    const size_t      body_size  = 2097152u;
    const size_t      total      = header_len + body_size;

    uint8_t* buf = (uint8_t*)malloc(total);
    assert_non_null(buf);
    memcpy(buf, headers, header_len);
    memset(buf + header_len, 'X', body_size);

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, buf, total, &consumed, &status, &body_start, &body_len);

    free(buf);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_int_equal(body_len, body_size);
}

/** Non-hex chunk size must return error. */
static void test_parse_chunk_size_non_hex(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* "XYZ" is not a valid hex chunk size. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "XYZ\r\n"
                         "hello\r\n"
                         "0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_ERROR);
}

/** Chunk-size line with a chunk-extension (";ext") is tolerated (RFC 7230). */
static void test_parse_chunk_extension(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "5;ext\r\n"
                         "hello\r\n"
                         "0\r\n"
                         "\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_COMPLETE);
    assert_int_equal(status, 200);
    assert_int_equal(body_len, 5);
    assert_memory_equal(body_start, "hello", 5);
}

/** Truncated chunk body mid-stream must return NEED_MORE, not error. */
static void test_parse_chunked_truncated_body(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* Chunk announces 5 bytes but only 3 ("hel") are delivered. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "5\r\n"
                         "hel";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_NEED_MORE);
}

/** Missing terminating CRLF after the final "0" chunk must return NEED_MORE. */
static void test_parse_chunked_truncated_terminator(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* Final "0\r\n" present, but the closing "\r\n" of the body is absent. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "5\r\n"
                         "hello\r\n"
                         "0\r\n";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    assert_int_equal(result, PN_HTTP_PARSE_NEED_MORE);
}

/**
 * Identity body with no Content-Length and no Transfer-Encoding: the body
 * bytes must be delivered to the caller when the connection closes.
 */
static void test_parse_identity_body_read_until_close(void** state)
{
    (void)state;
    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* No Content-Length, no Transfer-Encoding — body framed by close. */
    uint8_t response[] = "HTTP/1.1 200 OK\r\n"
                         "Server: x\r\n"
                         "\r\n"
                         "BODYDATA";

    size_t                 consumed   = 0;
    uint16_t               status     = 0;
    const uint8_t*         body_start = NULL;
    size_t                 body_len   = 0;
    pn_http_parse_result_t result     = pn_http_parser_feed(
        &parser, response, sizeof(response) - 1, &consumed, &status, &body_start, &body_len);

    (void)result;
    assert_int_equal(status, 200);
    assert_int_equal(body_len, 8);
    assert_memory_equal(body_start, "BODYDATA", 8);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_simple_200),
        cmocka_unit_test(test_parse_chunked),
        cmocka_unit_test(test_parse_no_body_204),
        cmocka_unit_test(test_parse_byte_by_byte),
        cmocka_unit_test(test_parse_partial_header),
        cmocka_unit_test(test_parse_malformed_status),
        cmocka_unit_test(test_parse_gzip_flag),
        cmocka_unit_test(test_parse_connection_close),
        cmocka_unit_test(test_parse_multiple_chunks),
        cmocka_unit_test(test_parse_chunk_size_overflow),
        cmocka_unit_test(test_parse_content_length_uint32_overflow),
        cmocka_unit_test(test_parse_content_length_overflow),
        cmocka_unit_test(test_parse_2mb_content_length),
        cmocka_unit_test(test_parse_chunk_size_non_hex),
        cmocka_unit_test(test_parse_chunk_extension),
        cmocka_unit_test(test_parse_chunked_truncated_body),
        cmocka_unit_test(test_parse_chunked_truncated_terminator),
        cmocka_unit_test(test_parse_identity_body_read_until_close),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

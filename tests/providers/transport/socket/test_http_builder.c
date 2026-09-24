/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "providers/transport/socket/http_builder.h"

#include "pubnub/config.h"
#include "pubnub/providers/transport_types.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

/* Helper: zero-init a request with method and host. */
static void init_request(pubnub_http_request_t* req,
                         pubnub_http_method_t   method,
                         const char*            host)
{
    memset(req, 0, sizeof(*req));
    req->method = method;
    req->host   = host;
}

/* Test: simple GET with 2 path segments and 1 query param. */
static void test_build_get_simple(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "ps.pndsn.com");

    /* Path: /v2/publish */
    req.path_segments[0].ptr = "v2";
    req.path_segments[0].len = 2;
    req.path_segments[1].ptr = "publish";
    req.path_segments[1].len = 7;
    req.path_segment_count   = 2;

    /* Query: uuid=test-user */
    req.query_params[0].key.ptr   = "uuid";
    req.query_params[0].key.len   = 4;
    req.query_params[0].value.ptr = "test-user";
    req.query_params[0].value.len = 9;
    req.query_param_count         = 1;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);
    assert_true(len > 0);

    /* Verify request line. */
    const char* expected_line = "GET /v2/publish?uuid=test-user HTTP/1.1\r\n";
    assert_true(NULL != strstr((const char*)buf, expected_line));

    /* Verify Host header. */
    assert_true(NULL != strstr((const char*)buf, "Host: ps.pndsn.com\r\n"));

    /* Verify terminator. */
    assert_true(0 == memcmp(buf + len - 2, "\r\n", 2));
}

/* Test: POST with body (Content-Length header). */
static void test_build_post_with_body(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_POST, "ps.pndsn.com");

    req.path_segments[0].ptr = "publish";
    req.path_segments[0].len = 7;
    req.path_segment_count   = 1;

    const uint8_t body_data[] = "test body content";
    req.body                  = body_data;
    req.body_len              = sizeof(body_data) - 1;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);

    /* Verify Content-Length. */
    char expected[64];
    snprintf(expected,
             sizeof(expected),
             "Content-Length: %u\r\n",
             (unsigned int)req.body_len);
    assert_true(NULL != strstr((const char*)buf, expected));
}

/* Test: multiple query parameters. */
static void test_build_multiple_query_params(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "ps.pndsn.com");

    req.path_segments[0].ptr = "v1";
    req.path_segments[0].len = 2;
    req.path_segment_count   = 1;

    req.query_params[0].key.ptr   = "uuid";
    req.query_params[0].key.len   = 4;
    req.query_params[0].value.ptr = "user1";
    req.query_params[0].value.len = 5;

    req.query_params[1].key.ptr   = "auth";
    req.query_params[1].key.len   = 4;
    req.query_params[1].value.ptr = "token123";
    req.query_params[1].value.len = 8;

    req.query_params[2].key.ptr   = "pnsdk";
    req.query_params[2].key.len   = 5;
    req.query_params[2].value.ptr = "PubNub-C%2F1.0.0";
    req.query_params[2].value.len = 16;

    req.query_param_count = 3;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);

    /* Verify query string. */
    const char* expected =
        "GET /v1?uuid=user1&auth=token123&pnsdk=PubNub-C%2F1.0.0 HTTP/1.1\r\n";
    assert_true(NULL != strstr((const char*)buf, expected));
}

/* Test: custom headers. */
static void test_build_with_custom_headers(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "ps.pndsn.com");

    req.path_segments[0].ptr = "test";
    req.path_segments[0].len = 4;
    req.path_segment_count   = 1;

    req.headers[0].key.ptr   = "X-Custom-Header";
    req.headers[0].key.len   = 15;
    req.headers[0].value.ptr = "value1";
    req.headers[0].value.len = 6;

    req.headers[1].key.ptr   = "Authorization";
    req.headers[1].key.len   = 13;
    req.headers[1].value.ptr = "Bearer token";
    req.headers[1].value.len = 12;

    req.header_count = 2;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);

    /* Verify custom headers. */
    assert_true(NULL != strstr((const char*)buf, "X-Custom-Header: value1\r\n"));
    assert_true(NULL != strstr((const char*)buf, "Authorization: Bearer token\r\n"));
}

/* Test: IPv6 host with bracketed format. */
static void test_build_ipv6_host(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "[::1]:8080");

    req.path_segments[0].ptr = "test";
    req.path_segments[0].len = 4;
    req.path_segment_count   = 1;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);

    /* Verify Host header. */
    assert_true(NULL != strstr((const char*)buf, "Host: [::1]:8080\r\n"));
}

/* Test: buffer too small. */
static void test_build_buffer_too_small(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "ps.pndsn.com");

    req.path_segments[0].ptr = "v2";
    req.path_segments[0].len = 2;
    req.path_segment_count   = 1;

    uint8_t buf[32];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, -1);
}

/* Test: no query params (path only). */
static void test_build_no_query_params(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "ps.pndsn.com");

    req.path_segments[0].ptr = "time";
    req.path_segments[0].len = 4;
    req.path_segment_count   = 1;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);

    /* Verify no '?' in output. */
    const char* expected = "GET /time HTTP/1.1\r\n";
    assert_true(NULL != strstr((const char*)buf, expected));
}

/* Test: Accept-Encoding header present iff PUBNUB_ENABLE_COMPRESSION is set. */
static void test_build_compression_header(void** state)
{
    (void)state;

    pubnub_http_request_t req;
    init_request(&req, PUBNUB_HTTP_GET, "ps.pndsn.com");

    req.path_segments[0].ptr = "test";
    req.path_segments[0].len = 4;
    req.path_segment_count   = 1;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_http_build_headers(&req, buf, sizeof(buf), &len);
    assert_int_equal(rc, 0);

    /* Verify Accept-Encoding present when PUBNUB_ENABLE_COMPRESSION is set. */
    if (PUBNUB_ENABLE_COMPRESSION) {
        assert_true(NULL != strstr((const char*)buf, "Accept-Encoding"));
    } else {
        assert_true(NULL == strstr((const char*)buf, "Accept-Encoding"));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_build_get_simple),
        cmocka_unit_test(test_build_post_with_body),
        cmocka_unit_test(test_build_multiple_query_params),
        cmocka_unit_test(test_build_with_custom_headers),
        cmocka_unit_test(test_build_ipv6_host),
        cmocka_unit_test(test_build_buffer_too_small),
        cmocka_unit_test(test_build_no_query_params),
        cmocka_unit_test(test_build_compression_header),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

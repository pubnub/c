/**
 * @file test_keepalive.c
 * @brief cmocka tests for HTTP keep-alive connection reuse logic.
 *
 * Copyright PubNub Inc.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

#include "providers/transport/socket/keepalive.h"

/** Test reuse with same host, port, and TLS state within limits. */
static void test_reuse_same_host(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 10,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms (1 second later) */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 1);
}

/** Test cannot reuse with different host. */
static void test_reuse_different_host(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api1.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 5,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api2.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 0);
}

/** Test cannot reuse with different port. */
static void test_reuse_different_port(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 80,
        .secure          = 0,
        .requests_served = 5,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 0);
}

/** Test cannot reuse with TLS/plaintext mismatch. */
static void test_reuse_tls_mismatch(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 5,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 0,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 0);
}

/** Test cannot reuse when max requests exceeded. */
static void test_reuse_max_requests_exceeded(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 1000,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 0);
}

/** Test cannot reuse when idle timeout exceeded. */
static void test_reuse_idle_timeout(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 10,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1100000, /* now_ms (100 seconds later) */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms (50 seconds) */
    );

    assert_int_equal(result, 0);
}

/** Test should_close returns 1 when CONNECTION_CLOSE flag is set. */
static void test_should_close_connection_close(void** state)
{
    (void)state;

    uint8_t flags = 0x08; /* PN_HTTP_FLAG_CONNECTION_CLOSE */

    int result = pn_keepalive_should_close(flags);

    assert_int_equal(result, 1);
}

/** Test should_close returns 0 when CONNECTION_CLOSE flag is not set. */
static void test_should_close_keepalive(void** state)
{
    (void)state;

    uint8_t flags = 0x00; /* No flags */

    int result = pn_keepalive_should_close(flags);

    assert_int_equal(result, 0);
}

/** Test should_close ignores other flags. */
static void test_should_close_other_flags(void** state)
{
    (void)state;

    uint8_t flags = 0x07; /* CHUNKED | GZIP | DEFLATE, but no CONNECTION_CLOSE */

    int result = pn_keepalive_should_close(flags);

    assert_int_equal(result, 0);
}

/** Test cannot reuse with NULL pointers. */
static void test_reuse_null_connected_host(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = NULL,
        .port            = 443,
        .secure          = 1,
        .requests_served = 5,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 0);
}

/** Test cannot reuse when new_host is NULL. */
static void test_reuse_null_new_host(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 5,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = NULL,
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 0);
}

/** Test reuse at exact max_requests boundary. */
static void test_reuse_exact_max_requests(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 999,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result = pn_keepalive_can_reuse(&conn,
                                        &target,
                                        1001000, /* now_ms */
                                        1000,    /* max_requests */
                                        50000    /* max_idle_ms */
    );

    assert_int_equal(result, 1);
}

/** Test reuse at exact idle timeout boundary. */
static void test_reuse_exact_idle_timeout(void** state)
{
    (void)state;

    pn_keepalive_conn_state_t conn = {
        .host            = "api.pubnub.com",
        .port            = 443,
        .secure          = 1,
        .requests_served = 10,
        .idle_since_ms   = 1000000,
    };
    pn_keepalive_target_t target = {
        .host   = "api.pubnub.com",
        .port   = 443,
        .secure = 1,
    };

    int result =
        pn_keepalive_can_reuse(&conn,
                               &target,
                               1050000, /* now_ms (exactly 50 seconds) */
                               1000,    /* max_requests */
                               50000    /* max_idle_ms (exactly 50 seconds) */
        );

    assert_int_equal(result, 1);
}

static const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_reuse_same_host),
    cmocka_unit_test(test_reuse_different_host),
    cmocka_unit_test(test_reuse_different_port),
    cmocka_unit_test(test_reuse_tls_mismatch),
    cmocka_unit_test(test_reuse_max_requests_exceeded),
    cmocka_unit_test(test_reuse_idle_timeout),
    cmocka_unit_test(test_should_close_connection_close),
    cmocka_unit_test(test_should_close_keepalive),
    cmocka_unit_test(test_should_close_other_flags),
    cmocka_unit_test(test_reuse_null_connected_host),
    cmocka_unit_test(test_reuse_null_new_host),
    cmocka_unit_test(test_reuse_exact_max_requests),
    cmocka_unit_test(test_reuse_exact_idle_timeout),
};

int main(void)
{
    return cmocka_run_group_tests(tests, NULL, NULL);
}

typedef int pn_nonempty_test_keepalive_t;

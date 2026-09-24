/* Copyright (c) 2024-2026 PubNub Inc. */

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

extern const pn_socket_platform_ops_t pn_posix_socket_ops;

/**
 * @brief Test socket creation and destruction for IPv4.
 */
static void test_socket_create_ipv4(void** state)
{
    (void)state;

    pn_socket_t sock = pn_posix_socket_ops.socket_create(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, PN_AF_INET, 0);

    assert_true(PN_INVALID_SOCKET != sock);

    pn_posix_socket_ops.socket_destroy(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock);
}

/**
 * @brief Test socket creation and destruction for IPv6.
 */
static void test_socket_create_ipv6(void** state)
{
    (void)state;

    pn_socket_t sock = pn_posix_socket_ops.socket_create(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, PN_AF_INET6, 0);

    assert_true(PN_INVALID_SOCKET != sock);

    pn_posix_socket_ops.socket_destroy(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock);
}

/**
 * @brief Test setting a socket to non-blocking mode.
 */
static void test_socket_set_nonblocking(void** state)
{
    (void)state;

    pn_socket_t sock = pn_posix_socket_ops.socket_create(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, PN_AF_INET, 0);

    assert_true(PN_INVALID_SOCKET != sock);

    const int rc = pn_posix_socket_ops.socket_set_nonblocking(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock);

    assert_int_equal(0, rc);

    pn_posix_socket_ops.socket_destroy(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock);
}

/**
 * @brief Test setting keepalive configuration on a socket.
 */
static void test_socket_keepalive(void** state)
{
    (void)state;

    pn_socket_t sock = pn_posix_socket_ops.socket_create(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, PN_AF_INET, 0);

    assert_true(PN_INVALID_SOCKET != sock);

    pubnub_tcp_keepalive_config_t keepalive = PUBNUB_TCP_KEEPALIVE_CONFIG_INIT;
    const int                     rc = pn_posix_socket_ops.socket_set_keepalive(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock, &keepalive);

    assert_int_equal(0, rc);

    pn_posix_socket_ops.socket_destroy(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock);
}

/**
 * @brief Test poll_add and poll_remove operations.
 */
static void test_poll_add_remove(void** state)
{
    (void)state;

    pn_poll_set_t poll_set;
    const int     init_rc = pn_posix_socket_ops.poll_init(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set);

    assert_int_equal(0, init_rc);

    pn_socket_t sock = pn_posix_socket_ops.socket_create(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, PN_AF_INET, 0);

    assert_true(PN_INVALID_SOCKET != sock);

    const int add_rc = pn_posix_socket_ops.poll_add(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops,
        &poll_set,
        sock,
        PN_POLL_READ | PN_POLL_WRITE);

    assert_int_equal(0, add_rc);

    const size_t count_after_add = pn_posix_socket_ops.poll_ready_count(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set);

    const int remove_rc = pn_posix_socket_ops.poll_remove(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set, sock);

    assert_int_equal(0, remove_rc);

    pn_posix_socket_ops.socket_destroy(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, sock);

    pn_posix_socket_ops.poll_deinit(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set);
}

/**
 * @brief Verify poll_wait with an empty poll set sleeps and returns 0.
 */
static void test_poll_wait_empty_set(void** state)
{
    (void)state;

    pn_poll_set_t poll_set;
    assert_int_equal(
        0,
        pn_posix_socket_ops.poll_init(
            (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set));

    /* Empty poll set — should sleep for ~50ms and return 0 (no events). */
    const int rc = pn_posix_socket_ops.poll_wait(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set, 50);

    assert_int_equal(0, rc);
    assert_int_equal(
        0,
        pn_posix_socket_ops.poll_ready_count(
            (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set));

    pn_posix_socket_ops.poll_deinit(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, &poll_set);
}

/**
 * @brief Test DNS server discovery.
 */
static void test_dns_discover(void** state)
{
    (void)state;

    if (!PUBNUB_ENABLE_CUSTOM_DNS
        || NULL == pn_posix_socket_ops.dns_discover_servers) {
        return;
    }

    pn_sockaddr_t servers[8];
    size_t        count = 0;
    const int     rc    = pn_posix_socket_ops.dns_discover_servers(
        (struct pn_socket_platform_ops*)&pn_posix_socket_ops, servers, 8, &count);

    assert_int_equal(0, rc);
    assert_true(count > 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_socket_create_ipv4),
        cmocka_unit_test(test_socket_create_ipv6),
        cmocka_unit_test(test_socket_set_nonblocking),
        cmocka_unit_test(test_socket_keepalive),
        cmocka_unit_test(test_poll_add_remove),
        cmocka_unit_test(test_poll_wait_empty_set),
        cmocka_unit_test(test_dns_discover),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

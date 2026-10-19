/* Copyright (c) 2024-2026 PubNub Inc. */

/*
 * POSIX socket platform ops tests. The pending-connect test needs an
 * overflowed accept queue (Linux only); elsewhere it skips, or fails when
 * PN_TEST_REQUIRE_PENDING=1.
 */

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

extern const pn_socket_platform_ops_t pn_posix_socket_ops;

#define OPS (&pn_posix_socket_ops)

#define PN_TEST_MAX_CLIENTS 8

/**
 * @brief Open a loopback TCP socket bound to an ephemeral port.
 *
 * @param backlog Listen backlog, or a negative value to bind without listening.
 * @param out_addr Receives the bound address in pn_sockaddr_t form.
 * @return Socket fd, or -1 on failure.
 */
static int test_open_loopback(int backlog, pn_sockaddr_t* out_addr)
{
    struct sockaddr_in sa  = {0};
    socklen_t          len = sizeof(sa);
    int                fd  = socket(AF_INET, SOCK_STREAM, 0);

    if (0 > fd) {
        return -1;
    }

    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;

    if (0 != bind(fd, (struct sockaddr*)&sa, sizeof(sa))
        || (0 <= backlog && 0 != listen(fd, backlog))
        || 0 != getsockname(fd, (struct sockaddr*)&sa, &len)) {
        close(fd);
        return -1;
    }

    memset(out_addr, 0, sizeof(*out_addr));
    out_addr->family = PN_AF_INET;
    out_addr->port   = ntohs(sa.sin_port);
    memcpy(out_addr->addr.ipv4, &sa.sin_addr.s_addr, 4);
    return fd;
}

/**
 * @brief Create a non-blocking socket and start a connect to @p addr.
 */
static pn_socket_t test_start_connect(const pn_sockaddr_t* addr, int* out_rc)
{
    pn_socket_t sock = OPS->socket_create(OPS, PN_AF_INET, 0);

    assert_true(PN_INVALID_SOCKET != sock);
    assert_int_equal(0, OPS->socket_set_nonblocking(OPS, sock));
    *out_rc = OPS->socket_connect(OPS, sock, addr);
    return sock;
}

/**
 * @brief Wait for a raw poll event on @p fd.
 *
 * @return Non-zero when any of @p events (or error/hang-up) is reported.
 */
static int test_poll_ready(int fd, short events, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = events, .revents = 0};
    const int     rc  = poll(&pfd, 1, timeout_ms);

    return 0 < rc && 0 != pfd.revents;
}

/**
 * @brief Connect to a loopback listener and wait until the kernel reports it
 * writable. The connection is left in the listener's accept queue.
 */
static pn_socket_t test_connect_established(const pn_sockaddr_t* addr)
{
    int         rc   = 0;
    pn_socket_t sock = test_start_connect(addr, &rc);

    assert_true(0 <= rc);
    assert_true(test_poll_ready((int)sock, POLLOUT, 1000));
    return sock;
}

/**
 * @brief A connect that has completed must report 1.
 */
static void test_posix_ops_check_connect_completed_returns_one(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
    const int     lfd  = test_open_loopback(1, &addr);
    assert_true(0 <= lfd);

    pn_socket_t sock = test_connect_established(&addr);

    assert_int_equal(1, OPS->socket_check_connect(OPS, sock));

    OPS->socket_destroy(OPS, sock);
    close(lfd);
}

/** @brief check_connect on an established socket keeps returning 1. */
static void test_posix_ops_check_connect_connected_is_idempotent(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
    const int     lfd  = test_open_loopback(1, &addr);
    assert_true(0 <= lfd);

    pn_socket_t sock = test_connect_established(&addr);

    for (int i = 0; i < 5; ++i) {
        assert_int_equal(1, OPS->socket_check_connect(OPS, sock));
    }

    OPS->socket_destroy(OPS, sock);
    close(lfd);
}

/**
 * @brief A refused connect reports a negative refused error.
 *
 * BSD stacks drop SYNs to unlistened ports; a closed listener's port is used.
 */
static void test_posix_ops_check_connect_refused_returns_negative(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
#if defined(__linux__)
    const int bfd = test_open_loopback(-1, &addr);
    assert_true(0 <= bfd);
#else
    int bfd = test_open_loopback(0, &addr);
    assert_true(0 <= bfd);
    close(bfd);
    bfd = -1;
#endif

    int         rc   = 0;
    pn_socket_t sock = test_start_connect(&addr, &rc);

    if (0 > rc) {
        assert_int_equal(-ECONNREFUSED, rc);
    } else {
        assert_int_equal(0, rc);
        assert_true(test_poll_ready((int)sock, POLLOUT, 2000));
        rc = OPS->socket_check_connect(OPS, sock);
        assert_int_equal(-ECONNREFUSED, rc);
    }

    OPS->socket_destroy(OPS, sock);
    if (0 <= bfd) {
        close(bfd);
    }
}

/**
 * @brief A connection reset by the peer after establishment reports an error.
 *
 * The server closes with SO_LINGER {1, 0} so the kernel sends RST, not FIN.
 */
static void test_posix_ops_check_connect_peer_reset_returns_negative(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
    const int     lfd  = test_open_loopback(1, &addr);
    assert_true(0 <= lfd);

    pn_socket_t sock = test_connect_established(&addr);
    assert_int_equal(1, OPS->socket_check_connect(OPS, sock));

    assert_true(test_poll_ready(lfd, POLLIN, 1000));
    const int afd = accept(lfd, NULL, NULL);
    assert_true(0 <= afd);

    const struct linger lg = {.l_onoff = 1, .l_linger = 0};
    assert_int_equal(0, setsockopt(afd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)));
    close(afd);

    assert_true(test_poll_ready((int)sock, POLLIN, 2000));
    assert_true(0 > OPS->socket_check_connect(OPS, sock));

    OPS->socket_destroy(OPS, sock);
    close(lfd);
}

#if defined(__linux__)
/** @brief Fail (PN_TEST_REQUIRE_PENDING=1) or skip: no pending socket. */
static void test_pending_unavailable(const char* reason)
{
    const char* require = getenv("PN_TEST_REQUIRE_PENDING");

    if (NULL != require && 0 == strcmp("1", require)) {
        fail_msg("PN_TEST_REQUIRE_PENDING=1 but no pending socket: %s", reason);
    }
    print_message("skip reason: %s\n", reason);
    skip();
}

/**
 * @brief Whether the kernel resets (instead of dropping) overflowing SYNs.
 */
static int test_tcp_abort_on_overflow(void)
{
    char  buf[8] = {0};
    FILE* fp     = fopen("/proc/sys/net/ipv4/tcp_abort_on_overflow", "r");

    if (NULL == fp) {
        return 0;
    }
    if (NULL == fgets(buf, (int)sizeof(buf), fp)) {
        buf[0] = '\0';
    }
    fclose(fp);
    return '1' == buf[0];
}
#endif

/** @brief A connect still in flight must report 0, not "connected". */
static void test_posix_ops_check_connect_pending_returns_zero(void** state)
{
    (void)state;

#if defined(__linux__)
    pn_sockaddr_t addr = {0};
    pn_socket_t   clients[PN_TEST_MAX_CLIENTS];
    pn_socket_t   pending = PN_INVALID_SOCKET;
    size_t        count   = 0;

    if (test_tcp_abort_on_overflow()) {
        test_pending_unavailable("tcp_abort_on_overflow=1: overflowing SYNs "
                                 "are reset instead of dropped");
        return;
    }

    const int lfd = test_open_loopback(0, &addr);
    assert_true(0 <= lfd);

    while (count < PN_TEST_MAX_CLIENTS && PN_INVALID_SOCKET == pending) {
        int         rc = 0;
        pn_socket_t s  = test_start_connect(&addr, &rc);

        clients[count++] = s;
        if (0 == rc && !test_poll_ready((int)s, POLLOUT, 50)) {
            pending = s;
        }
    }

    if (PN_INVALID_SOCKET == pending) {
        for (size_t i = 0; i < count; ++i) {
            OPS->socket_destroy(OPS, clients[i]);
        }
        close(lfd);
        test_pending_unavailable("accept-queue overflow did not leave a "
                                 "connect pending");
        return;
    }

    const int first  = OPS->socket_check_connect(OPS, pending);
    const int second = OPS->socket_check_connect(OPS, pending);

    for (size_t i = 0; i < count; ++i) {
        OPS->socket_destroy(OPS, clients[i]);
    }
    close(lfd);

    assert_int_equal(0, first);
    assert_int_equal(0, second);
#else
    print_message("skip reason: no deterministic way to leave a loopback "
                  "connect pending on this platform\n");
    skip();
#endif
}

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
        cmocka_unit_test(test_posix_ops_check_connect_completed_returns_one),
        cmocka_unit_test(test_posix_ops_check_connect_connected_is_idempotent),
        cmocka_unit_test(test_posix_ops_check_connect_refused_returns_negative),
        cmocka_unit_test(test_posix_ops_check_connect_peer_reset_returns_negative),
        cmocka_unit_test(test_posix_ops_check_connect_pending_returns_zero),
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

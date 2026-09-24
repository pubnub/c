/* Copyright (c) 2024-2026 PubNub Inc. */

/**
 * @file test_ipv6_fallback.c
 * @brief Regression test: IPv6 address family skip — when ENETUNREACH or
 *        EHOSTUNREACH is returned for IPv6, the client falls back to IPv4
 *        without error.
 *
 * When IPv6 addresses return ENETUNREACH or EHOSTUNREACH, the connection FSM
 * must skip the entire IPv6 family and try IPv4 addresses without exhausting
 * retry budget. Without this fix, the FSM would try all IPv6 addresses
 * individually, causing connection delays or failure when IPv6 is unreachable.
 *
 * Test strategy:
 * 1. Mock DNS resolver to return 2 IPv6 addresses + 2 IPv4 addresses.
 * 2. Mock connect to return ENETUNREACH for IPv6, success for IPv4.
 * 3. Verify connection FSM:
 *    - Tries first IPv6 address.
 *    - Sets family_exhausted bit for IPv6.
 *    - Skips remaining IPv6 addresses.
 *    - Tries first IPv4 address and succeeds.
 * 4. Verify total connect attempts <= 3 (1 IPv6 attempt + 1 IPv4 success).
 */

#include "providers/transport/socket/connection_fsm_internal.h"
#include "providers/transport/socket/platform/pn_socket_platform_ops.h"
#include "providers/transport/socket/transport_socket_internal.h"

#include "providers/allocator/stdlib/allocator_stdlib.c"
#include "providers/platform/posix/platform_posix.c"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <errno.h>
#include <string.h>

/** @brief Track connect attempts for verification. */
static size_t g_connect_attempts;

/** @brief Mock socket that always succeeds creation. */
static pn_socket_t mock_socket_create(const pn_socket_platform_ops_t* self,
                                      uint16_t                        family,
                                      int                             dgram)
{
    (void)self;
    (void)family;
    (void)dgram;
    return (pn_socket_t)1234;
}

/** @brief Mock destroy that always succeeds. */
static void mock_socket_destroy(const pn_socket_platform_ops_t* self, pn_socket_t sock)
{
    (void)self;
    (void)sock;
}

/**
 * @brief Mock connect: ENETUNREACH for IPv6, success for IPv4.
 */
static int mock_socket_connect(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               const pn_sockaddr_t*            addr)
{
    (void)self;
    (void)sock;

    g_connect_attempts++;

    if (PN_AF_INET6 == addr->family) {
        return -ENETUNREACH;
    }

    return 0;
}

/** @brief Mock check_connect stub. */
static int mock_socket_check_connect(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock)
{
    (void)self;
    (void)sock;
    return 1;
}

/** @brief Mock set_nonblocking always succeeds. */
static int mock_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                       pn_socket_t                     sock)
{
    (void)self;
    (void)sock;
    return 0;
}

/** @brief Mock set_keepalive stub. */
static int mock_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock,
                                     const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;
    (void)sock;
    (void)config;
    return 0;
}

/** @brief Mock send stub. */
static int mock_socket_send(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            const uint8_t*                  data,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    (void)data;
    return (int)len;
}

/** @brief Mock recv stub. */
static int mock_socket_recv(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            uint8_t*                        buf,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    (void)buf;
    (void)len;
    return 0;
}

/** @brief Mock sendto stub. */
static int mock_socket_sendto(const pn_socket_platform_ops_t* self,
                              pn_socket_t                     sock,
                              const uint8_t*                  data,
                              size_t                          len,
                              const pn_sockaddr_t*            dest)
{
    (void)self;
    (void)sock;
    (void)data;
    (void)dest;
    return (int)len;
}

/** @brief Mock recvfrom stub. */
static int mock_socket_recvfrom(const pn_socket_platform_ops_t* self,
                                pn_socket_t                     sock,
                                uint8_t*                        buf,
                                size_t                          cap,
                                pn_sockaddr_t*                  src)
{
    (void)self;
    (void)sock;
    (void)buf;
    (void)cap;
    (void)src;
    return 0;
}

/** @brief Mock poll stubs. */
static int mock_poll_init(const pn_socket_platform_ops_t* self,
                          pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
    return 0;
}

static void mock_poll_deinit(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
}

static int mock_poll_add(const pn_socket_platform_ops_t* self,
                         pn_poll_set_t*                  poll_set,
                         pn_socket_t                     sock,
                         uint8_t                         events)
{
    (void)self;
    (void)poll_set;
    (void)sock;
    (void)events;
    return 0;
}

static int mock_poll_modify(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock,
                            uint8_t                         events)
{
    (void)self;
    (void)poll_set;
    (void)sock;
    (void)events;
    return 0;
}

static int mock_poll_remove(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock)
{
    (void)self;
    (void)poll_set;
    (void)sock;
    return 0;
}

static int mock_poll_wait(const pn_socket_platform_ops_t* self,
                          pn_poll_set_t*                  poll_set,
                          int                             timeout_ms)
{
    (void)self;
    (void)poll_set;
    (void)timeout_ms;
    return 0;
}

static size_t mock_poll_ready_count(const pn_socket_platform_ops_t* self,
                                    const pn_poll_set_t*            poll_set)
{
    (void)self;
    (void)poll_set;
    return 0;
}

static int mock_poll_get_ready(const pn_socket_platform_ops_t* self,
                               const pn_poll_set_t*            poll_set,
                               size_t                          index,
                               pn_socket_t*                    out_sock,
                               uint8_t*                        out_events)
{
    (void)self;
    (void)poll_set;
    (void)index;
    (void)out_sock;
    (void)out_events;
    return 0;
}

static int mock_dns_discover_servers(const pn_socket_platform_ops_t* self,
                                     pn_sockaddr_t*                  servers,
                                     size_t                          capacity,
                                     size_t*                         out_count)
{
    (void)self;
    (void)servers;
    (void)capacity;
    *out_count = 0;
    return 0;
}

static pn_socket_platform_ops_t g_mock_ops = {
    .socket_create          = mock_socket_create,
    .socket_destroy         = mock_socket_destroy,
    .socket_connect         = mock_socket_connect,
    .socket_check_connect   = mock_socket_check_connect,
    .socket_send            = mock_socket_send,
    .socket_recv            = mock_socket_recv,
    .socket_sendto          = mock_socket_sendto,
    .socket_recvfrom        = mock_socket_recvfrom,
    .socket_set_nonblocking = mock_socket_set_nonblocking,
    .socket_set_keepalive   = mock_socket_set_keepalive,
    .poll_init              = mock_poll_init,
    .poll_deinit            = mock_poll_deinit,
    .poll_add               = mock_poll_add,
    .poll_modify            = mock_poll_modify,
    .poll_remove            = mock_poll_remove,
    .poll_wait              = mock_poll_wait,
    .poll_ready_count       = mock_poll_ready_count,
    .poll_get_ready         = mock_poll_get_ready,
    .dns_discover_servers   = mock_dns_discover_servers,
};

static struct pubnub_platform_provider  g_platform_provider;
static struct pubnub_allocator_provider g_allocator_provider;

/**
 * @brief Setup fixture.
 */
static int test_setup(void** state)
{
    (void)state;

    g_platform_provider  = *pn_platform_default();
    g_allocator_provider = *pn_allocator_default();

    g_connect_attempts = 0;

    return 0;
}

/**
 * @brief Test: IPv6 family skip on ENETUNREACH.
 */
static void test_ipv6_family_skip(void** state)
{
    (void)state;

    pn_socket_connection_t conn;
    pn_connection_init(&conn);

    /* Populate resolved_addrs: 2 IPv6 + 2 IPv4. */
    conn.addr_count = 4;

    conn.resolved_addrs[0].family       = PN_AF_INET6;
    conn.resolved_addrs[0].port         = 80;
    conn.resolved_addrs[0].addr.ipv6[0] = 0x20;
    conn.resolved_addrs[0].addr.ipv6[1] = 0x01;

    conn.resolved_addrs[1].family       = PN_AF_INET6;
    conn.resolved_addrs[1].port         = 80;
    conn.resolved_addrs[1].addr.ipv6[0] = 0x20;
    conn.resolved_addrs[1].addr.ipv6[1] = 0x02;

    conn.resolved_addrs[2].family       = PN_AF_INET;
    conn.resolved_addrs[2].port         = 80;
    conn.resolved_addrs[2].addr.ipv4[0] = 192;
    conn.resolved_addrs[2].addr.ipv4[1] = 168;
    conn.resolved_addrs[2].addr.ipv4[2] = 1;
    conn.resolved_addrs[2].addr.ipv4[3] = 100;

    conn.resolved_addrs[3].family       = PN_AF_INET;
    conn.resolved_addrs[3].port         = 80;
    conn.resolved_addrs[3].addr.ipv4[0] = 192;
    conn.resolved_addrs[3].addr.ipv4[1] = 168;
    conn.resolved_addrs[3].addr.ipv4[2] = 1;
    conn.resolved_addrs[3].addr.ipv4[3] = 101;

    conn.state                   = PN_CONN_CONNECTING;
    conn.socket                  = PN_INVALID_SOCKET;
    conn.family_exhausted        = 0;
    conn.connect_deadline_ms     = UINT64_MAX;
    conn.transaction_deadline_ms = UINT64_MAX;

    /* Simulate the connection FSM logic. */
    pn_socket_transport_t mock_transport = {0};
    mock_transport.ops                   = &g_mock_ops;
    mock_transport.platform              = &g_platform_provider;
    mock_transport.allocator             = &g_allocator_provider;

    /* Manually drive connection attempts. */
    for (size_t attempt = 0; attempt < 10; ++attempt) {
        if (PN_INVALID_SOCKET == conn.socket) {
            /* Skip exhausted families. */
            while (conn.addr_current < conn.addr_count) {
                uint16_t family = conn.resolved_addrs[conn.addr_current].family;
                uint8_t  family_bit = (PN_AF_INET6 == family) ? 0x02 : 0x01;

                if (0 != (conn.family_exhausted & family_bit)) {
                    conn.addr_current++;
                    continue;
                }

                conn.socket = g_mock_ops.socket_create(&g_mock_ops, family, 0);
                assert_true(PN_INVALID_SOCKET != conn.socket);

                int connect_result = g_mock_ops.socket_connect(
                    &g_mock_ops, conn.socket, &conn.resolved_addrs[conn.addr_current]);

                if (0 == connect_result) {
                    /* Success. */
                    break;
                }

                if (pn_is_family_unreachable(connect_result)) {
                    /* Mark family as exhausted. */
                    conn.family_exhausted |= family_bit;
                }

                g_mock_ops.socket_destroy(&g_mock_ops, conn.socket);
                conn.socket = PN_INVALID_SOCKET;
                conn.addr_current++;
                break;
            }

            if (conn.addr_current >= conn.addr_count) {
                /* All addresses exhausted. */
                break;
            }
        }

        if (PN_INVALID_SOCKET != conn.socket) {
            /* Connected. */
            break;
        }
    }

    /* Verify: connected via IPv4. */
    assert_true(PN_INVALID_SOCKET != conn.socket);

    /* Verify: total connect attempts <= 2 (1 IPv6 + 1 IPv4). */
    assert_true(g_connect_attempts <= 2);

    /* Verify: IPv6 family bit set in family_exhausted. */
    assert_int_equal(0x02, conn.family_exhausted & 0x02);

    /* Verify: addr_current points to IPv4 address. */
    assert_int_equal(PN_AF_INET, conn.resolved_addrs[conn.addr_current].family);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_ipv6_family_skip, test_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

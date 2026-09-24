/* Copyright (c) 2024-2026 PubNub Inc. */

#include "providers/transport/socket/dns/dns_resolver.h"

#include "mock/mock_dns_server.h"
#include "providers/platform/posix/platform_posix.c"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <unistd.h>

static struct pubnub_platform_provider g_platform_provider;

/* pn_posix_socket_ops is defined in posix_socket_ops.c (part of
 * pubnub_provider_transport). Declare it extern so this test TU can
 * reference it without pulling in the whole implementation file. */
extern const pn_socket_platform_ops_t pn_posix_socket_ops;

/**
 * @brief Setup fixture for each test.
 *
 * Initializes the POSIX platform provider and socket ops.
 */
static int test_setup(void** state)
{
    (void)state;

    g_platform_provider = *pn_platform_default();

    return 0;
}

/**
 * @brief Teardown fixture for each test.
 */
static int test_teardown(void** state)
{
    (void)state;
    return 0;
}

/**
 * @brief Override the DNS server list with a specific server and mark it valid.
 *
 * Must be called before pn_dns_resolver_start to prevent the automatic
 * server refresh from overwriting the mock server address.
 */
static void resolver_override_server_(pn_dns_resolver_t* resolver, uint16_t port)
{
    resolver->servers[0].family       = PN_AF_INET;
    resolver->servers[0].port         = port;
    resolver->servers[0].addr.ipv4[0] = 127;
    resolver->servers[0].addr.ipv4[1] = 0;
    resolver->servers[0].addr.ipv4[2] = 0;
    resolver->servers[0].addr.ipv4[3] = 1;
    resolver->server_count            = 1;
    /* Mark valid so start() doesn't refresh servers from /etc/resolv.conf. */
    resolver->server_list_invalid = 0;
    resolver->server_list_timestamp_ms =
        g_platform_provider.monotonic_ms(&g_platform_provider);
}

/**
 * @brief Test: resolve a hostname and verify results are cached.
 */
static void test_resolve_cached(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    assert_int_equal(0, mock_dns_server_start(&mock));

    uint32_t a_addr = htonl(0x08080808);
    mock_dns_server_set_response(&mock, "test.example.com", a_addr, NULL, 60);

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    resolver_override_server_(&resolver, mock_dns_server_port(&mock));

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    pn_dns_state_t state_before = pn_dns_resolver_state(&resolver);
    assert_true(PN_DNS_STATE_IDLE != state_before);

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_sockaddr_t addrs[8];
    size_t        count = 0;
    assert_int_equal(0, pn_dns_resolver_get_results(&resolver, addrs, 8, &count));
    assert_true(count > 0);
    assert_int_equal(PN_AF_INET, addrs[0].family);

    resolver.state = PN_DNS_STATE_IDLE;

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    size_t count2 = 0;
    assert_int_equal(0, pn_dns_resolver_get_results(&resolver, addrs, 8, &count2));
    assert_int_equal(count, count2);

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

/**
 * @brief Test: resolve, advance time past TTL, resolve again.
 */
static void test_resolve_cache_expiry(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    assert_int_equal(0, mock_dns_server_start(&mock));

    uint32_t a_addr = htonl(0x08080808);
    mock_dns_server_set_response(&mock, "test.example.com", a_addr, NULL, 1);

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    resolver_override_server_(&resolver, mock_dns_server_port(&mock));

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    sleep(2);

    resolver.state = PN_DNS_STATE_IDLE;
    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    assert_int_not_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

/**
 * @brief Test: resolve, invalidate, resolve again → new query.
 */
static void test_resolve_invalidate(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    assert_int_equal(0, mock_dns_server_start(&mock));

    uint32_t a_addr = htonl(0x08080808);
    mock_dns_server_set_response(&mock, "test.example.com", a_addr, NULL, 60);

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    resolver_override_server_(&resolver, mock_dns_server_port(&mock));

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_dns_resolver_invalidate(&resolver, "test.example.com");

    /* Re-apply mock server: invalidate() resets server_list_invalid=1 so
     * that network-change detection re-discovers servers. Re-pin the mock. */
    resolver_override_server_(&resolver, mock_dns_server_port(&mock));

    resolver.state = PN_DNS_STATE_IDLE;
    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    assert_int_not_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

/**
 * @brief Test: first server timeout, second server responds → success.
 */
static void test_resolve_server_rotation(void** state)
{
    (void)state;

    mock_dns_server_t mock1;
    assert_int_equal(0, mock_dns_server_start(&mock1));
    mock_dns_server_set_silent(&mock1, 1);

    mock_dns_server_t mock2;
    assert_int_equal(0, mock_dns_server_start(&mock2));
    uint32_t a_addr = htonl(0x01010101);
    mock_dns_server_set_response(&mock2, "test.example.com", a_addr, NULL, 60);

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    resolver.servers[0].family       = PN_AF_INET;
    resolver.servers[0].port         = mock_dns_server_port(&mock1);
    resolver.servers[0].addr.ipv4[0] = 127;
    resolver.servers[0].addr.ipv4[1] = 0;
    resolver.servers[0].addr.ipv4[2] = 0;
    resolver.servers[0].addr.ipv4[3] = 1;

    resolver.servers[1].family       = PN_AF_INET;
    resolver.servers[1].port         = mock_dns_server_port(&mock2);
    resolver.servers[1].addr.ipv4[0] = 127;
    resolver.servers[1].addr.ipv4[1] = 0;
    resolver.servers[1].addr.ipv4[2] = 0;
    resolver.servers[1].addr.ipv4[3] = 1;

    resolver.server_count        = 2;
    resolver.server_list_invalid = 0;
    resolver.server_list_timestamp_ms =
        g_platform_provider.monotonic_ms(&g_platform_provider);

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s || PN_DNS_STATE_FAILED == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_sockaddr_t addrs[8];
    size_t        count = 0;
    assert_int_equal(0, pn_dns_resolver_get_results(&resolver, addrs, 8, &count));
    assert_true(count > 0);

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock1);
    mock_dns_server_stop(&mock2);
}

/**
 * @brief Test: all servers timeout → FAILED state.
 */
static void test_resolve_all_servers_fail(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    assert_int_equal(0, mock_dns_server_start(&mock));
    mock_dns_server_set_silent(&mock, 1);

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    resolver_override_server_(&resolver, mock_dns_server_port(&mock));

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    for (int i = 0; i < 300; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s || PN_DNS_STATE_FAILED == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_FAILED, pn_dns_resolver_state(&resolver));

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

/**
 * @brief Test: verify A and AAAA queries have different transaction IDs.
 */
static void test_unique_txn_ids(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    assert_int_equal(0, mock_dns_server_start(&mock));

    uint32_t a_addr        = htonl(0x08080808);
    uint8_t  aaaa_addr[16] = {
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88};
    mock_dns_server_set_response(&mock, "test.example.com", a_addr, aaaa_addr, 60);

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    resolver_override_server_(&resolver, mock_dns_server_port(&mock));

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    assert_int_not_equal(resolver.txn_id_a, resolver.txn_id_aaaa);

    for (int i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

#if PUBNUB_TEST_NETWORK

/**
 * @brief Live integration test: dual-stack resolution of h2.pubnubapi.com.
 *
 * Queries the real system DNS server for h2.pubnubapi.com and verifies that
 * the resolver returns at least one IPv4 (A) address and at least one IPv6
 * (AAAA) address — confirming the full encode → send → receive → decode
 * pipeline works end-to-end for dual-stack hosts.
 *
 * Only runs when PUBNUB_TEST_NETWORK=ON (requires outbound internet access).
 */
static void test_resolve_dual_stack_live(void** state)
{
    (void)state;

    pn_dns_resolver_t resolver;
    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    /* Use the real system DNS servers (populated by pn_dns_resolver_init
     * via dns_discover_servers). Do NOT call resolver_override_server_ here
     * so that the real /etc/resolv.conf or equivalent is used. */

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "h2.pubnubapi.com"));

    /* Drive the resolver for up to 5 seconds (500 × 10 ms). */
    for (int i = 0; i < 500; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s || PN_DNS_STATE_FAILED == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    pn_sockaddr_t addrs[16];
    size_t        count = 0;
    assert_int_equal(0, pn_dns_resolver_get_results(&resolver, addrs, 16, &count));

    /* h2.pubnubapi.com has both A and AAAA records; verify at least one of each. */
    int has_ipv4 = 0;
    int has_ipv6 = 0;
    for (size_t i = 0; i < count; ++i) {
        if (PN_AF_INET == addrs[i].family) {
            has_ipv4 = 1;
        } else if (PN_AF_INET6 == addrs[i].family) {
            has_ipv6 = 1;
        }
    }

    assert_true(count > 0);
    assert_true(has_ipv4);
    assert_true(has_ipv6);

    pn_dns_resolver_deinit(&resolver);
}

#endif /* PUBNUB_TEST_NETWORK */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_resolve_cached, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_resolve_cache_expiry, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_resolve_invalidate, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_resolve_server_rotation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_resolve_all_servers_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_unique_txn_ids, test_setup, test_teardown),
#if PUBNUB_TEST_NETWORK
        cmocka_unit_test_setup_teardown(
            test_resolve_dual_stack_live, test_setup, test_teardown),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

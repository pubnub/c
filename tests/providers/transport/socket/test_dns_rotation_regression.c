/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "providers/transport/socket/dns/dns_resolver.h"

#include "mock/mock_dns_server.h"
#include "providers/platform/posix/platform_posix.c"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <unistd.h>

/**
 * @file test_dns_rotation_regression.c
 * @brief Regression guard for DNS server-rotation termination.
 *
 * A legacy resolver design tracked server rotation with a family-dependent
 * bitmask whose "exhausted" sentinel was unreachable on an IPv4-only host, so
 * rotation never terminated and the resolver looped forever. The next-gen
 * resolver rotates with a plain array index: tick_rotating increments
 * current_server_idx and declares FAILED once it reaches server_count. That is
 * family-independent and always reaches the terminal state.
 *
 * These tests configure IPv4-only servers (the exact condition that defeated
 * the legacy sentinel) and lock in that rotation:
 *   - advances the index by exactly one per rotation,
 *   - never wraps past or exceeds server_count,
 *   - reaches FAILED after exactly server_count advances,
 *   - resets to index 0 on the next resolution (no cross-attempt leakage),
 *   - and does not rotate at all when the first server answers.
 *
 * These tests assert the resolver-level terminal state (FAILED). The end-to-end
 * consequence — a FAILED resolver ending the transaction with a transport error
 * and releasing the shared resolver back to IDLE so a later connection can
 * retry — is asserted one layer up by the connection state-machine's
 * DNS-failure test.
 */

static struct pubnub_platform_provider g_platform_provider;

/* pn_posix_socket_ops is defined in posix_socket_ops.c (part of
 * pubnub_provider_transport). Declare it extern so this test TU can
 * reference it without pulling in the whole implementation file. */
extern const pn_socket_platform_ops_t pn_posix_socket_ops;

/**
 * @brief Setup fixture: initialize the POSIX platform provider.
 */
static int test_setup(void** state)
{
    (void)state;

    g_platform_provider = *pn_platform_default();

    return 0;
}

/**
 * @brief Teardown fixture.
 */
static int test_teardown(void** state)
{
    (void)state;
    return 0;
}

/**
 * @brief Populate one resolver server slot with a 127.0.0.1 IPv4 address.
 *
 * @param resolver Resolver instance.
 * @param idx      Server slot index.
 * @param port     UDP port (host byte order).
 */
static void set_ipv4_server_(pn_dns_resolver_t* resolver, size_t idx, uint16_t port)
{
    resolver->servers[idx].family       = PN_AF_INET;
    resolver->servers[idx].port         = port;
    resolver->servers[idx].addr.ipv4[0] = 127;
    resolver->servers[idx].addr.ipv4[1] = 0;
    resolver->servers[idx].addr.ipv4[2] = 0;
    resolver->servers[idx].addr.ipv4[3] = 1;
}

/**
 * @brief Pin the resolver server list so start() does not re-discover servers.
 *
 * @param resolver Resolver instance.
 * @param count    Active server count.
 */
static void pin_servers_valid_(pn_dns_resolver_t* resolver, size_t count)
{
    resolver->server_count        = count;
    resolver->server_list_invalid = 0;
    resolver->server_list_timestamp_ms =
        g_platform_provider.monotonic_ms(&g_platform_provider);
}

/**
 * @brief Force the current server to time out and drive one rotation decision.
 *
 * Pushes the query deadline into the past so the WAITING state times out on the
 * next tick, then ticks twice: once to enter ROTATING, once to let
 * tick_rotating advance the server index (or declare FAILED). This keeps the
 * rotation deterministic and instantaneous instead of waiting for the real
 * per-server UDP timeout.
 *
 * @param resolver Resolver instance (state QUERY_SENT for the current server).
 * @return State after the rotation decision (QUERY_SENT for the next server,
 *         or FAILED once the last server is exhausted).
 */
static pn_dns_state_t force_rotate_once_(pn_dns_resolver_t* resolver)
{
    pn_dns_state_t waited;

    resolver->deadline_ms = 0;

    waited = pn_dns_resolver_tick(resolver);
    assert_int_equal(PN_DNS_STATE_ROTATING, waited);

    return pn_dns_resolver_tick(resolver);
}

/**
 * @brief Test: a responding first server reaches DONE without any rotation.
 *
 * Locks in that the happy path costs zero index advances — the immunity fix
 * must not have turned every resolution into a rotation walk.
 */
static void test_first_server_responds_no_rotation(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    pn_dns_resolver_t resolver;
    pn_sockaddr_t     addrs[8];
    size_t            count = 0;
    int               i;

    assert_int_equal(0, mock_dns_server_start(&mock));
    mock_dns_server_set_response(
        &mock, "test.example.com", htonl(0x08080808), NULL, 60);

    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    set_ipv4_server_(&resolver, 0, mock_dns_server_port(&mock));
    pin_servers_valid_(&resolver, 1);

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    for (i = 0; i < 400; ++i) {
        pn_dns_state_t s = pn_dns_resolver_tick(&resolver);
        if (PN_DNS_STATE_DONE == s) {
            break;
        }
        usleep(10000);
    }

    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));
    assert_int_equal(0, (int)resolver.current_server_idx);

    assert_int_equal(0, pn_dns_resolver_get_results(&resolver, addrs, 8, &count));
    assert_true(count > 0);
    assert_int_equal(PN_AF_INET, addrs[0].family);

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

/**
 * @brief Test: a single dead server exhausts to FAILED after one advance.
 *
 * Boundary N=1: the index reaches server_count (1) exactly once and stops.
 */
static void test_single_server_exhausts_after_one_advance(void** state)
{
    (void)state;

    mock_dns_server_t mock;
    pn_dns_resolver_t resolver;

    assert_int_equal(0, mock_dns_server_start(&mock));
    mock_dns_server_set_silent(&mock, 1);

    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    set_ipv4_server_(&resolver, 0, mock_dns_server_port(&mock));
    pin_servers_valid_(&resolver, 1);

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));
    assert_int_equal(0, (int)resolver.current_server_idx);

    assert_int_equal(PN_DNS_STATE_FAILED, force_rotate_once_(&resolver));
    assert_int_equal(1, (int)resolver.current_server_idx);
    assert_int_equal((int)resolver.server_count, (int)resolver.current_server_idx);

    pn_dns_resolver_deinit(&resolver);
    mock_dns_server_stop(&mock);
}

/**
 * @brief Test: N dead IPv4 servers exhaust to FAILED after exactly N advances.
 *
 * This is the core regression: on an IPv4-only configuration where every
 * server times out, rotation must terminate. The index advances by exactly one
 * per rotation, never wraps, equals server_count at FAILED, and a further tick
 * in FAILED is a no-op that does not re-arm rotation.
 */
static void test_rotation_exhausts_to_failed(void** state)
{
    (void)state;

    const size_t      server_count = 3;
    mock_dns_server_t mocks[3];
    pn_dns_resolver_t resolver;
    size_t            i;

    for (i = 0; i < server_count; ++i) {
        assert_int_equal(0, mock_dns_server_start(&mocks[i]));
        mock_dns_server_set_silent(&mocks[i], 1);
    }

    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    for (i = 0; i < server_count; ++i) {
        set_ipv4_server_(&resolver, i, mock_dns_server_port(&mocks[i]));
    }
    pin_servers_valid_(&resolver, server_count);

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));
    assert_int_equal(PN_DNS_STATE_QUERY_SENT, pn_dns_resolver_state(&resolver));
    assert_int_equal(0, (int)resolver.current_server_idx);

    for (i = 0; i < server_count; ++i) {
        pn_dns_state_t s = force_rotate_once_(&resolver);

        /* Exactly one advance per rotation; index never wraps or overruns. */
        assert_int_equal((int)(i + 1), (int)resolver.current_server_idx);
        assert_true(resolver.current_server_idx <= resolver.server_count);

        if (i + 1 < server_count) {
            assert_int_equal(PN_DNS_STATE_QUERY_SENT, s);
        } else {
            assert_int_equal(PN_DNS_STATE_FAILED, s);
        }
    }

    assert_int_equal(PN_DNS_STATE_FAILED, pn_dns_resolver_state(&resolver));
    assert_int_equal((int)server_count, (int)resolver.current_server_idx);

    /* A tick in FAILED must stay terminal and must not re-arm rotation. */
    assert_int_equal(PN_DNS_STATE_FAILED, pn_dns_resolver_tick(&resolver));
    assert_int_equal(PN_DNS_STATE_FAILED, pn_dns_resolver_state(&resolver));
    assert_int_equal((int)server_count, (int)resolver.current_server_idx);

    pn_dns_resolver_deinit(&resolver);
    for (i = 0; i < server_count; ++i) {
        mock_dns_server_stop(&mocks[i]);
    }
}

/**
 * @brief Test: a fresh resolution restarts at index 0 after a failed attempt.
 *
 * After rotation exhausts to FAILED, the next start() must reset
 * current_server_idx to 0 so a prior attempt's exhausted index cannot leak in
 * and skip servers or short-circuit to FAILED.
 */
static void test_start_resets_index_after_failure(void** state)
{
    (void)state;

    const size_t      server_count = 2;
    mock_dns_server_t mocks[2];
    pn_dns_resolver_t resolver;
    size_t            i;

    for (i = 0; i < server_count; ++i) {
        assert_int_equal(0, mock_dns_server_start(&mocks[i]));
        mock_dns_server_set_silent(&mocks[i], 1);
    }

    assert_int_equal(
        0,
        pn_dns_resolver_init(&resolver,
                             (pn_socket_platform_ops_t*)&pn_posix_socket_ops,
                             &g_platform_provider));

    for (i = 0; i < server_count; ++i) {
        set_ipv4_server_(&resolver, i, mock_dns_server_port(&mocks[i]));
    }
    pin_servers_valid_(&resolver, server_count);

    assert_int_equal(0, pn_dns_resolver_start(&resolver, "test.example.com"));

    for (i = 0; i < server_count; ++i) {
        force_rotate_once_(&resolver);
    }

    assert_int_equal(PN_DNS_STATE_FAILED, pn_dns_resolver_state(&resolver));
    assert_int_equal((int)server_count, (int)resolver.current_server_idx);

    /* Second resolution: reset to IDLE (as the fsm does on DNS failure) and
     * start fresh. The index must return to 0. */
    resolver.state = PN_DNS_STATE_IDLE;
    assert_int_equal(0, pn_dns_resolver_start(&resolver, "other.example.com"));
    assert_int_equal(0, (int)resolver.current_server_idx);
    assert_int_not_equal(PN_DNS_STATE_FAILED, pn_dns_resolver_state(&resolver));
    assert_int_not_equal(PN_DNS_STATE_IDLE, pn_dns_resolver_state(&resolver));

    pn_dns_resolver_deinit(&resolver);
    for (i = 0; i < server_count; ++i) {
        mock_dns_server_stop(&mocks[i]);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_first_server_responds_no_rotation, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_single_server_exhausts_after_one_advance, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_rotation_exhausts_to_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_start_resets_index_after_failure, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

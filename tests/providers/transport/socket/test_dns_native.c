/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "dns_resolver.h"

#include <cmocka.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

extern const pn_socket_platform_ops_t pn_posix_socket_ops;

static int pn_test_addr_is_valid(const pn_sockaddr_t* addr)
{
    if (PN_AF_INET == addr->family) {
        uint8_t all_zero[4]  = {0, 0, 0, 0};
        uint8_t broadcast[4] = {255, 255, 255, 255};
        if (0 == memcmp(addr->addr.ipv4, all_zero, 4)) {
            return 0;
        }
        if (0 == memcmp(addr->addr.ipv4, broadcast, 4)) {
            return 0;
        }
        return 1;
    }
    if (PN_AF_INET6 == addr->family) {
        uint8_t all_zero[16] = {0};
        return 0 != memcmp(addr->addr.ipv6, all_zero, 16);
    }
    return 0;
}

static void drive_resolver_to_completion(pn_dns_resolver_t* resolver)
{
    int max_ticks = 500;
    while (PN_DNS_STATE_DONE != resolver->state
           && PN_DNS_STATE_FAILED != resolver->state && max_ticks-- > 0) {
        struct timespec ts = {0, 10000000}; /* 10ms */
        nanosleep(&ts, NULL);
        pn_dns_resolver_tick(resolver);
    }
}

static uint64_t mock_monotonic_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int mock_random_bytes(struct pubnub_platform_provider* self,
                             uint8_t*                         buf,
                             size_t                           len)
{
    (void)self;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i ^ 0xAB);
    }
    return 0;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic_ms,
    .sleep_ms      = NULL,
    .random_bytes  = mock_random_bytes,
    .secure_zero   = NULL,
    .lock_size     = NULL,
    .lock_init     = NULL,
    .lock_destroy  = NULL,
    .lock_acquire  = NULL,
    .lock_release  = NULL,
    .thread_create = NULL,
    .thread_join   = NULL,
    .file_load     = NULL,
};

static void test_native_dns_resolves_localhost(void** state)
{
    (void)state;

    const pn_socket_platform_ops_t* ops = &pn_posix_socket_ops;

    union {
        uint8_t  raw[PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE];
        void*    _align_ptr;
        uint64_t _align_u64;
    } dns_ctx = {0};

    assert_non_null(ops->dns_resolve_start);
    assert_non_null(ops->dns_resolve_poll);
    assert_non_null(ops->dns_resolve_get_results);

    int rc = ops->dns_resolve_start(ops, &dns_ctx, "localhost", 5000);
    assert_int_equal(0, rc);

    int poll_rc = 0;
    for (int i = 0; i < 100; ++i) {
        poll_rc = ops->dns_resolve_poll(ops, &dns_ctx);
        if (0 != poll_rc) {
            break;
        }
        struct timespec ts = {0, 10000000}; /* 10ms */
        nanosleep(&ts, NULL);
    }
    assert_int_equal(1, poll_rc);

    pn_sockaddr_t addrs[4] = {0};
    size_t        count    = 0;
    rc = ops->dns_resolve_get_results(ops, &dns_ctx, addrs, 4, &count);
    assert_int_equal(0, rc);
    assert_true(count > 0);

    int found_loopback = 0;
    for (size_t i = 0; i < count; ++i) {
        if (PN_AF_INET == addrs[i].family) {
            uint8_t expected[4] = {127, 0, 0, 1};
            if (0 == memcmp(addrs[i].addr.ipv4, expected, 4)) {
                found_loopback = 1;
            }
        }
    }
    assert_int_equal(1, found_loopback);
}

static void test_native_dns_handles_nxdomain(void** state)
{
    (void)state;

    const pn_socket_platform_ops_t* ops = &pn_posix_socket_ops;

    union {
        uint8_t  raw[PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE];
        void*    _align_ptr;
        uint64_t _align_u64;
    } dns_ctx = {0};

    /* RFC 6761 §6.4: The ".invalid" TLD is guaranteed non-resolvable by
     * conforming resolvers. Captive portals or non-conforming forwarders
     * may still intercept this; the test accepts timeout as a valid
     * outcome. */
    int rc = ops->dns_resolve_start(
        ops, &dns_ctx, "this.hostname.does.not.exist.invalid", 5000);
    assert_int_equal(0, rc);

    int poll_rc = 0;
    for (int i = 0; i < 200; ++i) {
        poll_rc = ops->dns_resolve_poll(ops, &dns_ctx);
        if (0 != poll_rc) {
            break;
        }
        struct timespec ts = {0, 50000000}; /* 50ms */
        nanosleep(&ts, NULL);
    }

    /* NXDOMAIN must not report successful resolution. Acceptable outcomes:
     * -1 = resolver reported failure (most platforms), or
     *  0 = resolution timed out / no callback delivered (e.g., macOS
     *      mDNSResponder for truly invalid TLDs).
     * Only poll_rc == 1 would indicate a bug (or a pathological network). */
    assert_true(-1 == poll_rc || 0 == poll_rc);
}

static void test_native_dns_resolves_real_hostname(void** state)
{
    (void)state;

    const pn_socket_platform_ops_t* ops = &pn_posix_socket_ops;

    union {
        uint8_t  raw[PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE];
        void*    _align_ptr;
        uint64_t _align_u64;
    } dns_ctx = {0};

    int rc = ops->dns_resolve_start(ops, &dns_ctx, "ps.pndsn.com", 10000);
    assert_int_equal(0, rc);

    int poll_rc = 0;
    for (int i = 0; i < 200; ++i) {
        poll_rc = ops->dns_resolve_poll(ops, &dns_ctx);
        if (0 != poll_rc) {
            break;
        }
        struct timespec ts = {0, 50000000}; /* 50ms */
        nanosleep(&ts, NULL);
    }
    assert_int_equal(1, poll_rc);

    pn_sockaddr_t addrs[8] = {0};
    size_t        count    = 0;
    rc = ops->dns_resolve_get_results(ops, &dns_ctx, addrs, 8, &count);
    assert_int_equal(0, rc);
    assert_true(count > 0);

    for (size_t i = 0; i < count; ++i) {
        assert_true(pn_test_addr_is_valid(&addrs[i]));
    }
}

#ifndef __APPLE__
static void test_native_dns_blocking_completes_immediately(void** state)
{
    (void)state;

    const pn_socket_platform_ops_t* ops = &pn_posix_socket_ops;

    union {
        uint8_t  raw[PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE];
        void*    _align_ptr;
        uint64_t _align_u64;
    } dns_ctx = {0};

    /* On Linux/BSD, getaddrinfo is blocking — dns_resolve_start completes
     * resolution synchronously. The first poll must return non-zero. */
    int rc = ops->dns_resolve_start(ops, &dns_ctx, "localhost", 5000);
    assert_int_equal(0, rc);

    int poll_rc = ops->dns_resolve_poll(ops, &dns_ctx);
    assert_int_not_equal(0, poll_rc);
    assert_int_equal(1, poll_rc);
}
#endif /* !__APPLE__ */

static void test_resolver_full_path_localhost(void** state)
{
    (void)state;

    pn_dns_resolver_t resolver = {0};
    int               rc =
        pn_dns_resolver_init(&resolver, &pn_posix_socket_ops, &s_mock_platform);
    assert_int_equal(0, rc);

    rc = pn_dns_resolver_start(&resolver, "localhost");
    assert_int_equal(0, rc);

    drive_resolver_to_completion(&resolver);
    assert_int_equal(PN_DNS_STATE_DONE, resolver.state);

    pn_sockaddr_t addrs[8] = {0};
    size_t        count    = 0;
    rc = pn_dns_resolver_get_results(&resolver, addrs, 8, &count);
    assert_int_equal(0, rc);
    assert_true(count > 0);

    int found_loopback = 0;
    for (size_t i = 0; i < count; ++i) {
        assert_true(pn_test_addr_is_valid(&addrs[i]));
        if (PN_AF_INET == addrs[i].family) {
            uint8_t expected[4] = {127, 0, 0, 1};
            if (0 == memcmp(addrs[i].addr.ipv4, expected, 4)) {
                found_loopback = 1;
            }
        }
    }
    assert_int_equal(1, found_loopback);

    pn_dns_resolver_deinit(&resolver);
}

static void test_resolver_full_path_real_hostname(void** state)
{
    (void)state;

    pn_dns_resolver_t resolver = {0};
    int               rc =
        pn_dns_resolver_init(&resolver, &pn_posix_socket_ops, &s_mock_platform);
    assert_int_equal(0, rc);

    rc = pn_dns_resolver_start(&resolver, "ps.pndsn.com");
    assert_int_equal(0, rc);

    drive_resolver_to_completion(&resolver);
    assert_int_equal(PN_DNS_STATE_DONE, resolver.state);

    pn_sockaddr_t addrs[8] = {0};
    size_t        count    = 0;
    rc = pn_dns_resolver_get_results(&resolver, addrs, 8, &count);
    assert_int_equal(0, rc);
    assert_true(count > 0);

    for (size_t i = 0; i < count; ++i) {
        assert_true(pn_test_addr_is_valid(&addrs[i]));
    }

    pn_dns_resolver_deinit(&resolver);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_native_dns_resolves_localhost),
        cmocka_unit_test(test_native_dns_handles_nxdomain),
        cmocka_unit_test(test_native_dns_resolves_real_hostname),
#ifndef __APPLE__
        cmocka_unit_test(test_native_dns_blocking_completes_immediately),
#endif
        cmocka_unit_test(test_resolver_full_path_localhost),
        cmocka_unit_test(test_resolver_full_path_real_hostname),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

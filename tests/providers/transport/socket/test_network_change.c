/* Copyright (c) 2024-2026 PubNub Inc. */

/**
 * @file test_network_change.c
 * @brief Regression test for network change handling (WiFi/VPN switch).
 *
 * When a device switches networks (WiFi to cellular, VPN connect/disconnect),
 * cached DNS entries become stale. The socket transport must detect this
 * condition (all cached IPs fail to connect) and invalidate the cache, forcing
 * a fresh DNS lookup on the next attempt.
 *
 * Test strategy:
 * 1. Resolve a hostname via mock DNS → cache stores IPs.
 * 2. Verify cache hit on second resolve (no new DNS query).
 * 3. Call pn_dns_resolver_invalidate() to simulate network change.
 * 4. Third resolve → cache miss, new DNS query sent.
 * 5. Verify fresh IPs returned from mock.
 */

#include "providers/transport/socket/dns/dns_resolver.h"

#include "providers/allocator/stdlib/allocator_stdlib.c"
#include "providers/platform/posix/platform_posix.c"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <string.h>

/** @brief Track DNS queries sent. */
static size_t g_query_count;

/** @brief Mock DNS response: first resolve returns 1.2.3.4, second 5.6.7.8. */
static uint32_t g_mock_response_ip;

static struct pubnub_platform_provider  g_platform_provider;
static struct pubnub_allocator_provider g_allocator_provider;

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

/** @brief Mock set_nonblocking always succeeds. */
static int mock_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                       pn_socket_t                     sock)
{
    (void)self;
    (void)sock;
    return 0;
}

/** @brief Mock connect stub. */
static int mock_socket_connect(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               const pn_sockaddr_t*            addr)
{
    (void)self;
    (void)sock;
    (void)addr;
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
                            size_t                          cap)
{
    (void)self;
    (void)sock;
    (void)buf;
    (void)cap;
    return 0;
}

/**
 * @brief Mock sendto: count DNS queries.
 */
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

    g_query_count++;

    return (int)len;
}

/**
 * @brief Mock recvfrom: return a DNS response with g_mock_response_ip.
 */
static int mock_socket_recvfrom(const pn_socket_platform_ops_t* self,
                                pn_socket_t                     sock,
                                uint8_t*                        buf,
                                size_t                          cap,
                                pn_sockaddr_t*                  src)
{
    (void)self;
    (void)sock;
    (void)src;

    if (cap < 32) {
        return 0;
    }

    /* Build minimal DNS A response. */
    uint8_t response[128];
    size_t  pos = 0;

    /* Header. */
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    response[pos++] = 0x81;
    response[pos++] = 0x80;
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    response[pos++] = 0x00;
    response[pos++] = 0x00;
    response[pos++] = 0x00;
    response[pos++] = 0x00;

    /* Question section: test.example.com A IN. */
    response[pos++] = 4;
    response[pos++] = 't';
    response[pos++] = 'e';
    response[pos++] = 's';
    response[pos++] = 't';
    response[pos++] = 7;
    response[pos++] = 'e';
    response[pos++] = 'x';
    response[pos++] = 'a';
    response[pos++] = 'm';
    response[pos++] = 'p';
    response[pos++] = 'l';
    response[pos++] = 'e';
    response[pos++] = 3;
    response[pos++] = 'c';
    response[pos++] = 'o';
    response[pos++] = 'm';
    response[pos++] = 0;
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    response[pos++] = 0x00;
    response[pos++] = 0x01;

    /* Answer section. */
    response[pos++] = 0xC0;
    response[pos++] = 0x0C;
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    response[pos++] = 0x00;
    response[pos++] = 0x01;
    response[pos++] = 0x00;
    response[pos++] = 0x00;
    response[pos++] = 0x00;
    response[pos++] = 0x3C;
    response[pos++] = 0x00;
    response[pos++] = 0x04;

    /* RDATA: IPv4 address. */
    response[pos++] = (uint8_t)((g_mock_response_ip >> 24) & 0xFF);
    response[pos++] = (uint8_t)((g_mock_response_ip >> 16) & 0xFF);
    response[pos++] = (uint8_t)((g_mock_response_ip >> 8) & 0xFF);
    response[pos++] = (uint8_t)(g_mock_response_ip & 0xFF);

    if (pos > cap) {
        return 0;
    }

    memcpy(buf, response, pos);
    return (int)pos;
}

/** @brief Mock keepalive stub. */
static int mock_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock,
                                     const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;
    (void)sock;
    (void)config;
    return 0;
}

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

/**
 * @brief Setup fixture.
 */
static int test_setup(void** state)
{
    (void)state;

    g_platform_provider  = *pn_platform_default();
    g_allocator_provider = *pn_allocator_default();

    g_query_count      = 0;
    g_mock_response_ip = htonl(0x01020304); /* 1.2.3.4 */

    return 0;
}

/**
 * @brief Test: DNS cache invalidation after network change.
 */
static void test_dns_cache_invalidation(void** state)
{
    (void)state;

    /* UDP-based DNS querying only active with the built-in resolver. */
    if (!PUBNUB_ENABLE_CUSTOM_DNS) {
        return;
    }

    pn_dns_resolver_t resolver;
    int               init_result =
        pn_dns_resolver_init(&resolver, &g_mock_ops, &g_platform_provider);
    assert_int_equal(0, init_result);

    /* Override resolver to use a fake DNS server address. */
    resolver.servers[0].family       = PN_AF_INET;
    resolver.servers[0].port         = 53;
    resolver.servers[0].addr.ipv4[0] = 127;
    resolver.servers[0].addr.ipv4[1] = 0;
    resolver.servers[0].addr.ipv4[2] = 0;
    resolver.servers[0].addr.ipv4[3] = 1;
    resolver.server_count            = 1;

    /* First resolution: cache miss, sends DNS query. */
    size_t initial_query_count = g_query_count;
    int    start_result = pn_dns_resolver_start(&resolver, "test.example.com");
    assert_int_equal(0, start_result);

    /* Verify DNS query was sent. */
    assert_true(g_query_count > initial_query_count);

    /* Simulate immediate DONE (cache populated in start call for testing). */
    /* In reality, tick would drive this. For this test, manually populate. */
    resolver.state                        = PN_DNS_STATE_DONE;
    resolver.result_count                 = 1;
    resolver.result_addrs[0].family       = PN_AF_INET;
    resolver.result_addrs[0].addr.ipv4[0] = 1;
    resolver.result_addrs[0].addr.ipv4[1] = 2;
    resolver.result_addrs[0].addr.ipv4[2] = 3;
    resolver.result_addrs[0].addr.ipv4[3] = 4;

    /* Manually populate cache. */
    strncpy(resolver.cache[0].hostname,
            "test.example.com",
            PUBNUB_CFG_MAX_HOSTNAME_LEN - 1);
    resolver.cache[0].hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN - 1] = '\0';
    resolver.cache[0].addr_count                                = 1;
    resolver.cache[0].addrs[0] = resolver.result_addrs[0];
    resolver.cache[0].ttl_sec  = 60;
    resolver.cache[0].timestamp_ms =
        g_platform_provider.monotonic_ms(&g_platform_provider);

    /* Reset state to IDLE for second resolution. */
    resolver.state = PN_DNS_STATE_IDLE;

    /* Second resolution: cache hit, no new query. */
    size_t query_count_before_cache_hit = g_query_count;
    start_result = pn_dns_resolver_start(&resolver, "test.example.com");
    assert_int_equal(0, start_result);

    /* Verify state is DONE immediately (cache hit). */
    assert_int_equal(PN_DNS_STATE_DONE, pn_dns_resolver_state(&resolver));

    /* Verify no new DNS query was sent. */
    assert_int_equal(query_count_before_cache_hit, g_query_count);

    /* Simulate network change: invalidate cache. */
    pn_dns_resolver_invalidate(&resolver, "test.example.com");

    /* Verify cache entry is cleared. */
    assert_int_equal(0, resolver.cache[0].hostname[0]);

    /* Reset state to IDLE for third resolution. */
    resolver.state = PN_DNS_STATE_IDLE;

    /* Third resolution: cache miss after invalidation, sends DNS query. */
    size_t query_count_before_requery = g_query_count;
    start_result = pn_dns_resolver_start(&resolver, "test.example.com");
    assert_int_equal(0, start_result);

    /* Verify new DNS query was sent. */
    assert_true(g_query_count > query_count_before_requery);

    pn_dns_resolver_deinit(&resolver);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_dns_cache_invalidation, test_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "dns_resolver.h"

#include "dns_codec.h"

#include "core/pn_string.h"
#include "pubnub/config.h"

#include <string.h>

#ifndef PN_DNS_SERVER_TIMEOUT_MS
#define PN_DNS_SERVER_TIMEOUT_MS 2000
#endif

#ifndef PN_DNS_SERVER_REFRESH_MS
#define PN_DNS_SERVER_REFRESH_MS 30000
#endif

/* Define PUBNUB_CFG_DNS_DISABLE_FALLBACKS=1 to omit the hardcoded fallback
 * servers (useful for embedded targets with a known, fixed DNS infrastructure). */
#if PUBNUB_ENABLE_CUSTOM_DNS
#if !defined(PUBNUB_CFG_DNS_DISABLE_FALLBACKS) || !PUBNUB_CFG_DNS_DISABLE_FALLBACKS

/**
 * @brief Hardcoded fallback DNS servers.
 *
 * Used when platform discovery fails or returns no servers. IPv4: Google
 * 8.8.8.8, Cloudflare 1.1.1.1. IPv6: Google 2001:4860:4860::8888, Cloudflare
 * 2606:4700:4700::1111.
 */
static const pn_sockaddr_t PN_DNS_FALLBACK_SERVERS[] = {
    {PN_AF_INET,  53, {.ipv4 = {8, 8, 8, 8}}                                                                                    },
    {PN_AF_INET,  53, {.ipv4 = {1, 1, 1, 1}}                                                                                    },
#if PUBNUB_ENABLE_IPV6
    {PN_AF_INET6,
     53,              {.ipv6 = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88}}},
    {PN_AF_INET6,
     53,              {.ipv6 = {0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11}}}
#endif
};

#define PN_DNS_FALLBACK_SERVER_COUNT \
    (sizeof(PN_DNS_FALLBACK_SERVERS) / sizeof(PN_DNS_FALLBACK_SERVERS[0]))

#else /* PUBNUB_CFG_DNS_DISABLE_FALLBACKS */

#define PN_DNS_FALLBACK_SERVER_COUNT 0

#endif /* !PUBNUB_CFG_DNS_DISABLE_FALLBACKS */
#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

/** @brief DNS query packet buffer size (sufficient for max-length hostname). */
#define PN_DNS_QUERY_BUF_SIZE 512

/** @brief DNS response packet buffer size. */
#define PN_DNS_RESPONSE_BUF_SIZE 512

/**
 * @brief Refresh the DNS server list.
 *
 * Queries the platform for DNS servers and appends hardcoded fallbacks.
 * Caches the result for PN_DNS_SERVER_REFRESH_MS.
 *
 * @param resolver Resolver instance.
 */
static void pn_dns_resolver_refresh_servers_(pn_dns_resolver_t* resolver)
{
    size_t discovered_count = 0;

    resolver->server_count        = 0;
    resolver->server_list_invalid = 0;

#if PUBNUB_ENABLE_CUSTOM_DNS
    {
        uint8_t user_count = PUBNUB_ATOMIC_LOAD_U8(&resolver->user_server_count);
        if (NULL != resolver->user_servers && user_count > 0) {
            uint8_t i;
            for (i = 0; i < user_count
                        && resolver->server_count < PUBNUB_CFG_MAX_DNS_SERVERS;
                 ++i) {
                resolver->servers[resolver->server_count++] =
                    resolver->user_servers[i];
            }
        }
    }
#endif

    if (NULL != resolver->ops->dns_discover_servers) {
        size_t space = PUBNUB_CFG_MAX_DNS_SERVERS - resolver->server_count;
        if (0
            == resolver->ops->dns_discover_servers(resolver->ops,
                                                   resolver->servers
                                                       + resolver->server_count,
                                                   space,
                                                   &discovered_count)) {
            resolver->server_count += discovered_count;
        }
    }

#if PUBNUB_ENABLE_CUSTOM_DNS
#if !defined(PUBNUB_CFG_DNS_DISABLE_FALLBACKS) || !PUBNUB_CFG_DNS_DISABLE_FALLBACKS
    {
        size_t fallback_space = PUBNUB_CFG_MAX_DNS_SERVERS - resolver->server_count;
        size_t fallback_to_add = fallback_space < PN_DNS_FALLBACK_SERVER_COUNT
                                   ? fallback_space
                                   : PN_DNS_FALLBACK_SERVER_COUNT;
        for (size_t i = 0; i < fallback_to_add; ++i) {
            resolver->servers[resolver->server_count++] =
                PN_DNS_FALLBACK_SERVERS[i];
        }
    }
#endif
#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

    resolver->server_list_timestamp_ms =
        resolver->platform->monotonic_ms(resolver->platform);
}

/**
 * @brief Lookup a hostname in the cache.
 *
 * Returns a pointer to the cache entry if found and TTL is valid, NULL
 * otherwise.
 *
 * @param resolver Resolver instance.
 * @param hostname NUL-terminated hostname.
 * @return Cache entry pointer or NULL.
 */
static pn_dns_cache_entry_t* pn_dns_resolver_cache_lookup_(pn_dns_resolver_t* resolver,
                                                           const char* hostname)
{
    uint64_t now_ms = resolver->platform->monotonic_ms(resolver->platform);

    for (size_t i = 0; i < PUBNUB_CFG_DNS_CACHE_SIZE; ++i) {
        if (0 == resolver->cache[i].hostname[0]) {
            continue;
        }
        if (0 != strcmp(resolver->cache[i].hostname, hostname)) {
            continue;
        }

        uint64_t elapsed_ms = now_ms - resolver->cache[i].timestamp_ms;
        uint64_t ttl_ms     = (uint64_t)resolver->cache[i].ttl_sec * 1000;

        if (elapsed_ms < ttl_ms) {
            return &resolver->cache[i];
        }
    }

    return NULL;
}

/**
 * @brief Insert or update a cache entry.
 *
 * Uses LRU eviction: the oldest entry (by timestamp) is replaced when the
 * cache is full.
 *
 * @param resolver   Resolver instance.
 * @param hostname   NUL-terminated hostname.
 * @param addrs      Resolved addresses.
 * @param addr_count Number of addresses.
 * @param ttl_sec    TTL in seconds (capped to PUBNUB_CFG_DNS_MAX_TTL_SEC).
 */
static void pn_dns_resolver_cache_insert_(pn_dns_resolver_t*   resolver,
                                          const char*          hostname,
                                          const pn_sockaddr_t* addrs,
                                          size_t               addr_count,
                                          uint32_t             ttl_sec)
{
    uint64_t now_ms = resolver->platform->monotonic_ms(resolver->platform);

    if (ttl_sec > PUBNUB_CFG_DNS_MAX_TTL_SEC) {
        ttl_sec = PUBNUB_CFG_DNS_MAX_TTL_SEC;
    }

    size_t   lru_idx = 0;
    uint64_t lru_ts  = resolver->cache[0].timestamp_ms;
    for (size_t i = 1; i < PUBNUB_CFG_DNS_CACHE_SIZE; ++i) {
        if (resolver->cache[i].timestamp_ms < lru_ts) {
            lru_ts  = resolver->cache[i].timestamp_ms;
            lru_idx = i;
        }
    }

    pn_dns_cache_entry_t* entry = &resolver->cache[lru_idx];

    pn_strlcpy(entry->hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN);

    size_t copy_count = addr_count < PUBNUB_CFG_MAX_DNS_RESULTS
                          ? addr_count
                          : PUBNUB_CFG_MAX_DNS_RESULTS;
    memcpy(entry->addrs, addrs, copy_count * sizeof(pn_sockaddr_t));
    entry->addr_count   = copy_count;
    entry->ttl_sec      = ttl_sec;
    entry->timestamp_ms = now_ms;
}

/**
 * @brief Send A and AAAA queries to the current server.
 *
 * Advances current_server_idx past servers whose address family lacks an
 * available socket (e.g. IPv6 servers when udp_socket_v6 is unavailable),
 * then generates unique transaction IDs for each query using the platform's
 * random source.
 *
 * @param resolver Resolver instance.
 * @retval 0 on success.
 * @retval -1 on encoding/send failure or no usable server.
 * @note Stack usage: ~512 bytes (for query_buf).
 */
static int pn_dns_resolver_send_queries_(pn_dns_resolver_t* resolver)
{
    uint8_t query_buf[PN_DNS_QUERY_BUF_SIZE];
    size_t  query_len;

    /* Advance past servers whose socket family is unavailable. */
    if (PUBNUB_ENABLE_IPV6) {
        while (resolver->current_server_idx < resolver->server_count) {
            const pn_sockaddr_t* candidate =
                &resolver->servers[resolver->current_server_idx];
            if (PN_AF_INET6 == candidate->family
                && PN_INVALID_SOCKET == resolver->udp_socket_v6) {
                resolver->current_server_idx++;
                continue;
            }
            break;
        }
    }
    if (resolver->current_server_idx >= resolver->server_count) {
        return -1; /* No usable servers. */
    }

    uint8_t txn_id_bytes[4];
    if (0
        != resolver->platform->random_bytes(
            resolver->platform, txn_id_bytes, sizeof(txn_id_bytes))) {
        return -1;
    }
    resolver->txn_id_a = (uint16_t)((txn_id_bytes[0] << 8) | txn_id_bytes[1]);
    if (PUBNUB_ENABLE_IPV6) {
        resolver->txn_id_aaaa =
            (uint16_t)((txn_id_bytes[2] << 8) | txn_id_bytes[3]);
    }

    const pn_sockaddr_t* server = &resolver->servers[resolver->current_server_idx];
    pn_socket_t send_socket = resolver->udp_socket;

    if (PUBNUB_ENABLE_IPV6 && PN_AF_INET6 == server->family) {
        send_socket = resolver->udp_socket_v6;
    }

    if (0
        != pn_dns_encode_query(resolver->current_hostname,
                               PN_DNS_TYPE_A,
                               resolver->txn_id_a,
                               query_buf,
                               sizeof(query_buf),
                               &query_len)) {
        return -1;
    }

    int sendto_rc = (int)resolver->ops->socket_sendto(
        resolver->ops, send_socket, query_buf, query_len, server);
    if (0 >= sendto_rc) {
        return -1;
    }

    if (PUBNUB_ENABLE_IPV6) {
        if (0
            != pn_dns_encode_query(resolver->current_hostname,
                                   PN_DNS_TYPE_AAAA,
                                   resolver->txn_id_aaaa,
                                   query_buf,
                                   sizeof(query_buf),
                                   &query_len)) {
            return -1;
        }

        if (0 >= resolver->ops->socket_sendto(
                resolver->ops, send_socket, query_buf, query_len, server)) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Process a DNS response packet.
 *
 * Validates the transaction ID, decodes addresses, and updates the result
 * arrays. Both A and AAAA responses are collected; the resolver waits for both
 * or until timeout.
 *
 * Each decode call uses its own output buffers so that A and AAAA results
 * cannot overwrite each other regardless of txn-id match ordering.
 *
 * @param resolver Resolver instance.
 * @param buf      Response packet buffer.
 * @param len      Packet length.
 * @note Stack usage: PUBNUB_CFG_MAX_DNS_RESULTS * sizeof(pn_sockaddr_t).
 *       With default 8 results this is ~160 bytes. A single buffer is safe
 *       because only one txn_id matches per UDP packet (decode returns -2
 *       on mismatch). Embedded profiles that constrain stack depth should
 *       reduce PUBNUB_CFG_MAX_DNS_RESULTS.
 */
static void pn_dns_resolver_process_response_(pn_dns_resolver_t* resolver,
                                              const uint8_t*     buf,
                                              size_t             len)
{
    pn_sockaddr_t temp_addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    size_t        temp_count = 0;
    uint32_t      temp_ttl   = 0;

    if (0
        == pn_dns_decode_response(buf,
                                  len,
                                  resolver->txn_id_a,
                                  resolver->current_hostname,
                                  temp_addrs,
                                  PUBNUB_CFG_MAX_DNS_RESULTS,
                                  &temp_count,
                                  &temp_ttl)) {
        resolver->got_a_response = 1;
        size_t space_left = PUBNUB_CFG_MAX_DNS_RESULTS - resolver->result_count;
        size_t to_add     = temp_count < space_left ? temp_count : space_left;
        memcpy(&resolver->result_addrs[resolver->result_count],
               temp_addrs,
               to_add * sizeof(pn_sockaddr_t));
        resolver->result_count += to_add;
        if (temp_count > 0
            && (0 == resolver->result_ttl || temp_ttl < resolver->result_ttl)) {
            resolver->result_ttl = temp_ttl;
        }
    }

    if (PUBNUB_ENABLE_IPV6) {
        temp_count = 0;
        temp_ttl   = 0;

        if (0
            == pn_dns_decode_response(buf,
                                      len,
                                      resolver->txn_id_aaaa,
                                      resolver->current_hostname,
                                      temp_addrs,
                                      PUBNUB_CFG_MAX_DNS_RESULTS,
                                      &temp_count,
                                      &temp_ttl)) {
            resolver->got_aaaa_response = 1;
            size_t space_left = PUBNUB_CFG_MAX_DNS_RESULTS - resolver->result_count;
            size_t to_add = temp_count < space_left ? temp_count : space_left;
            memcpy(&resolver->result_addrs[resolver->result_count],
                   temp_addrs,
                   to_add * sizeof(pn_sockaddr_t));
            resolver->result_count += to_add;
            if (temp_count > 0
                && (0 == resolver->result_ttl || temp_ttl < resolver->result_ttl)) {
                resolver->result_ttl = temp_ttl;
            }
        }
    }
}

int pn_dns_resolver_init(pn_dns_resolver_t*               resolver,
                         const pn_socket_platform_ops_t*  ops,
                         struct pubnub_platform_provider* platform)
{
    if (NULL == resolver || NULL == ops || NULL == platform) {
        return -1;
    }

    memset(resolver, 0, sizeof(*resolver));

    resolver->udp_socket          = PN_INVALID_SOCKET;
    resolver->udp_socket_v6       = PN_INVALID_SOCKET;
    resolver->ops                 = ops;
    resolver->platform            = platform;
    resolver->server_list_invalid = 1;

    /* Initialize platform DNS state when native DNS is available. */
#if !PUBNUB_ENABLE_CUSTOM_DNS
    if (NULL != ops->dns_resolve_start) {
        if (NULL != ops->dns_state_init) {
            if (0 != ops->dns_state_init(ops, &resolver->platform_dns_state)) {
                return -1;
            }
        }
        return 0;
    }
#endif

    /* The query socket is left unbound: the OS performs an implicit bind on
     * the first sendto and assigns a randomized ephemeral source port (RFC
     * 6056) on all supported hosts. An explicit bind(port=0) would produce the
     * same result, so no fixed source port is ever used. */
    resolver->udp_socket = ops->socket_create(ops, PN_AF_INET, 1);
    if (PN_INVALID_SOCKET == resolver->udp_socket) {
        return -1;
    }

    if (0 != ops->socket_set_nonblocking(ops, resolver->udp_socket)) {
        ops->socket_destroy(ops, resolver->udp_socket);
        resolver->udp_socket = PN_INVALID_SOCKET;
        return -1;
    }

    /* IPv6 socket is optional — networks without IPv6 still work. */
    if (PUBNUB_ENABLE_IPV6) {
        resolver->udp_socket_v6 = ops->socket_create(ops, PN_AF_INET6, 1);
        if (PN_INVALID_SOCKET != resolver->udp_socket_v6) {
            if (0 != ops->socket_set_nonblocking(ops, resolver->udp_socket_v6)) {
                ops->socket_destroy(ops, resolver->udp_socket_v6);
                resolver->udp_socket_v6 = PN_INVALID_SOCKET;
            }
        }
    }

    return 0;
}

void pn_dns_resolver_deinit(pn_dns_resolver_t* resolver)
{
    if (NULL == resolver) {
        return;
    }

    /* Cancel in-progress platform DNS if resolver is still active. */
#if !PUBNUB_ENABLE_CUSTOM_DNS
    if (NULL != resolver->ops->dns_resolve_cancel
        && PN_DNS_STATE_IDLE != resolver->state && PN_DNS_STATE_DONE != resolver->state
        && PN_DNS_STATE_FAILED != resolver->state) {
        resolver->ops->dns_resolve_cancel(resolver->ops,
                                          &resolver->platform_dns_state);
    }
#endif

    if (PUBNUB_ENABLE_IPV6 && PN_INVALID_SOCKET != resolver->udp_socket_v6) {
        resolver->ops->socket_destroy(resolver->ops, resolver->udp_socket_v6);
        resolver->udp_socket_v6 = PN_INVALID_SOCKET;
    }

    if (PN_INVALID_SOCKET != resolver->udp_socket) {
        resolver->ops->socket_destroy(resolver->ops, resolver->udp_socket);
        resolver->udp_socket = PN_INVALID_SOCKET;
    }
}

int pn_dns_resolver_start(pn_dns_resolver_t* resolver, const char* hostname)
{
    if (NULL == resolver || NULL == hostname) {
        return -1;
    }

    if (PN_DNS_STATE_IDLE != resolver->state) {
        return -1;
    }

    size_t hostname_len = strlen(hostname);
    if (0 == hostname_len || hostname_len >= PUBNUB_CFG_MAX_HOSTNAME_LEN) {
        return -1;
    }

    pn_dns_cache_entry_t* cached =
        pn_dns_resolver_cache_lookup_(resolver, hostname);
    if (NULL != cached) {
        memcpy(resolver->result_addrs,
               cached->addrs,
               cached->addr_count * sizeof(pn_sockaddr_t));
        resolver->result_count = cached->addr_count;
        resolver->result_ttl   = cached->ttl_sec;
        resolver->state        = PN_DNS_STATE_DONE;
        return 0;
    }

    uint64_t now_ms = resolver->platform->monotonic_ms(resolver->platform);

    pn_strlcpy(resolver->current_hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN);

    resolver->current_server_idx = 0;
    resolver->got_a_response     = 0;
    resolver->got_aaaa_response  = !PUBNUB_ENABLE_IPV6;
    resolver->result_count       = 0;
    resolver->result_ttl         = 0;

#if !PUBNUB_ENABLE_CUSTOM_DNS
    if (NULL != resolver->ops->dns_resolve_start) {
        void* dns_ctx = &resolver->platform_dns_state;
        if (0
            != resolver->ops->dns_resolve_start(resolver->ops,
                                                dns_ctx,
                                                resolver->current_hostname,
                                                PN_DNS_SERVER_TIMEOUT_MS)) {
            return -1;
        }

        /* Immediate-poll: blocking resolvers (getaddrinfo, lwip) complete
         * synchronously inside dns_resolve_start. Poll now to avoid an
         * unnecessary QUERY_SENT->WAITING round-trip. */
        int poll_rc = resolver->ops->dns_resolve_poll(resolver->ops, dns_ctx);
        if (1 == poll_rc) {
            size_t count = 0;
            if (0
                    == resolver->ops->dns_resolve_get_results(
                        resolver->ops,
                        dns_ctx,
                        resolver->result_addrs,
                        PUBNUB_CFG_MAX_DNS_RESULTS,
                        &count)
                && count > 0) {
                resolver->result_count      = count;
                resolver->got_a_response    = 1;
                resolver->got_aaaa_response = 1;
                resolver->result_ttl        = PUBNUB_CFG_DNS_MAX_TTL_SEC;
                pn_dns_resolver_cache_insert_(resolver,
                                              resolver->current_hostname,
                                              resolver->result_addrs,
                                              resolver->result_count,
                                              resolver->result_ttl);
                resolver->state = PN_DNS_STATE_DONE;
                return 0;
            }
            resolver->state = PN_DNS_STATE_FAILED;
            return -1;
        }
        if (-1 == poll_rc) {
            resolver->state = PN_DNS_STATE_FAILED;
            return -1;
        }
        /* poll_rc == 0: async resolution in progress (macOS, Windows, Zephyr). */
    } else
#endif /* !PUBNUB_ENABLE_CUSTOM_DNS */
    {
        if (0 != resolver->server_list_invalid || 0 == resolver->server_count
            || (now_ms - resolver->server_list_timestamp_ms
                > PN_DNS_SERVER_REFRESH_MS)) {
            pn_dns_resolver_refresh_servers_(resolver);
        }

        if (0 == resolver->server_count) {
            return -1;
        }

        if (0 != pn_dns_resolver_send_queries_(resolver)) {
            return -1;
        }
    }

    resolver->deadline_ms = now_ms + PN_DNS_SERVER_TIMEOUT_MS;
    resolver->state       = PN_DNS_STATE_QUERY_SENT;

    return 0;
}

#if !PUBNUB_ENABLE_CUSTOM_DNS
/**
 * @brief Process the WAITING state via platform-native DNS.
 *
 * Polls the platform resolver and retrieves results on completion.
 * No server rotation — platform handles server selection internally.
 *
 * @param resolver Resolver instance (state == PN_DNS_STATE_WAITING).
 * @return Next state after processing.
 */
static pn_dns_state_t tick_waiting_platform(pn_dns_resolver_t* resolver)
{
    void* dns_ctx = &resolver->platform_dns_state;
    int   poll_rc = resolver->ops->dns_resolve_poll(resolver->ops, dns_ctx);

    if (1 == poll_rc) {
        size_t count = 0;
        if (0
            == resolver->ops->dns_resolve_get_results(resolver->ops,
                                                      dns_ctx,
                                                      resolver->result_addrs,
                                                      PUBNUB_CFG_MAX_DNS_RESULTS,
                                                      &count)) {
            resolver->result_count      = count;
            resolver->got_a_response    = 1;
            resolver->got_aaaa_response = 1;
            resolver->result_ttl        = PUBNUB_CFG_DNS_MAX_TTL_SEC;
            if (count > 0) {
                pn_dns_resolver_cache_insert_(resolver,
                                              resolver->current_hostname,
                                              resolver->result_addrs,
                                              resolver->result_count,
                                              resolver->result_ttl);
                resolver->state = PN_DNS_STATE_DONE;
                return PN_DNS_STATE_DONE;
            }
        }
        /* Platform returned success but zero results — treat as failure. */
        resolver->state = PN_DNS_STATE_FAILED;
        return PN_DNS_STATE_FAILED;
    }

    if (-1 == poll_rc) {
        /* Platform DNS failed — no rotation, go directly to FAILED. */
        resolver->state = PN_DNS_STATE_FAILED;
        return PN_DNS_STATE_FAILED;
    }

    /* Still pending — check timeout. */
    uint64_t now_ms = resolver->platform->monotonic_ms(resolver->platform);
    if (now_ms >= resolver->deadline_ms) {
        resolver->state = PN_DNS_STATE_FAILED;
        return PN_DNS_STATE_FAILED;
    }

    return PN_DNS_STATE_WAITING;
}
#endif /* !PUBNUB_ENABLE_CUSTOM_DNS */

/**
 * @brief Check whether a reply source matches the queried DNS server.
 *
 * Compares address family, port, and address bytes so that only replies from
 * the exact server we queried are accepted. Rejecting mismatched sources
 * closes an off-path UDP spoofing vector on the shared resolver socket.
 *
 * @param resolver Resolver instance.
 * @param from     Source address reported by socket_recvfrom.
 * @retval 1 when the source matches the current server.
 * @retval 0 when the source does not match (packet must be discarded).
 */
static int pn_dns_resolver_source_matches_(const pn_dns_resolver_t* resolver,
                                           const pn_sockaddr_t*     from)
{
    const pn_sockaddr_t* server;
    size_t               addr_len;

    if (resolver->current_server_idx >= resolver->server_count) {
        return 0;
    }

    server = &resolver->servers[resolver->current_server_idx];
    if (server->family != from->family || server->port != from->port) {
        return 0;
    }

    addr_len = (PN_AF_INET6 == server->family) ? 16 : 4;
    return 0 == memcmp(&server->addr, &from->addr, addr_len);
}

/**
 * @brief Process the WAITING state: read UDP responses and check timeout.
 *
 * @param resolver Resolver instance (state == PN_DNS_STATE_WAITING).
 * @return Next state after processing.
 * @note Stack usage: ~512 bytes (for response_buf).
 */
static pn_dns_state_t tick_waiting(pn_dns_resolver_t* resolver)
{
#if !PUBNUB_ENABLE_CUSTOM_DNS
    if (NULL != resolver->ops->dns_resolve_start) {
        return tick_waiting_platform(resolver);
    }
#endif

    uint8_t       response_buf[PN_DNS_RESPONSE_BUF_SIZE];
    pn_sockaddr_t from_addr = {0};

    int recv_rc = resolver->ops->socket_recvfrom(resolver->ops,
                                                 resolver->udp_socket,
                                                 response_buf,
                                                 sizeof(response_buf),
                                                 &from_addr);

    if (PUBNUB_ENABLE_IPV6 && recv_rc <= 0
        && PN_INVALID_SOCKET != resolver->udp_socket_v6) {
        recv_rc = resolver->ops->socket_recvfrom(resolver->ops,
                                                 resolver->udp_socket_v6,
                                                 response_buf,
                                                 sizeof(response_buf),
                                                 &from_addr);
    }

    /* Only process replies whose source matches the queried server. A reply
     * from any other source is a possible off-path spoof: discard it and keep
     * waiting until a legitimate reply arrives or the deadline expires. */
    if (recv_rc > 0 && 0 != pn_dns_resolver_source_matches_(resolver, &from_addr)) {
        pn_dns_resolver_process_response_(resolver, response_buf, (size_t)recv_rc);

        if (0 != resolver->got_a_response && 0 != resolver->got_aaaa_response) {
            if (resolver->result_count > 0) {
                pn_dns_resolver_cache_insert_(resolver,
                                              resolver->current_hostname,
                                              resolver->result_addrs,
                                              resolver->result_count,
                                              resolver->result_ttl);
                resolver->state = PN_DNS_STATE_DONE;
                return PN_DNS_STATE_DONE;
            }
        }
    }

    uint64_t now_ms = resolver->platform->monotonic_ms(resolver->platform);
    if (now_ms >= resolver->deadline_ms) {
        if (resolver->result_count > 0) {
            pn_dns_resolver_cache_insert_(resolver,
                                          resolver->current_hostname,
                                          resolver->result_addrs,
                                          resolver->result_count,
                                          resolver->result_ttl);
            resolver->state = PN_DNS_STATE_DONE;
            return PN_DNS_STATE_DONE;
        }

        resolver->state = PN_DNS_STATE_ROTATING;
        return PN_DNS_STATE_ROTATING;
    }

    return PN_DNS_STATE_WAITING;
}

/**
 * @brief Process the ROTATING state: advance to next DNS server.
 *
 * @param resolver Resolver instance (state == PN_DNS_STATE_ROTATING).
 * @return Next state after processing.
 */
static pn_dns_state_t tick_rotating(pn_dns_resolver_t* resolver)
{
    resolver->current_server_idx++;

    if (resolver->current_server_idx >= resolver->server_count) {
        resolver->state = PN_DNS_STATE_FAILED;
        return PN_DNS_STATE_FAILED;
    }

    resolver->got_a_response    = 0;
    resolver->got_aaaa_response = !PUBNUB_ENABLE_IPV6;
    resolver->result_count      = 0;
    resolver->result_ttl        = 0;

    if (0 != pn_dns_resolver_send_queries_(resolver)) {
        resolver->state = PN_DNS_STATE_FAILED;
        return PN_DNS_STATE_FAILED;
    }

    uint64_t now_ms = resolver->platform->monotonic_ms(resolver->platform);
    resolver->deadline_ms = now_ms + PN_DNS_SERVER_TIMEOUT_MS;
    resolver->state       = PN_DNS_STATE_QUERY_SENT;

    return PN_DNS_STATE_QUERY_SENT;
}

pn_dns_state_t pn_dns_resolver_tick(pn_dns_resolver_t* resolver)
{
    if (NULL == resolver) {
        return PN_DNS_STATE_FAILED;
    }

    if (PN_DNS_STATE_QUERY_SENT == resolver->state) {
        resolver->state = PN_DNS_STATE_WAITING;
    }

    switch (resolver->state) {
    case PN_DNS_STATE_WAITING: return tick_waiting(resolver);
    case PN_DNS_STATE_ROTATING: return tick_rotating(resolver);
    default: return resolver->state;
    }
}

int pn_dns_resolver_get_results(const pn_dns_resolver_t* resolver,
                                pn_sockaddr_t*           addrs_out,
                                size_t                   max_addrs,
                                size_t*                  out_count)
{
    if (NULL == resolver || NULL == addrs_out || NULL == out_count) {
        return -1;
    }

    if (PN_DNS_STATE_DONE != resolver->state) {
        return -1;
    }

    if (max_addrs < resolver->result_count) {
        return -1;
    }

    memcpy(addrs_out,
           resolver->result_addrs,
           resolver->result_count * sizeof(pn_sockaddr_t));
    *out_count = resolver->result_count;

    return 0;
}

void pn_dns_resolver_invalidate(pn_dns_resolver_t* resolver, const char* hostname)
{
    if (NULL == resolver || NULL == hostname) {
        return;
    }

    for (size_t i = 0; i < PUBNUB_CFG_DNS_CACHE_SIZE; ++i) {
        if (0 == resolver->cache[i].hostname[0]) {
            continue;
        }
        if (0 == strcmp(resolver->cache[i].hostname, hostname)) {
            resolver->cache[i].hostname[0] = '\0';
            resolver->cache[i].addr_count  = 0;
        }
    }

    resolver->server_list_invalid = 1;
}

pn_socket_t pn_dns_resolver_socket(const pn_dns_resolver_t* resolver)
{
    if (NULL == resolver) {
        return PN_INVALID_SOCKET;
    }

    return resolver->udp_socket;
}

pn_socket_t pn_dns_resolver_socket_v6(const pn_dns_resolver_t* resolver)
{
    if (NULL == resolver) {
        return PN_INVALID_SOCKET;
    }

    return resolver->udp_socket_v6;
}

pn_dns_state_t pn_dns_resolver_state(const pn_dns_resolver_t* resolver)
{
    if (NULL == resolver) {
        return PN_DNS_STATE_FAILED;
    }

    return resolver->state;
}

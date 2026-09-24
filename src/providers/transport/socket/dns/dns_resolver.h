/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_DNS_RESOLVER_H
#define PN_DNS_RESOLVER_H

#include "providers/transport/socket/platform/pn_socket_platform_ops.h"
#include "providers/transport/socket/platform/pn_socket_types.h"

#include "pubnub/providers/platform.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @file dns_resolver.h
 * @brief Async DNS resolver with caching, server discovery, and failover.
 */

/** @brief Maximum number of cached hostname resolutions. */
#ifndef PUBNUB_CFG_DNS_CACHE_SIZE
#define PUBNUB_CFG_DNS_CACHE_SIZE 8
#endif

/** @brief Maximum addresses returned per hostname resolution. */
#ifndef PUBNUB_CFG_MAX_DNS_RESULTS
#define PUBNUB_CFG_MAX_DNS_RESULTS 8
#endif

/** @brief Maximum DNS servers to query (discovered + fallback). */
#ifndef PUBNUB_CFG_MAX_DNS_SERVERS
#define PUBNUB_CFG_MAX_DNS_SERVERS 8
#endif

/** @brief Maximum hostname length (including NUL terminator). */
#ifndef PUBNUB_CFG_MAX_HOSTNAME_LEN
#define PUBNUB_CFG_MAX_HOSTNAME_LEN 64
#endif

/**
 * @brief DNS resolver states.
 *
 * The resolver state machine progresses from IDLE → QUERY_SENT → WAITING →
 * DONE/FAILED. ROTATING indicates server failover after timeout.
 */
typedef enum {
    PN_DNS_STATE_IDLE = 0,   /**< No query in progress. */
    PN_DNS_STATE_QUERY_SENT, /**< Queries sent to current server. */
    PN_DNS_STATE_WAITING,    /**< Awaiting response or timeout. */
    PN_DNS_STATE_ROTATING,   /**< Rotating to next server after timeout. */
    PN_DNS_STATE_DONE,       /**< Resolution complete, results available. */
    PN_DNS_STATE_FAILED      /**< All servers exhausted, no resolution. */
} pn_dns_state_t;

/**
 * @brief Cache entry for a resolved hostname.
 *
 * Stores the hostname, resolved addresses, TTL, and insertion timestamp.
 * Entries expire when (current_time - timestamp) > ttl_sec.
 */
typedef struct pn_dns_cache_entry {
    char          hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN]; /**< NUL-terminated. */
    pn_sockaddr_t addrs[PUBNUB_CFG_MAX_DNS_RESULTS]; /**< Resolved addresses. */
    size_t        addr_count;   /**< Number of addresses. */
    uint32_t      ttl_sec;      /**< TTL in seconds. */
    uint64_t      timestamp_ms; /**< Insertion time (monotonic ms). */
} pn_dns_cache_entry_t;

/**
 * @brief DNS resolver instance.
 *
 * Manages a persistent UDP socket, server list, resolution cache, and current
 * query state. Stack-allocatable; all arrays sized by PUBNUB_CFG_* macros.
 *
 * Stack-allocatable; all arrays sized by PUBNUB_CFG_* macros.
 * Typical sizes:
 * - Default config (cache=8, results=8, servers=8): ~2464 bytes
 * - Embedded config (cache=2, results=4, servers=4): ~700 bytes
 *
 * For constrained targets, override defaults via CMake:
 * -DPUBNUB_CFG_DNS_CACHE_SIZE=2 -DPUBNUB_CFG_MAX_DNS_RESULTS=4
 * -DPUBNUB_CFG_MAX_DNS_SERVERS=4
 */
typedef struct pn_dns_resolver {
    pn_socket_t udp_socket; /**< Persistent UDP socket for DNS queries (IPv4). */
    pn_socket_t udp_socket_v6; /**< Persistent UDP socket for DNS queries (IPv6). */

    pn_sockaddr_t servers[PUBNUB_CFG_MAX_DNS_SERVERS]; /**< DNS server list. */
    size_t        server_count;        /**< Active server count. */
    uint64_t server_list_timestamp_ms; /**< Last refresh time (monotonic ms). */
    uint8_t  server_list_invalid;      /**< 1 = needs refresh, 0 = valid. */

#if PUBNUB_ENABLE_CUSTOM_DNS
    /** Pointer to user-supplied servers (owned by transport, not freed here). */
    const pn_sockaddr_t* user_servers;
    /** Published server count; acquire/release atomic for lock-free
     *  visibility from the setter thread to the poll thread. */
    PUBNUB_ATOMIC_UINT8 user_server_count;
#endif

    pn_dns_cache_entry_t cache[PUBNUB_CFG_DNS_CACHE_SIZE]; /**< Resolution cache. */

    pn_dns_state_t state; /**< Current state machine state. */
    char current_hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN]; /**< Query hostname. */
    size_t        current_server_idx; /**< Index in servers array. */
    uint64_t      deadline_ms;        /**< Query timeout deadline. */
    uint16_t      txn_id_a;           /**< Transaction ID for A query. */
    uint16_t      txn_id_aaaa;        /**< Transaction ID for AAAA query. */
    uint8_t       got_a_response;     /**< 1 = A received, 0 = not yet. */
    uint8_t       got_aaaa_response;  /**< 1 = AAAA received, 0 = not yet. */
    pn_sockaddr_t result_addrs[PUBNUB_CFG_MAX_DNS_RESULTS]; /**< Results. */
    size_t        result_count;          /**< Number of results. */
    uint32_t      result_ttl;            /**< Minimum TTL across responses. */

    const pn_socket_platform_ops_t* ops; /**< Platform ops vtable. */
    struct pubnub_platform_provider* platform; /**< Platform provider for random/time. */

    /**
     * Per-instance platform DNS state buffer.
     *
     * Holds the platform-specific DNS resolution state (e.g., result
     * arrays, completion flags, async handles). Eliminates file-scope
     * static state so multiple resolver instances can operate
     * concurrently without corruption. Passed as dns_ctx to all
     * dns_resolve_* vtable calls.
     *
     * Only present when using platform-native DNS (custom DNS OFF).
     * When custom DNS is enabled, the resolver uses its own UDP socket
     * and the platform provides dns_discover_servers only.
     *
     * Conditionally compiled: sizeof(pn_dns_resolver_t) depends on
     * PUBNUB_ENABLE_CUSTOM_DNS. This struct is internal (never in
     * public headers), so layout variation is acceptable.
     */
#if !PUBNUB_ENABLE_CUSTOM_DNS
    union {
        uint8_t  raw[PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE];
        void*    _align_ptr;
        uint64_t _align_u64;
    } platform_dns_state;
#endif
} pn_dns_resolver_t;

/**
 * @brief Initialize a DNS resolver instance.
 *
 * Creates a persistent non-blocking UDP socket for DNS queries. The socket is
 * reused across all queries and must be explicitly registered in the
 * transport's poll set by the caller.
 *
 * @param resolver Resolver instance (caller-allocated).
 * @param ops      Platform ops vtable (must remain valid for resolver
 * lifetime).
 * @param platform Platform provider (must remain valid for resolver lifetime).
 * @retval 0 on success.
 * @retval -1 on socket creation/setup failure.
 */
int pn_dns_resolver_init(pn_dns_resolver_t*               resolver,
                         const pn_socket_platform_ops_t*  ops,
                         struct pubnub_platform_provider* platform);

/**
 * @brief Deinitialize a DNS resolver instance.
 *
 * Closes the UDP socket and releases any associated resources. Safe to call
 * multiple times (subsequent calls are no-ops).
 *
 * @param resolver Resolver instance.
 */
void pn_dns_resolver_deinit(pn_dns_resolver_t* resolver);

/**
 * @brief Start a DNS resolution for a hostname.
 *
 * Checks the cache first. If the hostname is cached and TTL is valid, the
 * resolver transitions to DONE immediately. Otherwise, refreshes the server
 * list (if needed), sends A and AAAA queries to the first server, and
 * transitions to QUERY_SENT.
 *
 * @param resolver Resolver instance (must be in IDLE state).
 * @param hostname NUL-terminated hostname (max PUBNUB_CFG_MAX_HOSTNAME_LEN -
 * 1).
 * @retval 0 on success (queries sent or cache hit).
 * @retval -1 on validation/socket error.
 */
int pn_dns_resolver_start(pn_dns_resolver_t* resolver, const char* hostname);

/**
 * @brief Tick the DNS resolver state machine.
 *
 * Drives the resolver forward: checks for UDP responses when in WAITING,
 * rotates to the next server on timeout, and transitions to DONE/FAILED.
 * Call this function on each poll iteration (typically when the UDP socket is
 * readable or after a timeout).
 *
 * @param resolver Resolver instance.
 * @return Current state after the tick (PN_DNS_STATE_*).
 * @note NOT ISR-safe. This function performs socket I/O and state mutations;
 *       it must be called from a task/thread context, not from an interrupt
 *       handler. For RTOS targets, call from the network task that owns the
 *       poll loop.
 */
pn_dns_state_t pn_dns_resolver_tick(pn_dns_resolver_t* resolver);

/**
 * @brief Retrieve resolved addresses after successful resolution.
 *
 * Call after the resolver reaches DONE state. Results are valid until the next
 * pn_dns_resolver_start() call or until the resolver is deinitialized.
 *
 * @param resolver   Resolver instance (must be in DONE state).
 * @param addrs_out  Output array for resolved addresses.
 * @param max_addrs  Capacity of addrs_out.
 * @param out_count  Number of addresses written (valid only when return is 0).
 * @retval 0 on success.
 * @retval -1 if resolver is not in DONE state or max_addrs is too small.
 */
int pn_dns_resolver_get_results(const pn_dns_resolver_t* resolver,
                                pn_sockaddr_t*           addrs_out,
                                size_t                   max_addrs,
                                size_t*                  out_count);

/**
 * @brief Invalidate a cached hostname.
 *
 * Removes the hostname from the cache and marks the server list for refresh.
 * Use this when a connection to a resolved address fails (e.g., TCP connect
 * timeout), forcing a fresh DNS lookup on the next resolution attempt.
 *
 * @param resolver Resolver instance.
 * @param hostname NUL-terminated hostname to invalidate.
 */
void pn_dns_resolver_invalidate(pn_dns_resolver_t* resolver, const char* hostname);

/**
 * @brief Get the resolver's UDP socket for external poll integration.
 *
 * The caller must add this socket to their poll set and monitor for
 * PN_POLL_READ events. When readable, call pn_dns_resolver_tick() to process
 * incoming responses.
 *
 * @param resolver Resolver instance.
 * @return UDP socket handle (PN_INVALID_SOCKET if not initialized).
 */
pn_socket_t pn_dns_resolver_socket(const pn_dns_resolver_t* resolver);

/**
 * @brief Get the resolver's IPv6 UDP socket for external poll integration.
 *
 * Returns the IPv6 DNS socket, or PN_INVALID_SOCKET if IPv6 was unavailable
 * at init time. When valid, add this socket to the poll set alongside the
 * IPv4 socket returned by pn_dns_resolver_socket().
 *
 * @param resolver Resolver instance.
 * @return IPv6 UDP socket handle (PN_INVALID_SOCKET if not available).
 */
pn_socket_t pn_dns_resolver_socket_v6(const pn_dns_resolver_t* resolver);

/**
 * @brief Get the current resolver state.
 *
 * @param resolver Resolver instance.
 * @return Current state (PN_DNS_STATE_*).
 */
pn_dns_state_t pn_dns_resolver_state(const pn_dns_resolver_t* resolver);

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_DNS_CACHE_SIZE >= 1,
                     "DNS cache size must be at least 1");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_DNS_RESULTS >= 1,
                     "Max DNS results must be at least 1");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_DNS_SERVERS >= 1,
                     "Max DNS servers must be at least 1");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_HOSTNAME_LEN >= 8,
                     "Max hostname length must be at least 8");

#endif /* PN_DNS_RESOLVER_H */

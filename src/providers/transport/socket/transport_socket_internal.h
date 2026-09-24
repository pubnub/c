/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TRANSPORT_SOCKET_INTERNAL_H
#define PN_TRANSPORT_SOCKET_INTERNAL_H

#include "connection_fsm_internal.h"
#include "dns/dns_resolver.h"
#include "providers/transport/socket/platform/pn_socket_platform_ops.h"
#include "providers/transport/socket/platform/pn_socket_types.h"
#include "proxy/proxy_interface.h"
#include "tls/pn_tls_backend.h"

#include "pubnub/config.h"
#include "pubnub/pubnub_compat.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Socket-based transport provider implementation.
 *
 * Wraps a connection pool, DNS resolver, and poll set into a full
 * pubnub_transport_provider_t. The vtable is the first member so
 * that a `pubnub_transport_provider_t*` can be cast directly to
 * `pn_socket_transport_t*`.
 *
 * The connection pool is fixed-size, with one slot per in-flight
 * request. Connections support HTTP/1.1 keep-alive reuse.
 */
struct pn_socket_transport {
    /** Transport vtable (MUST be first member for cast trick). */
    pubnub_transport_provider_t vtable;

    /**
     * Connection pool. One slot per in-flight request. Each slot
     * drives a single HTTP request through the connection FSM.
     */
    pn_socket_connection_t connections[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];

    /** DNS resolver (shared across all connections). */
    pn_dns_resolver_t resolver;

    /** Poll set (monitors all active sockets + DNS UDP socket). */
    pn_poll_set_t poll_set;

    /** Platform socket operations vtable. Immutable after init. */
    const pn_socket_platform_ops_t* ops;

    /** TLS backend vtable (NULL if TLS disabled at compile time). */
    pn_tls_backend_t* tls_backend;

    /** Long-lived TLS context (NULL if TLS disabled or not created). */
    void* tls_ctx;

    /** Platform provider for time/random. */
    struct pubnub_platform_provider* platform;

    /** Allocator provider. */
    struct pubnub_allocator_provider* allocator;

    /** Logger provider (may be NULL). */
    struct pubnub_logger_provider* logger;

    /** Proxy module for HTTP CONNECT tunneling (NULL if no proxy). */
    pn_proxy_module_t* proxy_module;

    /**
     * Internal proxy config (copied from public config at init).
     * Stored here so the proxy module can reference it for the
     * transport lifetime without depending on external ownership.
     */
    pn_proxy_config_t proxy_config_stored;

    /** TCP keepalive configuration applied to new connections. */
    pubnub_tcp_keepalive_config_t keepalive_config;

#if PUBNUB_ENABLE_CUSTOM_DNS
    /** User-supplied DNS server addresses (parsed at set time). */
    pn_sockaddr_t user_servers[2];

    /** Number of valid entries in user_servers (0, 1, or 2). */
    uint8_t user_server_count;
#endif

    /** TLS configuration (stored for ctx_create).
     *  Only accessed from the poll thread after init. */
    pn_tls_config_t tls_config;

    /**
     * Pending CA PEM set by the user thread via set_tls_ca_bundle.
     * The poll thread swaps it into tls_config.ca_pem inside
     * socket_apply_pending_tls_config, avoiding a concurrent
     * free-while-read on the PEM buffer during ctx_create.
     *
     * Check pending_ca_pem_set to distinguish "no update" from
     * "user explicitly set NULL." Ownership: allocator-owned once
     * stored; the poll thread frees the old ca_pem after the swap.
     */
    const char* pending_ca_pem;

    /** 1 = pending_ca_pem holds a new value (possibly NULL). */
    uint8_t pending_ca_pem_set;

    /**
     * Pending skip_verify value. 0xFF = no pending update (sentinel);
     * 0 or 1 = pending value to apply on the poll thread.
     */
    uint8_t pending_skip_verify;

    /**
     * Written by the user thread (set_tls_ca_bundle / set_tls_verify) and read
     * by the bg poll thread in pn_connection_start. Atomic to ensure visibility
     * across cores on SMP targets (e.g., ESP32-S3 dual Cortex-A9).
     */
    PUBNUB_ATOMIC_UINT8 tls_ctx_stale;

    /** Self-pipe read end (registered in poll set for wake). */
    pn_socket_t wake_pipe_rd;

    /** Self-pipe write end (written by wake()). */
    pn_socket_t wake_pipe_wr;

    /** 1 if init() has been called successfully, 0 otherwise. */
    uint8_t initialized;
};

/**
 * @brief Create a socket transport provider instance.
 *
 * Allocates a pn_socket_transport_t and populates the vtable. The
 * instance is not fully usable until init() is called by the SDK
 * core during context initialization.
 *
 * @param ops        Platform socket operations vtable (must remain
 *                   valid for the transport lifetime).
 * @param tls_backend TLS backend vtable (NULL to disable TLS).
 * @param tls_config TLS configuration (copied; may be NULL if
 *                   tls_backend is NULL).
 * @param keepalive  TCP keepalive settings (copied; NULL uses
 *                   defaults).
 * @param allocator  Allocator for the transport struct itself.
 * @return Transport provider pointer, or NULL on allocation failure.
 */
pubnub_transport_provider_t*
pn_socket_transport_create(const pn_socket_platform_ops_t*      ops,
                           pn_tls_backend_t*                    tls_backend,
                           const pn_tls_config_t*               tls_config,
                           const pubnub_tcp_keepalive_config_t* keepalive,
                           struct pubnub_allocator_provider*    allocator);

/**
 * @brief Destroy a socket transport provider instance.
 *
 * Calls deinit() if still initialized, then frees the struct via the
 * allocator that was passed to create.
 *
 * @param transport Transport provider pointer (NULL-safe).
 * @param allocator Allocator used during create.
 */
void pn_socket_transport_destroy(pubnub_transport_provider_t*      transport,
                                 struct pubnub_allocator_provider* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_TRANSPORT_SOCKET_INTERNAL_H */

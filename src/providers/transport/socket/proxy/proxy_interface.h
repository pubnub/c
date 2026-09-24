/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PROXY_INTERFACE_H
#define PN_PROXY_INTERFACE_H

#include "providers/transport/socket/platform/pn_socket_types.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @file proxy_interface.h
 * @brief Pluggable HTTP proxy module interface for CONNECT tunneling.
 */

/* Forward declarations */
typedef struct pn_socket_connection pn_socket_connection_t;
typedef struct pn_socket_transport  pn_socket_transport_t;
struct pubnub_allocator_provider;

/**
 * @brief Proxy negotiation result.
 */
typedef enum {
    /** Proxy tunnel established successfully. */
    PN_PROXY_COMPLETE = 0,
    /** Negotiation ongoing (call tick again). */
    PN_PROXY_IN_PROGRESS = 1,
    /** Negotiation failed. */
    PN_PROXY_ERROR = -1
} pn_proxy_result_t;

/**
 * @brief Proxy authentication type.
 */
typedef enum {
    /** No authentication required. */
    PN_PROXY_AUTH_NONE = 0,
    /** HTTP Basic authentication (RFC 7617). */
    PN_PROXY_AUTH_BASIC = 1,
    /** HTTP Digest authentication (RFC 7616). */
    PN_PROXY_AUTH_DIGEST = 2,
    /** NTLM authentication (Microsoft proprietary). */
    PN_PROXY_AUTH_NTLM = 3
} pn_proxy_auth_t;

/**
 * @brief Proxy configuration.
 *
 * Describes the proxy server and authentication credentials.
 * All string fields are NUL-terminated and must remain valid for the
 * lifetime of the proxy module.
 */
typedef struct pn_proxy_config {
    /** Proxy hostname (NUL-terminated). */
    const char* host;
    /** Proxy port. */
    uint16_t port;
    /** Authentication method. */
    pn_proxy_auth_t auth_type;
    /** Auth username (NULL if none). */
    const char* username;
    /** Auth password (NULL if none). */
    const char* password;
} pn_proxy_config_t;

/**
 * @brief Proxy module interface.
 *
 * Pluggable module for HTTP proxy negotiation (CONNECT tunneling).
 * The connection FSM calls negotiate_start() when entering
 * PN_CONN_PROXY_NEGOTIATING, then calls negotiate_tick() on each
 * poll iteration until COMPLETE or ERROR.
 *
 * Future implementations will support Basic, Digest, and NTLM auth
 * with WPAD/PAC auto-discovery.
 *
 * All callbacks are invoked outside ISR context and must be non-blocking.
 * The socket is in non-blocking mode during negotiation.
 */
typedef struct pn_proxy_module {
    /**
     * @brief Start proxy negotiation.
     *
     * Sends HTTP CONNECT request to the proxy server to establish
     * a tunnel to the target host:port. The socket is already connected
     * to the proxy server when this is called.
     *
     * @param self         Proxy module instance.
     * @param conn         Connection slot (socket connected to proxy).
     * @param transport    Transport context (for I/O helpers).
     * @param target_host  Target hostname to tunnel to (NUL-terminated).
     * @param target_port  Target port to tunnel to.
     * @return PN_PROXY_IN_PROGRESS on success, PN_PROXY_ERROR on failure.
     */
    pn_proxy_result_t (*negotiate_start)(struct pn_proxy_module* self,
                                         pn_socket_connection_t* conn,
                                         pn_socket_transport_t*  transport,
                                         const char*             target_host,
                                         uint16_t                target_port);

    /**
     * @brief Drive proxy negotiation forward (non-blocking).
     *
     * Called on each poll tick while in PN_CONN_PROXY_NEGOTIATING state.
     * Continues sending/receiving proxy protocol data until the tunnel
     * is established or negotiation fails.
     *
     * @param self       Proxy module instance.
     * @param conn       Connection slot.
     * @param transport  Transport context.
     * @return PN_PROXY_COMPLETE when tunnel ready, PN_PROXY_IN_PROGRESS
     *         to continue, PN_PROXY_ERROR on failure.
     */
    pn_proxy_result_t (*negotiate_tick)(struct pn_proxy_module* self,
                                        pn_socket_connection_t* conn,
                                        pn_socket_transport_t*  transport);

    /**
     * @brief Destroy the proxy module and free resources.
     *
     * Called during transport cleanup or when proxy negotiation completes.
     * Safe to call with NULL self.
     *
     * @param self       Proxy module instance (may be NULL).
     * @param allocator  Allocator for deallocation.
     */
    void (*destroy)(struct pn_proxy_module*           self,
                    struct pubnub_allocator_provider* allocator);
} pn_proxy_module_t;

#endif /* PN_PROXY_INTERFACE_H */

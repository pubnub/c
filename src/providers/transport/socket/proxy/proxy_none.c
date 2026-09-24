/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file proxy_none.c
 * @brief No-op proxy module for direct connections (no proxy).
 *
 * Used as the default when no proxy is configured. All operations
 * return immediate success — the connection FSM skips proxy negotiation
 * and proceeds directly to TLS handshake (if enabled) or HTTP exchange.
 */

#include "proxy_interface.h"
#include <stddef.h>

/**
 * @brief Start proxy negotiation (no-op).
 *
 * Direct connection mode — no proxy negotiation needed.
 * Returns PN_PROXY_COMPLETE immediately so the FSM skips the
 * PN_CONN_PROXY_NEGOTIATING state.
 *
 * @param self         Proxy module instance (unused).
 * @param conn         Connection slot (unused).
 * @param transport    Transport context (unused).
 * @param target_host  Target hostname (unused).
 * @param target_port  Target port (unused).
 * @return PN_PROXY_COMPLETE always.
 */
static pn_proxy_result_t pn_proxy_none_negotiate_start(struct pn_proxy_module* self,
                                                       pn_socket_connection_t* conn,
                                                       pn_socket_transport_t* transport,
                                                       const char* target_host,
                                                       uint16_t    target_port)
{
    (void)self;
    (void)conn;
    (void)transport;
    (void)target_host;
    (void)target_port;

    return PN_PROXY_COMPLETE;
}

/**
 * @brief Drive proxy negotiation forward (no-op).
 *
 * Should never be called in direct connection mode (FSM skips
 * PN_CONN_PROXY_NEGOTIATING when negotiate_start returns COMPLETE).
 * Returns COMPLETE defensively if invoked.
 *
 * @param self       Proxy module instance (unused).
 * @param conn       Connection slot (unused).
 * @param transport  Transport context (unused).
 * @return PN_PROXY_COMPLETE always.
 */
static pn_proxy_result_t pn_proxy_none_negotiate_tick(struct pn_proxy_module* self,
                                                      pn_socket_connection_t* conn,
                                                      pn_socket_transport_t* transport)
{
    (void)self;
    (void)conn;
    (void)transport;

    return PN_PROXY_COMPLETE;
}

/**
 * @brief Destroy the proxy module (no-op).
 *
 * No resources to free for the no-op module.
 * Safe to call with NULL self.
 *
 * @param self       Proxy module instance (unused).
 * @param allocator  Allocator (unused).
 */
static void pn_proxy_none_destroy(struct pn_proxy_module*           self,
                                  struct pubnub_allocator_provider* allocator)
{
    (void)self;
    (void)allocator;
}

/**
 * @brief No-op proxy module vtable.
 *
 * Use this when no proxy is configured. All operations return
 * immediate success — direct connection mode.
 */
// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_proxy_module_t pn_proxy_none = {
    .negotiate_start = pn_proxy_none_negotiate_start,
    .negotiate_tick  = pn_proxy_none_negotiate_tick,
    .destroy         = pn_proxy_none_destroy};

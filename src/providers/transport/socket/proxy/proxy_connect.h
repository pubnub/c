/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file proxy_connect.h
 * @brief HTTP CONNECT tunnel proxy module.
 *
 * Implements `pn_proxy_module_t` for establishing an HTTP CONNECT
 * tunnel through an upstream proxy server with optional Basic
 * (RFC 7617), Digest (RFC 7616), or NTLM (NTLMv2) authentication.
 */

#ifndef PN_PROXY_CONNECT_H
#define PN_PROXY_CONNECT_H

#include "proxy_interface.h"

struct pubnub_allocator_provider;

/**
 * @brief Upper bound for the proxy CONNECT session struct size.
 *
 * Scrub/free ownership of the session lives in proxy_connect.c via
 * pn_proxy_connect_session_destroy(), which scrubs the exact struct
 * size. This macro remains as the compile-time budget validated by a
 * static assert in proxy_connect.c: the 2048 budget covers NTLM session
 * state, challenge/response buffers, and UTF-16 credential encoding
 * workspace. It must not be used as a scrub length — the session block
 * is allocated at sizeof(struct), which is smaller than this bound.
 */
#define PN_PROXY_CONNECT_SESSION_SIZE 2048

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Create an HTTP CONNECT proxy module.
 *
 * Allocates and initializes a proxy module that performs HTTP CONNECT
 * tunneling with optional Basic authentication. The returned module
 * implements the `pn_proxy_module_t` vtable.
 *
 * @param config    Proxy configuration (host, port, auth credentials).
 *                  The config must remain valid for the module lifetime.
 * @param allocator Allocator for the module struct. Must remain valid
 *                  until destroy() is called.
 * @return Proxy module pointer, or NULL on allocation failure.
 */
pn_proxy_module_t* pn_proxy_connect_create(const pn_proxy_config_t* config,
                                           struct pubnub_allocator_provider* allocator);

/**
 * @brief Securely scrub and free a proxy CONNECT session.
 *
 * Zeroes the exact session-struct byte count (credential-sensitive
 * challenge/response and NTLM workspace) before returning the block to
 * the allocator. Owns the scrub length internally — callers must not
 * pass a size, avoiding the over-scrub that a shared upper-bound
 * constant would cause.
 *
 * @param session   Session block returned by the negotiation path, or
 *                   NULL (no-op). Must have been allocated by this module.
 * @param allocator Allocator that owns @p session. When NULL, or when it
 *                   exposes no free() hook, the block is still scrubbed but
 *                   not reclaimed (arena allocators reclaim on reset).
 */
void pn_proxy_connect_session_destroy(void* session,
                                      struct pubnub_allocator_provider* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PROXY_CONNECT_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file keepalive.h
 * @brief HTTP/1.1 connection keep-alive and reuse logic.
 */

#ifndef PN_KEEPALIVE_H
#define PN_KEEPALIVE_H

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Snapshot of current connection state for keep-alive evaluation.
 */
typedef struct pn_keepalive_conn_state {
    /** Host the connection is currently connected to (NUL-terminated). */
    const char* host;
    /** Port of the current connection. */
    uint16_t port;
    /** 1 if connection is TLS, 0 if plaintext. */
    uint8_t secure;
    /** Number of requests already served on this connection. */
    uint16_t requests_served;
    /** Monotonic timestamp (ms) when connection became idle. */
    uint64_t idle_since_ms;
} pn_keepalive_conn_state_t;

/**
 * @brief Requested connection target for a new request.
 */
typedef struct pn_keepalive_target {
    /** Host for the new request (NUL-terminated). */
    const char* host;
    /** Port for the new request. */
    uint16_t port;
    /** 1 if new request requires TLS, 0 if plaintext. */
    uint8_t secure;
} pn_keepalive_target_t;

/**
 * @brief Check if a connection can be reused for a new request.
 *
 * Validates that the existing connection matches the new request's
 * host, port, and TLS state, and that keep-alive limits (max requests,
 * idle timeout) have not been exceeded.
 *
 * @param conn
 *        Current connection state. Must not be NULL.
 * @param target
 *        Requested connection target. Must not be NULL.
 * @param now_ms
 *        Current monotonic time (ms).
 * @param max_requests
 *        Maximum requests per connection (e.g., 1000).
 * @param max_idle_ms
 *        Maximum idle time in milliseconds (e.g., 50000).
 * @return
 *        1 if connection can be reused, 0 if not.
 */
int pn_keepalive_can_reuse(const pn_keepalive_conn_state_t* conn,
                           const pn_keepalive_target_t*     target,
                           uint64_t                         now_ms,
                           uint16_t                         max_requests,
                           uint32_t                         max_idle_ms);

/**
 * @brief Determine if a response indicates connection should be closed.
 *
 * Checks the HTTP parser flags for Connection: close.
 *
 * @param parser_flags
 *        Flags from pn_http_parser_t (PN_HTTP_FLAG_*).
 * @return
 *        1 if connection should be closed, 0 if keep-alive is OK.
 */
int pn_keepalive_should_close(uint8_t parser_flags);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_KEEPALIVE_H */

/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CONNECTION_FSM_INTERNAL_H
#define PN_CONNECTION_FSM_INTERNAL_H

#include "http_parser.h"
#include "providers/transport/socket/platform/pn_socket_types.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Forward declaration for the owning transport instance. */
typedef struct pn_socket_transport pn_socket_transport_t;

/**
 * @brief Connection FSM states.
 *
 * Drives a single HTTP request through DNS, TCP connect, optional TLS,
 * request send, and response receive. Terminal states: COMPLETE, FAILED,
 * CANCELLED.
 */
typedef enum {
    PN_CONN_IDLE = 0,
    PN_CONN_DNS_RESOLVING,
    PN_CONN_CONNECTING,
    PN_CONN_PROXY_NEGOTIATING,
    PN_CONN_TLS_HANDSHAKING,
    PN_CONN_SENDING_HEADERS,
    PN_CONN_SENDING_BODY,
    PN_CONN_RECEIVING_RESPONSE,
    PN_CONN_COMPLETE,
    PN_CONN_FAILED,
    PN_CONN_CLOSING,
    PN_CONN_KEEP_ALIVE_IDLE,
    PN_CONN_CANCELLED
} pn_conn_state_t;

/** @brief Maximum DNS result addresses stored per connection. */
#ifndef PUBNUB_CFG_MAX_DNS_RESULTS
#define PUBNUB_CFG_MAX_DNS_RESULTS 8
#endif

/** @brief Maximum hostname length including NUL. */
#ifndef PUBNUB_CFG_MAX_HOSTNAME_LEN
#define PUBNUB_CFG_MAX_HOSTNAME_LEN 64
#endif

/** @brief Header serialization buffer size. */
#ifndef PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE
#define PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE 512
#endif

/** @brief Default connect timeout (TCP + TLS) in milliseconds. */
#ifndef PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS
#define PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS 10000
#endif

/**
 * @brief Platform-portable error classification.
 *
 * Platform ops return negated errno (POSIX) or negated WSA error (Windows).
 * These helpers classify whether a connect error means the address family
 * is unreachable (triggering family-skip failover).
 */
static inline int pn_is_family_unreachable(int err)
{
    /* err is negative (from platform ops). Convert to positive for matching. */
    int code = (err < 0) ? -err : err;
    /* POSIX: ENETUNREACH=101 (Linux), 51 (macOS/BSD), EHOSTUNREACH=113 (Linux),
     * 65 (macOS/BSD) Windows: WSAENETUNREACH=10051, WSAEHOSTUNREACH=10065 */
    return (101 == code || 51 == code || 113 == code || 65 == code
            || 10051 == code || 10065 == code);
}

static inline int pn_is_connection_refused(int err)
{
    int code = (err < 0) ? -err : err;
    /* POSIX: ECONNREFUSED=111 (Linux), 61 (macOS/BSD)
     * Windows: WSAECONNREFUSED=10061 */
    return (111 == code || 61 == code || 10061 == code);
}

/**
 * @brief Per-connection state machine for the socket transport.
 *
 * Stack-allocatable. One instance per in-flight request slot. Drives
 * a single HTTP request from DNS resolution through response receipt.
 * The transport owns an array of these, sized by
 * PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS.
 */
typedef struct pn_socket_connection {
    /** Current FSM state. */
    pn_conn_state_t state;

    /** TCP socket handle (PN_INVALID_SOCKET when not connected). */
    pn_socket_t socket;

    /** TLS session (NULL when plaintext or not yet established). */
    void* tls_session;

    /** Resolved DNS addresses for the current request. */
    pn_sockaddr_t resolved_addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    /** Number of valid addresses in resolved_addrs. */
    uint8_t addr_count;
    /** Index of the address currently being tried. */
    uint8_t addr_current;
    /**
     * @brief Bitmask of exhausted address families.
     *
     * When an ENETUNREACH/EHOSTUNREACH error occurs on a specific family,
     * that family's bit is set to skip remaining addresses of the same
     * family. Bits: 0x01 = PN_AF_INET exhausted, 0x02 = PN_AF_INET6.
     */
    uint8_t family_exhausted;

    /** Serialized HTTP headers (request-line + headers + CRLF). */
    uint8_t header_buf[PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE];
    /** Total bytes of serialized headers in header_buf. */
    uint16_t header_len;
    /** Bytes of headers already sent. */
    uint16_t header_sent;
    /** Bytes of body already sent. */
    size_t body_sent;

    /**
     * @brief Receive buffer (owned by transport allocator).
     *
     * Grown on demand via @c buf_grow when the response exceeds the
     * initial capacity. On allocators without @c buf_grow (embedded arenas),
     * overflow fails with @c PUBNUB_ERR_BUFFER_TOO_SMALL.
     */
    pubnub_buffer_t rx_buf;

    /** Incremental HTTP response parser. */
    pn_http_parser_t parser;

    /** Deadline for TCP connect + TLS handshake (monotonic ms). */
    uint64_t connect_deadline_ms;
    /** Deadline for the entire transaction (monotonic ms). */
    uint64_t transaction_deadline_ms;

    /** Host this socket is currently connected to (keep-alive). */
    char connected_host[PUBNUB_CFG_MAX_HOSTNAME_LEN];
    /** Port of the current connection. */
    uint16_t connected_port;
    /** 1 if current connection uses TLS. */
    uint8_t connected_secure;
    /** Number of requests completed on this connection. */
    uint16_t requests_on_connection;
    /**
     * @brief 1 after a keep-alive stale-socket retry has already been
     *        attempted for the current request.
     *
     * Prevents infinite retry loops: when a send error occurs on a
     * reused keep-alive connection, the FSM closes the socket and
     * restarts the full DNS/TCP/TLS cycle once. If the retry also
     * fails with a send error, the request fails normally.
     */
    uint8_t keepalive_retry_used;
    /** Monotonic timestamp when connection became idle (keep-alive). */
    uint64_t idle_since_ms;

    /** Borrowed pointer to the current request (valid during active). */
    const pubnub_http_request_t* request;
    /** Borrowed pointer to the response descriptor to populate. */
    pubnub_http_response_t* response;

    /**
     * @brief Decompression output buffer (allocated when response is
     *        Content-Encoding gzip/deflate).
     *
     * Allocated after HTTP parsing completes when the parser flags indicate
     * a compressed payload. Freed in pn_connection_reset. The response body
     * pointers are redirected into this buffer after successful inflate.
     */
    uint8_t* decomp_buf;

    /**
     * @brief Hostname for DNS resolution (stored for deferred retry).
     *
     * When the shared DNS resolver is busy at send() time, the connection
     * enters DNS_RESOLVING and retries on subsequent ticks once the
     * resolver returns to IDLE. This field holds the target hostname
     * (or proxy hostname) so the retry can call pn_dns_resolver_start.
     */
    char dns_hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN];

    /**
     * @brief Per-connection proxy negotiation session state.
     *
     * Non-NULL when a connection is in PROXY_NEGOTIATING state. Allocated
     * at negotiate_start and freed on COMPLETE/ERROR or when the connection
     * is cancelled/reset. Holds per-negotiation buffers and progress state.
     */
    void* proxy_session;

    /**
     * @brief Number of HTTP redirects followed for the current request.
     *
     * Incremented on each 3xx redirect when follow_redirects is set.
     * Capped at PUBNUB_CFG_SOCKET_MAX_REDIRECTS to prevent infinite
     * redirect loops; stays 0 when that cap is 0 (redirects compiled out).
     */
    uint8_t redirect_count;

    /**
     * @brief Whether the redirect target uses HTTPS.
     *
     * Set when processing a Location header from a 3xx response.
     * Controls TLS negotiation and default port for the redirect
     * target connection.
     */
    uint8_t redirect_secure;

    /**
     * @brief Explicit port from the redirect Location URL.
     *
     * Non-zero when the Location URL contained an explicit port
     * (e.g. `https://host:8443/path`). Zero means use the scheme
     * default (443 for HTTPS, 80 for HTTP).
     */
    uint16_t redirect_port;

    /**
     * @brief 1 when proxy tunnel negotiation completed on this socket.
     *
     * Prevents re-negotiation when a deferred TLS handshake re-enters
     * conn_transition_after_connect via the CONNECTING tick loop.
     * Cleared when the socket is destroyed (conn_close_socket) since
     * the tunnel is gone with the socket.
     */
    uint8_t proxy_done;

    /**
     * @brief Heap-allocated redirect target host, or NULL if no redirect.
     *
     * Set when a 3xx response with a valid Location header is received.
     * Freed in pn_connection_reset. Allocated via transport allocator.
     */
    char* redirect_host;

    /**
     * @brief Heap-allocated redirect target path, or NULL if no redirect.
     *
     * Contains the full path and query string from the redirect URL
     * (without the leading '/') for use as a single HTTP path segment.
     * Freed in pn_connection_reset. Allocated via transport allocator.
     */
    char* redirect_path;

    /**
     * @brief Monotonically increasing generation counter for ABA safety.
     *
     * Incremented each time the slot is reset (returned to IDLE via
     * pn_connection_reset). Encoded into the opaque transport handle
     * returned by socket_send so that socket_cancel can detect stale
     * handles that reference a recycled connection slot. The 16-bit
     * counter wraps after 65536 reuse cycles per slot - negligible at
     * typical request rates.
     */
    uint16_t generation;
} pn_socket_connection_t;

/**
 * @brief Initialize a connection FSM to the idle state.
 *
 * Zero-initializes all fields and sets the socket to PN_INVALID_SOCKET.
 * Call once per slot during transport init.
 *
 * @param conn Connection instance (caller-allocated).
 */
void pn_connection_init(pn_socket_connection_t* conn);

/**
 * @brief Free the decompression buffer.
 *
 * The buffer comes from the allocator's general tier, so it must be
 * returned before the allocator is reset (arena deinit). Idempotent and
 * NULL-tolerant.
 *
 * No-op when the allocator exposes no free hook: such an allocator cannot
 * reclaim individual blocks, and clearing the pointer would strand the
 * block with no way to reach it again. Both bundled allocators (stdlib and
 * arena) do expose a free hook; the guard exists for a caller-supplied
 * allocator that does not.
 *
 * Declared here rather than kept file-static because the buffer is
 * owned by the connection but published by the transport's decompress
 * step, so both translation units need the same owner-side free.
 *
 * @param conn      Connection holding the buffer.
 * @param transport Owning transport instance (provides the allocator).
 */
void pn_conn_free_decomp_buf(pn_socket_connection_t* conn,
                             pn_socket_transport_t*  transport);

/**
 * @brief Start a new HTTP request on this connection.
 *
 * Checks for keep-alive reuse. If the existing connection matches the
 * new request's host/port/TLS and is within limits, skips DNS/connect/TLS
 * and transitions directly to SENDING_HEADERS. Otherwise starts DNS
 * resolution.
 *
 * @param conn      Connection instance (must be IDLE or KEEP_ALIVE_IDLE).
 * @param request   HTTP request descriptor (must remain valid until
 *                  terminal state).
 * @param response  Response descriptor to populate (must remain valid
 *                  until terminal state).
 * @param transport Owning transport instance (provides ops, TLS, etc.).
 * @return 0 on success, -1 on error (invalid state, header build failure).
 */
int pn_connection_start(pn_socket_connection_t*      conn,
                        const pubnub_http_request_t* request,
                        pubnub_http_response_t*      response,
                        pn_socket_transport_t*       transport);

/**
 * @brief Advance the connection state machine by one step.
 *
 * Non-blocking. Checks I/O readiness and deadlines, performs one unit
 * of work, and returns the new state. Call on every poll iteration for
 * connections that are not idle.
 *
 * @param conn      Connection instance.
 * @param transport Owning transport instance.
 * @return Current state after the tick.
 */
pn_conn_state_t pn_connection_tick(pn_socket_connection_t* conn,
                                   pn_socket_transport_t*  transport);

/**
 * @brief Cancel an in-progress request.
 *
 * Closes the socket and TLS session, sets the response to
 * PUBNUB_HTTP_ERROR with PUBNUB_ERR_CANCELLED, and transitions to
 * CANCELLED.
 *
 * @param conn      Connection instance.
 * @param transport Owning transport instance.
 */
void pn_connection_cancel(pn_socket_connection_t* conn,
                          pn_socket_transport_t*  transport);

/**
 * @brief Reset a connection to IDLE, closing any open resources.
 *
 * Closes socket and TLS session if open. Use to reclaim a slot after
 * a terminal state (COMPLETE, FAILED, CANCELLED) or to force-close a
 * keep-alive connection.
 *
 * @param conn      Connection instance.
 * @param transport Owning transport instance.
 */
void pn_connection_reset(pn_socket_connection_t* conn,
                         pn_socket_transport_t*  transport);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_CONNECTION_FSM_INTERNAL_H */

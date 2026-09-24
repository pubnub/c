/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "transport_socket_internal.h"

#include "http_builder.h"
#include "http_parser.h"
#include "keepalive.h"
#include "proxy/proxy_connect.h"

#include "core/pn_string.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

/** @brief Family-exhausted bitmask: IPv4 unreachable. */
#define PN_FAMILY_EXHAUSTED_V4 0x01
/** @brief Family-exhausted bitmask: IPv6 unreachable. */
#define PN_FAMILY_EXHAUSTED_V6 0x02
/* Redirect hop budget comes from PUBNUB_CFG_SOCKET_MAX_REDIRECTS. Zero
 * removes the redirect code entirely: following a hop needs a second
 * pubnub_http_request_t (~1KB of stack), which constrained targets that
 * never redirect should not have to budget for. */
#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS < 0 || PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 8
#error "PUBNUB_CFG_SOCKET_MAX_REDIRECTS must be 0..8"
#endif

static void conn_extract_hostname(const char* host, char* dst, size_t dst_size);
static const char* conn_effective_host(const pn_socket_connection_t* conn);

/**
 * @brief Close the socket and remove from poll if open.
 */
static void conn_close_socket(pn_socket_connection_t* conn,
                              pn_socket_transport_t*  transport)
{
    if (PN_INVALID_SOCKET != conn->socket) {
        transport->ops->socket_destroy(transport->ops, conn->socket);
        conn->socket = PN_INVALID_SOCKET;
    }
    conn->proxy_done = 0; /* proxy tunnel gone with the socket */
}

/**
 * @brief Destroy the TLS session if active.
 */
static void conn_destroy_tls(pn_socket_connection_t* conn,
                             pn_socket_transport_t*  transport)
{
    if (NULL != conn->tls_session && NULL != transport->tls_backend) {
        transport->tls_backend->session_destroy(conn->tls_session);
        conn->tls_session = NULL;
    }
}

/**
 * @brief Acquire a receive buffer from the allocator.
 *
 * @return 0 on success, -1 if allocation fails.
 */
static int conn_acquire_rx_buf(pn_socket_connection_t* conn,
                               pn_socket_transport_t*  transport)
{
    if (NULL != conn->rx_buf.data) {
        return 0; /* Already acquired (keep-alive reuse path). */
    }
    if (NULL == transport->allocator || NULL == transport->allocator->buf_acquire) {
        return -1;
    }
    conn->rx_buf =
        transport->allocator->buf_acquire(transport->allocator, PUBNUB_BUF_RX);
    if (NULL == conn->rx_buf.data || 0 == conn->rx_buf.cap) {
        conn->rx_buf = (pubnub_buffer_t){0};
        return -1;
    }
    conn->rx_buf.len = 0;
    return 0;
}

/**
 * @brief Release the receive buffer back to the allocator.
 */
static void conn_release_rx_buf(pn_socket_connection_t* conn,
                                pn_socket_transport_t*  transport)
{
    if (NULL != conn->rx_buf.data && NULL != transport->allocator
        && NULL != transport->allocator->buf_release) {
        transport->allocator->buf_release(transport->allocator, &conn->rx_buf);
        conn->rx_buf = (pubnub_buffer_t){0};
    }
}

/**
 * @brief Close transport resources only (TLS + socket), leaving rx_buf and
 *        decomp_buf intact for deferred consumption.
 *
 * Used by tick_closing (Connection: close path) where the response body
 * may still be read by a feature accessor after socket_poll returns.
 */
static void conn_close_transport(pn_socket_connection_t* conn,
                                 pn_socket_transport_t*  transport)
{
    conn_destroy_tls(conn, transport);
    conn_close_socket(conn, transport);
}

static uint64_t conn_now_ms(const pn_socket_transport_t* transport);

/**
 * @brief Close all connection resources (decomp_buf + TLS + socket + RX buffer).
 */
static void conn_close_all(pn_socket_connection_t* conn,
                           pn_socket_transport_t*  transport)
{
    /* Free decompression buffer first — it was allocated from the
     * general tier and must be returned before the allocator is
     * potentially reset (arena deinit). */
    pn_conn_free_decomp_buf(conn, transport);
    conn_destroy_tls(conn, transport);
    conn_close_socket(conn, transport);
    conn_release_rx_buf(conn, transport);
}

/**
 * @brief Mark the connection as failed with a transport error.
 *
 * Invalidates the DNS cache entry for the target hostname so that
 * subsequent connection attempts re-resolve instead of reusing a
 * potentially stale address until TTL expiry.
 */
static void conn_fail(pn_socket_connection_t* conn,
                      pn_socket_transport_t*  transport,
                      pubnub_res_t            error_code)
{
    PUBNUB_LOG(transport->logger,
               PUBNUB_LOG_LEVEL_WARNING,
               "conn[%d] connection failed: %u (%s)",
               (int)(conn - transport->connections),
               (unsigned)error_code,
               pubnub_res_str(error_code));
    conn_close_all(conn, transport);

    /* Only invalidate DNS cache on transport/network failures — not on OOM,
     * buffer overflow, or internal errors which have no bearing on DNS
     * validity. Use the effective host so that redirect-target DNS
     * entries are invalidated (not the original request host). */
    if (PUBNUB_ERR_TRANSPORT == error_code && NULL != conn->request
        && NULL != conn_effective_host(conn)) {
        char hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN];
        conn_extract_hostname(conn_effective_host(conn), hostname, sizeof(hostname));
        pn_dns_resolver_invalidate(&transport->resolver, hostname);
    }

    if (NULL != conn->response) {
        conn->response->completion      = PUBNUB_HTTP_ERROR;
        conn->response->transport_error = error_code;
    }
    conn->idle_since_ms = conn_now_ms(transport);
    conn->state         = PN_CONN_FAILED;
}

/**
 * @brief Get current monotonic time from the platform provider.
 */
static uint64_t conn_now_ms(const pn_socket_transport_t* transport)
{
    if (NULL == transport || NULL == transport->platform) {
        return UINT64_MAX; /* Force immediate timeout — fail-safe */
    }
    return transport->platform->monotonic_ms(transport->platform);
}

/**
 * @brief TLS-aware send helper.
 *
 * @return >0 bytes sent, 0 would-block, <0 error.
 */
static int conn_send(pn_socket_connection_t* conn,
                     pn_socket_transport_t*  transport,
                     const void*             buf,
                     size_t                  len)
{
    if (NULL != conn->tls_session && NULL != transport->tls_backend) {
        return transport->tls_backend->send(conn->tls_session, buf, len);
    }
    return transport->ops->socket_send(
        transport->ops, conn->socket, (const uint8_t*)buf, len);
}

/**
 * @brief TLS-aware recv helper.
 *
 * @return >0 bytes received, 0 would-block, -1 peer closed, <-1 error.
 */
static int conn_recv(pn_socket_connection_t* conn,
                     pn_socket_transport_t*  transport,
                     void*                   buf,
                     size_t                  len)
{
    if (NULL != conn->tls_session && NULL != transport->tls_backend) {
        return transport->tls_backend->recv(conn->tls_session, buf, len);
    }
    return transport->ops->socket_recv(
        transport->ops, conn->socket, (uint8_t*)buf, len);
}

/**
 * @brief Get the family-exhausted bit for a given address.
 */
static uint8_t conn_family_bit(const pn_sockaddr_t* addr)
{
    if (PN_AF_INET == addr->family) {
        return PN_FAMILY_EXHAUSTED_V4;
    }
    if (PN_AF_INET6 == addr->family) {
        return PN_FAMILY_EXHAUSTED_V6;
    }
    return 0;
}

/**
 * @brief Check if an address's family is exhausted.
 */
static int conn_family_is_exhausted(const pn_socket_connection_t* conn,
                                    const pn_sockaddr_t*          addr)
{
    return 0 != (conn->family_exhausted & conn_family_bit(addr));
}

/**
 * @brief Advance addr_current to the next non-exhausted address.
 *
 * @return 1 if a valid address was found, 0 if all exhausted.
 */
static int conn_advance_to_next_addr(pn_socket_connection_t* conn)
{
    while (conn->addr_current < conn->addr_count) {
        if (!conn_family_is_exhausted(conn,
                                      &conn->resolved_addrs[conn->addr_current])) {
            return 1;
        }
        conn->addr_current++;
    }
    return 0;
}

/**
 * @brief Attempt TCP connect to the current address.
 *
 * Creates a socket, sets non-blocking, and initiates connect. On
 * immediate success, applies keepalive. Returns the connect result
 * or advances to the next address on failure.
 *
 * @return 1 connected, 0 in-progress, -1 all addresses exhausted.
 */
static int conn_try_connect(pn_socket_connection_t* conn,
                            pn_socket_transport_t*  transport)
{
    while (conn_advance_to_next_addr(conn)) {
        pn_sockaddr_t* addr = &conn->resolved_addrs[conn->addr_current];

        pn_socket_t sock =
            transport->ops->socket_create(transport->ops, addr->family, 0);
        if (PN_INVALID_SOCKET == sock) {
            PUBNUB_LOG_TEXT(transport->logger,
                            PUBNUB_LOG_LEVEL_WARNING,
                            "socket_create failed");
            conn->addr_current++;
            continue;
        }

        int rc = transport->ops->socket_set_nonblocking(transport->ops, sock);
        if (rc < 0) {
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_WARNING,
                       "socket_set_nonblocking failed: rc=%d",
                       rc);
            transport->ops->socket_destroy(transport->ops, sock);
            conn->addr_current++;
            continue;
        }

        if (PN_AF_INET == addr->family) {
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_TRACE,
                       "TCP connect -> %u.%u.%u.%u:%u (%s)",
                       (unsigned)addr->addr.ipv4[0],
                       (unsigned)addr->addr.ipv4[1],
                       (unsigned)addr->addr.ipv4[2],
                       (unsigned)addr->addr.ipv4[3],
                       (unsigned)addr->port,
                       conn_effective_host(conn));
        } else if (PN_AF_INET6 == addr->family) {
            const uint8_t* b = addr->addr.ipv6;
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_TRACE,
                       "TCP connect -> [%x:%x:%x:%x:%x:%x:%x:%x]:%u (%s)",
                       (unsigned)((b[0] << 8) | b[1]),
                       (unsigned)((b[2] << 8) | b[3]),
                       (unsigned)((b[4] << 8) | b[5]),
                       (unsigned)((b[6] << 8) | b[7]),
                       (unsigned)((b[8] << 8) | b[9]),
                       (unsigned)((b[10] << 8) | b[11]),
                       (unsigned)((b[12] << 8) | b[13]),
                       (unsigned)((b[14] << 8) | b[15]),
                       (unsigned)addr->port,
                       conn_effective_host(conn));
            (void)b;
        }

        rc = transport->ops->socket_connect(transport->ops, sock, addr);
        if (rc > 0) {
            /* Immediate connection success. */
            conn->socket = sock;
            transport->ops->socket_set_keepalive(
                transport->ops, sock, &transport->keepalive_config);
            return 1;
        }
        if (0 == rc) {
            /* In-progress — wait for POLLOUT. */
            conn->socket = sock;
            return 0;
        }

        /* Error — check if family-level failure. */
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "socket_connect failed: rc=%d, addr_family=%u",
                   rc,
                   (unsigned)addr->family);
        transport->ops->socket_destroy(transport->ops, sock);
        if (pn_is_family_unreachable(rc)) {
            conn->family_exhausted |= conn_family_bit(addr);
        }
        conn->addr_current++;
    }

    /* All addresses exhausted. */
    PUBNUB_LOG_TEXT(
        transport->logger, PUBNUB_LOG_LEVEL_WARNING, "all addresses exhausted");
    return -1;
}

/**
 * @brief Extract the hostname without the port suffix.
 *
 * Copies at most PUBNUB_CFG_MAX_HOSTNAME_LEN-1 characters of the host
 * portion (excluding any ":port" or "[...]:port" suffix) into dst.
 */
static void conn_extract_hostname(const char* host, char* dst, size_t dst_size)
{
    if (NULL == host || 0 == dst_size) {
        if (dst_size > 0) {
            dst[0] = '\0';
        }
        return;
    }

    size_t len = strlen(host);
    if ('[' == host[0]) {
        /* IPv6 literal — copy up to and including ']'. */
        const char* bracket = strchr(host, ']');
        if (NULL != bracket) {
            len = (size_t)(bracket - host + 1);
        }
    } else {
        const char* colon = strrchr(host, ':');
        if (NULL != colon) {
            len = (size_t)(colon - host);
        }
    }

    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, host, len);
    dst[len] = '\0';
}

#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
/** @brief ASCII-only case-insensitive comparison for HTTP headers. */
static int pn_ascii_casecmp(const char* a, const char* b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca += 32;
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb += 32;
        }
        if (ca != cb) {
            return (int)ca - (int)cb;
        }
        if (0 == ca) {
            return 0;
        }
    }
    return 0;
}
#endif /* PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0 */

/**
 * @brief Get the effective host for this connection.
 *
 * Returns the redirect host when a redirect is active, otherwise
 * the original request host.
 */
static const char* conn_effective_host(const pn_socket_connection_t* conn)
{
    if (NULL != conn->redirect_host) {
        return conn->redirect_host;
    }
    return conn->request->host;
}

/**
 * @brief Get the effective secure flag for this connection.
 *
 * Returns the redirect secure flag when a redirect is active,
 * otherwise the original request secure flag.
 */
static uint8_t conn_effective_secure(const pn_socket_connection_t* conn)
{
    if (NULL != conn->redirect_host) {
        return conn->redirect_secure;
    }
    return conn->request->secure;
}

/**
 * @brief Resolve the effective port for this connection.
 *
 * Uses the redirect scheme's default port when redirecting,
 * otherwise delegates to pn_http_resolve_port on the original
 * request.
 */
static uint16_t conn_effective_port(const pn_socket_connection_t* conn)
{
    if (NULL != conn->redirect_host) {
        if (0 != conn->redirect_port) {
            return conn->redirect_port;
        }
        return conn->redirect_secure ? 443 : 80;
    }
    return pn_http_resolve_port(conn->request);
}

#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
/**
 * @brief Parse a redirect Location URL into host, path, scheme, and port.
 *
 * Splits "scheme://host[:port]/path?query" into separate heap-allocated
 * host and path strings. The path output excludes the leading '/'
 * (the HTTP builder prepends it for each path segment).
 * Extracts an explicit port from the authority component when present;
 * zero means the URL had no port (use scheme default).
 *
 * @param url       NUL-terminated absolute URL.
 * @param allocator Allocator for the output strings.
 * @param out_host  Receives heap-allocated host string.
 * @param out_path  Receives heap-allocated path+query string.
 * @param out_secure Receives 1 for https, 0 for http.
 * @return PUBNUB_OK on success, error code on failure.
 */
static pubnub_res_t pn_parse_redirect_url(const char* url,
                                          pubnub_allocator_provider_t* allocator,
                                          char**    out_host,
                                          char**    out_path,
                                          uint8_t*  out_secure,
                                          uint16_t* out_port)
{
    const char* scheme_end;
    const char* host_start;
    const char* path_start;
    const char* path_content;
    const char* port_start;
    size_t      scheme_len;
    size_t      host_len;

    if (NULL == url || NULL == allocator || NULL == out_host || NULL == out_path
        || NULL == out_secure || NULL == out_port) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_host   = NULL;
    *out_path   = NULL;
    *out_secure = 0;
    *out_port   = 0;

    scheme_end = strstr(url, "://");
    if (NULL == scheme_end) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    scheme_len = (size_t)(scheme_end - url);

    if (5 == scheme_len && 0 == memcmp(url, "https", 5)) {
        *out_secure = 1;
    } else if (4 == scheme_len && 0 == memcmp(url, "http", 4)) {
        *out_secure = 0;
    } else {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    host_start = scheme_end + 3;
    path_start = strchr(host_start, '/');
    if (NULL == path_start) {
        host_len = strlen(host_start);
    } else {
        host_len = (size_t)(path_start - host_start);
    }

    /* Parse optional port from the authority component.
     * IPv6: [addr]:port — look for "]:digits" after the closing bracket.
     * IPv4/name: host:port — last colon separates host from port. */
    port_start = NULL;
    if (host_len > 0 && '[' == host_start[0]) {
        const char* bracket = memchr(host_start, ']', host_len);
        if (NULL != bracket) {
            size_t after = (size_t)(bracket - host_start) + 1;
            if (after < host_len && ':' == host_start[after]) {
                port_start = host_start + after + 1;
            }
        }
    } else {
        const char* colon = memchr(host_start, ':', host_len);
        if (NULL != colon) {
            port_start = colon + 1;
        }
    }

    if (NULL != port_start) {
        const char*   host_end = host_start + host_len;
        unsigned long val      = 0;
        const char*   p        = port_start;
        while (p < host_end && *p >= '0' && *p <= '9') {
            val = val * 10 + (unsigned long)(*p - '0');
            if (val > 65535) {
                val = 0;
                break;
            }
            p++;
        }
        if (val >= 1 && val <= 65535 && p > port_start) {
            *out_port = (uint16_t)val;
        }
    }

    *out_host = pn_strndup(host_start, host_len, allocator);
    if (NULL == *out_host) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* A malicious Location header can smuggle CR/LF/space into the host,
     * which would inject extra lines into the outbound Host: header. */
    if (pn_str_has_header_unsafe_byte(*out_host)) {
        pn_strfree(*out_host, allocator);
        *out_host = NULL;
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == path_start) {
        *out_path = pn_strdup("", allocator);
        if (NULL == *out_path) {
            pn_strfree(*out_host, allocator);
            *out_host = NULL;
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        return PUBNUB_OK;
    }

    /* Path is everything after the leading '/'. The HTTP builder
     * prepends '/' before each path segment. */
    path_content = path_start + 1;
    *out_path    = pn_strdup(path_content, allocator);
    if (NULL == *out_path) {
        pn_strfree(*out_host, allocator);
        *out_host = NULL;
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    return PUBNUB_OK;
}
#endif /* PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0 */

/**
 * @brief Free redirect buffers on a connection.
 *
 * Safe to call when no redirect is active (both pointers NULL).
 */
static void conn_free_redirect(pn_socket_connection_t* conn,
                               pn_socket_transport_t*  transport)
{
    if (NULL != conn->redirect_host) {
        pn_strfree(conn->redirect_host, transport->allocator);
        conn->redirect_host = NULL;
    }
    if (NULL != conn->redirect_path) {
        pn_strfree(conn->redirect_path, transport->allocator);
        conn->redirect_path = NULL;
    }
    conn->redirect_count  = 0;
    conn->redirect_secure = 0;
    conn->redirect_port   = 0;
}

#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
/**
 * @brief Build HTTP headers for a redirect target.
 *
 * Only called from conn_build_headers when redirect_host is non-NULL.
 * The ~608B pubnub_http_request_t local stays off the stack for the
 * common (non-redirect) case.
 *
 * PUBNUB_NOINLINE is what makes that claim true. Inlined, this frame is
 * hoisted all the way into pn_connection_start's prologue, so every
 * request — redirect or not — pays for it. Measured at -Os on arm64:
 * pn_connection_start drops from 1104 to 128 bytes when inlining is
 * blocked here. The macro must lead the declaration: on IAR it expands
 * to a pragma that only binds when it precedes the storage class.
 *
 * This moves the cost off the hot path; it does not shrink it. A request
 * that actually redirects still peaks around 1232B through this frame,
 * which is why PUBNUB_CFG_SOCKET_MAX_REDIRECTS exists — targets that
 * cannot budget that peak set it to 0 and compile the path out.
 *
 * @return 0 on success, -1 on failure (buffer too small).
 */
PUBNUB_NOINLINE static int
conn_build_redirect_headers(pn_socket_connection_t*      conn,
                            const pubnub_http_request_t* request)
{
    pubnub_http_request_t redir_req = {0};
    size_t                out_len   = 0;
    int                   rc;

    /* RFC 7231: 307/308 preserve method; 301/302/303 should change to
     * GET. PubNub file downloads use 307 exclusively; preserving method
     * for all 3xx is an intentional simplification. */
    redir_req.method               = request->method;
    redir_req.host                 = conn->redirect_host;
    redir_req.secure               = conn->redirect_secure;
    redir_req.external             = 1;
    redir_req.timeout_ms           = request->timeout_ms;
    redir_req.body                 = request->body;
    redir_req.body_len             = request->body_len;
    redir_req.path_segment_count   = 1;
    redir_req.path_segments[0].ptr = conn->redirect_path;
    redir_req.path_segments[0].len = strlen(conn->redirect_path);

    rc = pn_http_build_headers(
        &redir_req, conn->header_buf, sizeof(conn->header_buf), &out_len);
    if (0 != rc) {
        return -1;
    }
    conn->header_len  = (uint16_t)out_len;
    conn->header_sent = 0;
    conn->body_sent   = 0;
    return 0;
}
#endif /* PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0 */

/**
 * @brief Build HTTP request headers for the current connection.
 *
 * When redirect data is present, delegates to conn_build_redirect_headers
 * so the large pubnub_http_request_t is only stack-allocated on the
 * redirect code path.
 *
 * @return 0 on success, -1 on failure (buffer too small).
 */
static int conn_build_headers(pn_socket_connection_t*      conn,
                              const pubnub_http_request_t* request)
{
    size_t out_len = 0;
    int    rc;

#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
    if (NULL != conn->redirect_host) {
        return conn_build_redirect_headers(conn, request);
    }
#endif

    rc = pn_http_build_headers(
        request, conn->header_buf, sizeof(conn->header_buf), &out_len);
    if (0 != rc) {
        return -1;
    }
    conn->header_len  = (uint16_t)out_len;
    conn->header_sent = 0;
    conn->body_sent   = 0;
    return 0;
}

/**
 * @brief Check whether any peer connection is TLS-handshaking to the
 *        same hostname.
 *
 * Scans the transport connection pool for another slot in
 * PN_CONN_TLS_HANDSHAKING whose TLS target hostname matches
 * @p self_hostname. Used to serialize concurrent TLS handshakes to
 * the same server, preventing server-side rate limiting that closes
 * one connection with EOF during handshake and bounding per-session
 * heap on constrained devices (mbedTLS: ~4-6 KB per active
 * ssl_handshake call).
 *
 * Called only from the bg thread; no lock, no allocation.
 *
 * @param t             Transport instance.
 * @param self          Connection to exclude from the scan.
 * @param self_hostname NUL-terminated hostname to match against.
 * @return 1 if another slot is handshaking to the same host, 0
 *         otherwise.
 */
static int conn_any_peer_tls_handshaking(const pn_socket_transport_t*  t,
                                         const pn_socket_connection_t* self,
                                         const char* self_hostname)
{
    int i;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        const pn_socket_connection_t* other = &t->connections[i];
        char                          other_host[PUBNUB_CFG_MAX_HOSTNAME_LEN];
        if (other == self) {
            continue;
        }
        if (PN_CONN_TLS_HANDSHAKING != other->state) {
            continue;
        }
        /* conn_effective_host returns the TLS target in all cases
         * (direct, proxy, redirect). Using dns_hostname here would
         * compare against the proxy hostname when proxied. */
        if (NULL == other->request) {
            continue;
        }
        conn_extract_hostname(
            conn_effective_host(other), other_host, sizeof(other_host));
        if (0 == strcmp(self_hostname, other_host)) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Transition from connected to TLS handshake or HTTP send.
 *
 * Common final step after TCP connect completes (with or without proxy).
 * If the request is secure and a TLS backend is available, creates a TLS
 * session and transitions to TLS_HANDSHAKING. Otherwise transitions
 * directly to SENDING_HEADERS.
 *
 * When another slot is already TLS-handshaking to the same hostname,
 * returns 1 (deferred) without changing state. The caller must set
 * PN_CONN_CONNECTING so the connection re-enters on the next poll.
 *
 * @return 0 on success (state updated), 1 if deferred (another slot is
 *         handshaking to the same hostname; state unchanged, caller must
 *         set PN_CONN_CONNECTING), -1 on TLS session creation failure.
 */
static int conn_transition_to_tls_or_http(pn_socket_connection_t* conn,
                                          pn_socket_transport_t*  transport)
{
    if (PUBNUB_ENABLE_SECURE_TRANSPORT && conn_effective_secure(conn)
        && NULL != transport->tls_backend) {
        char hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN];
        int  rc;
        conn_extract_hostname(conn_effective_host(conn), hostname, sizeof(hostname));

        /* Serialize TLS handshakes to the same hostname to reduce
         * amount of memory temporarily allocated for TSL handshake.
         * When another slot is handshaking to the same host: stay in
         * CONNECTING with the TCP socket already established.
         * tick_connecting re-enters here on the next poll iteration
         * via socket_check_connect. */
        if (conn_any_peer_tls_handshaking(transport, conn, hostname)) {
            return 1;
        }

        rc = transport->tls_backend->session_create(&conn->tls_session,
                                                    transport->tls_ctx,
                                                    conn->socket,
                                                    transport->ops,
                                                    hostname);
        if (rc < 0) {
            return -1;
        }
        conn->state = PN_CONN_TLS_HANDSHAKING;
        return 0;
    }

    /* A secure connection with no TLS backend must fail closed rather than
     * fall through to a plaintext send. Reaching here means the transport
     * was wired for TLS but no backend resolved — an internal misconfig,
     * never a runtime input, so we log and fail instead of leaking the
     * request over cleartext. */
    if (PUBNUB_ENABLE_SECURE_TRANSPORT && conn_effective_secure(conn)
        && NULL == transport->tls_backend) {
        PUBNUB_LOG_TEXT(transport->logger,
                        PUBNUB_LOG_LEVEL_ERROR,
                        "secure connection requested but no TLS backend is "
                        "configured; refusing to connect in plaintext");
        return -1;
    }

    conn->state = PN_CONN_SENDING_HEADERS;
    return 0;
}

/**
 * @brief Transition from connected state to proxy negotiation or TLS/HTTP.
 *
 * If a proxy module exists and the tunnel has not already been established
 * (proxy_done == 0), start proxy negotiation. Otherwise proceed directly
 * to TLS (if secure) or HTTP sending.
 *
 * @return 0 on success (state updated), 1 if deferred (TLS gate busy;
 *         caller must set PN_CONN_CONNECTING), -1 on proxy start or TLS
 *         session creation failure.
 */
static int conn_transition_after_connect(pn_socket_connection_t* conn,
                                         pn_socket_transport_t*  transport)
{
    /* Only negotiate when tunnel not yet established. Deferred TLS
     * re-enters here with proxy_done == 1; skip re-negotiation. */
    if (PUBNUB_ENABLE_PROXY && NULL != transport->proxy_module
        && 0 == conn->proxy_done) {
        uint16_t          target_port = conn_effective_port(conn);
        char              target_host[PUBNUB_CFG_MAX_HOSTNAME_LEN];
        pn_proxy_result_t rc;
        conn_extract_hostname(
            conn_effective_host(conn), target_host, sizeof(target_host));

        rc = transport->proxy_module->negotiate_start(
            transport->proxy_module, conn, transport, target_host, target_port);

        if (PN_PROXY_ERROR == rc) {
            return -1;
        }
        if (PN_PROXY_COMPLETE == rc) {
            conn->proxy_done = 1;
            return conn_transition_to_tls_or_http(conn, transport);
        }
        conn->state = PN_CONN_PROXY_NEGOTIATING;
        return 0;
    }

    return conn_transition_to_tls_or_http(conn, transport);
}

/**
 * @brief Tick: DNS_RESOLVING state.
 */
static pn_conn_state_t tick_dns_resolving(pn_socket_connection_t* conn,
                                          pn_socket_transport_t*  transport)
{
    pn_dns_state_t dns_state = pn_dns_resolver_state(&transport->resolver);

    /* Resolver is IDLE — this connection was deferred because the resolver
     * was busy at send() time, or the previous lookup just completed.
     * Attempt to start our own lookup now (will be a cache hit if the
     * same host was just resolved by another connection). */
    if (PN_DNS_STATE_IDLE == dns_state) {
        int start_rc =
            pn_dns_resolver_start(&transport->resolver, conn->dns_hostname);
        if (start_rc < 0) {
            /* Still cannot start — another connection grabbed the resolver
             * between state check and start call. Wait for next tick. */
            uint64_t now = conn_now_ms(transport);
            if (now >= conn->connect_deadline_ms) {
                conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
            }
            return conn->state;
        }
        dns_state = pn_dns_resolver_state(&transport->resolver);
    }

    if (PN_DNS_STATE_DONE == dns_state) {
        size_t   count = 0;
        int      rc;
        uint16_t port;
        uint8_t  i;

        /* Only the connection whose hostname was resolved may claim the
         * result. Deferred waiters for different hosts must wait for
         * IDLE before starting their own lookup. */
        if (0
            != strncmp(transport->resolver.current_hostname,
                       conn->dns_hostname,
                       sizeof(conn->dns_hostname) - 1U)) {
            return conn->state;
        }

        rc = pn_dns_resolver_get_results(&transport->resolver,
                                         conn->resolved_addrs,
                                         PUBNUB_CFG_MAX_DNS_RESULTS,
                                         &count);
        /* Reset resolver to IDLE so subsequent connections can start
         * their own DNS lookups. Cached results remain valid. */
        transport->resolver.state = PN_DNS_STATE_IDLE;

        if (rc < 0 || 0 == count) {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
            return conn->state;
        }
        conn->addr_count   = (uint8_t)count;
        conn->addr_current = 0;

        /* Set port: proxy port when proxied, target port otherwise. */
        if (NULL != transport->proxy_module
            && NULL != transport->proxy_config_stored.host) {
            port = transport->proxy_config_stored.port;
        } else {
            port = conn_effective_port(conn);
        }
        for (i = 0; i < conn->addr_count; i++) {
            conn->resolved_addrs[i].port = port;
        }

        conn->state = PN_CONN_CONNECTING;
        return conn->state;
    }

    if (PN_DNS_STATE_FAILED == dns_state) {
        /* Reset resolver to IDLE so subsequent connections can attempt
         * a fresh DNS lookup after a failure. */
        transport->resolver.state = PN_DNS_STATE_IDLE;
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "DNS resolution failed for host: %s",
                   conn_effective_host(conn));
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        return conn->state;
    }

    /* Still resolving — check connect deadline. */
    uint64_t now = conn_now_ms(transport);
    if (now >= conn->connect_deadline_ms) {
        conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
        return conn->state;
    }

    /* Drive the resolver forward. */
    pn_dns_resolver_tick(&transport->resolver);
    return conn->state;
}

/**
 * @brief Close socket, advance to next address, and attempt reconnection.
 *
 * Handles the fallback path when the current address fails (connect error
 * or post-connect transition failure). Closes the socket, advances the
 * address index, and retries. If immediate success on the next address
 * also fails transition, marks the connection as failed.
 */
static void conn_fallback_next_addr(pn_socket_connection_t* conn,
                                    pn_socket_transport_t*  transport)
{
    conn_close_socket(conn, transport);
    conn->addr_current++;

    /* Refresh the connect deadline so that the new TCP+TLS attempt
     * gets a full budget rather than inheriting the remnant of the
     * previous (failed) address's window. Without this, a slow first
     * attempt leaves almost no time for the fallback. */
    uint64_t now              = conn_now_ms(transport);
    conn->connect_deadline_ms = now + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS;

    PUBNUB_LOG(transport->logger,
               PUBNUB_LOG_LEVEL_TRACE,
               "TCP connect fallback: trying address %u of %u"
               " for %s (new deadline in %u ms)",
               (unsigned)(conn->addr_current + 1),
               (unsigned)conn->addr_count,
               conn_effective_host(conn),
               (unsigned)PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS);

    int try_rc = conn_try_connect(conn, transport);
    if (1 == try_rc) {
        int transition_rc = conn_transition_after_connect(conn, transport);
        if (1 == transition_rc) {
            conn->state = PN_CONN_CONNECTING;
        } else if (transition_rc < 0) {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        }
    } else if (-1 == try_rc) {
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
    }
}

/**
 * @brief Handle a successful TCP connect: apply keepalive and transition.
 *
 * On transition failure, falls back to the next address. On deferral
 * (TLS gate busy for same hostname), sets CONNECTING to re-enter on
 * the next poll without destroying the established TCP socket.
 */
static void conn_handle_connected(pn_socket_connection_t* conn,
                                  pn_socket_transport_t*  transport)
{
    int rc;

    transport->ops->socket_set_keepalive(
        transport->ops, conn->socket, &transport->keepalive_config);
    rc = conn_transition_after_connect(conn, transport);
    if (1 == rc) {
        uint64_t pn_now    = conn_now_ms(transport);
        uint64_t pn_budget = (pn_now < conn->connect_deadline_ms)
                               ? (conn->connect_deadline_ms - pn_now)
                               : 0U;
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_TRACE,
                   "conn[%d] TLS deferred: queued behind peer, "
                   "budget %u ms remaining",
                   (int)(conn - transport->connections),
                   (unsigned)pn_budget);
        (void)pn_now;
        (void)pn_budget;
        conn->state = PN_CONN_CONNECTING;
    } else if (rc < 0) {
        /* Permanent failure (e.g. no TLS backend) — fail closed, not
         * per-address retry. */
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
    } else {
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_TRACE,
                   "conn[%d] TCP connected fd=%d to %s",
                   (int)(conn - transport->connections),
                   (int)conn->socket,
                   conn_effective_host(conn));
        conn->connect_deadline_ms =
            conn_now_ms(transport) + (uint64_t)PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS;
    }
}

/**
 * @brief Check the connect deadline after a TLS deferral.
 *
 * When conn_handle_connected defers TLS (a peer is handshaking to the
 * same hostname), the connection stays in CONNECTING with TCP already
 * established. This helper bounds the wait so a stuck peer handshake
 * cannot stall the deferred connection indefinitely.
 */
static void conn_check_tls_deferred_deadline(pn_socket_connection_t* conn,
                                             pn_socket_transport_t*  transport)
{
    if (PN_CONN_CONNECTING == conn->state) {
        uint64_t now = conn_now_ms(transport);
        if (now >= conn->connect_deadline_ms) {
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "conn[%d] TLS deferred timeout: waited %u ms",
                       (int)(conn - transport->connections),
                       (unsigned)(now
                                  - (conn->connect_deadline_ms
                                     - PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS)));
            conn_close_socket(conn, transport);
            conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
        }
    }
}

/**
 * @brief Tick: CONNECTING state.
 */
static pn_conn_state_t tick_connecting(pn_socket_connection_t* conn,
                                       pn_socket_transport_t*  transport)
{
    if (PN_INVALID_SOCKET == conn->socket) {
        /* No socket yet — try connecting to current/next address. */
        int rc = conn_try_connect(conn, transport);
        if (1 == rc) {
            conn_handle_connected(conn, transport);
            conn_check_tls_deferred_deadline(conn, transport);
            return conn->state;
        }
        if (0 == rc) {
            return conn->state;
        }
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        return conn->state;
    }

    /* Socket exists — check if connect completed. */
    int rc = transport->ops->socket_check_connect(transport->ops, conn->socket);
    if (1 == rc) {
        conn_handle_connected(conn, transport);
        conn_check_tls_deferred_deadline(conn, transport);
        return conn->state;
    }

    if (0 == rc) {
        /* Still in progress — check deadline. */
        uint64_t now = conn_now_ms(transport);
        if (now >= conn->connect_deadline_ms) {
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_TRACE,
                       "TCP connect deadline expired for %s"
                       " (addr %u of %u, fd=%d)",
                       conn_effective_host(conn),
                       (unsigned)(conn->addr_current + 1),
                       (unsigned)conn->addr_count,
                       (int)conn->socket);
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "TCP connect timeout for host: %s",
                       conn_effective_host(conn));
            conn_close_socket(conn, transport);
            conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
        }
        return conn->state;
    }

    /* Connect error on current address — try next. */
    if (pn_is_family_unreachable(rc)) {
        conn->family_exhausted |=
            conn_family_bit(&conn->resolved_addrs[conn->addr_current]);
    }
    conn_fallback_next_addr(conn, transport);
    return conn->state;
}

/**
 * @brief Tick: PROXY_NEGOTIATING state.
 *
 * Drives the proxy module's negotiate_tick until the tunnel is
 * established (COMPLETE), fails (ERROR), or times out.
 */
static pn_conn_state_t tick_proxy_negotiating(pn_socket_connection_t* conn,
                                              pn_socket_transport_t*  transport)
{
    if (NULL == transport->proxy_module) {
        conn_fail(conn, transport, PUBNUB_ERR_INTERNAL);
        return conn->state;
    }

    pn_proxy_result_t rc = transport->proxy_module->negotiate_tick(
        transport->proxy_module, conn, transport);

    if (PN_PROXY_COMPLETE == rc) {
        int tls_rc;
        /* Tunnel established — free session and proceed to TLS or HTTP. */
        if (PUBNUB_ENABLE_PROXY && NULL != conn->proxy_session) {
            pn_proxy_connect_session_destroy(conn->proxy_session,
                                             transport->allocator);
            conn->proxy_session = NULL;
        }
        conn->proxy_done = 1;
        tls_rc           = conn_transition_to_tls_or_http(conn, transport);
        if (1 == tls_rc) {
            conn->state = PN_CONN_CONNECTING;
        } else if (tls_rc < 0) {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        }
        return conn->state;
    }

    if (PN_PROXY_ERROR == rc) {
        /* Free session on error. */
        if (PUBNUB_ENABLE_PROXY && NULL != conn->proxy_session) {
            pn_proxy_connect_session_destroy(conn->proxy_session,
                                             transport->allocator);
            conn->proxy_session = NULL;
        }
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        return conn->state;
    }

    /* PN_PROXY_IN_PROGRESS — check connect deadline. */
    uint64_t now = conn_now_ms(transport);
    if (now >= conn->connect_deadline_ms) {
        if (PUBNUB_ENABLE_PROXY && NULL != conn->proxy_session) {
            pn_proxy_connect_session_destroy(conn->proxy_session,
                                             transport->allocator);
            conn->proxy_session = NULL;
        }
        conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
    }
    return conn->state;
}

/**
 * @brief Tick: TLS_HANDSHAKING state.
 */
static pn_conn_state_t tick_tls_handshaking(pn_socket_connection_t* conn,
                                            pn_socket_transport_t*  transport)
{
    if (NULL == transport->tls_backend || NULL == conn->tls_session) {
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        return conn->state;
    }

    int rc = transport->tls_backend->handshake(conn->tls_session);
    if (PN_TLS_OK == rc) {
        conn->state = PN_CONN_SENDING_HEADERS;
        return conn->state;
    }

    if (PN_TLS_WANT_READ == rc || PN_TLS_WANT_WRITE == rc) {
        /* Need to wait for socket readiness — check deadline. */
        uint64_t now = conn_now_ms(transport);
        if (now >= conn->connect_deadline_ms) {
            int try_rc;
            int transition_rc;
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "conn[%d] TLS handshake timed out for host: %s",
                       (int)(conn - transport->connections),
                       conn_effective_host(conn));
            conn_close_all(conn, transport);
            /* Try next address with a fresh connect budget. */
            PUBNUB_LOG(transport->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "conn[%d] TLS timeout on address %u of %u for %s,"
                       " trying next (new deadline in %u ms)",
                       (int)(conn - transport->connections),
                       (unsigned)(conn->addr_current + 1),
                       (unsigned)conn->addr_count,
                       conn_effective_host(conn),
                       (unsigned)PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS);
            conn->addr_current++;
            conn->connect_deadline_ms = now + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS;
            try_rc = conn_try_connect(conn, transport);
            if (1 == try_rc) {
                transition_rc = conn_transition_after_connect(conn, transport);
                if (1 == transition_rc) {
                    conn->state = PN_CONN_CONNECTING;
                } else if (transition_rc < 0) {
                    conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
                }
            } else if (0 == try_rc) {
                /* New TCP connection in-progress: must wait for it to
                 * complete before starting a new TLS session
                 * (tls_session is NULL now). Drop back to CONNECTING
                 * so tick_connecting handles POLLOUT. */
                conn->state = PN_CONN_CONNECTING;
            } else {
                conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
            }
        }
        return conn->state;
    }

    {
        uint64_t now_tls;
        int      try_rc;
        int      transition_rc;

        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "conn[%d] TLS error on address %u of %u for %s,"
                   " trying next (new deadline in %u ms)",
                   (int)(conn - transport->connections),
                   (unsigned)(conn->addr_current + 1),
                   (unsigned)conn->addr_count,
                   conn_effective_host(conn),
                   (unsigned)PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS);
        conn_close_all(conn, transport);
        conn->addr_current++;

        now_tls = conn_now_ms(transport);
        conn->connect_deadline_ms = now_tls + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS;
        try_rc = conn_try_connect(conn, transport);
        if (1 == try_rc) {
            transition_rc = conn_transition_after_connect(conn, transport);
            if (1 == transition_rc) {
                conn->state = PN_CONN_CONNECTING;
            } else if (transition_rc < 0) {
                conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
            }
        } else if (0 == try_rc) {
            /* New TCP connection in-progress: must wait for POLLOUT
             * before TLS. tls_session was cleared by conn_close_all. */
            conn->state = PN_CONN_CONNECTING;
        } else {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        }
    }
    return conn->state;
}

/**
 * @brief Tick: SENDING_HEADERS state.
 */
static pn_conn_state_t tick_sending_headers(pn_socket_connection_t* conn,
                                            pn_socket_transport_t*  transport)
{
    size_t remaining = (size_t)(conn->header_len - conn->header_sent);
    int    rc =
        conn_send(conn, transport, conn->header_buf + conn->header_sent, remaining);

    if (rc > 0) {
        conn->header_sent += (uint16_t)rc;
        if (conn->header_sent >= conn->header_len) {
            /* Headers fully sent. */
            if (NULL != conn->request->body && conn->request->body_len > 0) {
                conn->state = PN_CONN_SENDING_BODY;
            } else {
                if (0 != conn_acquire_rx_buf(conn, transport)) {
                    conn_fail(conn, transport, PUBNUB_ERR_OUT_OF_MEMORY);
                    return conn->state;
                }
                pn_http_parser_init(&conn->parser);
                conn->state = PN_CONN_RECEIVING_RESPONSE;
            }
        }
        return conn->state;
    }

    if (0 == rc) {
        /* Would-block — check transaction deadline. */
        uint64_t now = conn_now_ms(transport);
        if (now >= conn->transaction_deadline_ms) {
            conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
        }
        return conn->state;
    }

    /* Send error — stale keep-alive socket detected when this is a
     * reused connection and no retry has been attempted yet. Close
     * everything and restart with a fresh DNS/TCP/TLS cycle. */
    if (conn->requests_on_connection > 0 && !conn->keepalive_retry_used) {
        int restart_rc;
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "stale keep-alive on header write "
                   "(served %u requests); restarting fresh connection",
                   (unsigned)conn->requests_on_connection);
        conn_close_all(conn, transport);
        conn->requests_on_connection = 0;
        conn->header_sent            = 0;
        conn->keepalive_retry_used   = 1;
        conn->state                  = PN_CONN_IDLE;
        restart_rc =
            pn_connection_start(conn, conn->request, conn->response, transport);
        if (0 != restart_rc) {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        }
        return conn->state;
    }

    PUBNUB_LOG(
        transport->logger, PUBNUB_LOG_LEVEL_WARNING, "header send error: rc=%d", rc);
    conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
    return conn->state;
}

/**
 * @brief Tick: SENDING_BODY state.
 */
static pn_conn_state_t tick_sending_body(pn_socket_connection_t* conn,
                                         pn_socket_transport_t*  transport)
{
    size_t remaining = conn->request->body_len - conn->body_sent;
    int    rc        = conn_send(
        conn, transport, conn->request->body + conn->body_sent, remaining);

    if (rc > 0) {
        conn->body_sent += (size_t)rc;
        if (conn->body_sent >= conn->request->body_len) {
            if (0 != conn_acquire_rx_buf(conn, transport)) {
                conn_fail(conn, transport, PUBNUB_ERR_OUT_OF_MEMORY);
                return conn->state;
            }
            pn_http_parser_init(&conn->parser);
            conn->state = PN_CONN_RECEIVING_RESPONSE;
        }
        return conn->state;
    }

    if (0 == rc) {
        /* Would-block — check transaction deadline. */
        uint64_t now = conn_now_ms(transport);
        if (now >= conn->transaction_deadline_ms) {
            conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
        }
        return conn->state;
    }

    /* Send error — stale keep-alive retry (same logic as headers). */
    if (conn->requests_on_connection > 0 && !conn->keepalive_retry_used) {
        int restart_rc;
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "stale keep-alive on body write "
                   "(served %u requests); restarting fresh connection",
                   (unsigned)conn->requests_on_connection);
        conn_close_all(conn, transport);
        conn->requests_on_connection = 0;
        conn->header_sent            = 0;
        conn->body_sent              = 0;
        conn->keepalive_retry_used   = 1;
        conn->state                  = PN_CONN_IDLE;
        restart_rc =
            pn_connection_start(conn, conn->request, conn->response, transport);
        if (0 != restart_rc) {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        }
        return conn->state;
    }

    PUBNUB_LOG(
        transport->logger, PUBNUB_LOG_LEVEL_WARNING, "body send error: rc=%d", rc);
    conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
    return conn->state;
}

/**
 * @brief Ensure the RX buffer has room for at least one more recv.
 *
 * Pre-sizes the buffer to the full body once Content-Length is known,
 * then falls back to reactive doubling when the buffer fills. The stdlib
 * allocator reallocs transparently; embedded arenas expose no buf_grow
 * and fail with a specific error code rather than a generic transport
 * error.
 *
 * @note On failure conn_fail has already been invoked, so conn->state is
 *       terminal and the caller must return immediately.
 *
 * @param conn      Connection instance (rx_buf must be acquired).
 * @param transport Owning transport instance.
 * @retval 0  Room is available for the next recv.
 * @retval -1 Buffer cannot grow; conn_fail was invoked.
 */
static int conn_rx_buf_ensure_space(pn_socket_connection_t* conn,
                                    pn_socket_transport_t*  transport)
{
    pubnub_allocator_provider_t* alloc   = transport->allocator;
    size_t                       new_cap = 0;
    int                          grew    = -1;

    /* Pre-size RX buffer once when Content-Length is known and the
     * body has not started arriving yet. Fires at most once per
     * response because body_received increments after first bytes. */
    if (PN_HTTP_STATE_BODY_CONTENT_LENGTH == conn->parser.state
        && 0 == conn->parser.body_received && conn->parser.content_length > 0
        && UINT32_MAX != conn->parser.body_start_offset
        && (uint32_t)conn->parser.content_length
               > (uint32_t)(conn->rx_buf.cap - conn->parser.body_start_offset)) {
        size_t needed = (size_t)conn->parser.body_start_offset
                      + (size_t)conn->parser.content_length;
        if (0 != PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE
            && needed > PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE) {
            conn_fail(conn, transport, PUBNUB_ERR_BUFFER_TOO_SMALL);
            return -1;
        }
        if (NULL == alloc || NULL == alloc->buf_grow) {
            conn_fail(conn, transport, PUBNUB_ERR_BUFFER_TOO_SMALL);
            return -1;
        }
        /* Best-effort; the reactive doubling below is the fallback. */
        alloc->buf_grow(alloc, &conn->rx_buf, needed);
    }

    if (conn->rx_buf.len < conn->rx_buf.cap) {
        return 0;
    }

    new_cap = conn->rx_buf.cap * 2U;
    if (0 != PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE
        && new_cap > PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE) {
        conn_fail(conn, transport, PUBNUB_ERR_BUFFER_TOO_SMALL);
        return -1;
    }
    if (NULL != alloc && NULL != alloc->buf_grow) {
        grew = alloc->buf_grow(alloc, &conn->rx_buf, new_cap);
    }
    if (0 != grew) {
        conn_fail(conn, transport, PUBNUB_ERR_BUFFER_TOO_SMALL);
        return -1;
    }
    return 0;
}

/**
 * @brief Publish a fully received response and transition to COMPLETE.
 *
 * Shared by the clean parse-complete path and the peer-close path so both
 * populate the response identically — in particular both extract the
 * captured headers, without which callers lose Retry-After and every
 * other header on a connection-close-terminated response.
 *
 * Reads the status code from the parser rather than taking it as an
 * argument: pn_http_parser_feed assigns its status out-parameter from
 * parser.status_code on every exit path, so the two are equivalent.
 *
 * @note Mutates conn->state, setting it to PN_CONN_COMPLETE.
 *
 * @param conn      Connection whose response should be finalized.
 * @param transport Owning transport instance (unused beyond symmetry
 *                  with the other tick helpers).
 */
static void conn_finalize_response(pn_socket_connection_t* conn,
                                   pn_socket_transport_t*  transport)
{
    (void)transport;

    conn->response->completion  = PUBNUB_HTTP_COMPLETE;
    conn->response->status_code = (int)conn->parser.status_code;

    if (UINT32_MAX != conn->parser.body_start_offset) {
        uint32_t boff        = conn->parser.body_start_offset;
        conn->response->body = conn->rx_buf.data + boff;
        /* Chunked responses are reassembled in-place; the write cursor
         * marks the true end of the decoded payload. */
        if (0 != (conn->parser.flags & PN_HTTP_FLAG_CHUNKED)) {
            conn->response->body_len = conn->parser.chunk_write_pos - boff;
        } else if (0 != (conn->parser.flags & PN_HTTP_FLAG_HAS_CONTENT_LENGTH)) {
            /* Clamp to Content-Length: any bytes past it (pipelined data
             * or a buggy server) must never be counted as body. */
            size_t avail             = conn->rx_buf.len - boff;
            conn->response->body_len = avail < conn->parser.content_length
                                         ? avail
                                         : conn->parser.content_length;
        } else {
            /* Identity body framed by connection close: every remaining
             * byte is body content. */
            conn->response->body_len = conn->rx_buf.len - boff;
        }
    } else {
        conn->response->body     = NULL;
        conn->response->body_len = 0;
    }

    /* Views alias the rx_buf, which outlives the response until the
     * slot is released. */
    if (0 == conn->response->header_count) {
        pn_http_parser_get_headers(&conn->parser,
                                   conn->rx_buf.data,
                                   conn->response->headers,
                                   PUBNUB_CFG_HTTP_MAX_RESP_HEADERS,
                                   &conn->response->header_count);
    }

    conn->state = PN_CONN_COMPLETE;
}

/**
 * @brief Log a receive error, including the TLS-level error when present.
 */
static void conn_log_recv_error(pn_socket_connection_t* conn,
                                pn_socket_transport_t*  transport,
                                int                     rc)
{
    /* Compiled-out logging turns every PUBNUB_LOG below into ((void)0),
     * leaving the status code unreferenced. */
    (void)rc;

    PUBNUB_LOG(transport->logger, PUBNUB_LOG_LEVEL_WARNING, "recv error: rc=%d", rc);

    if (NULL != conn->tls_session && NULL != transport->tls_backend) {
        int tls_err = transport->tls_backend->get_session_error(conn->tls_session);
        PUBNUB_LOG(transport->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "TLS recv error: %d",
                   tls_err);
        (void)tls_err;
    }
}

/**
 * @brief Tick: RECEIVING_RESPONSE state.
 */
static pn_conn_state_t tick_receiving_response(pn_socket_connection_t* conn,
                                               pn_socket_transport_t* transport)
{
    size_t space;
    int    rc;

    if (NULL == conn->rx_buf.data) {
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        return conn->state;
    }

    if (0 != conn_rx_buf_ensure_space(conn, transport)) {
        return conn->state;
    }

    space = conn->rx_buf.cap - conn->rx_buf.len;
    rc = conn_recv(conn, transport, conn->rx_buf.data + conn->rx_buf.len, space);

    if (rc > 0) {
        size_t         consumed   = 0;
        uint16_t       status     = 0;
        const uint8_t* body_start = NULL;
        size_t         body_len   = 0;

        conn->rx_buf.len += (size_t)rc;

        /* Feed the full accumulated buffer from offset 0; the parser
         * resumes from parser->pos so previously parsed bytes are skipped. */
        pn_http_parse_result_t result = pn_http_parser_feed(&conn->parser,
                                                            conn->rx_buf.data,
                                                            conn->rx_buf.len,
                                                            &consumed,
                                                            &status,
                                                            &body_start,
                                                            &body_len);

        if (PN_HTTP_PARSE_COMPLETE == result) {
            conn_finalize_response(conn, transport);
            return conn->state;
        }

        if (PN_HTTP_PARSE_ERROR == result) {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
            return conn->state;
        }

        /* NEED_MORE — continue on next tick. */
        return conn->state;
    }

    if (0 == rc) {
        /* Would-block — check transaction deadline. */
        if (conn_now_ms(transport) >= conn->transaction_deadline_ms) {
            conn_fail(conn, transport, PUBNUB_ERR_TIMEOUT);
        }
        return conn->state;
    }

    if (-1 == rc) {
        /* Peer closed (TCP FIN). The parser decides whether the close
         * terminates the response: a fully received Content-Length body or
         * an identity body framed by close (RFC 7230 §3.3.3 rule 7) is
         * finalized; a close mid status line, headers, or chunked/
         * Content-Length body fails. */
        if (PN_HTTP_PARSE_COMPLETE == pn_http_parser_signal_eof(&conn->parser)) {
            conn_finalize_response(conn, transport);
        } else {
            conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
        }
        return conn->state;
    }

    conn_log_recv_error(conn, transport, rc);
    conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
    return conn->state;
}

#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
/**
 * @brief Handle a 3xx response — parse Location, update redirect state, restart FSM.
 *
 * @return 1 if a redirect was started (conn->state already set); 0 to fall through.
 */
static int tick_complete_handle_redirect(pn_socket_connection_t* conn,
                                         pn_socket_transport_t*  transport)
{
    unsigned int         hdr_i;
    pubnub_string_view_t location_val = {NULL, 0};
    char*                url;
    char*                new_host;
    char*                new_path;
    uint8_t              new_secure;
    uint16_t             new_port;
    pubnub_res_t         prc;

    if (conn->redirect_count >= PUBNUB_CFG_SOCKET_MAX_REDIRECTS) {
        conn_free_redirect(conn, transport);
        conn_close_all(conn, transport);
        if (NULL != conn->response) {
            conn->response->completion      = PUBNUB_HTTP_ERROR;
            conn->response->transport_error = PUBNUB_ERR_TRANSPORT;
        }
        conn->state = PN_CONN_FAILED;
        return 1;
    }

    for (hdr_i = 0; hdr_i < conn->response->header_count; hdr_i++) {
        if (8 == conn->response->headers[hdr_i].key.len
            && 0
                   == pn_ascii_casecmp(
                       conn->response->headers[hdr_i].key.ptr, "location", 8)) {
            location_val = conn->response->headers[hdr_i].value;
            break;
        }
    }

    if (NULL == location_val.ptr || 0 == location_val.len) {
        return 0;
    }

    url = pn_strndup(location_val.ptr, location_val.len, transport->allocator);
    if (NULL == url) {
        return 0;
    }

    new_host   = NULL;
    new_path   = NULL;
    new_secure = 0;
    new_port   = 0;
    prc        = pn_parse_redirect_url(
        url, transport->allocator, &new_host, &new_path, &new_secure, &new_port);
    pn_strfree(url, transport->allocator);

    if (PUBNUB_OK != prc) {
        return 0;
    }

    /* Refuse an https->http downgrade. A redirect that drops TLS would
     * silently expose the request (auth token, payload) in plaintext, so a
     * secure origin must never be talked out of TLS by a Location header. */
    if (conn_effective_secure(conn) && 0 == new_secure) {
        PUBNUB_LOG_TEXT(transport->logger,
                        PUBNUB_LOG_LEVEL_WARNING,
                        "rejecting redirect: https->http downgrade blocked");
        pn_strfree(new_host, transport->allocator);
        pn_strfree(new_path, transport->allocator);
        conn_free_redirect(conn, transport);
        conn_close_all(conn, transport);
        if (NULL != conn->response) {
            conn->response->completion      = PUBNUB_HTTP_ERROR;
            conn->response->transport_error = PUBNUB_ERR_TRANSPORT;
        }
        conn->state = PN_CONN_FAILED;
        return 1;
    }

    if (NULL != conn->redirect_host) {
        pn_strfree(conn->redirect_host, transport->allocator);
    }
    if (NULL != conn->redirect_path) {
        pn_strfree(conn->redirect_path, transport->allocator);
    }
    conn->redirect_host   = new_host;
    conn->redirect_path   = new_path;
    conn->redirect_secure = new_secure;
    conn->redirect_port   = new_port;
    conn->redirect_count++;

    conn_close_all(conn, transport);

    conn->response->completion   = PUBNUB_HTTP_PENDING;
    conn->response->status_code  = 0;
    conn->response->body         = NULL;
    conn->response->body_len     = 0;
    conn->response->header_count = 0;
    conn->state                  = PN_CONN_IDLE;
    conn->requests_on_connection = 0;

    if (0 != pn_connection_start(conn, conn->request, conn->response, transport)) {
        conn_fail(conn, transport, PUBNUB_ERR_TRANSPORT);
    }
    return 1;
}
#endif /* PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0 */

/** @brief Handle COMPLETE state — decide keep-alive vs close. */
static pn_conn_state_t tick_complete(pn_socket_connection_t* conn,
                                     pn_socket_transport_t*  transport)
{
#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
    if (conn->request->follow_redirects && NULL != transport->allocator
        && conn->response->status_code >= 300 && conn->response->status_code < 400) {
        if (tick_complete_handle_redirect(conn, transport)) {
            return conn->state;
        }
    }
#endif

    /* Save redirect state before conn_free_redirect resets the counter.
     * Redirected connections target a different host (e.g. S3 for file
     * downloads) and must not be kept alive in the pool — a pooled S3
     * connection is useless for subsequent PubNub API requests and would
     * occupy a slot, potentially stalling publish/subscribe. */
    uint8_t was_redirected = (conn->redirect_count > 0);

    /* A redirect chain that ended in a final 2xx (or any non-redirect)
     * response no longer needs the redirect target strings. */
    conn_free_redirect(conn, transport);

    int should_close =
        was_redirected || pn_keepalive_should_close(conn->parser.flags);

    /* External requests target third-party servers (e.g. S3 for file
     * uploads) with unknown keep-alive policies. AWS S3 may close
     * idle connections after ~5 s while the SDK idle timeout is
     * longer, leading to stale-socket failures on reuse. Close
     * unconditionally to avoid that race. */
    if (!should_close && NULL != conn->request && conn->request->external) {
        should_close = 1;
    }

    conn->requests_on_connection++;

    if (should_close
        || conn->requests_on_connection >= PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS) {
        conn->state = PN_CONN_CLOSING;
        return conn->state;
    }

    /* Preserve connection for reuse. */
    conn_extract_hostname(conn_effective_host(conn),
                          conn->connected_host,
                          sizeof(conn->connected_host));
    conn->connected_port       = conn_effective_port(conn);
    conn->connected_secure     = conn_effective_secure(conn);
    conn->idle_since_ms        = conn_now_ms(transport);
    conn->keepalive_retry_used = 0;
    conn->state                = PN_CONN_KEEP_ALIVE_IDLE;
    return conn->state;
}

/**
 * @brief Handle CLOSING state — tear down the connection.
 */
static pn_conn_state_t tick_closing(pn_socket_connection_t* conn,
                                    pn_socket_transport_t*  transport)
{
    /* Close only TLS + socket. rx_buf and decomp_buf are kept alive so
     * that route_completions / feature callbacks can still read the
     * body after this poll cycle. They are freed when the connection
     * is reused (pn_connection_start) or reset (pn_connection_reset). */
    conn_close_transport(conn, transport);
    conn->connected_host[0]      = '\0';
    conn->connected_port         = 0;
    conn->connected_secure       = 0;
    conn->requests_on_connection = 0;
    conn->keepalive_retry_used   = 0;
    conn->state                  = PN_CONN_IDLE;
    return conn->state;
}

void pn_conn_free_decomp_buf(pn_socket_connection_t* conn,
                             pn_socket_transport_t*  transport)
{
    if (NULL == conn || NULL == transport) {
        return;
    }
    if (NULL != conn->decomp_buf && NULL != transport->allocator
        && NULL != transport->allocator->free) {
        PN_FREE(transport->allocator, conn->decomp_buf);
        conn->decomp_buf = NULL;
    }
}

void pn_connection_init(pn_socket_connection_t* conn)
{
    if (NULL == conn) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
    conn->socket      = PN_INVALID_SOCKET;
    conn->tls_session = NULL;
    conn->state       = PN_CONN_IDLE;
    conn->generation  = 1;
}

/** @brief Recreate the TLS context when `tls_ctx_stale` is set and no active
 *         sessions exist. Safe to call only from the single-threaded poll context. */
static void socket_apply_pending_tls_config(pn_socket_transport_t* transport)
{
    int i;
    int has_active_tls = 0;
    if (!PUBNUB_ATOMIC_LOAD_U8(&transport->tls_ctx_stale)
        || NULL == transport->tls_backend) {
        return;
    }
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        if (NULL != transport->connections[i].tls_session) {
            has_active_tls = 1;
            break;
        }
    }
    if (!has_active_tls) {
        /* Claim the gate with a single atomic exchange-to-zero before
         * consuming staged config. If a concurrent writer re-arms the flag
         * (staging a newer bundle) after this point, the flag stays set and
         * we re-apply on a later poll — a separate load-then-clear would
         * leave a window that silently drops the newer bundle. */
        (void)PUBNUB_ATOMIC_EXCHANGE_U8(&transport->tls_ctx_stale, 0);

        /* Swap any pending user-thread values into tls_config before
         * ctx_create reads the config. Safe here: single-threaded
         * poll context and no active TLS sessions reference ca_pem. */
        if (transport->pending_ca_pem_set) {
            pn_strfree(transport->tls_config.ca_pem, transport->allocator);
            transport->tls_config.ca_pem  = transport->pending_ca_pem;
            transport->pending_ca_pem     = NULL;
            transport->pending_ca_pem_set = 0;
        }
        if (0xFF != transport->pending_skip_verify) {
            transport->tls_config.skip_verify = transport->pending_skip_verify;
            transport->pending_skip_verify    = 0xFF;
        }

        pubnub_provider_deps_t deps = {0};
        deps.allocator              = transport->allocator;
        deps.platform               = transport->platform;
        deps.logger                 = transport->logger;
        void* new_ctx =
            transport->tls_backend->ctx_create(&transport->tls_config, &deps);
        if (NULL != new_ctx) {
            transport->tls_backend->ctx_destroy(transport->tls_ctx);
            transport->tls_ctx = new_ctx;
        } else {
            /* Context creation failed; re-arm the gate to retry on the
             * next poll. The consumed config is already folded into
             * tls_config, so the retry re-reads it. */
            PUBNUB_ATOMIC_STORE_U8(&transport->tls_ctx_stale, 1);
        }
    }
}

/**
 * @brief Attempt to reuse a keep-alive connection for a new request.
 *
 * Compares the request target against the connected host/port/TLS mode
 * and the per-connection request and idle-time limits.
 *
 * @note Mutates conn->state. On reuse the parser is re-initialized, any
 *       stale decompression buffer from the previous response on this
 *       connection is freed, and the state becomes SENDING_HEADERS. On
 *       refusal all connection resources are closed and
 *       requests_on_connection is zeroed, leaving the state unchanged so
 *       the caller can start a fresh connection.
 *
 * @param conn        Connection in KEEP_ALIVE_IDLE holding a live socket.
 * @param transport   Owning transport instance.
 * @param request     Incoming request descriptor.
 * @param now         Current monotonic time in milliseconds.
 * @param host_scratch Caller-owned scratch buffer for the request
 *                    hostname. Clobbered on both the reuse and the
 *                    refusal path, so the caller must not rely on its
 *                    contents after this call. Borrowing the caller's
 *                    buffer keeps the two hostname arrays from stacking
 *                    into a single frame.
 * @param scratch_cap Capacity of host_scratch in bytes.
 * @retval 1 Connection reused; conn->state is already set.
 * @retval 0 Cannot reuse; caller must start a fresh connection.
 */
static int conn_try_keepalive_reuse(pn_socket_connection_t*      conn,
                                    pn_socket_transport_t*       transport,
                                    const pubnub_http_request_t* request,
                                    uint64_t                     now,
                                    char*                        host_scratch,
                                    size_t                       scratch_cap)
{
    uint16_t                  new_port   = pn_http_resolve_port(request);
    pn_keepalive_conn_state_t conn_state = {
        .host            = conn->connected_host,
        .port            = conn->connected_port,
        .secure          = conn->connected_secure,
        .requests_served = conn->requests_on_connection,
        .idle_since_ms   = conn->idle_since_ms,
    };
    pn_keepalive_target_t target = {
        .host   = host_scratch,
        .port   = new_port,
        .secure = request->secure,
    };
    int reuse;

    conn_extract_hostname(request->host, host_scratch, scratch_cap);

    reuse = pn_keepalive_can_reuse(&conn_state,
                                   &target,
                                   now,
                                   PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS,
                                   PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS);

    PUBNUB_LOG(transport->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "keepalive check: reuse=%d, conn_host=%s, "
               "req_host=%s, fd=%d",
               reuse,
               conn->connected_host,
               host_scratch,
               (int)conn->socket);

    if (reuse) {
        pn_conn_free_decomp_buf(conn, transport);
        pn_http_parser_init(&conn->parser);
        conn->state = PN_CONN_SENDING_HEADERS;
        return 1;
    }

    conn_close_all(conn, transport);
    conn->requests_on_connection = 0;
    return 0;
}

/**
 * @brief Choose the hostname and port for the outgoing TCP connection.
 *
 * With a proxy configured the connection targets the proxy and the real
 * host is tunneled via CONNECT; otherwise it targets the effective
 * request host, which is the redirect target when one is active.
 *
 * @param conn      Connection instance.
 * @param transport Owning transport instance.
 * @param out_host  Buffer receiving the NUL-terminated hostname.
 * @param host_cap  Capacity of out_host in bytes.
 * @param out_port  Receives the TCP port to connect to.
 */
static void conn_select_connect_target(pn_socket_connection_t* conn,
                                       pn_socket_transport_t*  transport,
                                       char*                   out_host,
                                       size_t                  host_cap,
                                       uint16_t*               out_port)
{
    if (NULL != transport->proxy_module
        && NULL != transport->proxy_config_stored.host) {
        pn_strlcpy(out_host, transport->proxy_config_stored.host, host_cap);
        *out_port = transport->proxy_config_stored.port;
        return;
    }

    conn_extract_hostname(conn_effective_host(conn), out_host, host_cap);
    *out_port = conn_effective_port(conn);
}

/**
 * @brief Start DNS resolution for the connect target.
 *
 * Records the hostname for deferred retry from tick_dns_resolving, kicks
 * off the resolver, and consumes an immediate cache hit when one is
 * available.
 *
 * @note Mutates conn->state: CONNECTING on a cache hit, DNS_RESOLVING
 *       when the lookup is pending or the resolver is busy with another
 *       connection. On a cache hit conn->resolved_addrs, addr_count and
 *       addr_current are populated.
 *
 * @note Whenever results are claimed the shared resolver is returned to
 *       IDLE, on both the success and the failure path, so a lookup that
 *       yields no usable address cannot wedge other connections.
 *
 * @param conn      Connection instance.
 * @param transport Owning transport instance.
 * @param hostname  Hostname to resolve.
 * @param port      TCP port stamped onto every resolved address.
 * @retval 0  State set; the FSM continues on a subsequent tick.
 * @retval -1 Hard failure — the resolver produced no usable address. The
 *            resolver has been returned to IDLE and is free for reuse.
 */
static int conn_begin_dns(pn_socket_connection_t* conn,
                          pn_socket_transport_t*  transport,
                          const char*             hostname,
                          uint16_t                port)
{
    size_t  count = 0;
    uint8_t i;
    int     rc;

    pn_strlcpy(conn->dns_hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN);

    rc = pn_dns_resolver_start(&transport->resolver, hostname);
    if (rc < 0) {
        /* Resolver is busy with another connection's lookup. Enter
         * DNS_RESOLVING and retry on subsequent ticks — once the active
         * lookup completes the cache will serve this request instantly. */
        conn->state = PN_CONN_DNS_RESOLVING;
        return 0;
    }

    if (PN_DNS_STATE_DONE != pn_dns_resolver_state(&transport->resolver)) {
        conn->state = PN_CONN_DNS_RESOLVING;
        return 0;
    }

    rc = pn_dns_resolver_get_results(&transport->resolver,
                                     conn->resolved_addrs,
                                     PUBNUB_CFG_MAX_DNS_RESULTS,
                                     &count);

    /* Release the shared resolver before inspecting the outcome. Leaving
     * it in DONE on the failure path would wedge every other connection:
     * pn_dns_resolver_start refuses to run while a lookup is unclaimed,
     * so the whole transport would stop resolving. */
    transport->resolver.state = PN_DNS_STATE_IDLE;

    if (rc < 0 || 0 == count) {
        return -1;
    }
    conn->addr_count   = (uint8_t)count;
    conn->addr_current = 0;

    for (i = 0; i < conn->addr_count; i++) {
        conn->resolved_addrs[i].port = port;
    }

    conn->state = PN_CONN_CONNECTING;
    return 0;
}

int pn_connection_start(pn_socket_connection_t*      conn,
                        const pubnub_http_request_t* request,
                        pubnub_http_response_t*      response,
                        pn_socket_transport_t*       transport)
{
    char     hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN];
    uint16_t connect_port;
    uint64_t now;
    uint32_t timeout;

    if (NULL == transport || NULL == transport->platform) {
        if (NULL != response) {
            response->completion      = PUBNUB_HTTP_ERROR;
            response->transport_error = PUBNUB_ERR_NOT_INITIALIZED;
        }
        return -1;
    }

    if (NULL == conn || NULL == request || NULL == response) {
        return -1;
    }

    if (PN_CONN_IDLE != conn->state && PN_CONN_KEEP_ALIVE_IDLE != conn->state) {
        return -1;
    }

    /* Free deferred buffers from a prior request that went through the
     * close path (tick_closing). Safe because pn_connection_start is
     * called only when dispatching a new request, after the core has
     * finished reading the previous response. */
    if (PN_CONN_IDLE == conn->state) {
        pn_conn_free_decomp_buf(conn, transport);
        conn_release_rx_buf(conn, transport);
    }

    socket_apply_pending_tls_config(transport);

    conn->request  = request;
    conn->response = response;

    /* keepalive_retry_used is NOT reset here — it must survive the
     * re-entrant pn_connection_start() call the stale-keepalive retry
     * path makes from within a tick. It is zeroed in pn_connection_init,
     * pn_connection_reset, and tick_closing which cover all
     * fresh-dispatch entry points. */

    /* Reset send/recv tracking. */
    conn->header_sent      = 0;
    conn->header_len       = 0;
    conn->body_sent        = 0;
    conn->rx_buf.len       = 0;
    conn->family_exhausted = 0;
    conn->addr_count       = 0;
    conn->addr_current     = 0;

    /* Compute deadlines. */
    now     = conn_now_ms(transport);
    timeout = request->timeout_ms;
    if (0 == timeout) {
        timeout = PUBNUB_CFG_TRANSACTION_TIMEOUT_MS;
    }
    conn->connect_deadline_ms     = now + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS;
    conn->transaction_deadline_ms = now + (uint64_t)timeout;

    /* Build headers early (needed for both reuse and fresh paths). */
    if (0 != conn_build_headers(conn, request)) {
        return -1;
    }

    /* hostname doubles as keep-alive scratch; the reuse check either
     * returns 1 (we are done with it) or leaves it to be overwritten by
     * conn_select_connect_target below. */
    if (PN_CONN_KEEP_ALIVE_IDLE == conn->state && PN_INVALID_SOCKET != conn->socket
        && conn_try_keepalive_reuse(
            conn, transport, request, now, hostname, sizeof(hostname))) {
        return 0;
    }

    /* When a proxy is configured the connection targets the proxy port;
     * the real host is tunneled via CONNECT. */
    conn_select_connect_target(
        conn, transport, hostname, sizeof(hostname), &connect_port);

    return conn_begin_dns(conn, transport, hostname, connect_port);
}

pn_conn_state_t pn_connection_tick(pn_socket_connection_t* conn,
                                   pn_socket_transport_t*  transport)
{
    if (NULL == conn || NULL == transport) {
        return PN_CONN_FAILED;
    }

    switch (conn->state) {
    case PN_CONN_IDLE:
    case PN_CONN_KEEP_ALIVE_IDLE:
    case PN_CONN_CANCELLED:
        /* No work to do in these states. */
        return conn->state;

    case PN_CONN_DNS_RESOLVING: return tick_dns_resolving(conn, transport);

    case PN_CONN_CONNECTING: return tick_connecting(conn, transport);

    case PN_CONN_PROXY_NEGOTIATING:
        return tick_proxy_negotiating(conn, transport);

    case PN_CONN_TLS_HANDSHAKING: return tick_tls_handshaking(conn, transport);

    case PN_CONN_SENDING_HEADERS: return tick_sending_headers(conn, transport);

    case PN_CONN_SENDING_BODY: return tick_sending_body(conn, transport);

    case PN_CONN_RECEIVING_RESPONSE:
        return tick_receiving_response(conn, transport);

    case PN_CONN_COMPLETE: return tick_complete(conn, transport);

    case PN_CONN_CLOSING: return tick_closing(conn, transport);

    case PN_CONN_FAILED: return conn->state;
    }

    /* Unreachable — all enum values covered. */
    return conn->state;
}

void pn_connection_cancel(pn_socket_connection_t* conn,
                          pn_socket_transport_t*  transport)
{
    if (NULL == conn || NULL == transport) {
        return;
    }

    /* Only cancel if actively processing. */
    if (PN_CONN_IDLE == conn->state || PN_CONN_KEEP_ALIVE_IDLE == conn->state
        || PN_CONN_COMPLETE == conn->state || PN_CONN_FAILED == conn->state
        || PN_CONN_CANCELLED == conn->state) {
        return;
    }

    /* If this connection owns the current DNS query, reset the resolver
     * to IDLE so other waiting connections can start their own lookups. */
    if (PN_CONN_DNS_RESOLVING == conn->state
        && 0
               == strncmp(transport->resolver.current_hostname,
                          conn->dns_hostname,
                          sizeof(conn->dns_hostname) - 1U)) {
        transport->resolver.state = PN_DNS_STATE_IDLE;
    }

    /* Free proxy session if mid-negotiation. */
    if (PUBNUB_ENABLE_PROXY && NULL != conn->proxy_session) {
        pn_proxy_connect_session_destroy(conn->proxy_session, transport->allocator);
        conn->proxy_session = NULL;
    }

    /* Free redirect buffers to prevent leaks on cancel. */
    conn_free_redirect(conn, transport);

    conn_close_all(conn, transport);

    if (NULL != conn->response) {
        conn->response->completion      = PUBNUB_HTTP_ERROR;
        conn->response->transport_error = PUBNUB_ERR_CANCELLED;
    }
    conn->idle_since_ms = conn_now_ms(transport);
    conn->state         = PN_CONN_CANCELLED;
}

void pn_connection_reset(pn_socket_connection_t* conn,
                         pn_socket_transport_t*  transport)
{
    uint16_t next_gen;
    if (NULL == conn || NULL == transport) {
        return;
    }

    /* Bump generation before recycling so stale tagged handles that
     * encode the old generation are rejected by socket_cancel. */
    next_gen = (uint16_t)(conn->generation + 1U);
    if (0 == next_gen) {
        next_gen = 1;
    }

    /* Free proxy session if any. */
    if (PUBNUB_ENABLE_PROXY && NULL != conn->proxy_session) {
        pn_proxy_connect_session_destroy(conn->proxy_session, transport->allocator);
        conn->proxy_session = NULL;
    }

    pn_conn_free_decomp_buf(conn, transport);

    /* Free redirect buffers if any. */
    conn_free_redirect(conn, transport);

    conn_close_all(conn, transport);

    conn->state                  = PN_CONN_IDLE;
    conn->socket                 = PN_INVALID_SOCKET;
    conn->tls_session            = NULL;
    conn->proxy_session          = NULL;
    conn->proxy_done             = 0;
    conn->decomp_buf             = NULL;
    conn->addr_count             = 0;
    conn->addr_current           = 0;
    conn->family_exhausted       = 0;
    conn->header_len             = 0;
    conn->header_sent            = 0;
    conn->body_sent              = 0;
    conn->rx_buf.len             = 0;
    conn->connected_host[0]      = '\0';
    conn->connected_port         = 0;
    conn->connected_secure       = 0;
    conn->requests_on_connection = 0;
    conn->keepalive_retry_used   = 0;
    conn->idle_since_ms          = 0;
    conn->request                = NULL;
    conn->response               = NULL;
    conn->generation             = next_gen;
}

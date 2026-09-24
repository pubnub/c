/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file transport_curl.c
 * @brief libcurl-backed HTTP transport provider.
 *
 * The `curl` transport is the default for hosted profiles
 * (`full`, `minimal`). It wraps libcurl's multi-handle interface
 * behind the five-callback provider contract validated in
 * `client.c` at context init:
 *
 *   - @ref pn_curl_transport_send   - builds a URL from the structured
 *       request descriptor, configures a `CURL*` easy handle, attaches
 *       it to a shared `CURLM*` multi handle, and returns the
 *       per-request tracking struct as the opaque transport handle.
 *   - @ref pn_curl_transport_poll   - drives I/O via
 *       `curl_multi_perform`, harvests finished transfers with
 *       `curl_multi_info_read`, and populates each request's response
 *       descriptor with the HTTP status and body bytes accumulated by
 *       the write callback.
 *   - @ref pn_curl_transport_cancel - detaches a transfer from the
 *       multi handle and tears down its per-request state.
 *   - @ref pn_curl_transport_init   - calls `curl_global_init` (ref-
 *       counted, safe to call per context), creates the multi handle,
 *       and caches the shared dependency pointers (allocator, logger,
 *       platform).
 *   - @ref pn_curl_transport_deinit - drains in-flight transfers,
 *       destroys the multi handle, and calls `curl_global_cleanup`.
 *
 * Each context gets its own `pn_curl_transport_t` instance (the
 * serialization header classifies this as a per-context provider);
 * the multi handle and the cached deps live inside that extended
 * struct via first-member embedding of the `pubnub_transport_provider_t`
 * vtable.
 *
 * TLS is on by default when `PUBNUB_ENABLE_SECURE_TRANSPORT` is set
 * (the profile default) - libcurl auto-selects the platform's TLS
 * backend (Secure Transport on macOS, OpenSSL/GnuTLS on Linux,
 * Schannel on Windows) through its own build-time configuration, so
 * this provider does not pick one explicitly.
 *
 * Response headers are intentionally NOT parsed on this branch; the
 * header count stays at 0 and feature code reads the body directly.
 * Feature-level header consumption (e.g. retry-after, signatures)
 * will land alongside the first feature that needs it.
 *
 * ## Proxy support
 *
 * Supported proxy types (via CURLOPT_PROXYTYPE):
 *   - PUBNUB_PROXY_HTTP_CONNECT  -> CURLPROXY_HTTP
 *   - PUBNUB_PROXY_SOCKS5        -> CURLPROXY_SOCKS5
 *
 * Authentication:
 *   - PUBNUB_PROXY_AUTH_BASIC -> CURLOPT_PROXYUSERPWD
 *
 * Limitations:
 *   - SOCKS5 support depends on libcurl being built with a SOCKS
 *     backend. If absent, libcurl returns CURLE_NOT_BUILT_IN at
 *     transfer time which this provider maps to PUBNUB_HTTP_ERROR.
 *   - HTTPS-to-proxy (proxy tunneling over TLS to the proxy itself)
 *     is not yet exposed; add CURLOPT_PROXY_SSL* options when needed.
 */

#include "pubnub/providers/transport.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/proxy.h"
#include "pubnub/tcp_keepalive.h"
#include "pubnub/config.h"
#include "pubnub/pubnub_compat.h"

#include "pn_format.h"
#include "pn_string.h"
#include "transport_curl_internal.h"

#include <curl/curl.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc);

/**
 * @brief Extended transport provider carrying the libcurl multi
 *        handle and cached dependency pointers.
 *
 * The vtable lives at offset 0 so a `pubnub_transport_provider_t*`
 * can be recovered by first-member cast.  `allocator` is used to
 * acquire response-body buffers; `multi` is the shared transfer
 * engine every in-flight request attaches to.
 */
typedef struct pn_curl_transport {
    pubnub_transport_provider_t   base;   /* must be first member */
    pubnub_allocator_provider_t*  allocator;
    pubnub_logger_provider_t*     logger; /**< Shared logger, may be NULL. */
    CURLM*                        multi;
    const pubnub_proxy_config_t*  proxy;
    pubnub_tcp_keepalive_config_t keepalive;
    const char*                   user_dns_primary;
    const char*                   user_dns_secondary;
    const char*                   ca_pem; /**< Owned PEM CA bundle, or NULL. */
    uint8_t skip_verify;                  /**< 1 = skip TLS verification. */
    /** Set after first CURLOPT_DNS_SERVERS NOT_BUILT_IN warning. */
    volatile uint8_t dns_cares_warned;

    /* Pending CA PEM staged by the user thread via set_tls_ca_bundle and
     * swapped into ca_pem on the bg poll thread in send(). Staging avoids
     * freeing the buffer while request setup may be reading it on another
     * thread. Ownership: allocator-owned once stored; the bg thread frees
     * the old ca_pem after the swap. */
    const char* pending_ca_pem;

    /** 1 = pending_ca_pem holds a new value (possibly NULL). */
    uint8_t pending_ca_pem_set;

    /** Publication gate: written by the user thread (set_tls_ca_bundle),
     *  read by the bg poll thread in send(). Atomic for cross-core
     *  visibility on SMP targets. */
    PUBNUB_ATOMIC_UINT8 ca_pem_stale;
} pn_curl_transport_t;

/**
 * @brief Per-request tracking state returned as the opaque
 *        transport handle from @ref pn_curl_transport_send.
 *
 * Owned by the transport: allocated in `send`, released in
 * `poll`'s completion sweep, `cancel`, or `deinit`. The response
 * buffer (`rx_buf`) is acquired from the allocator on `send` and
 * released alongside the tracking struct - matching the body-
 * ownership contract in `providers/transport_types.h` (body is
 * valid until the next send/cancel on the same handle).
 */
/** Per-header average budget in bytes for response header storage. */
#define PN_CURL_HDR_AVG_SIZE 128

typedef struct pn_curl_request {
    pn_curl_transport_t*    transport;
    CURL*                   easy;
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;

    /* Response-body accumulator.
     *
     * Acquired from the allocator with PUBNUB_BUF_RX at send time
     * (malloc on hosted profiles, arena region on embedded). Grown in
     * place via allocator->buf_grow when the response exceeds the
     * initial capacity (heap allocator realloc's; arena allocator
     * returns failure, causing the transfer to abort with
     * BUFFER_TOO_SMALL). response.body points into rx_buf.data as a
     * non-owning view for the SDK core to read.
     *
     * The slot does not carry a dedicated RX buffer field; rx_buf lives
     * on the transport's per-request tracking struct. If a future slot
     * revision adds an RX buffer field, this transport should write into
     * the slot's rx_buf instead of its own tracking struct. */
    pubnub_buffer_t rx_buf;
    size_t          rx_written;

    /* URL and header-list ownership. Both strings/slist live for
     * the duration of the transfer and are freed on completion. */
    char*              url;
    struct curl_slist* header_slist;

    /* Response header storage for TRACE logging.
     *
     * curl's header callback buffer is transient; header strings are
     * copied here as NUL-terminated "key\0value\0" pairs. The
     * response->headers[] views point into this buffer. */
    char   hdr_storage[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS * PN_CURL_HDR_AVG_SIZE];
    size_t hdr_storage_used;
} pn_curl_request_t;

/**
 * @brief libcurl write callback: append @p size * @p nmemb bytes
 *        into the request's RX buffer.
 *
 * Delegates to @ref pn_curl_rx_append_or_grow which centralises the
 * grow-or-fail logic in a form that is unit-testable without a
 * real libcurl transfer (see `transport_curl_internal.h`).
 */
static size_t pn_curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    pn_curl_request_t* req      = (pn_curl_request_t*)userdata;
    size_t             incoming = size * nmemb;

    return pn_curl_rx_append_or_grow(
        req->transport->allocator, &req->rx_buf, &req->rx_written, ptr, incoming);
}

/**
 * @brief libcurl header callback: capture response headers into
 *        the request's inline storage buffer.
 *
 * Each invocation receives one header line (including CRLF). Status
 * lines ("HTTP/...") and the empty terminator line are skipped. The
 * name and value are copied NUL-terminated into hdr_storage and the
 * response->headers[] views are updated.
 */
/**
 * @brief Case-insensitive ASCII comparison for HTTP header names.
 *
 * Uses `| 0x20` folding which maps A-Z to a-z. Safe for US-ASCII
 * header names per RFC 7230. Local to this file.
 */
static int pn_header_name_eq(const char* a, const char* b, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        if ((a[i] | 0x20) != (b[i] | 0x20)) {
            return 0;
        }
    }
    return 1;
}

static size_t pn_curl_header_cb(char* buffer, size_t size, size_t nitems, void* userdata)
{
    pn_curl_request_t*      req  = (pn_curl_request_t*)userdata;
    pubnub_http_response_t* resp = req->response;
    size_t                  len  = size * nitems;

    /* Skip status line (starts with "HTTP/"). */
    if (len >= 5 && 0 == memcmp(buffer, "HTTP/", 5)) {
        return len;
    }

    /* Skip empty line (end-of-headers marker). */
    if (len <= 2) {
        return len;
    }

    /* Already at capacity. */
    if (resp->header_count >= PUBNUB_CFG_HTTP_MAX_RESP_HEADERS) {
        return len;
    }

    /* Find the colon separator. */
    size_t colon = 0;
    while (colon < len && ':' != buffer[colon]) {
        ++colon;
    }
    if (colon >= len) {
        return len;
    }

    size_t key_len = colon;

    /* Value starts after ':' — skip leading whitespace. */
    size_t val_start = colon + 1;
    while (val_start < len && ' ' == buffer[val_start]) {
        ++val_start;
    }

    /* Trim trailing CRLF/whitespace from value. */
    size_t val_end = len;
    while (val_end > val_start
           && ('\r' == buffer[val_end - 1] || '\n' == buffer[val_end - 1]
               || ' ' == buffer[val_end - 1])) {
        --val_end;
    }
    size_t val_len = val_end - val_start;

    /* Check storage budget: key + NUL + value + NUL. */
    size_t need = key_len + 1 + val_len + 1;
    size_t cap  = sizeof(req->hdr_storage) - req->hdr_storage_used;
    if (need > cap) {
        return len;
    }

    /* Copy key NUL-terminated. */
    char* key_dst = req->hdr_storage + req->hdr_storage_used;
    memcpy(key_dst, buffer, key_len);
    key_dst[key_len] = '\0';
    req->hdr_storage_used += key_len + 1;

    /* Copy value NUL-terminated. */
    char* val_dst = req->hdr_storage + req->hdr_storage_used;
    memcpy(val_dst, buffer + val_start, val_len);
    val_dst[val_len] = '\0';
    req->hdr_storage_used += val_len + 1;

    /* Point the response header views into hdr_storage. */
    unsigned int idx             = resp->header_count;
    resp->headers[idx].key.ptr   = key_dst;
    resp->headers[idx].key.len   = key_len;
    resp->headers[idx].value.ptr = val_dst;
    resp->headers[idx].value.len = val_len;
    resp->header_count++;

    /* Pre-size RX buffer when Content-Length is known. */
    if (14 == key_len && pn_header_name_eq(key_dst, "Content-Length", 14)) {
        size_t      content_len = 0;
        const char* p;
        int         digits = 0;
        for (p = val_dst; *p >= '0' && *p <= '9' && digits < 20; ++p, ++digits) {
            content_len = content_len * 10 + (size_t)(*p - '0');
        }
        if (content_len > 0 && content_len > req->rx_buf.cap) {
            int skip_grow = 0;
            if (0 != PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE
                && content_len > PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE) {
                skip_grow = 1;
            }
            if (!skip_grow) {
                pubnub_allocator_provider_t* alloc = req->transport->allocator;
                if (NULL != alloc && NULL != alloc->buf_grow) {
                    /* Best-effort; write callback's doubling is fallback. */
                    alloc->buf_grow(alloc, &req->rx_buf, content_len);
                }
            }
        }
    }

    return len;
}

/**
 * @brief Append @p chunk_len bytes into @p buf, growing via
 *        @p allocator->buf_grow when capacity runs out.
 *
 * Respects the allocator-provider header's "buf_grow may be NULL"
 * contract (`include/pubnub/providers/allocator.h:174-187`): a NULL
 * @c buf_grow is treated as "grow unsupported" and the append
 * aborts by returning 0. Also returns 0 when @c buf_grow is
 * present but fails (non-zero return). Callers - principally
 * @ref pn_curl_write_cb - propagate the 0 return to libcurl to abort
 * the in-flight transfer.
 *
 * On success returns @p chunk_len unchanged so a caller can hand
 * the value directly back to libcurl.
 */
size_t pn_curl_rx_append_or_grow(pubnub_allocator_provider_t* allocator,
                                 pubnub_buffer_t*             buf,
                                 size_t*                      written,
                                 const char*                  chunk,
                                 size_t                       chunk_len)
{
    size_t needed = *written + chunk_len;

    if (needed > buf->cap) {
        if (0 != PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE
            && needed > PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE) {
            return 0;
        }
        if (NULL == allocator->buf_grow
            || 0 != allocator->buf_grow(allocator, buf, needed)) {
            /* Either the allocator does not support grow at all
             * (arena / fixed-pool backends) or the grow attempt
             * failed (OOM, cap exceeded). Signal short-write to
             * libcurl so it aborts the transfer cleanly. */
            return 0;
        }
    }

    memcpy(buf->data + *written, chunk, chunk_len);
    *written += chunk_len;
    buf->len = *written;
    return chunk_len;
}

/**
 * @brief Validate that every string-view pointer that will be
 *        dereferenced by the URL builder is non-NULL when its
 *        length is greater than zero.
 *
 * Caller-side feature code should populate these fields from
 * string literals or pre-allocated scratch, but a misconfigured
 * feature or middleware could produce a len > 0 / ptr == NULL
 * combination that is undefined behaviour when handed to memcpy.
 * This defensive pass gives a clean NULL return from
 * @ref build_url rather than a crash.
 *
 * @param request Borrowed request descriptor.
 * @return Non-zero if every populated string view is valid.
 */
static int url_string_views_are_valid(const pubnub_http_request_t* request)
{
    if (NULL == request->host) {
        return 0;
    }
    for (unsigned int i = 0; i < request->path_segment_count; i++) {
        if (request->path_segments[i].len > 0
            && NULL == request->path_segments[i].ptr) {
            return 0;
        }
    }
    for (unsigned int i = 0; i < request->query_param_count; i++) {
        if ((request->query_params[i].key.len > 0
             && NULL == request->query_params[i].key.ptr)
            || (request->query_params[i].value.len > 0
                && NULL == request->query_params[i].value.ptr)) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Select the URL scheme based on the request's secure flag.
 *
 * `https` when TLS is requested, `http` otherwise. Returned
 * pointer points into static const storage.
 */
static const char* url_scheme(const pubnub_http_request_t* request)
{
    return request->secure ? "https" : "http";
}

/**
 * @brief Return the default port for the request's scheme.
 *
 * Knowledge of default ports is local to this transport: different
 * transport implementations (e.g. MQTT) have different defaults.
 */
static uint16_t url_default_port(const pubnub_http_request_t* request)
{
    return request->secure ? 443 : 80;
}

/**
 * @brief Parse an optional `:port` suffix from @p host.
 *
 * Supports both plain hostnames/IPv4 ("host:port") and
 * bracketed IPv6 literals ("[::1]:port"). Returns 0 when
 * no valid port suffix is present.
 *
 * @p host_len_out receives the hostname length to use in
 * URL assembly (excludes the colon and port digits for
 * plain hosts; includes brackets for IPv6).
 */
static uint16_t parse_host_port(const char* host, size_t* host_len_out)
{
    const char* end = host;
    while ('\0' != *end) {
        end++;
    }
    const size_t full_len = (size_t)(end - host);

    /* Bracketed IPv6: [addr]:port */
    if ('[' == host[0]) {
        const char* close = NULL;
        for (const char* p = host + 1; p < end; p++) {
            if (']' == *p) {
                close = p;
                break;
            }
        }
        if (NULL == close) {
            *host_len_out = full_len;
            return 0;
        }
        /* Host portion includes brackets: "[::1]" */
        size_t bracket_len = (size_t)(close - host) + 1;
        if (close + 1 == end) {
            *host_len_out = bracket_len;
            return 0;
        }
        if (':' != *(close + 1)) {
            *host_len_out = full_len;
            return 0;
        }
        /* Parse digits after "]:" (cap at 5 to prevent overflow on
         * ILP32 targets where unsigned long is 32 bits). */
        const char*   dp          = close + 2;
        unsigned long port_val    = 0;
        int           digit_count = 0;
        while (*dp >= '0' && *dp <= '9') {
            if (digit_count >= 5) {
                *host_len_out = full_len;
                return 0;
            }
            port_val = port_val * 10 + (unsigned long)(*dp - '0');
            dp++;
            digit_count++;
        }
        if (dp == close + 2 || '\0' != *dp || port_val > 65535) {
            *host_len_out = full_len;
            return 0;
        }
        *host_len_out = bracket_len;
        return (uint16_t)port_val;
    }

    /* Plain hostname or IPv4: find last colon. */
    const char* colon = NULL;
    for (const char* p = host; p < end; p++) {
        if (':' == *p) {
            colon = p;
        }
    }
    if (NULL == colon) {
        *host_len_out = full_len;
        return 0;
    }

    unsigned long port_val    = 0;
    const char*   dp          = colon + 1;
    int           digit_count = 0;
    while (*dp >= '0' && *dp <= '9') {
        if (digit_count >= 5) {
            *host_len_out = full_len;
            return 0;
        }
        port_val = port_val * 10 + (unsigned long)(*dp - '0');
        dp++;
        digit_count++;
    }
    if (dp == colon + 1 || '\0' != *dp || port_val > 65535) {
        *host_len_out = full_len;
        return 0;
    }
    *host_len_out = (size_t)(colon - host);
    return (uint16_t)port_val;
}

/**
 * @brief Compute the exact byte count the URL buffer must hold,
 *        including the trailing NUL.
 *
 * Accounts for: `scheme`, `://`, `host` (without embedded port),
 * optionally `:` + port digits (when the effective port differs
 * from the scheme default), one `/` per path segment plus the
 * segment bytes, and `?` + `N-1` `&` + `key=value` per query
 * parameter.
 *
 * @param request Borrowed request descriptor.
 * @return Byte count required for the assembled URL (> 0).
 */
static size_t request_url_len(const pubnub_http_request_t* request)
{
    const char* scheme = url_scheme(request);

    size_t   host_len  = 0;
    uint16_t host_port = parse_host_port(request->host, &host_len);
    uint16_t eff_port = (0 != host_port) ? host_port : url_default_port(request);

    size_t needed = strlen(scheme) + strlen("://") + host_len + 1 /* NUL */;

    if (eff_port != url_default_port(request)) {
        needed += 1 /* ':' */ + 5; /* max port digits (65535) */
    }

    for (unsigned int i = 0; i < request->path_segment_count; i++) {
        needed += 1 /* '/' */ + request->path_segments[i].len;
    }

    if (request->query_param_count > 0) {
        needed += 1;                                       /* '?' */
        for (unsigned int i = 0; i < request->query_param_count; i++) {
            needed += request->query_params[i].key.len + 1 /* '=' */
                    + request->query_params[i].value.len;
        }
        /* N-1 '&' separators between N params. */
        needed += request->query_param_count - 1;
    }
    return needed;
}

/**
 * @brief Write the `scheme://host[:port]` prefix into @p url.
 *
 * The port suffix is only emitted when the effective port differs
 * from the scheme default (443 for HTTPS, 80 for HTTP). The
 * effective port comes from the host string's embedded `:port`
 * suffix if present, otherwise the scheme default.
 *
 * @param url     Destination buffer (capacity @p cap).
 * @param cap     Total capacity of @p url.
 * @param request Borrowed request descriptor.
 * @return Number of bytes written, or 0 on formatting failure /
 *         capacity overflow.
 */
static size_t url_write_origin(char* url, size_t cap, const pubnub_http_request_t* request)
{
    size_t   host_len  = 0;
    uint16_t host_port = parse_host_port(request->host, &host_len);
    uint16_t eff_port = (0 != host_port) ? host_port : url_default_port(request);

    int written;
    if (eff_port != url_default_port(request)) {
        written = pn_snprintf(url,
                              cap,
                              "%s://%.*s:%u",
                              url_scheme(request),
                              (int)host_len,
                              request->host,
                              (unsigned)eff_port);
    } else {
        written = pn_snprintf(
            url, cap, "%s://%.*s", url_scheme(request), (int)host_len, request->host);
    }
    if (written < 0 || (size_t)written >= cap) {
        return 0;
    }
    return (size_t)written;
}

/**
 * @brief Write each path segment prefixed by `/` into @p url.
 *
 * Idempotent on `path_segment_count == 0` (writes nothing).
 *
 * @param url     Destination buffer (capacity @p cap).
 * @param offset  Current write position (already-used prefix).
 * @param cap     Total capacity of @p url.
 * @param request Borrowed request descriptor.
 * @return New write offset on success, 0 on capacity overflow.
 */
static size_t url_write_path_segments(char*                        url,
                                      size_t                       offset,
                                      size_t                       cap,
                                      const pubnub_http_request_t* request)
{
    for (unsigned int i = 0; i < request->path_segment_count; i++) {
        const size_t seg_len = request->path_segments[i].len;
        if (offset + 1 + seg_len >= cap) {
            return 0;
        }
        url[offset++] = '/';
        memcpy(url + offset, request->path_segments[i].ptr, seg_len);
        offset += seg_len;
    }
    return offset;
}

/**
 * @brief Write the `?k=v&k=v` query string suffix into @p url.
 *
 * First param uses `?` as separator, subsequent ones use `&`.
 * Key and value are written verbatim - the feature wire layer
 * is responsible for URL-encoding before populating the
 * descriptor.
 *
 * @param url     Destination buffer (capacity @p cap).
 * @param offset  Current write position.
 * @param cap     Total capacity of @p url.
 * @param request Borrowed request descriptor.
 * @return New write offset on success, 0 on capacity overflow.
 */
static size_t url_write_query_string(char*                        url,
                                     size_t                       offset,
                                     size_t                       cap,
                                     const pubnub_http_request_t* request)
{
    for (unsigned int i = 0; i < request->query_param_count; i++) {
        const char   separator = (0 == i) ? '?' : '&';
        const size_t key_len   = request->query_params[i].key.len;
        const size_t value_len = request->query_params[i].value.len;
        const size_t chunk = 1 /* sep */ + key_len + 1 /* '=' */ + value_len;

        if (offset + chunk >= cap) {
            return 0;
        }
        url[offset++] = separator;
        memcpy(url + offset, request->query_params[i].key.ptr, key_len);
        offset += key_len;
        url[offset++] = '=';
        memcpy(url + offset, request->query_params[i].value.ptr, value_len);
        offset += value_len;
    }
    return offset;
}

/**
 * @brief Build a full URL string from the structured request
 *        descriptor into an allocator-owned buffer.
 *
 * Format: `scheme://host:port/path_segments?key=value&key=value`.
 * Scheme is `https` when secure transport is compiled in, `http`
 * otherwise. Path segments and query values are passed through
 * verbatim - the feature wire layer is responsible for URL-
 * encoding before populating the descriptor.
 *
 * Memory: the returned buffer comes from @p allocator and must
 * be released via `allocator->free` (typically inside
 * @ref pn_curl_request_destroy). This keeps every transport-local
 * heap allocation flowing through the provider abstraction so
 * embedded profiles that route malloc/free through an arena see
 * URL assembly as well.
 *
 * @param request   Borrowed request descriptor.
 * @param allocator Transport's allocator (borrowed).
 * @return Pointer to the assembled URL on success, NULL on any
 *         validation failure, OOM, or write-pass capacity overflow.
 */
static char* build_url(const pubnub_http_request_t* request,
                       pubnub_allocator_provider_t* allocator)
{
    if (!url_string_views_are_valid(request)) {
        return NULL;
    }

    const size_t needed = request_url_len(request);
    char*        url    = (char*)PN_ALLOC(allocator, needed, 0);
    if (NULL == url) {
        return NULL;
    }

    size_t offset = url_write_origin(url, needed, request);
    if (0 == offset) {
        PN_FREE(allocator, url);
        return NULL;
    }

    offset = url_write_path_segments(url, offset, needed, request);
    if (0 == offset) {
        PN_FREE(allocator, url);
        return NULL;
    }

    offset = url_write_query_string(url, offset, needed, request);
    if (0 == offset) {
        PN_FREE(allocator, url);
        return NULL;
    }

    url[offset] = '\0';
    return url;
}

/**
 * @brief Release every resource owned by a @ref pn_curl_request_t.
 *
 * Idempotent: safe to call with a partially-initialised struct
 * where some fields are NULL (e.g. after an early-out in the
 * constructor below). Called from the completion sweep in
 * @ref pn_curl_transport_poll, from @ref pn_curl_transport_cancel, and
 * from @ref pn_curl_transport_deinit to tear down any lingering
 * transfers.
 *
 * Every heap allocation owned by the tracking struct routes
 * through the transport's allocator provider so that embedded
 * profiles which override the general `alloc`/`free` callbacks
 * see the transport's allocations as well. Only libcurl-owned
 * resources (`CURL*`, `curl_slist*`) use the library's own
 * destructors.
 */
static void pn_curl_request_destroy(pn_curl_request_t* req)
{
    if (NULL == req) {
        return;
    }

    pubnub_allocator_provider_t* allocator = req->transport->allocator;

    if (NULL != req->easy) {
        curl_easy_cleanup(req->easy);
    }
    if (NULL != req->header_slist) {
        curl_slist_free_all(req->header_slist);
    }
    if (NULL != req->url) {
        PN_FREE(allocator, req->url);
    }
    if (NULL != req->rx_buf.data) {
        allocator->buf_release(allocator, &req->rx_buf);
    }

    /* The tracking struct itself was allocated via allocator->alloc
     * in pn_curl_request_new(); match it with allocator->free. */
    PN_FREE(allocator, req);
}

/**
 * @brief Allocate and seed a @ref pn_curl_request_t instance.
 *
 * Walks the fallible setup steps in order (allocator->alloc for
 * the struct itself, PUBNUB_BUF_RX acquisition, URL assembly,
 * curl_easy_init) and returns a fully-usable tracking struct on
 * success. Any failure triggers a @ref pn_curl_request_destroy of
 * the partially-initialised struct, sets
 * `response->completion = PUBNUB_HTTP_ERROR`, and returns NULL.
 *
 * @param transport Extended transport (provides allocator + multi).
 * @param request   Borrowed request descriptor (non-NULL).
 * @param response  Response descriptor to signal failure on
 *                  (non-NULL).
 * @return Newly-created tracking struct or NULL on failure.
 */
static pn_curl_request_t* pn_curl_request_new(pn_curl_transport_t*    transport,
                                              pubnub_http_request_t*  request,
                                              pubnub_http_response_t* response)
{
    pubnub_allocator_provider_t* allocator = transport->allocator;

    pn_curl_request_t* req =
        (pn_curl_request_t*)PN_ALLOC(allocator, sizeof(*req), 0);
    if (NULL == req) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_TRANSPORT;
        return NULL;
    }
    /* alloc does not zero; memset so pn_curl_request_destroy's
     * NULL-guarded field checks work on an early-out. */
    memset(req, 0, sizeof(*req));

    req->transport = transport;
    req->request   = request;
    req->response  = response;

    req->rx_buf = allocator->buf_acquire(allocator, PUBNUB_BUF_RX);
    if (NULL == req->rx_buf.data) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_TRANSPORT;
        pn_curl_request_destroy(req);
        return NULL;
    }

    req->url = build_url(request, allocator);
    if (NULL == req->url) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_TRANSPORT;
        pn_curl_request_destroy(req);
        return NULL;
    }

    req->easy = curl_easy_init();
    if (NULL == req->easy) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_TRANSPORT;
        pn_curl_request_destroy(req);
        return NULL;
    }

    return req;
}

/**
 * @brief Apply the universal easy-handle options: URL, write
 *        callback, privacy, user agent, and TLS verify.
 *
 * These options apply to every request regardless of method or
 * payload shape.  `curl_easy_setopt` with the constants used here
 * fails only with `CURLE_UNKNOWN_OPTION` (caller-built against a
 * newer libcurl than the runtime), which is a compile-against-
 * newer-ABI condition we do not defend against at runtime.
 */
static void pn_curl_request_apply_core_options(pn_curl_request_t* req)
{
    curl_easy_setopt(req->easy, CURLOPT_URL, req->url);
    curl_easy_setopt(req->easy, CURLOPT_WRITEFUNCTION, pn_curl_write_cb);
    curl_easy_setopt(req->easy, CURLOPT_WRITEDATA, req);
    curl_easy_setopt(req->easy, CURLOPT_HEADERFUNCTION, pn_curl_header_cb);
    curl_easy_setopt(req->easy, CURLOPT_HEADERDATA, req);
    curl_easy_setopt(req->easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(req->easy, CURLOPT_PRIVATE, req);
    curl_easy_setopt(req->easy, CURLOPT_USERAGENT, PUBNUB_SDK_IDENTIFIER);

    /* Send the path exactly as built. Without this, libcurl runs RFC 3986
     * dot-segment removal on "/./" and "/../" before transmitting, so a
     * channel or file named "." or ".." would be silently rewritten out of
     * the request path. The SDK percent-encodes such segments upstream, but
     * PATH_AS_IS is the belt-and-suspenders guarantee curl never normalizes. */
#ifdef CURLOPT_PATH_AS_IS
    curl_easy_setopt(req->easy, CURLOPT_PATH_AS_IS, 1L);
#endif

    if (req->request->follow_redirects) {
        curl_easy_setopt(req->easy, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(req->easy, CURLOPT_MAXREDIRS, 3L);
    }

    /* Restrict the protocol allowlist to a single scheme. This blocks
     * SSRF-style abuse via unexpected schemes (file:, gopher:, ...) and,
     * by pinning REDIR_PROTOCOLS to the same value, prevents an
     * https->http downgrade when a redirect is followed. When secure
     * transport is compiled in, only https is ever permitted. */
    {
#if LIBCURL_VERSION_NUM >= 0x075500 /* 7.85.0 */
        const char* proto = PUBNUB_ENABLE_SECURE_TRANSPORT ? "https" : "http";
        curl_easy_setopt(req->easy, CURLOPT_PROTOCOLS_STR, proto);
        curl_easy_setopt(req->easy, CURLOPT_REDIR_PROTOCOLS_STR, proto);
#else
        long proto = PUBNUB_ENABLE_SECURE_TRANSPORT ? (long)CURLPROTO_HTTPS
                                                    : (long)CURLPROTO_HTTP;
        curl_easy_setopt(req->easy, CURLOPT_PROTOCOLS, proto);
        curl_easy_setopt(req->easy, CURLOPT_REDIR_PROTOCOLS, proto);
#endif
    }

    if (req->request->secure) {
        long verify = req->transport->skip_verify ? 0L : 1L;
        curl_easy_setopt(req->easy, CURLOPT_SSL_VERIFYPEER, verify);
        curl_easy_setopt(req->easy, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
        /* Enforce TLS 1.2 as the negotiated floor; refuse SSLv3/TLS1.0/1.1. */
        curl_easy_setopt(req->easy, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
        if (NULL != req->transport->ca_pem) {
            struct curl_blob blob;
            blob.data  = (void*)req->transport->ca_pem;
            blob.len   = strlen(req->transport->ca_pem);
            blob.flags = CURL_BLOB_COPY;
            curl_easy_setopt(req->easy, CURLOPT_CAINFO_BLOB, &blob);
        }
#ifdef _WIN32
        else {
            /* On Windows, libcurl built with OpenSSL has no default
             * CA bundle. CURLSSLOPT_NATIVE_CA loads trusted roots
             * from the Windows Certificate Store. */
            curl_easy_setopt(req->easy, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
        }
#endif
    }

    /* TCP keep-alive — detects dead peers from VPN disconnect or NAT
     * timeout. Controlled by the user's config (via deps at init). */
    if (req->transport->keepalive.enabled) {
        curl_easy_setopt(req->easy, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(req->easy,
                         CURLOPT_TCP_KEEPIDLE,
                         (long)req->transport->keepalive.idle_sec);
        curl_easy_setopt(req->easy,
                         CURLOPT_TCP_KEEPINTVL,
                         (long)req->transport->keepalive.interval_sec);
/* CURLOPT_TCP_KEEPCNT was added in libcurl 7.86.0; Apple's SDK
 * omits it despite reporting a later version number. */
#ifdef CURLOPT_TCP_KEEPCNT
        curl_easy_setopt(req->easy,
                         CURLOPT_TCP_KEEPCNT,
                         (long)req->transport->keepalive.probe_count);
#endif
    } else {
        curl_easy_setopt(req->easy, CURLOPT_TCP_KEEPALIVE, 0L);
    }

    /* Request compressed responses; curl handles decompression
     * transparently. */
    if (PUBNUB_ENABLE_COMPRESSION) {
        curl_easy_setopt(req->easy, CURLOPT_ACCEPT_ENCODING, "");
    }

    /* Custom DNS servers (requires libcurl built with c-ares).
     * CURLOPT_DNS_SERVERS expects comma-separated "host" or "host:port"
     * entries. IPv6 addresses MUST be bracket-enclosed: [::1] not ::1. */
    if (NULL != req->transport->user_dns_primary) {
        char        dns_buf[160] = {0};
        size_t      off          = 0;
        const char* addrs[2];
        size_t      i;
        addrs[0] = req->transport->user_dns_primary;
        addrs[1] = req->transport->user_dns_secondary;
        for (i = 0; i < 2; i++) {
            size_t      alen;
            int         is_v6;
            const char* addr = addrs[i];
            if (NULL == addr) {
                break;
            }
            if (i > 0 && off + 1 < sizeof(dns_buf)) {
                dns_buf[off++] = ',';
            }
            alen  = strlen(addr);
            is_v6 = (NULL != strchr(addr, ':'));
            if (is_v6 && off + alen + 2 < sizeof(dns_buf)) {
                dns_buf[off++] = '[';
                memcpy(dns_buf + off, addr, alen);
                off += alen;
                dns_buf[off++] = ']';
            } else if (!is_v6 && off + alen < sizeof(dns_buf)) {
                memcpy(dns_buf + off, addr, alen);
                off += alen;
            }
        }
        dns_buf[off] = '\0';
        if (off > 0) {
            CURLcode dns_rc =
                curl_easy_setopt(req->easy, CURLOPT_DNS_SERVERS, dns_buf);
            /* c-ares-less libcurl silently ignores custom DNS servers;
             * warn once so the user knows the system resolver is active. */
            if (CURLE_NOT_BUILT_IN == dns_rc && !req->transport->dns_cares_warned) {
                req->transport->dns_cares_warned = 1;
                PUBNUB_LOG_TEXT(
                    req->transport->logger,
                    PUBNUB_LOG_LEVEL_WARNING,
                    "CURLOPT_DNS_SERVERS not supported: libcurl was built "
                    "without c-ares. Custom DNS servers will not be used; "
                    "the system resolver is active. Rebuild libcurl with "
                    "c-ares or switch to the socket transport.");
            }
        }
    }
}

/**
 * @brief Apply proxy settings from the transport's cached proxy
 *        config to the easy handle.
 *
 * No-op when no proxy is configured (proxy == NULL or type ==
 * PUBNUB_PROXY_NONE).
 *
 * @return 0 on success, @c PUBNUB_ERR_NOT_SUPPORTED when the proxy
 *         type or auth scheme is unsupported, -1 for other errors.
 */
static int pn_curl_request_apply_proxy(pn_curl_request_t* req)
{
    const pubnub_proxy_config_t* proxy = req->transport->proxy;
    if (NULL == proxy || PUBNUB_PROXY_NONE == proxy->type) {
        return 0;
    }
    if (NULL == proxy->host) {
        return -1;
    }

    /* Map SDK proxy type to libcurl proxy type. */
    long curl_proxy_type;
    switch (proxy->type) {
    case PUBNUB_PROXY_HTTP_CONNECT: curl_proxy_type = CURLPROXY_HTTP; break;
    case PUBNUB_PROXY_SOCKS5: curl_proxy_type = CURLPROXY_SOCKS5; break;
    default: return PUBNUB_ERR_NOT_SUPPORTED;
    }

    /* Build "host:port" string on the stack - proxy host strings
     * are short (hostnames or IP addresses). */
    char proxy_url[512];
    int  n = pn_snprintf(
        proxy_url, sizeof(proxy_url), "%s:%u", proxy->host, (unsigned)proxy->port);
    if (n < 0 || (size_t)n >= sizeof(proxy_url)) {
        return -1;
    }

    curl_easy_setopt(req->easy, CURLOPT_PROXY, proxy_url);
    curl_easy_setopt(req->easy, CURLOPT_PROXYTYPE, curl_proxy_type);

    /* Authentication. */
    if (PUBNUB_PROXY_AUTH_BASIC == proxy->auth && NULL != proxy->username) {
        curl_easy_setopt(req->easy, CURLOPT_PROXYAUTH, (long)CURLAUTH_BASIC);
        curl_easy_setopt(req->easy, CURLOPT_PROXYUSERNAME, proxy->username);
        if (NULL != proxy->password) {
            curl_easy_setopt(req->easy, CURLOPT_PROXYPASSWORD, proxy->password);
        }
    } else if (PUBNUB_PROXY_AUTH_NONE != proxy->auth && NULL != proxy->username) {
        /* Non-BASIC auth with credentials: unsupported by this
         * transport, do not silently proceed unauthenticated. */
        return PUBNUB_ERR_NOT_SUPPORTED;
    }

    return 0;
}

/**
 * @brief Apply the HTTP-method-specific easy-handle options.
 *
 * GET flips CURLOPT_HTTPGET; POST/PATCH configure the body via
 * CURLOPT_POSTFIELDS + CURLOPT_POSTFIELDSIZE (libcurl keeps a
 * reference to the caller's body pointer - the caller-valid-
 * until-completion contract in `providers/transport.h` permits
 * this); DELETE uses CURLOPT_CUSTOMREQUEST.
 *
 * Body bytes are only configured when the request descriptor
 * carries a non-NULL body pointer; a NULL body for POST/PATCH is
 * a valid empty-payload request.
 */
static void pn_curl_request_apply_method(pn_curl_request_t* req)
{
    pubnub_http_request_t* request = req->request;
    switch (request->method) {
    case PUBNUB_HTTP_GET:
        curl_easy_setopt(req->easy, CURLOPT_HTTPGET, 1L);
        break;
    case PUBNUB_HTTP_POST:
        curl_easy_setopt(req->easy, CURLOPT_POST, 1L);
        if (NULL != request->body) {
            curl_easy_setopt(req->easy, CURLOPT_POSTFIELDS, request->body);
            curl_easy_setopt(
                req->easy, CURLOPT_POSTFIELDSIZE, (long)request->body_len);
        }
        break;
    case PUBNUB_HTTP_PATCH:
        curl_easy_setopt(req->easy, CURLOPT_CUSTOMREQUEST, "PATCH");
        if (NULL != request->body) {
            curl_easy_setopt(req->easy, CURLOPT_POSTFIELDS, request->body);
            curl_easy_setopt(
                req->easy, CURLOPT_POSTFIELDSIZE, (long)request->body_len);
        }
        break;
    case PUBNUB_HTTP_DELETE:
        curl_easy_setopt(req->easy, CURLOPT_CUSTOMREQUEST, "DELETE");
        break;
    }
}

/**
 * @brief Format a single `Key: Value` line into an allocator-
 *        owned NUL-terminated buffer.
 *
 * libcurl's `curl_slist_append` takes NUL-terminated strings;
 * the request descriptor uses length-counted string views
 * because feature code often derives keys/values from
 * non-terminated buffers. This helper bridges the two by
 * writing `key + ": " + value + NUL` into a freshly-allocated
 * buffer sized exactly for the line. Callers own the result
 * and must release it with the same allocator once the slist
 * has copied the string internally.
 *
 * Returns NULL on OOM so the caller can propagate the failure
 * as an immediate transfer rejection.
 */
static char* format_header_line(const pubnub_kv_t*           header,
                                pubnub_allocator_provider_t* allocator)
{
    const size_t key_len   = header->key.len;
    const size_t value_len = header->value.len;
    const size_t line_len  = key_len + value_len + 3; /* ": " + NUL */

    char* line = (char*)PN_ALLOC(allocator, line_len, 0);
    if (NULL == line) {
        return NULL;
    }
    memcpy(line, header->key.ptr, key_len);
    line[key_len]     = ':';
    line[key_len + 1] = ' ';
    memcpy(line + key_len + 2, header->value.ptr, value_len);
    line[key_len + 2 + value_len] = '\0';
    return line;
}

/**
 * @brief Build the libcurl header slist from the request
 *        descriptor's headers array.
 *
 * Heap-allocates each line via the provider's allocator (no
 * silent truncation even for long Bearer-token headers), appends
 * to the slist, and releases the formatting buffer once the
 * slist has copied the bytes. On the first OOM or
 * `curl_slist_append` failure, the caller is expected to run the
 * existing cleanup path (`pn_curl_request_destroy`) which releases
 * every partially-built slist entry.
 *
 * Returns 0 on success, -1 on allocation / libcurl failure. On
 * non-zero return the caller should treat the request as rejected.
 */
static int pn_curl_request_apply_headers(pn_curl_request_t* req)
{
    pubnub_allocator_provider_t* allocator = req->transport->allocator;
    pubnub_http_request_t*       request   = req->request;

    for (unsigned int i = 0; i < request->header_count; i++) {
        char* line = format_header_line(&request->headers[i], allocator);
        if (NULL == line) {
            return -1;
        }

        struct curl_slist* next = curl_slist_append(req->header_slist, line);
        /* curl_slist_append copies the string; the formatting
         * buffer can be released whether append succeeded or not. */
        PN_FREE(allocator, line);

        if (NULL == next) {
            return -1;
        }
        req->header_slist = next;
    }

    if (NULL != req->header_slist) {
        curl_easy_setopt(req->easy, CURLOPT_HTTPHEADER, req->header_slist);
    }
    return 0;
}

/**
 * @brief Attach the configured easy handle to the transport's
 *        multi handle so @ref pn_curl_transport_poll can drive it.
 *
 * Returns 0 on success, -1 on libcurl failure (unlikely - the
 * only non-OK result is CURLM_OUT_OF_MEMORY). On non-zero return
 * the caller is expected to tear down the tracking struct.
 */
static int pn_curl_request_attach(pn_curl_request_t* req)
{
    CURLMcode rc = curl_multi_add_handle(req->transport->multi, req->easy);
    return (CURLM_OK == rc) ? 0 : -1;
}

/**
 * @brief Swap a CA PEM staged by the user thread into the live
 *        `ca_pem` field.
 *
 * Runs on the bg poll thread (via `send`) before request setup reads
 * `ca_pem`. The `ca_pem_stale` gate is claimed with one atomic exchange-to-zero
 * (not a separate load + clear) so a concurrent writer's re-arm is never
 * silently dropped — a set flag after the claim fires again on the next poll.
 */
static void pn_curl_apply_pending_tls_config(pn_curl_transport_t* transport)
{
    if (!PUBNUB_ATOMIC_EXCHANGE_U8(&transport->ca_pem_stale, 0)) {
        return;
    }

    if (transport->pending_ca_pem_set) {
        pn_strfree(transport->ca_pem, transport->allocator);
        transport->ca_pem             = transport->pending_ca_pem;
        transport->pending_ca_pem     = NULL;
        transport->pending_ca_pem_set = 0;
    }
}

/**
 * @brief Submit an HTTP request to the curl multi handle.
 *
 * Orchestrates the small helpers above: create the tracking
 * struct, apply core / method / header options, attach to the
 * multi handle. Each fallible step tears down the partial state
 * through @ref pn_curl_request_destroy on failure, so no leaks are
 * possible along any error path.
 */
static pubnub_transport_handle_t*
pn_curl_transport_send(pubnub_transport_provider_t* self,
                       pubnub_http_request_t*       request,
                       pubnub_http_response_t*      response)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;

    if (NULL == request || NULL == response) {
        /* Without the response pointer we cannot signal failure
         * either; the caller is violating the contract. */
        if (NULL != response) {
            response->completion      = PUBNUB_HTTP_ERROR;
            response->transport_error = PUBNUB_ERR_TRANSPORT;
        }
        return NULL;
    }

    /* Swap in any CA PEM staged by a concurrent user-thread setter
     * before request setup reads transport->ca_pem. */
    pn_curl_apply_pending_tls_config(transport);

    pn_curl_request_t* req = pn_curl_request_new(transport, request, response);
    if (NULL == req) {
        /* pn_curl_request_new already set response->completion. */
        return NULL;
    }

    pn_curl_request_apply_core_options(req);
    pn_curl_request_apply_method(req);

    if (0 != pn_curl_request_apply_proxy(req)
        || 0 != pn_curl_request_apply_headers(req)
        || 0 != pn_curl_request_attach(req)) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_TRANSPORT;
        pn_curl_request_destroy(req);
        return NULL;
    }

    response->completion = PUBNUB_HTTP_PENDING;
    return (pubnub_transport_handle_t*)req;
}

static int pn_curl_transport_poll(pubnub_transport_provider_t* self,
                                  unsigned int                 timeout_ms)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;

    /* Use curl_multi_poll where available (libcurl 7.66+) to wait
     * for activity; otherwise the cooperative caller is expected
     * to pass timeout_ms = 0 and loop.  libcurl's timeout is an
     * `int` (milliseconds); cap to INT_MAX defensively. */
    int numfds = 0;
    int cm_timeout_ms =
        (timeout_ms > (unsigned int)INT_MAX) ? INT_MAX : (int)timeout_ms;
    (void)curl_multi_poll(transport->multi, NULL, 0, cm_timeout_ms, &numfds);

    int still_running = 0;
    (void)curl_multi_perform(transport->multi, &still_running);

    /* Harvest completed transfers. */
    int completed = 0;
    for (;;) {
        int      msgs_in_queue = 0;
        CURLMsg* msg = curl_multi_info_read(transport->multi, &msgs_in_queue);
        if (NULL == msg) {
            break;
        }
        if (CURLMSG_DONE != msg->msg) {
            continue;
        }

        CURL*              easy      = msg->easy_handle;
        CURLcode           curl_code = msg->data.result;
        pn_curl_request_t* req       = NULL;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char**)&req);
        if (NULL == req) {
            /* Transfer without a tracking struct should be
             * impossible, but clean up defensively. */
            curl_multi_remove_handle(transport->multi, easy);
            curl_easy_cleanup(easy);
            continue;
        }

        if (CURLE_OK == curl_code) {
            long status = 0;
            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
            req->response->status_code = (int)status;
            req->response->body        = req->rx_buf.data;
            req->response->body_len    = req->rx_buf.len;
            req->response->completion  = PUBNUB_HTTP_COMPLETE;
        } else {
            /* Expose the curl error string as the response body so
             * pubnub_response_error_message() returns a useful diagnostic.
             * curl_easy_strerror() returns a static string — no copy needed. */
            const char* curl_err      = curl_easy_strerror(curl_code);
            req->response->body       = (const uint8_t*)curl_err;
            req->response->body_len   = strlen(curl_err);
            req->response->completion = PUBNUB_HTTP_ERROR;
            req->response->transport_error =
                (CURLE_OPERATION_TIMEDOUT == curl_code) ? PUBNUB_ERR_TIMEOUT
                                                        : PUBNUB_ERR_TRANSPORT;
        }

        curl_multi_remove_handle(transport->multi, easy);
        /* Detach from req before destroy - the body pointer we just
         * wrote into response must remain valid until the caller
         * signals completion handling, which happens on the same
         * poll tick. Ownership of the RX buffer passes to the
         * response descriptor; we only free the curl handle here. */
        req->easy = NULL;
        curl_easy_cleanup(easy);

        /* The body bytes live inside rx_buf.data which response->body
         * points at. Per the transport_types.h contract: "The body
         * pointer is valid until the next call to send() or cancel()
         * on the same transport handle, or until the provider is
         * destroyed."  We keep the tracking struct alive (minus the
         * easy handle) so the body remains valid; the SDK cancels
         * the handle via pn_curl_transport_cancel when it is done. */
        completed++;
    }

    return completed;
}

static void pn_curl_transport_cancel(pubnub_transport_provider_t* self,
                                     pubnub_transport_handle_t* transport_handle)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;
    pn_curl_request_t*   req       = (pn_curl_request_t*)transport_handle;

    if (NULL == req) {
        return;
    }

    /* If the easy handle is still attached (the request did not
     * complete via poll) detach it before cleanup. */
    if (NULL != req->easy) {
        curl_multi_remove_handle(transport->multi, req->easy);
    }
    pn_curl_request_destroy(req);
}

static int pn_curl_transport_init(pubnub_transport_provider_t*  self,
                                  const pubnub_provider_deps_t* deps)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;

    /* curl_global_init is ref-counted from libcurl 7.57.0 onward --
     * safe to call once per context init. */
    CURLcode gc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (CURLE_OK != gc) {
        return -1;
    }

    transport->multi = curl_multi_init();
    if (NULL == transport->multi) {
        curl_global_cleanup();
        return -1;
    }

    transport->allocator = deps->allocator;
    transport->logger    = deps->logger;
    transport->proxy     = deps->proxy;

    if (NULL != deps->tcp_keepalive) {
        transport->keepalive = *deps->tcp_keepalive;
    } else {
        memset(&transport->keepalive, 0, sizeof(transport->keepalive));
    }

    transport->user_dns_primary   = deps->dns_primary;
    transport->user_dns_secondary = deps->dns_secondary;
    return 0;
}

static void pn_curl_transport_deinit(pubnub_transport_provider_t* self)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;

    if (NULL != transport->multi) {
        /* Reap transfers that have already reached CURLMSG_DONE.
         *
         * NOTE: this only cleans up transfers libcurl has already
         * marked as finished. Live in-flight transfers (still
         * connecting or streaming) never show up in
         * curl_multi_info_read, so their `pn_curl_request_t` tracking
         * struct - including the RX buffer acquired from the
         * allocator - leaks until the SDK cancels them upstream.
         * In practice, `pubnub_deinit` cancels all outstanding
         * futures before calling transport deinit.
         * `curl_multi_cleanup` below still tears down libcurl's
         * own handles correctly.
         */
        CURLMsg* msg           = NULL;
        int      msgs_in_queue = 0;
        while (NULL
               != (msg = curl_multi_info_read(transport->multi, &msgs_in_queue))) {
            pn_curl_request_t* req = NULL;
            curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char**)&req);
            if (NULL != req) {
                req->easy = NULL; /* about to be freed below */
            }
            curl_multi_remove_handle(transport->multi, msg->easy_handle);
            curl_easy_cleanup(msg->easy_handle);
            pn_curl_request_destroy(req);
        }
        curl_multi_cleanup(transport->multi);
        transport->multi = NULL;
    }

    curl_global_cleanup();
    pn_strfree(transport->ca_pem, transport->allocator);
    transport->ca_pem = NULL;
    pn_strfree(transport->pending_ca_pem, transport->allocator);
    transport->pending_ca_pem     = NULL;
    transport->pending_ca_pem_set = 0;
    transport->allocator          = NULL;
    transport->proxy              = NULL;
}

/** @brief Thread-safe wake via curl_multi_wakeup (available since 7.68.0). */
#if LIBCURL_VERSION_NUM >= 0x074400 /* 7.68.0 */
static void pn_curl_transport_wake(pubnub_transport_provider_t* self)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;
    if (NULL != transport->multi) {
        curl_multi_wakeup(transport->multi);
    }
}
#endif

static void pn_curl_transport_set_tls_ca_bundle(pubnub_transport_provider_t* self,
                                                const char* ca_pem)
{
    pn_curl_transport_t* t = (pn_curl_transport_t*)self;

    /* Stage for the bg poll thread to swap in send(); freeing t->ca_pem
     * here could race a concurrent read during request setup. */
    const char* new_pem = NULL;
    if (NULL != ca_pem) {
        new_pem = pn_strdup(ca_pem, t->allocator);
        if (NULL == new_pem) {
            return;
        }
    }

    /* Free any prior pending PEM the bg thread has not consumed yet
     * (rapid successive setter calls). */
    pn_strfree(t->pending_ca_pem, t->allocator);
    t->pending_ca_pem     = new_pem;
    t->pending_ca_pem_set = 1;

    PUBNUB_ATOMIC_STORE_U8(&t->ca_pem_stale, 1);
}

static void pn_curl_transport_set_tls_verify(pubnub_transport_provider_t* self,
                                             uint8_t skip_verify)
{
    pn_curl_transport_t* t = (pn_curl_transport_t*)self;
    t->skip_verify         = skip_verify;
}

static pubnub_res_t pn_curl_transport_set_dns_servers(pubnub_transport_provider_t* self,
                                                      const char* primary,
                                                      const char* secondary)
{
    pn_curl_transport_t* transport = (pn_curl_transport_t*)self;
    transport->user_dns_primary    = primary;
    transport->user_dns_secondary  = secondary;
    return PUBNUB_OK;
}

/**
 * @brief Allocate a fresh per-context curl transport instance.
 *
 * Each context must have its own transport instance because the
 * multi handle and cached dependency pointers are per-context
 * state. The caller is responsible for calling `deinit()` to
 * release libcurl state. The struct memory itself is freed by
 * the owner (client.c via `transport_owned` and the allocator).
 *
 * @param alloc  Resolved allocator provider (must be non-NULL).
 * @return Transport provider ready for `init()`, or NULL on
 *         allocation failure (mapped to PUBNUB_ERR_PROVIDER_MISSING
 *         by the context init path in client.c).
 */
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc)
{
    if (NULL == alloc || NULL == alloc->alloc) {
        return NULL;
    }
    pn_curl_transport_t* transport = (pn_curl_transport_t*)PN_ALLOC(
        alloc, sizeof(pn_curl_transport_t), sizeof(void*));
    if (NULL == transport) {
        return NULL;
    }
    memset(transport, 0, sizeof(*transport));
    transport->base.send   = pn_curl_transport_send;
    transport->base.poll   = pn_curl_transport_poll;
    transport->base.cancel = pn_curl_transport_cancel;
#if LIBCURL_VERSION_NUM >= 0x074400 /* 7.68.0 */
    transport->base.wake = pn_curl_transport_wake;
#else
    transport->base.wake = NULL;
#endif
    transport->base.init              = pn_curl_transport_init;
    transport->base.deinit            = pn_curl_transport_deinit;
    transport->base.set_dns_servers   = pn_curl_transport_set_dns_servers;
    transport->base.set_tls_ca_bundle = pn_curl_transport_set_tls_ca_bundle;
    transport->base.set_tls_verify    = pn_curl_transport_set_tls_verify;

    return &transport->base;
}

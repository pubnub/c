/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file http_builder.h
 * @brief HTTP/1.1 request header serialization for socket transport.
 *
 * Serializes pubnub_http_request_t into wire-format HTTP/1.1 headers.
 * The socket transport uses scatter-gather I/O: this module builds the
 * header block, then the transport sends the body separately.
 */

#ifndef PN_HTTP_BUILDER_H
#define PN_HTTP_BUILDER_H

#include "pubnub/providers/transport_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Build HTTP/1.1 request headers into a buffer.
 *
 * Serializes the request line (method + path + query), Host header,
 * Content-Length (for POST/PATCH with body), caller-provided headers,
 * and Accept-Encoding (when compression enabled). Body is NOT included —
 * the transport sends it separately (scatter-gather I/O).
 *
 * Output format:
 * @code
 * GET /path/segments?key1=val1&key2=val2 HTTP/1.1\r\n
 * Host: hostname\r\n
 * Content-Length: 123\r\n
 * Accept-Encoding: gzip, deflate\r\n
 * Header1: Value1\r\n
 * \r\n
 * @endcode
 *
 * Path segments and query values are pre-encoded by the SDK middleware;
 * this function concatenates them verbatim without re-encoding.
 *
 * @param request   HTTP request descriptor (path_segments, query_params,
 *                  headers, etc.). Must not be NULL.
 * @param buf       Output buffer for serialized headers.
 * @param buf_size  Buffer capacity in bytes.
 * @param out_len   Written length on success (excluding NUL terminator;
 *                  output is NOT NUL-terminated).
 * @return 0 on success, -1 if buffer too small, -2 if request is invalid
 *         (NULL request, NULL host, NULL buf).
 */
int pn_http_build_headers(const pubnub_http_request_t* request,
                          uint8_t*                     buf,
                          size_t                       buf_size,
                          size_t*                      out_len);

/**
 * @brief Resolve the TCP port for a request.
 *
 * Parses an embedded port from the host string ("host:port",
 * "[::1]:port"), falling back to 443 for TLS or 80 for plaintext
 * when no port is present.
 *
 * @param request HTTP request descriptor. Must not be NULL.
 * @return Resolved port number, or 0 if request or host is NULL.
 */
uint16_t pn_http_resolve_port(const pubnub_http_request_t* request);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_HTTP_BUILDER_H */

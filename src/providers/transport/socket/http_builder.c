/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "http_builder.h"

#include "pubnub/config.h"
#include "core/pn_format.h"

#include <string.h>

/* Helper: append a literal string to the buffer. */
static int append_literal(uint8_t* buf, size_t buf_size, size_t* pos, const char* str)
{
    size_t len = strlen(str);
    if ((*pos) + len > buf_size) {
        return -1;
    }
    /* Intentional counted copy into a raw byte buffer — no NUL terminator
     * needed; the HTTP serializer tracks length explicitly via *pos. */
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(buf + (*pos), str, len);
    (*pos) += len;
    return 0;
}

/* Helper: append a string view to the buffer. */
static int append_view(uint8_t*                    buf,
                       size_t                      buf_size,
                       size_t*                     pos,
                       const pubnub_string_view_t* view)
{
    if ((*pos) + view->len > buf_size) {
        return -1;
    }
    memcpy(buf + (*pos), view->ptr, view->len);
    (*pos) += view->len;
    return 0;
}

/* Helper: append a single character to the buffer. */
static int append_char(uint8_t* buf, size_t buf_size, size_t* pos, char c)
{
    if ((*pos) + 1 > buf_size) {
        return -1;
    }
    buf[(*pos)] = (uint8_t)c;
    (*pos) += 1;
    return 0;
}

/* Map pubnub_http_method_t to HTTP verb string. */
static const char* method_to_string(pubnub_http_method_t method)
{
    switch (method) {
    case PUBNUB_HTTP_GET: return "GET";
    case PUBNUB_HTTP_POST: return "POST";
    case PUBNUB_HTTP_PATCH: return "PATCH";
    case PUBNUB_HTTP_DELETE: return "DELETE";
    default: return "GET";
    }
}

/* Build the request line: "METHOD /path?query HTTP/1.1\r\n". */
static int build_request_line(const pubnub_http_request_t* request,
                              uint8_t*                     buf,
                              size_t                       buf_size,
                              size_t*                      pos)
{
    const char* method_str = method_to_string(request->method);

    /* METHOD */
    if (0 != append_literal(buf, buf_size, pos, method_str)) {
        return -1;
    }
    if (0 != append_char(buf, buf_size, pos, ' ')) {
        return -1;
    }

    /* Path: join segments with '/' */
    if (0 != append_char(buf, buf_size, pos, '/')) {
        return -1;
    }
    for (unsigned int i = 0; i < request->path_segment_count; ++i) {
        const pubnub_string_view_t* seg = &request->path_segments[i];
        if (NULL == seg->ptr) {
            break;
        }
        if (0 != i) {
            if (0 != append_char(buf, buf_size, pos, '/')) {
                return -1;
            }
        }
        if (0 != append_view(buf, buf_size, pos, seg)) {
            return -1;
        }
    }

    /* Query string: join params with '&' */
    if (request->query_param_count > 0) {
        if (0 != append_char(buf, buf_size, pos, '?')) {
            return -1;
        }
        for (unsigned int i = 0; i < request->query_param_count; ++i) {
            const pubnub_kv_t* kv = &request->query_params[i];
            if (NULL == kv->key.ptr) {
                break;
            }
            if (0 != i) {
                if (0 != append_char(buf, buf_size, pos, '&')) {
                    return -1;
                }
            }
            if (0 != append_view(buf, buf_size, pos, &kv->key)) {
                return -1;
            }
            if (0 != append_char(buf, buf_size, pos, '=')) {
                return -1;
            }
            if (0 != append_view(buf, buf_size, pos, &kv->value)) {
                return -1;
            }
        }
    }

    /* HTTP version */
    if (0 != append_literal(buf, buf_size, pos, " HTTP/1.1\r\n")) {
        return -1;
    }

    return 0;
}

/* Build a single header line: "Key: Value\r\n". */
static int build_header_line(uint8_t*              buf,
                             size_t                buf_size,
                             size_t*               pos,
                             const char*           key,
                             const char*           value_literal,
                             pubnub_string_view_t* value_view)
{
    if (0 != append_literal(buf, buf_size, pos, key)) {
        return -1;
    }
    if (0 != append_literal(buf, buf_size, pos, ": ")) {
        return -1;
    }

    if (NULL != value_literal) {
        if (0 != append_literal(buf, buf_size, pos, value_literal)) {
            return -1;
        }
    } else if (NULL != value_view) {
        if (0 != append_view(buf, buf_size, pos, value_view)) {
            return -1;
        }
    }

    if (0 != append_literal(buf, buf_size, pos, "\r\n")) {
        return -1;
    }
    return 0;
}

uint16_t pn_http_resolve_port(const pubnub_http_request_t* request)
{
    if (NULL == request || NULL == request->host) {
        return 0;
    }

    const char* colon = NULL;
    const char* p     = request->host;
    if ('[' == *p) {
        /* IPv6 literal "[::1]:port" — find closing bracket. */
        const char* bracket = strchr(p, ']');
        if (NULL != bracket && ':' == *(bracket + 1)) {
            colon = bracket + 1;
        }
    } else {
        colon = strrchr(p, ':');
    }

    if (NULL != colon) {
        unsigned long port = 0;
        const char*   s    = colon + 1;
        while (*s >= '0' && *s <= '9') {
            port = port * 10 + (unsigned long)(*s - '0');
            s++;
        }
        if (port > 0 && port <= 65535) {
            return (uint16_t)port;
        }
    }

    return request->secure ? 443 : 80;
}

int pn_http_build_headers(const pubnub_http_request_t* request,
                          uint8_t*                     buf,
                          size_t                       buf_size,
                          size_t*                      out_len)
{
    size_t pos = 0;

    /* Validate inputs. */
    if (NULL == request || NULL == buf || NULL == request->host) {
        return -2;
    }

    /* Request line. */
    if (0 != build_request_line(request, buf, buf_size, &pos)) {
        return -1;
    }

    /* Host header. */
    if (0 != build_header_line(buf, buf_size, &pos, "Host", request->host, NULL)) {
        return -1;
    }

    /* Content-Length (only for POST/PATCH with body). */
    if ((PUBNUB_HTTP_POST == request->method || PUBNUB_HTTP_PATCH == request->method)
        && NULL != request->body && request->body_len > 0) {
        char len_buf[32];
        pn_snprintf(
            len_buf, sizeof(len_buf), "%llu", (unsigned long long)request->body_len);
        if (0 != build_header_line(buf, buf_size, &pos, "Content-Length", len_buf, NULL)) {
            return -1;
        }
    }

    /* Add Accept-Encoding when compression is enabled. */
    if (PUBNUB_ENABLE_COMPRESSION) {
        static const char ae[] = "Accept-Encoding: gzip, deflate\r\n";
        if (pos + sizeof(ae) - 1 > buf_size) {
            return -1;
        }
        memcpy(buf + pos, ae, sizeof(ae) - 1);
        pos += sizeof(ae) - 1;
    }

    /* User-provided headers. */
    for (unsigned int i = 0; i < request->header_count; ++i) {
        const pubnub_kv_t* kv = &request->headers[i];
        if (NULL == kv->key.ptr) {
            break;
        }
        /* Convert key to NUL-terminated string (borrow scratch). */
        char   key_buf[128];
        size_t key_len = kv->key.len;
        if (key_len >= sizeof(key_buf)) {
            key_len = sizeof(key_buf) - 1;
        }
        memcpy(key_buf, kv->key.ptr, key_len);
        key_buf[key_len] = '\0';

        if (0
            != build_header_line(
                buf, buf_size, &pos, key_buf, NULL, (pubnub_string_view_t*)&kv->value)) {
            return -1;
        }
    }

    /* Terminating CRLF (end of headers). */
    if (0 != append_literal(buf, buf_size, &pos, "\r\n")) {
        return -1;
    }

    if (NULL != out_len) {
        *out_len = pos;
    }
    return 0;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file http_parser.c
 * @brief Incremental HTTP/1.1 response parser implementation.
 */

#include "http_parser.h"
#include <string.h>
#include <stdint.h>

/** Convert ASCII alpha to lowercase (inline, no locale dependency). */
static inline char pn_ascii_lower(char c)
{
    return (char)(c | 0x20);
}

/** Case-insensitive prefix match for header names. */
static int pn_header_matches(const uint8_t* line, size_t len, const char* header)
{
    size_t header_len = strlen(header);
    size_t i;

    if (len < header_len) {
        return 0;
    }
    for (i = 0; i < header_len; ++i) {
        if (pn_ascii_lower((char)line[i]) != pn_ascii_lower(header[i])) {
            return 0;
        }
    }
    return 1;
}

/** Find CRLF in buffer. Returns offset or SIZE_MAX if not found. */
static size_t pn_find_crlf(const uint8_t* data, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; ++i) {
        if ('\r' == data[i] && '\n' == data[i + 1]) {
            return i;
        }
    }
    return SIZE_MAX;
}

/** Parse hex digit to value, returns 0-15 or -1 on invalid. */
static int pn_hex_digit(char c)
{
    if ('0' <= c && c <= '9') {
        return c - '0';
    }
    if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    }
    if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/**
 * @brief Whether a status code permits a response message body.
 *
 * Per RFC 7230 §3.3, 1xx (informational), 204 (No Content), and 304 (Not
 * Modified) responses never carry a body. Responses to HEAD requests are
 * also bodyless, but the parser does not know the request method, so that
 * case is not handled here — the socket transport does not issue HEAD.
 *
 * @return 1 if a body is permitted, 0 otherwise.
 */
static int pn_status_allows_body(uint16_t status)
{
    if (100 <= status && status < 200) {
        return 0;
    }
    if (204 == status || 304 == status) {
        return 0;
    }
    return 1;
}

/**
 * @brief Parse status line state.
 *
 * @return 1 = state advanced, 0 = need more data, -1 = error.
 */
static int feed_status_line(pn_http_parser_t* parser,
                            const uint8_t*    data,
                            size_t            len,
                            size_t*           pos)
{
    size_t         crlf = pn_find_crlf(data + *pos, len - *pos);
    const uint8_t* status_start;

    if (SIZE_MAX == crlf) {
        return 0;
    }

    /* Status line format: "HTTP/1.x NNN ..." — minimum 12 chars. */
    if (crlf < 12) {
        return -1;
    }
    if (0 != memcmp(data + *pos, "HTTP/1.", 7)) {
        return -1;
    }
    if (' ' != (char)data[*pos + 8]) {
        return -1;
    }

    /* Extract 3-digit status code after "HTTP/1.x ". */
    status_start = data + *pos + 9;
    if (status_start[0] < '0' || status_start[0] > '9' || status_start[1] < '0'
        || status_start[1] > '9' || status_start[2] < '0' || status_start[2] > '9') {
        return -1;
    }
    parser->status_code =
        (uint16_t)((status_start[0] - '0') * 100 + (status_start[1] - '0') * 10
                   + (status_start[2] - '0'));

    *pos += crlf + 2;
    parser->pos   = (uint32_t)*pos;
    parser->state = PN_HTTP_STATE_HEADERS;
    return 1;
}

/** @brief Parse Content-Length value into parser; returns -1 on overflow. */
static int parse_content_length(pn_http_parser_t* parser,
                                const uint8_t*    value,
                                size_t            vlen)
{
    uint64_t val         = 0;
    uint8_t  digit_count = 0;
    size_t   i;

    for (i = 0; i < vlen; ++i) {
        if (value[i] < '0' || value[i] > '9') {
            break;
        }
        if (++digit_count > 10) {
            return -1;
        }
        val = val * 10U + (uint64_t)(value[i] - '0');
    }
    if (val > UINT32_MAX) {
        return -1;
    }
    parser->content_length = (uint32_t)val;
    return 0;
}

/** @brief Parse Transfer-Encoding and set CHUNKED flag if applicable. */
static void parse_transfer_encoding(pn_http_parser_t* parser,
                                    const uint8_t*    value,
                                    size_t            vlen)
{
    char   lower_buf[8];
    size_t i;

    if (vlen >= 7) {
        for (i = 0; i < 7; ++i) {
            lower_buf[i] = pn_ascii_lower((char)value[i]);
        }
        lower_buf[7] = '\0';
        if (0 == memcmp(lower_buf, "chunked", 7)) {
            parser->flags |= PN_HTTP_FLAG_CHUNKED;
        }
    }
}

/** @brief Parse Content-Encoding and set GZIP/DEFLATE flags. */
static void parse_content_encoding(pn_http_parser_t* parser,
                                   const uint8_t*    value,
                                   size_t            vlen)
{
    char   lower_buf[8];
    size_t check_len = vlen < 7 ? vlen : 7;
    size_t i;

    if (vlen < 4) {
        return;
    }
    for (i = 0; i < check_len; ++i) {
        lower_buf[i] = pn_ascii_lower((char)value[i]);
    }
    lower_buf[check_len] = '\0';
    if (0 == memcmp(lower_buf, "gzip", 4)) {
        parser->flags |= PN_HTTP_FLAG_GZIP;
    } else if (vlen >= 7 && 0 == memcmp(lower_buf, "deflate", 7)) {
        parser->flags |= PN_HTTP_FLAG_DEFLATE;
    }
}

/** @brief Parse Connection header and set CLOSE flag if applicable. */
static void parse_connection(pn_http_parser_t* parser, const uint8_t* value, size_t vlen)
{
    char   lower_buf[6];
    size_t i;

    if (vlen >= 5) {
        for (i = 0; i < 5; ++i) {
            lower_buf[i] = pn_ascii_lower((char)value[i]);
        }
        lower_buf[5] = '\0';
        if (0 == memcmp(lower_buf, "close", 5)) {
            parser->flags |= PN_HTTP_FLAG_CONNECTION_CLOSE;
        }
    }
}

/** @brief Skip leading whitespace; return new pointer + updated length. */
static const uint8_t* skip_ws(const uint8_t* value, size_t* vlen)
{
    while (*vlen > 0 && ' ' == *value) {
        ++value;
        --(*vlen);
    }
    return value;
}

/**
 * @brief Parse one header line or detect end-of-headers.
 *
 * @return 1 = state advanced (or line consumed), 0 = need more data, -1 = error.
 */
static int feed_headers(pn_http_parser_t* parser, uint8_t* data, size_t len, size_t* pos)
{
    size_t         crlf = pn_find_crlf(data + *pos, len - *pos);
    const uint8_t* line;
    size_t         line_len;

    if (SIZE_MAX == crlf) {
        return 0;
    }

    /* Bound the total header section so a malicious or buggy server cannot
     * flood the parser with an endless header stream. The terminating empty
     * line is counted too; its two bytes are negligible against the cap. */
    parser->header_bytes += (uint32_t)(crlf + 2);
    if (parser->header_bytes > PUBNUB_CFG_MAX_HEADER_BYTES) {
        return -1;
    }

    /* Empty line ends headers. */
    if (0 == crlf) {
        *pos += 2;
        if (0 != (parser->flags & PN_HTTP_FLAG_CHUNKED)) {
            parser->state = PN_HTTP_STATE_BODY_CHUNKED_SIZE;
        } else if (0 != (parser->flags & PN_HTTP_FLAG_HAS_CONTENT_LENGTH)) {
            if (0 == parser->content_length) {
                parser->state = PN_HTTP_STATE_DONE;
                parser->pos   = (uint32_t)*pos;
                return 1;
            }
            parser->state = PN_HTTP_STATE_BODY_CONTENT_LENGTH;
        } else if (pn_status_allows_body(parser->status_code)) {
            /* No Content-Length and no Transfer-Encoding — the body is
             * framed by connection close (RFC 7230 §3.3.3 rule 7). */
            parser->state = PN_HTTP_STATE_BODY_UNTIL_CLOSE;
        } else {
            parser->state = PN_HTTP_STATE_DONE;
            parser->pos   = (uint32_t)*pos;
            return 1;
        }
        parser->pos = (uint32_t)*pos;
        return 1;
    }

    line     = data + *pos;
    line_len = crlf;

    if (pn_header_matches(line, line_len, "content-length:")) {
        size_t         vlen  = line_len - 15;
        const uint8_t* value = skip_ws(line + 15, &vlen);
        parser->flags |= PN_HTTP_FLAG_HAS_CONTENT_LENGTH;
        if (0 != parse_content_length(parser, value, vlen)) {
            return -1;
        }
    } else if (pn_header_matches(line, line_len, "transfer-encoding:")) {
        size_t         vlen  = line_len - 18;
        const uint8_t* value = skip_ws(line + 18, &vlen);
        parse_transfer_encoding(parser, value, vlen);
    } else if (pn_header_matches(line, line_len, "content-encoding:")) {
        size_t         vlen  = line_len - 17;
        const uint8_t* value = skip_ws(line + 17, &vlen);
        parse_content_encoding(parser, value, vlen);
    } else if (pn_header_matches(line, line_len, "connection:")) {
        size_t         vlen  = line_len - 11;
        const uint8_t* value = skip_ws(line + 11, &vlen);
        parse_connection(parser, value, vlen);
    }

    /* Capture header name:value spans for TRACE logging.
     * Find the colon separator and record offsets into the rx buffer. */
    if (parser->hdr_count < PUBNUB_CFG_HTTP_MAX_RESP_HEADERS) {
        size_t colon_pos = 0;
        while (colon_pos < line_len && ':' != line[colon_pos]) {
            ++colon_pos;
        }
        if (colon_pos < line_len) {
            uint8_t        idx        = parser->hdr_count;
            size_t         val_offset = colon_pos + 1;
            const uint8_t* val_ptr    = line + val_offset;
            size_t         val_len    = line_len - val_offset;

            parser->hdr_name_start[idx] = (uint32_t)*pos;
            parser->hdr_name_len[idx]   = (uint16_t)colon_pos;

            /* Value starts after ':' — skip leading whitespace. */
            val_ptr    = skip_ws(val_ptr, &val_len);
            val_offset = (size_t)(val_ptr - line);

            /* Trim trailing whitespace from value. */
            while (val_len > 0 && ' ' == val_ptr[val_len - 1]) {
                --val_len;
            }

            parser->hdr_value_start[idx] = (uint32_t)(*pos + val_offset);
            parser->hdr_value_len[idx]   = (uint16_t)val_len;
            parser->hdr_count++;
        }
    }

    *pos += crlf + 2;
    parser->pos = (uint32_t)*pos;
    return 1;
}

/**
 * @brief Process content-length body state.
 *
 * @return 1 = body complete, 0 = need more data.
 */
static int feed_body_content_length(pn_http_parser_t* parser,
                                    const uint8_t*    data,
                                    size_t            len,
                                    size_t*           pos,
                                    const uint8_t**   body_start,
                                    size_t*           body_len)
{
    size_t remaining = parser->content_length - parser->body_received;
    size_t available = len - *pos;
    size_t chunk     = remaining < available ? remaining : available;

    if (UINT32_MAX == parser->body_start_offset) {
        parser->body_start_offset = (uint32_t)*pos;
    }
    *body_start = data + parser->body_start_offset;
    parser->body_received += (uint32_t)chunk;
    *pos += chunk;
    parser->pos = (uint32_t)*pos;

    /* Report total body accumulated so far across all calls. */
    *body_len = parser->body_received;

    if (parser->body_received >= parser->content_length) {
        parser->state = PN_HTTP_STATE_DONE;
        return 1;
    }

    return 0;
}

/**
 * @brief Accumulate an identity body framed by connection close.
 *
 * Consumes every currently-available byte as body content. The body length
 * is unknown until the connection closes, so this reports the running total
 * and always signals "need more"; @c pn_http_parser_signal_eof finalizes the
 * response when the peer closes the connection.
 *
 * Body bytes are not copied — @p body_start points into the caller's rx
 * buffer and @p body_len is the total accumulated so far. Growth of that
 * buffer (and any resulting bound) is the caller's responsibility.
 *
 * @return Always 0 (need more data — the body ends at connection close).
 */
static int feed_body_until_close(pn_http_parser_t* parser,
                                 const uint8_t*    data,
                                 size_t            len,
                                 size_t*           pos,
                                 const uint8_t**   body_start,
                                 size_t*           body_len)
{
    size_t available = len - *pos;

    if (UINT32_MAX == parser->body_start_offset) {
        parser->body_start_offset = (uint32_t)*pos;
    }
    *body_start = data + parser->body_start_offset;
    parser->body_received += (uint32_t)available;
    *pos += available;
    parser->pos = (uint32_t)*pos;

    /* Report total body accumulated so far across all calls. */
    *body_len = parser->body_received;
    return 0;
}

/**
 * @brief Process chunked-size line state.
 *
 * @return 1 = state advanced, 0 = need more data, -1 = error.
 */
static int feed_chunked_size(pn_http_parser_t* parser,
                             const uint8_t*    data,
                             size_t            len,
                             size_t*           pos)
{
    size_t   crlf        = pn_find_crlf(data + *pos, len - *pos);
    uint32_t chunk_size  = 0;
    uint8_t  digit_count = 0;
    size_t   i;

    if (SIZE_MAX == crlf) {
        return 0;
    }

    /* Parse hex chunk size — max 8 hex digits (uint32_t max = FFFFFFFF). */
    for (i = 0; i < crlf; ++i) {
        char c = (char)data[*pos + i];
        int  digit;

        if (' ' == c || '\t' == c || ';' == c) {
            break;
        }
        digit = pn_hex_digit(c);
        if (-1 == digit) {
            return -1;
        }
        if (++digit_count > 8) {
            return -1;
        }
        chunk_size = (chunk_size << 4) | (uint32_t)digit;
    }

    parser->chunk_remaining = chunk_size;
    *pos += crlf + 2;

    if (0 == chunk_size) {
        parser->state = PN_HTTP_STATE_BODY_CHUNKED_TRAILER;
    } else {
        /* Initialise write cursor and body_start_offset at first chunk entry. */
        if (0 == parser->body_received) {
            parser->chunk_write_pos   = (uint32_t)*pos;
            parser->body_start_offset = (uint32_t)*pos;
        }
        parser->state = PN_HTTP_STATE_BODY_CHUNKED_DATA;
    }
    parser->pos = (uint32_t)*pos;
    return 1;
}

/**
 * @brief Process chunked data state.
 *
 * @return 1 = chunk consumed (advance to size), 0 = need more data, -1 = error.
 */
static int feed_chunked_data(pn_http_parser_t* parser,
                             uint8_t*          data,
                             size_t            len,
                             size_t*           pos,
                             const uint8_t**   body_start,
                             size_t*           body_len)
{
    size_t available = len - *pos;
    size_t chunk = parser->chunk_remaining < available ? parser->chunk_remaining
                                                       : available;

    /*
     * In-place reassembly: move chunk payload bytes to the write
     * cursor, eliminating chunk-size lines between chunks.
     */
    if (parser->chunk_write_pos != (uint32_t)*pos) {
        memmove(data + parser->chunk_write_pos, data + *pos, chunk);
    }

    *body_start = data + parser->body_start_offset;
    *body_len += chunk;
    parser->body_received += (uint32_t)chunk;
    parser->chunk_remaining -= (uint32_t)chunk;
    parser->chunk_write_pos += (uint32_t)chunk;
    *pos += chunk;

    if (0 == parser->chunk_remaining) {
        /* Expect CRLF after chunk data. */
        if (*pos + 2 > len) {
            parser->pos = (uint32_t)*pos;
            return 0;
        }
        if ('\r' != data[*pos] || '\n' != data[*pos + 1]) {
            return -1;
        }
        *pos += 2;
        parser->pos   = (uint32_t)*pos;
        parser->state = PN_HTTP_STATE_BODY_CHUNKED_SIZE;
        return 1;
    }

    parser->pos = (uint32_t)*pos;
    return 0;
}

/**
 * @brief Process chunked trailer state.
 *
 * @return 1 = body complete, 0 = need more data, 2 = trailer line skipped.
 */
static int feed_chunked_trailer(pn_http_parser_t* parser,
                                const uint8_t*    data,
                                size_t            len,
                                size_t*           pos)
{
    size_t crlf = pn_find_crlf(data + *pos, len - *pos);
    if (SIZE_MAX == crlf) {
        return 0;
    }

    /* Empty line ends chunked body. */
    if (0 == crlf) {
        *pos += 2;
        parser->state = PN_HTTP_STATE_DONE;
        parser->pos   = (uint32_t)*pos;
        return 1;
    }

    /* Skip trailer headers. */
    *pos += crlf + 2;
    parser->pos = (uint32_t)*pos;
    return 2;
}

void pn_http_parser_init(pn_http_parser_t* parser)
{
    *parser                   = (pn_http_parser_t){0};
    parser->state             = PN_HTTP_STATE_STATUS_LINE;
    parser->body_start_offset = UINT32_MAX;
    parser->hdr_count         = 0;
}

void pn_http_parser_reset(pn_http_parser_t* parser)
{
    pn_http_parser_init(parser);
}

pn_http_parse_result_t pn_http_parser_feed(pn_http_parser_t* parser,
                                           uint8_t*          data,
                                           size_t            len,
                                           size_t*           consumed,
                                           uint16_t*         status_code,
                                           const uint8_t**   body_start,
                                           size_t*           body_len)
{
    size_t pos = parser->pos;
    int    rc;

    *consumed   = 0;
    *body_start = NULL;
    *body_len   = 0;

    while (pos < len) {
        switch (parser->state) {
        case PN_HTTP_STATE_STATUS_LINE:
            rc = feed_status_line(parser, data, len, &pos);
            if (0 == rc) {
                parser->pos = (uint32_t)pos;
                *consumed   = pos;
                return PN_HTTP_PARSE_NEED_MORE;
            }
            if (rc < 0) {
                return PN_HTTP_PARSE_ERROR;
            }
            break;

        case PN_HTTP_STATE_HEADERS:
            rc = feed_headers(parser, data, len, &pos);
            if (0 == rc) {
                parser->pos = (uint32_t)pos;
                *consumed   = pos;
                return PN_HTTP_PARSE_NEED_MORE;
            }
            if (rc < 0) {
                return PN_HTTP_PARSE_ERROR;
            }
            /* Headers done and zero content-length → immediate complete. */
            if (PN_HTTP_STATE_DONE == parser->state) {
                *status_code = parser->status_code;
                *consumed    = pos;
                return PN_HTTP_PARSE_COMPLETE;
            }
            break;

        case PN_HTTP_STATE_BODY_CONTENT_LENGTH:
            rc = feed_body_content_length(
                parser, data, len, &pos, body_start, body_len);
            if (1 == rc) {
                *status_code = parser->status_code;
                *consumed    = pos;
                return PN_HTTP_PARSE_COMPLETE;
            }
            *consumed = pos;
            return PN_HTTP_PARSE_NEED_MORE;

        case PN_HTTP_STATE_BODY_UNTIL_CLOSE:
            feed_body_until_close(parser, data, len, &pos, body_start, body_len);
            /* Body ends at connection close; report status now so callers
             * that inspect a NEED_MORE result still see it. */
            *status_code = parser->status_code;
            *consumed    = pos;
            return PN_HTTP_PARSE_NEED_MORE;

        case PN_HTTP_STATE_BODY_CHUNKED_SIZE:
            rc = feed_chunked_size(parser, data, len, &pos);
            if (0 == rc) {
                parser->pos = (uint32_t)pos;
                *consumed   = pos;
                return PN_HTTP_PARSE_NEED_MORE;
            }
            if (rc < 0) {
                return PN_HTTP_PARSE_ERROR;
            }
            break;

        case PN_HTTP_STATE_BODY_CHUNKED_DATA:
            rc = feed_chunked_data(parser, data, len, &pos, body_start, body_len);
            if (0 == rc) {
                *consumed = pos;
                return PN_HTTP_PARSE_NEED_MORE;
            }
            if (rc < 0) {
                return PN_HTTP_PARSE_ERROR;
            }
            break;

        case PN_HTTP_STATE_BODY_CHUNKED_TRAILER:
            rc = feed_chunked_trailer(parser, data, len, &pos);
            if (0 == rc) {
                parser->pos = (uint32_t)pos;
                *consumed   = pos;
                return PN_HTTP_PARSE_NEED_MORE;
            }
            if (1 == rc) {
                *status_code = parser->status_code;
                *consumed    = pos;
                return PN_HTTP_PARSE_COMPLETE;
            }
            break;

        case PN_HTTP_STATE_DONE:
            *status_code = parser->status_code;
            parser->pos  = (uint32_t)pos;
            *consumed    = pos;
            return PN_HTTP_PARSE_COMPLETE;

        default: break;
        }
    }

    parser->pos = (uint32_t)pos;
    *consumed   = pos;
    return PN_HTTP_PARSE_NEED_MORE;
}

pn_http_parse_result_t pn_http_parser_signal_eof(pn_http_parser_t* parser)
{
    if (NULL == parser) {
        return PN_HTTP_PARSE_ERROR;
    }

    switch (parser->state) {
    case PN_HTTP_STATE_BODY_UNTIL_CLOSE:
        /* Connection close is the body terminator for identity bodies. */
        parser->state = PN_HTTP_STATE_DONE;
        return PN_HTTP_PARSE_COMPLETE;

    case PN_HTTP_STATE_DONE:
        /* Body already fully received (e.g. satisfied Content-Length). */
        return PN_HTTP_PARSE_COMPLETE;

    default:
        /* Closed mid status line, headers, Content-Length, or chunked body. */
        return PN_HTTP_PARSE_ERROR;
    }
}

void pn_http_parser_get_headers(const pn_http_parser_t* parser,
                                uint8_t*                data,
                                pubnub_kv_t*            out,
                                unsigned int            out_cap,
                                unsigned int*           out_count)
{
    unsigned int n;
    unsigned int i;

    if (NULL == parser || NULL == data || NULL == out || NULL == out_count) {
        if (NULL != out_count) {
            *out_count = 0;
        }
        return;
    }

    n = parser->hdr_count;
    if (n > out_cap) {
        n = out_cap;
    }

    for (i = 0; i < n; ++i) {
        /* NUL-terminate the key in-place by overwriting the ':' that
         * immediately follows the field name in the rx buffer. */
        data[parser->hdr_name_start[i] + parser->hdr_name_len[i]] = '\0';

        out[i].key.ptr   = (const char*)(data + parser->hdr_name_start[i]);
        out[i].key.len   = parser->hdr_name_len[i];
        out[i].value.ptr = (const char*)(data + parser->hdr_value_start[i]);
        out[i].value.len = parser->hdr_value_len[i];
    }

    *out_count = n;
}

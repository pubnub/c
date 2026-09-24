/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file http_parser.h
 * @brief Incremental HTTP/1.1 response parser for socket transport.
 */

#ifndef PN_HTTP_PARSER_H
#define PN_HTTP_PARSER_H

#include "pubnub/config.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** HTTP parser parse result codes. */
typedef enum pn_http_parse_result {
    /** Parser needs more data to complete response. */
    PN_HTTP_PARSE_NEED_MORE = 0,
    /** Response parsing completed successfully. */
    PN_HTTP_PARSE_COMPLETE = 1,
    /** Malformed response or protocol error. */
    PN_HTTP_PARSE_ERROR = -1
} pn_http_parse_result_t;

/** HTTP response flags. */
enum pn_http_parser_flags {
    /** Transfer-Encoding: chunked. */
    PN_HTTP_FLAG_CHUNKED = 0x01,
    /** Content-Encoding: gzip. */
    PN_HTTP_FLAG_GZIP = 0x02,
    /** Content-Encoding: deflate. */
    PN_HTTP_FLAG_DEFLATE = 0x04,
    /** Connection: close. */
    PN_HTTP_FLAG_CONNECTION_CLOSE = 0x08,
    /**
     * A Content-Length header was present. Distinguishes an explicit
     * Content-Length: 0 (zero-length body) from a response with no
     * Content-Length and no Transfer-Encoding (body framed by close).
     */
    PN_HTTP_FLAG_HAS_CONTENT_LENGTH = 0x10
};

/** HTTP parser internal state. */
typedef enum pn_http_parser_state {
    PN_HTTP_STATE_STATUS_LINE          = 0,
    PN_HTTP_STATE_HEADERS              = 1,
    PN_HTTP_STATE_BODY_CONTENT_LENGTH  = 2,
    PN_HTTP_STATE_BODY_CHUNKED_SIZE    = 3,
    PN_HTTP_STATE_BODY_CHUNKED_DATA    = 4,
    PN_HTTP_STATE_BODY_CHUNKED_TRAILER = 5,
    /**
     * Identity body framed by connection close (no Content-Length, no
     * Transfer-Encoding). Body bytes accumulate until EOF is signalled.
     */
    PN_HTTP_STATE_BODY_UNTIL_CLOSE = 6,
    PN_HTTP_STATE_DONE             = 7
} pn_http_parser_state_t;

/**
 * @brief Incremental HTTP/1.1 response parser.
 *
 * Stack-allocatable state machine. Callers must feed the full accumulated
 * receive buffer from offset 0 on every tick; the parser resumes from
 * @c pos. Chunked responses are reassembled in-place into the buffer, so
 * the @c data parameter of @c pn_http_parser_feed must be mutable.
 */
typedef struct pn_http_parser {
    /** Current parser state. */
    uint8_t state;
    /** Response flags (PN_HTTP_FLAG_*). */
    uint8_t flags;
    /** HTTP status code (200, 404, etc.). */
    uint16_t status_code;
    /** Content-Length value (0 when chunked or not specified). */
    uint32_t content_length;
    /** Bytes of body received so far. */
    uint32_t body_received;
    /** Bytes remaining in current chunk (chunked mode only). */
    uint32_t chunk_remaining;
    /** Parse position within the full rx buffer; persists across calls. */
    uint32_t pos;
    /**
     * Write cursor for in-place chunked reassembly.
     * chunk_write_pos <= pos always; memmove is safe (no destructive overlap).
     */
    uint32_t chunk_write_pos;
    /**
     * Byte offset of body start within the full rx buffer.
     * Set once when body bytes are first seen; UINT32_MAX means not yet seen.
     */
    uint32_t body_start_offset;
    /**
     * Accumulated bytes of the header section (each header line plus its
     * CRLF). Capped by PUBNUB_CFG_MAX_HEADER_BYTES so a malicious server
     * cannot exhaust memory or force an unbounded scan with an endless
     * header stream.
     */
    uint32_t header_bytes;

    /** Number of captured response headers. */
    uint8_t hdr_count;
    /** Header field name start offsets within the rx buffer. */
    uint32_t hdr_name_start[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
    /** Header field name lengths. */
    uint16_t hdr_name_len[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
    /** Header field value start offsets within the rx buffer. */
    uint32_t hdr_value_start[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
    /** Header field value lengths. */
    uint16_t hdr_value_len[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
} pn_http_parser_t;

PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_HTTP_MAX_RESP_HEADERS <= 255,
    "pn_http_parser_t.hdr_count is uint8_t; max 255 resp headers");

/**
 * @brief Initialize HTTP parser to initial state.
 *
 * @param parser Parser instance to initialize.
 */
void pn_http_parser_init(pn_http_parser_t* parser);

/**
 * @brief Reset parser to initial state for reuse.
 *
 * @param parser Parser instance to reset.
 */
void pn_http_parser_reset(pn_http_parser_t* parser);

/**
 * @brief Feed data into the parser incrementally.
 *
 * Call with the full accumulated receive buffer from offset 0 on every tick.
 * The parser resumes from @c parser->pos, so previously parsed bytes are not
 * re-examined. For chunked responses, chunk data is reassembled in-place by
 * overwriting chunk-size framing bytes; @p data must therefore be mutable.
 *
 * @param parser      Parser instance (pos persists across calls).
 * @param data        Mutable receive buffer; chunked responses are
 *                    reassembled in-place.
 * @param len         Total bytes in @p data (including already-parsed prefix).
 * @param consumed    Output: total bytes consumed from start of @p data.
 * @param status_code Output: HTTP status code (valid after COMPLETE).
 * @param body_start  Output: pointer to body start within @p data.
 *                    Valid until the buffer is released.
 * @param body_len    Output: decoded body length in bytes.
 * @return PN_HTTP_PARSE_NEED_MORE if more data needed,
 *         PN_HTTP_PARSE_COMPLETE when response fully parsed,
 *         PN_HTTP_PARSE_ERROR on malformed input.
 */
pn_http_parse_result_t pn_http_parser_feed(pn_http_parser_t* parser,
                                           uint8_t*          data,
                                           size_t            len,
                                           size_t*           consumed,
                                           uint16_t*         status_code,
                                           const uint8_t**   body_start,
                                           size_t*           body_len);

/**
 * @brief Signal end-of-input (peer closed the connection) to the parser.
 *
 * HTTP/1.x permits a response body to be framed by connection close when
 * neither Content-Length nor Transfer-Encoding is present (RFC 7230
 * §3.3.3, message body length rule 7). Call this when the peer closes the
 * connection (recv returns 0 / TCP FIN) so the parser can finalize a
 * read-until-close identity body.
 *
 * On COMPLETE, read the accumulated body from the last @c pn_http_parser_feed
 * outputs (or from @c parser->body_start_offset into the rx buffer); this
 * call does not itself re-emit the body view.
 *
 * @param parser Parser instance.
 * @return PN_HTTP_PARSE_COMPLETE when the response is complete at close
 *         (read-until-close body terminated by the close, or a body that
 *         was already fully received); PN_HTTP_PARSE_ERROR when the
 *         connection closed mid-message (truncated status line, headers,
 *         Content-Length body, or chunked body).
 */
pn_http_parse_result_t pn_http_parser_signal_eof(pn_http_parser_t* parser);

/**
 * @brief Copy captured response headers into a caller-provided kv array.
 *
 * Views alias into @p data (the same rx buffer passed to pn_http_parser_feed);
 * they are valid until the buffer is released. Call after PN_HTTP_PARSE_COMPLETE.
 *
 * Each header key is NUL-terminated in-place by overwriting the ':'
 * separator that follows the field name in the rx buffer. This is safe
 * because parsing is complete and the header section precedes the body.
 *
 * @param parser     Parser instance (post-COMPLETE).
 * @param data       The rx buffer (mutable; keys are NUL-terminated in-place).
 * @param out        Caller-owned array to receive the key/value views.
 * @param out_cap    Capacity of @p out in entries.
 * @param out_count  Number of entries written.
 */
void pn_http_parser_get_headers(const pn_http_parser_t* parser,
                                uint8_t*                data,
                                pubnub_kv_t*            out,
                                unsigned int            out_cap,
                                unsigned int*           out_count);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_HTTP_PARSER_H */

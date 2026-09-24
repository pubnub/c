/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_http_parse.c
 * @brief libFuzzer harness for the socket transport HTTP response parser.
 *
 * Feeds arbitrary bytes to pn_http_parser_feed() simulating raw TCP
 * receive data.  The parser must not crash, read out of bounds, or
 * infinite-loop on any input.  Exercises both chunked and
 * content-length transfer modes.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "providers/transport/socket/http_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (0 == size || size > 65536) {
        return 0;
    }

    /* The parser modifies data in-place for chunked reassembly,
     * so we need a mutable copy. */
    uint8_t buf[65536];
    memcpy(buf, data, size);

    pn_http_parser_t parser;
    pn_http_parser_init(&parser);

    /* Feed data in variable-sized chunks to exercise incremental
     * parsing paths. Use the first byte as a chunk-size hint. */
    size_t chunk_size = 1 + (data[0] % 64);
    size_t offset     = 0;

    while (offset < size) {
        size_t remaining = size - offset;
        size_t feed_len  = chunk_size < remaining ? chunk_size : remaining;

        size_t         consumed    = 0;
        uint16_t       status_code = 0;
        const uint8_t* body_start  = NULL;
        size_t         body_len    = 0;

        pn_http_parse_result_t rc = pn_http_parser_feed(
            &parser, buf, offset + feed_len, &consumed, &status_code, &body_start, &body_len);

        if (PN_HTTP_PARSE_ERROR == rc) {
            break;
        }

        if (consumed <= offset) {
            /* No forward progress; avoid infinite loop. */
            break;
        }
        offset = consumed;

        if (PN_HTTP_PARSE_COMPLETE == rc) {
            /* Exercise header accessor after successful parse. */
            pubnub_kv_t  headers[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
            unsigned int hdr_count = 0;
            pn_http_parser_get_headers(
                &parser, buf, headers, PUBNUB_CFG_HTTP_MAX_RESP_HEADERS, &hdr_count);

            /* Touch values to surface memory issues under ASan. */
            for (unsigned int i = 0; i < hdr_count; ++i) {
                volatile char k = headers[i].key.ptr ? headers[i].key.ptr[0] : 0;
                volatile char v =
                    headers[i].value.ptr ? headers[i].value.ptr[0] : 0;
                (void)k;
                (void)v;
            }
            break;
        }
    }

    return 0;
}

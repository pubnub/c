/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_url_encode.h"

#include <stdint.h>
#include <string.h>

static int pn_is_unreserved(unsigned char c)
{
    /* RFC 3986 unreserved characters. */
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
        || c == '-' || c == '_' || c == '.' || c == '~') {
        return 1;
    }
    return 0;
}

pubnub_res_t pn_url_encode_n(const char* input,
                             size_t      input_len,
                             char*       output,
                             size_t      out_size,
                             int         encode)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t            pos   = 0;
    /* "." / ".." are dot-segments; encode the leading dot as %2E so path
     * normalization cannot strip the segment from the request URL. */
    int dot_segment = 0;

    if (NULL == output || 0 == out_size) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == input && input_len > 0) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    dot_segment = (1 == input_len && '.' == input[0])
               || (2 == input_len && '.' == input[0] && '.' == input[1]);

    for (size_t i = 0; i < input_len; ++i) {
        unsigned char c            = (unsigned char)input[i];
        int           keep_literal = pn_is_unreserved(c)
                        || (PN_ENCODE_KEEP_COMMAS == encode && ',' == c);
        if (dot_segment && 0 == i) {
            keep_literal = 0;
        }
        if (keep_literal) {
            if (pos + 1 >= out_size) {
                return PUBNUB_ERR_BUFFER_TOO_SMALL;
            }
            output[pos++] = (char)c;
        } else {
            if (pos + 3 >= out_size) {
                return PUBNUB_ERR_BUFFER_TOO_SMALL;
            }
            output[pos++] = '%';
            output[pos++] = hex[(c >> 4) & 0x0FU];
            output[pos++] = hex[c & 0x0FU];
        }
    }

    output[pos] = '\0';
    return PUBNUB_OK;
}

pubnub_res_t pn_url_encode(const char* input, char* output, size_t out_size, int encode)
{
    if (NULL == input) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_url_encode_n(input, strlen(input), output, out_size, encode);
}

char* pn_url_encode_alloc_n(const uint8_t*               input,
                            size_t                       input_len,
                            pubnub_allocator_provider_t* allocator,
                            int                          encode)
{
    if (NULL == allocator || (NULL == input && input_len > 0)) {
        return NULL;
    }

    /* Overflow guard: 3 * input_len + 1 must fit in size_t. */
    if (input_len > (SIZE_MAX - 1) / 3) {
        return NULL;
    }

    const size_t encoded_cap = input_len * 3 + 1;
    char*        buf         = (char*)PN_ALLOC(allocator, encoded_cap, 0);
    if (NULL == buf) {
        return NULL;
    }

    const pubnub_res_t rc =
        pn_url_encode_n((const char*)input, input_len, buf, encoded_cap, encode);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, buf);
        return NULL;
    }
    return buf;
}

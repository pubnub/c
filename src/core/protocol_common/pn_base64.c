/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_base64.h"

static const char pn_b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Decode table mapping ASCII byte to 6-bit value.
 *
 * 0xFF marks invalid characters; 0xFE marks `=` padding.
 */
// clang-format off
static const uint8_t pn_b64_decode_table[256] = {
    /* 0x00 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0x10 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0x20 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF,  62,  0xFF, 0xFF, 0xFF,  63,
    /* 0x30 */  52,   53,   54,   55,   56,   57,   58,   59,    60,   61,  0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
    /* 0x40 */ 0xFF,   0,    1,    2,    3,    4,    5,    6,     7,    8,    9,   10,   11,   12,   13,   14,
    /* 0x50 */  15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0x60 */ 0xFF,  26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
    /* 0x70 */  41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0x80 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0x90 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0xA0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0xB0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0xC0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0xD0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0xE0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0xF0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};
// clang-format on

size_t pn_base64_encoded_len(size_t input_len)
{
    /* Standard base64: ceil(input_len / 3) * 4, plus NUL. */
    return ((input_len + 2) / 3) * 4 + 1;
}

pubnub_res_t pn_base64_encode(const uint8_t* input,
                              size_t         input_len,
                              char*          output,
                              size_t         out_size)
{
    if (NULL == output) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == input && 0 != input_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    const size_t need = pn_base64_encoded_len(input_len);
    if (out_size < need) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    size_t i = 0;
    size_t j = 0;

    /* Process full 3-byte groups. */
    while (i + 3 <= input_len) {
        const uint32_t triplet = ((uint32_t)input[i] << 16)
                               | ((uint32_t)input[i + 1] << 8)
                               | (uint32_t)input[i + 2];
        output[j]     = pn_b64_alphabet[(triplet >> 18) & 0x3F];
        output[j + 1] = pn_b64_alphabet[(triplet >> 12) & 0x3F];
        output[j + 2] = pn_b64_alphabet[(triplet >> 6) & 0x3F];
        output[j + 3] = pn_b64_alphabet[triplet & 0x3F];
        i += 3;
        j += 4;
    }

    /* Handle trailing bytes with `=` padding. */
    const size_t remain = input_len - i;
    if (1 == remain) {
        const uint32_t triplet = (uint32_t)input[i] << 16;
        output[j]              = pn_b64_alphabet[(triplet >> 18) & 0x3F];
        output[j + 1]          = pn_b64_alphabet[(triplet >> 12) & 0x3F];
        output[j + 2]          = '=';
        output[j + 3]          = '=';
        j += 4;
    } else if (2 == remain) {
        const uint32_t triplet =
            ((uint32_t)input[i] << 16) | ((uint32_t)input[i + 1] << 8);
        output[j]     = pn_b64_alphabet[(triplet >> 18) & 0x3F];
        output[j + 1] = pn_b64_alphabet[(triplet >> 12) & 0x3F];
        output[j + 2] = pn_b64_alphabet[(triplet >> 6) & 0x3F];
        output[j + 3] = '=';
        j += 4;
    }

    output[j] = '\0';

    return PUBNUB_OK;
}

size_t pn_base64_decoded_max_len(size_t encoded_len)
{
    return (encoded_len / 4) * 3;
}

pubnub_res_t pn_base64_decode(const char* input,
                              size_t      input_len,
                              uint8_t*    output,
                              size_t      out_size,
                              size_t*     out_len)
{
    if (NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out_len = 0;

    if (NULL == input && 0 != input_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == output && 0 != out_size) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Empty input is a valid encoding of zero bytes. */
    if (0 == input_len) {
        return PUBNUB_OK;
    }

    /* Valid base64 must be a multiple of 4 characters. */
    if (0 != (input_len % 4)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Determine actual decoded length by inspecting padding. */
    size_t padding = 0;
    if ('=' == input[input_len - 1]) {
        padding++;
    }
    if (input_len >= 2 && '=' == input[input_len - 2]) {
        padding++;
    }

    const size_t decoded_len = (input_len / 4) * 3 - padding;
    if (out_size < decoded_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    size_t       di       = 0;
    const size_t data_end = input_len - (padding > 0 ? 4 : 0);

    /* Process all full 4-char groups (no padding). */
    for (size_t si = 0; si < data_end; si += 4) {
        const uint8_t a = pn_b64_decode_table[(uint8_t)input[si]];
        const uint8_t b = pn_b64_decode_table[(uint8_t)input[si + 1]];
        const uint8_t c = pn_b64_decode_table[(uint8_t)input[si + 2]];
        const uint8_t d = pn_b64_decode_table[(uint8_t)input[si + 3]];

        if (0xFF == a || 0xFF == b || 0xFF == c || 0xFF == d) {
            return PUBNUB_ERR_CRYPTO;
        }
        if (0xFE == a || 0xFE == b || 0xFE == c || 0xFE == d) {
            /* Padding in the middle of the stream. */
            return PUBNUB_ERR_CRYPTO;
        }

        const uint32_t triplet = ((uint32_t)a << 18) | ((uint32_t)b << 12)
                               | ((uint32_t)c << 6) | (uint32_t)d;
        output[di]     = (uint8_t)((triplet >> 16) & 0xFF);
        output[di + 1] = (uint8_t)((triplet >> 8) & 0xFF);
        output[di + 2] = (uint8_t)(triplet & 0xFF);
        di += 3;
    }

    /* Process the last group with padding. */
    if (padding > 0) {
        const size_t  si = data_end;
        const uint8_t a  = pn_b64_decode_table[(uint8_t)input[si]];
        const uint8_t b  = pn_b64_decode_table[(uint8_t)input[si + 1]];

        if (0xFF == a || 0xFF == b || 0xFE == a || 0xFE == b) {
            return PUBNUB_ERR_CRYPTO;
        }

        if (2 == padding) {
            /* 2 data chars + "==" → 1 byte */
            const uint32_t triplet = ((uint32_t)a << 18) | ((uint32_t)b << 12);
            output[di]             = (uint8_t)((triplet >> 16) & 0xFF);
            di += 1;
        } else {
            /* 3 data chars + "=" → 2 bytes */
            const uint8_t c = pn_b64_decode_table[(uint8_t)input[si + 2]];
            if (0xFF == c || 0xFE == c) {
                return PUBNUB_ERR_CRYPTO;
            }
            const uint32_t triplet =
                ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
            output[di]     = (uint8_t)((triplet >> 16) & 0xFF);
            output[di + 1] = (uint8_t)((triplet >> 8) & 0xFF);
            di += 2;
        }
    }

    *out_len = di;

    return PUBNUB_OK;
}

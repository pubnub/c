/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_base64url.c
 * @brief Base64url encoder (RFC 4648 §5, no padding).
 */

#include "pn_base64url.h"

static const char kB64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t pn_base64url_encoded_len(size_t input_len)
{
    /* Each 3 bytes -> 4 chars; trailing 1 byte -> 2 chars,
     * trailing 2 bytes -> 3 chars (unpadded). */
    const size_t full   = input_len / 3;
    const size_t remain = input_len % 3;
    size_t       out    = full * 4;

    if (remain == 1) {
        out += 2;
    } else if (remain == 2) {
        out += 3;
    }

    return out;
}

pubnub_res_t pn_base64url_encode(const uint8_t* input,
                                 size_t         input_len,
                                 char*          output,
                                 size_t         out_size)
{
    if (out_size == 0) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    if (output == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (input == NULL && input_len != 0) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    const size_t need = pn_base64url_encoded_len(input_len);
    if (need + 1 > out_size) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    size_t i = 0;
    size_t j = 0;
    while (i + 3 <= input_len) {
        const uint32_t triplet = ((uint32_t)input[i] << 16)
                               | ((uint32_t)input[i + 1] << 8)
                               | (uint32_t)input[i + 2];
        output[j]     = kB64UrlAlphabet[(triplet >> 18) & 0x3F];
        output[j + 1] = kB64UrlAlphabet[(triplet >> 12) & 0x3F];
        output[j + 2] = kB64UrlAlphabet[(triplet >> 6) & 0x3F];
        output[j + 3] = kB64UrlAlphabet[triplet & 0x3F];
        i += 3;
        j += 4;
    }

    const size_t remain = input_len - i;
    if (remain == 1) {
        const uint32_t triplet = (uint32_t)input[i] << 16;
        output[j]              = kB64UrlAlphabet[(triplet >> 18) & 0x3F];
        output[j + 1]          = kB64UrlAlphabet[(triplet >> 12) & 0x3F];
        j += 2;
    } else if (remain == 2) {
        const uint32_t triplet =
            ((uint32_t)input[i] << 16) | ((uint32_t)input[i + 1] << 8);
        output[j]     = kB64UrlAlphabet[(triplet >> 18) & 0x3F];
        output[j + 1] = kB64UrlAlphabet[(triplet >> 12) & 0x3F];
        output[j + 2] = kB64UrlAlphabet[(triplet >> 6) & 0x3F];
        j += 3;
    }

    output[j] = '\0';

    return PUBNUB_OK;
}

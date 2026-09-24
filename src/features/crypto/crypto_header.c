/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_header.h"

#include <string.h>

static const uint8_t pn_crypto_sentinel_bytes[PN_CRYPTO_SENTINEL_LEN] = {0x50,
                                                                         0x4E,
                                                                         0x45,
                                                                         0x44}; /* "PNED" */

int pn_crypto_header_is_present(const uint8_t* input, size_t input_len)
{
    if (NULL == input || input_len < PN_CRYPTO_SENTINEL_LEN) {
        return 0;
    }

    return 0 == memcmp(input, pn_crypto_sentinel_bytes, PN_CRYPTO_SENTINEL_LEN);
}

pubnub_res_t pn_crypto_header_parse(const uint8_t*      input,
                                    size_t              input_len,
                                    pn_crypto_header_t* header)
{
    size_t metadata_len;
    size_t header_offset;

    if (NULL == input || NULL == header) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (!pn_crypto_header_is_present(input, input_len)) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (input_len < PN_CRYPTO_MIN_HEADER) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* Validate version byte at offset 4. */
    if (input[4] > PN_CRYPTO_VERSION) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* Read metadata length at offset 9. */
    if (0xFF == input[9]) {
        /* Extended length: 2-byte big-endian at offsets 10-11. */
        if (input_len < 12) {
            return PUBNUB_ERR_CRYPTO;
        }
        metadata_len  = ((size_t)input[10] << 8) | (size_t)input[11];
        header_offset = 12;
    } else {
        metadata_len  = (size_t)input[9];
        header_offset = 10;
    }

    /* Verify metadata fits within input. */
    if (header_offset + metadata_len > input_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* Populate output. */
    memcpy(header->identifier, &input[5], 4);
    header->metadata_len = metadata_len;
    header->header_len   = header_offset + metadata_len;

    return PUBNUB_OK;
}

size_t pn_crypto_header_size(size_t metadata_len)
{
    /* sentinel(4) + ver(1) + id(4) + length_field + metadata */
    size_t length_field_size = (metadata_len >= 255) ? 3 : 1;

    return PN_CRYPTO_SENTINEL_LEN + 1 + 4 + length_field_size + metadata_len;
}

size_t pn_crypto_header_serialize(const uint8_t identifier[4],
                                  size_t        metadata_len,
                                  uint8_t*      output,
                                  size_t        output_cap)
{
    size_t prefix_len;
    size_t offset = 0;

    if (NULL == identifier || NULL == output) {
        return 0;
    }

    /* Compute prefix size (everything before metadata). */
    prefix_len = PN_CRYPTO_SENTINEL_LEN + 1 + 4 + ((metadata_len >= 255) ? 3 : 1);

    if (output_cap < prefix_len) {
        return 0;
    }

    /* Sentinel. */
    memcpy(output, pn_crypto_sentinel_bytes, PN_CRYPTO_SENTINEL_LEN);
    offset += PN_CRYPTO_SENTINEL_LEN;

    /* Version. */
    output[offset] = (uint8_t)PN_CRYPTO_VERSION;
    offset++;

    /* Identifier. */
    memcpy(&output[offset], identifier, 4);
    offset += 4;

    /* Metadata length encoding. */
    if (metadata_len < 255) {
        output[offset] = (uint8_t)metadata_len;
        offset++;
    } else {
        output[offset] = 0xFF;
        offset++;
        output[offset] = (uint8_t)((metadata_len >> 8) & 0xFF);
        offset++;
        output[offset] = (uint8_t)(metadata_len & 0xFF);
        offset++;
    }

    return offset;
}

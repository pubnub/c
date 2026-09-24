/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CRYPTO_HEADER_H
#define PN_CRYPTO_HEADER_H

#include "pubnub/config.h"
#include "pubnub/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

#define PN_CRYPTO_SENTINEL     "PNED"
#define PN_CRYPTO_SENTINEL_LEN 4
#define PN_CRYPTO_VERSION      1
#define PN_CRYPTO_MIN_HEADER   10 /* sentinel(4) + ver(1) + id(4) + len(1) */

/**
 * @brief Parsed PNED header descriptor.
 *
 * Populated by pn_crypto_header_parse on success. The metadata bytes
 * themselves are located at input + header_len - metadata_len.
 */
typedef struct pn_crypto_header {
    uint8_t identifier[4]; /**< Cryptor algorithm identifier. */
    size_t  metadata_len;  /**< Length of metadata following the header. */
    size_t  header_len;    /**< Total header size including metadata. */
} pn_crypto_header_t;

/**
 * @brief Check whether input starts with a PNED sentinel.
 *
 * @param input     Raw bytes (may be NULL if input_len == 0).
 * @param input_len Length of input buffer in bytes.
 * @return 1 if the PNED header sentinel is present, 0 otherwise.
 */
int pn_crypto_header_is_present(const uint8_t* input, size_t input_len);

/**
 * @brief Parse a PNED header from raw bytes.
 *
 * Validates sentinel, version, metadata length encoding, and bounds.
 * Does NOT read past input + input_len.
 *
 * @param input     Raw encrypted bytes with PNED header prefix.
 * @param input_len Total length of input buffer.
 * @param header    Output struct populated on success.
 * @return PUBNUB_OK on success, PUBNUB_ERR_CRYPTO on invalid/truncated
 *         input.
 */
pubnub_res_t pn_crypto_header_parse(const uint8_t*      input,
                                    size_t              input_len,
                                    pn_crypto_header_t* header);

/**
 * @brief Compute serialized header size for a given metadata length.
 *
 * Returns the total number of bytes the header occupies (sentinel +
 * version + identifier + length field + metadata).
 *
 * @param metadata_len Length of metadata to be embedded.
 * @return Total header size in bytes.
 */
size_t pn_crypto_header_size(size_t metadata_len);

/**
 * @brief Serialize the PNED header prefix into an output buffer.
 *
 * Writes sentinel + version + identifier + length encoding. Does NOT
 * write the metadata itself — the caller appends metadata bytes after
 * the returned offset.
 *
 * @param identifier  4-byte cryptor algorithm identifier.
 * @param metadata_len Length of metadata that will follow.
 * @param output      Destination buffer (at least output_cap bytes).
 * @param output_cap  Capacity of output buffer.
 * @return Bytes written (header prefix before metadata), or 0 if
 *         output_cap is insufficient.
 */
size_t pn_crypto_header_serialize(const uint8_t identifier[4],
                                  size_t        metadata_len,
                                  uint8_t*      output,
                                  size_t        output_cap);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_CRYPTO_HEADER_H */

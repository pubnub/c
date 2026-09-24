/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_INFLATE_H
#define PN_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/** @brief Return code: success. */
#define PN_INFLATE_OK 0
/** @brief Return code: output buffer too small to hold decompressed
 *  data. */
#define PN_INFLATE_ERR_OVERFLOW (-1)
/** @brief Return code: invalid or corrupt compressed data /
 *  unsupported format. */
#define PN_INFLATE_ERR_INVALID (-2)

struct pubnub_allocator_provider;
struct pubnub_logger_provider;

/**
 * @brief Decompress gzip-compressed data.
 *
 * Inflates a gzip stream (RFC 1952) into the output buffer.
 * The output buffer must be pre-allocated by the caller with
 * sufficient capacity. If the output buffer is too small, returns
 * an error (caller should grow the buffer and retry).
 *
 * @param input      Compressed input data.
 * @param input_len  Length of compressed data.
 * @param output     Output buffer for decompressed data.
 * @param output_cap Capacity of output buffer.
 * @param out_len    Actual decompressed length written.
 * @param allocator  Allocator for internal working memory (~11KB for
 *                   tinfl backend). Required by tinfl; ignored by
 *                   zlib (which uses its own internal allocation).
 *                   Must not be NULL when built with tinfl backend.
 * @param logger     Logger for diagnostic output (may be NULL).
 * @retval PN_INFLATE_OK on success.
 * @retval PN_INFLATE_ERR_OVERFLOW if output buffer too small.
 * @retval PN_INFLATE_ERR_INVALID on format error.
 */
int pn_inflate_gzip(const uint8_t*                    input,
                    size_t                            input_len,
                    uint8_t*                          output,
                    size_t                            output_cap,
                    size_t*                           out_len,
                    struct pubnub_allocator_provider* allocator,
                    struct pubnub_logger_provider*    logger);

/**
 * @brief Decompress raw deflate data.
 *
 * Inflates a raw deflate stream (RFC 1951) into the output buffer.
 *
 * @param input      Compressed input data.
 * @param input_len  Length of compressed data.
 * @param output     Output buffer for decompressed data.
 * @param output_cap Capacity of output buffer.
 * @param out_len    Actual decompressed length written.
 * @param allocator  Allocator for internal working memory (~11KB for
 *                   tinfl backend). Required by tinfl; ignored by
 *                   zlib (which uses its own internal allocation).
 *                   Must not be NULL when built with tinfl backend.
 * @param logger     Logger for diagnostic output (may be NULL).
 * @retval PN_INFLATE_OK on success.
 * @retval PN_INFLATE_ERR_OVERFLOW if output buffer too small.
 * @retval PN_INFLATE_ERR_INVALID on format error.
 */
int pn_inflate_deflate(const uint8_t*                    input,
                       size_t                            input_len,
                       uint8_t*                          output,
                       size_t                            output_cap,
                       size_t*                           out_len,
                       struct pubnub_allocator_provider* allocator,
                       struct pubnub_logger_provider*    logger);

#endif /* PN_INFLATE_H */

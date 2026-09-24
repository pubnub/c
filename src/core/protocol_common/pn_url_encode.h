/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/** @brief Shared URL percent-encoding utilities (internal, not installed). */

#ifndef PN_URL_ENCODE_H
#define PN_URL_ENCODE_H

#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Do not percent-encode the value; copy verbatim. */
#define PN_ENCODE_NONE 0
/** @brief Percent-encode the entire value (RFC 3986). */
#define PN_ENCODE_FULL 1
/** @brief Percent-encode but preserve literal commas as delimiters. */
#define PN_ENCODE_KEEP_COMMAS 2

/**
 * @brief Percent-encode exactly @p input_len bytes into @p output.
 *
 * Does not require NUL termination in @p input. NUL bytes within
 * the range are encoded as `%00` (per RFC 3986).
 *
 * @param input      Input bytes (may contain NUL).
 * @param input_len  Number of bytes to encode.
 * @param output     Output buffer (NUL-terminated on success).
 * @param out_size   Output buffer capacity including NUL terminator.
 * @param encode     PN_ENCODE_FULL or PN_ENCODE_KEEP_COMMAS.
 * @return `PUBNUB_OK` on success, an error code on NULL pointer / zero
 *         @p out_size, or insufficient output capacity.
 */
pubnub_res_t pn_url_encode_n(const char* input,
                             size_t      input_len,
                             char*       output,
                             size_t      out_size,
                             int         encode);

/**
 * @brief Percent-encode a NUL-terminated string into a buffer.
 *
 * Convenience wrapper around @ref pn_url_encode_n that uses
 * `strlen(input)` as the length.
 *
 * @param input    NUL-terminated input string.
 * @param output   Output buffer.
 * @param out_size Output buffer capacity including NUL terminator.
 * @param encode   PN_ENCODE_FULL or PN_ENCODE_KEEP_COMMAS.
 * @return `PUBNUB_OK` on success, an error code when the output is too
 *         small or @p input is NULL.
 */
pubnub_res_t pn_url_encode(const char* input, char* output, size_t out_size, int encode);

/**
 * @brief Percent-encode exactly @p input_len bytes into a freshly
 *        allocated buffer.
 *
 * Allocates worst-case capacity (3 * input_len + 1) via @p allocator
 * and encodes in-place. Intended for serialized message payloads that
 * arrive as `uint8_t*` from the serialization provider - avoids an
 * intermediate cast at the call site.
 *
 * @param input      Input bytes (may contain NUL).
 * @param input_len  Number of bytes to encode.
 * @param allocator  Allocator provider (borrowed, must be non-NULL).
 * @param encode     PN_ENCODE_FULL or PN_ENCODE_KEEP_COMMAS.
 * @return NUL-terminated encoded string (allocator-owned), or NULL on
 *         allocation failure, encoding failure, or overflow.
 */
char* pn_url_encode_alloc_n(const uint8_t*               input,
                            size_t                       input_len,
                            pubnub_allocator_provider_t* allocator,
                            int                          encode);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_URL_ENCODE_H */

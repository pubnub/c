/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_base64.h
 * @brief Standard base64 (RFC 4648 §4) encoding and decoding.
 *
 * Internal-only helper; not installed as a public header. Used by the
 * crypto module to encode and decode cipher output in the standard
 * base64 alphabet with `=` padding.
 *
 * Encoding uses the standard `A-Za-z0-9+/` alphabet with `=` padding
 * to a 4-character boundary.
 */

#ifndef PN_BASE64_H
#define PN_BASE64_H

#include "pubnub/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Compute output buffer size needed for encoding @p input_len
 *        bytes, including the NUL terminator.
 *
 * The returned value accounts for `=` padding and the trailing NUL.
 * For @p input_len 0 the return value is 1 (the NUL byte alone).
 *
 * @param input_len Number of bytes to encode.
 * @return Required buffer size (encoded chars + NUL).
 */
size_t pn_base64_encoded_len(size_t input_len);

/**
 * @brief Base64-encode @p input_len bytes from @p input into @p
 *        output.
 *
 * The output is NUL-terminated and padded with `=` to a 4-character
 * boundary per RFC 4648 §4. @p out_size must be at least
 * `pn_base64_encoded_len(input_len)` bytes.
 *
 * @param input     Input bytes (may be NULL only if @p input_len is
 *                  0).
 * @param input_len Number of input bytes to encode.
 * @param output    Destination buffer (must be non-NULL when
 *                  @p out_size > 0).
 * @param out_size  Capacity of @p output including the NUL
 *                  terminator.
 * @return `PUBNUB_OK` on success,
 *         `PUBNUB_ERR_INVALID_ARGUMENT` on NULL pointer violations,
 *         `PUBNUB_ERR_BUFFER_TOO_SMALL` if @p out_size is
 *         insufficient.
 */
pubnub_res_t pn_base64_encode(const uint8_t* input,
                              size_t         input_len,
                              char*          output,
                              size_t         out_size);

/**
 * @brief Compute worst-case decoded output size for @p encoded_len
 *        base64 characters.
 *
 * The actual decoded length may be 1 or 2 bytes shorter due to
 * padding. Use the @p out_len output of pn_base64_decode() for the
 * true length.
 *
 * @param encoded_len Number of base64 characters (excluding NUL).
 * @return Maximum decoded byte count.
 */
size_t pn_base64_decoded_max_len(size_t encoded_len);

/**
 * @brief Decode a base64-encoded string into raw bytes.
 *
 * Handles `=` padding (0, 1, or 2 trailing `=` chars). Writes the
 * actual decoded byte count to @p out_len.
 *
 * @param input     Base64 input string (not required to be
 *                  NUL-terminated; @p input_len governs length).
 * @param input_len Length of @p input in characters.
 * @param output    Destination buffer for decoded bytes.
 * @param out_size  Capacity of @p output in bytes.
 * @param out_len   Receives the actual decoded byte count on success.
 *                  Set to 0 on failure.
 * @return `PUBNUB_OK` on success,
 *         `PUBNUB_ERR_INVALID_ARGUMENT` on NULL pointer violations or
 *         invalid input length (not a multiple of 4),
 *         `PUBNUB_ERR_BUFFER_TOO_SMALL` if @p out_size is
 *         insufficient,
 *         `PUBNUB_ERR_CRYPTO` on invalid base64 characters.
 */
pubnub_res_t pn_base64_decode(const char* input,
                              size_t      input_len,
                              uint8_t*    output,
                              size_t      out_size,
                              size_t*     out_len);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_BASE64_H */

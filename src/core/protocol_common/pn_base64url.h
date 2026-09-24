/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_base64url.h
 * @brief Base64url (RFC 4648 §5) encoding helper, no padding.
 *
 * Internal-only helper; not installed as a public header. Used by the
 * signature middleware to encode the HMAC-SHA256 output into a form
 * safe to place in a URL query parameter without further escaping.
 *
 * Encoding differences from standard base64:
 *   - `+` becomes `-`
 *   - `/` becomes `_`
 *   - `=` padding is omitted
 *
 * The encoder writes into a caller-provided buffer and never
 * allocates. It NUL-terminates the output on success.
 */

#ifndef PN_BASE64URL_H
#define PN_BASE64URL_H

#include "pubnub/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Compute the exact output length for @p input_len input bytes.
 *
 * The length does NOT include the NUL terminator. For @p input_len 0
 * the return value is 0.
 *
 * @param input_len Number of bytes to encode.
 * @return Output length in characters (without NUL).
 */
size_t pn_base64url_encoded_len(size_t input_len);

/**
 * @brief Base64url-encode @p input_len bytes from @p input into @p output.
 *
 * The output is NUL-terminated; @p out_size must be at least
 * `pn_base64url_encoded_len(input_len) + 1` bytes. Padding is
 * omitted per RFC 4648 §5.
 *
 * @param input     Input bytes (may be NULL only if @p input_len == 0).
 * @param input_len Number of input bytes to encode.
 * @param output    Destination buffer (must be non-NULL when
 *                  @p out_size > 0).
 * @param out_size  Capacity of @p output including the NUL terminator.
 * @return `PUBNUB_OK` on success, an error code on invalid argument
 *         pairing or insufficient @p out_size.
 */
pubnub_res_t pn_base64url_encode(const uint8_t* input,
                                 size_t         input_len,
                                 char*          output,
                                 size_t         out_size);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_BASE64URL_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Self-contained MD4 hash (RFC 1320) for NTLM authentication.
 *
 * Bundled because mbedTLS 3.x removed MD4 and OpenSSL 3.x deprecated
 * it. Only used once per NTLM handshake (computing the NT password
 * hash), so the performance impact of a non-optimized implementation
 * is negligible.
 */

#ifndef PN_PROXY_MD4_H
#define PN_PROXY_MD4_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Compute MD4 hash of a byte buffer (single-shot).
 *
 * @param data   Input bytes (may be NULL only if len is 0).
 * @param len    Number of input bytes.
 * @param digest Output buffer (exactly 16 bytes).
 */
void pn_proxy_md4(const uint8_t* data, size_t len, uint8_t digest[16]);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PROXY_MD4_H */

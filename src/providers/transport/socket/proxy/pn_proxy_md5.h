/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Self-contained streaming MD5 hash (RFC 1321) for Digest and
 *        NTLM proxy authentication.
 *
 * Bundled so that HTTP proxy support (a non-TLS feature) does not
 * pull in a build-time dependency on OpenSSL or mbedTLS. Used only
 * during proxy negotiation, so the performance impact of a
 * non-optimized implementation is negligible.
 *
 * The struct definition is exposed here (not opaque) because callers
 * allocate the context on the stack during proxy negotiation.
 */

#ifndef PN_PROXY_MD5_H
#define PN_PROXY_MD5_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Streaming MD5 context (RFC 1321). */
typedef struct pn_proxy_md5_ctx {
    uint32_t state[4];   /**< Chaining variables A, B, C, D. */
    uint64_t count;      /**< Total message length in bytes. */
    uint8_t  buffer[64]; /**< Partial-block accumulation buffer. */
} pn_proxy_md5_ctx_t;

/**
 * @brief Initialize an MD5 context for streaming computation.
 *
 * @param ctx Caller-allocated context.
 */
void pn_proxy_md5_init(pn_proxy_md5_ctx_t* ctx);

/**
 * @brief Feed data into the MD5 computation.
 *
 * @param ctx  Active context.
 * @param data Input bytes.
 * @param len  Number of bytes.
 */
void pn_proxy_md5_update(pn_proxy_md5_ctx_t* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize and produce the 16-byte MD5 digest.
 *
 * @param ctx    Active context (undefined state after this call).
 * @param digest Output buffer (exactly 16 bytes).
 */
void pn_proxy_md5_final(pn_proxy_md5_ctx_t* ctx, uint8_t digest[16]);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PROXY_MD5_H */

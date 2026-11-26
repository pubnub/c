/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CRYPTO_INTERNAL_H
#define PN_CRYPTO_INTERNAL_H

#include "core/pn_crypto_module.h"

#if PUBNUB_ENABLE_CRYPTO

#include "pubnub/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Encrypt plaintext to an allocated binary blob (internal).
 *
 * Allocates the output buffer via @p alloc. The caller must free
 * @c *output via @c alloc->free(alloc, *output) when done.
 *
 * @param module     Initialized module (non-NULL).
 * @param input      Plaintext bytes.
 * @param input_len  Plaintext length.
 * @param output     Receives allocated output buffer pointer.
 * @param output_len Receives output length.
 * @param alloc      Allocator for the output buffer.
 * @return PUBNUB_OK on success.
 */
pubnub_res_t pn_crypto_module_encrypt(pubnub_crypto_module_t*      module,
                                      const uint8_t*               input,
                                      size_t                       input_len,
                                      uint8_t**                    output,
                                      size_t*                      output_len,
                                      pubnub_allocator_provider_t* alloc);

/**
 * @brief Decrypt a binary blob to allocated plaintext (internal).
 *
 * Allocates the output buffer via @p alloc. The caller must free
 * @c *output via @c alloc->free(alloc, *output) when done.
 *
 * @param module     Initialized module (non-NULL).
 * @param input      Binary blob (header + ciphertext).
 * @param input_len  Blob length.
 * @param output     Receives allocated plaintext buffer.
 * @param output_len Receives plaintext length.
 * @param alloc      Allocator for the output buffer.
 * @return PUBNUB_OK on success.
 */
pubnub_res_t pn_crypto_module_decrypt(pubnub_crypto_module_t*      module,
                                      const uint8_t*               input,
                                      size_t                       input_len,
                                      uint8_t**                    output,
                                      size_t*                      output_len,
                                      pubnub_allocator_provider_t* alloc);

/**
 * @brief Encrypt plaintext and return as base64 string (internal).
 *
 * Allocates the output via @p alloc. Free @c *out_base64 via
 * @c alloc->free(alloc, *out_base64).
 *
 * @param module     Initialized module.
 * @param input      Plaintext bytes.
 * @param input_len  Plaintext length.
 * @param out_base64 Receives NUL-terminated base64 string.
 * @param out_len    Receives string length (excluding NUL).
 * @param alloc      Allocator.
 * @return PUBNUB_OK on success.
 */
pubnub_res_t pn_crypto_module_encrypt_to_base64(pubnub_crypto_module_t* module,
                                                const uint8_t*          input,
                                                size_t  input_len,
                                                char**  out_base64,
                                                size_t* out_len,
                                                pubnub_allocator_provider_t* alloc);

/**
 * @brief Decrypt a base64-encoded blob to plaintext (internal).
 *
 * Allocates the output via @p alloc. Free @c *output via
 * @c alloc->free(alloc, *output).
 *
 * @param module     Initialized module.
 * @param base64     Base64-encoded input.
 * @param base64_len Input length in characters.
 * @param output     Receives allocated plaintext buffer.
 * @param output_len Receives plaintext length.
 * @param alloc      Allocator.
 * @return PUBNUB_OK on success.
 */
pubnub_res_t pn_crypto_module_decrypt_from_base64(pubnub_crypto_module_t* module,
                                                  const char* base64,
                                                  size_t      base64_len,
                                                  uint8_t**   output,
                                                  size_t*     output_len,
                                                  pubnub_allocator_provider_t* alloc);

/**
 * @brief Create an AES-256-GCM cryptor for decryption only.
 *
 * Not part of the public API. @c pubnub_crypto_module_aes_cbc and
 * @c pubnub_crypto_module_legacy register this cryptor as a decryption
 * fallback. A module built with @c pubnub_crypto_module_create does
 * not receive it.
 *
 * Identifier: "ACGM". Encryption is not available: @c encrypt returns
 * @c PUBNUB_ERR_NOT_SUPPORTED and @c encrypt_size returns 0.
 *
 * Implemented by the linked crypto provider backend.
 *
 * @param cipher_key NUL-terminated cipher key string.
 * @param alloc      Allocator for cryptor state. @c NULL uses the
 *                   compiled-in default.
 * @return Cryptor instance, or @c NULL on failure.
 */
pubnub_crypto_provider_t* pn_cryptor_aes_gcm_create(const char* cipher_key,
                                                    pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_CRYPTO */

#endif /* PN_CRYPTO_INTERNAL_H */

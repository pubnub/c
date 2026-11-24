/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_MBEDTLS_FACTORIES_H
#define PN_MBEDTLS_FACTORIES_H

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Create an mbedTLS-backed ACRH (AES-256-CBC) cryptor.
 *
 * @param cipher_key NUL-terminated cipher key string.
 * @param alloc      Allocator for state allocation; NULL falls back to
 *                   compiled-in default.
 * @return Cryptor instance, or NULL on failure.
 */
pubnub_crypto_provider_t*
pn_mbedtls_cryptor_aes_cbc_create(const char*                  cipher_key,
                                  pubnub_allocator_provider_t* alloc);

/**
 * @brief Create an mbedTLS-backed legacy cryptor.
 *
 * @param cipher_key    NUL-terminated cipher key string.
 * @param use_random_iv 1 = random IV per encrypt, 0 = static IV.
 * @param alloc         Allocator; NULL falls back to compiled-in default.
 * @return Cryptor instance, or NULL on failure.
 */
pubnub_crypto_provider_t*
pn_mbedtls_cryptor_legacy_create(const char*                  cipher_key,
                                 int                          use_random_iv,
                                 pubnub_allocator_provider_t* alloc);

/**
 * @brief Create an mbedTLS-backed ACGM (AES-256-GCM) cryptor.
 *
 * Decrypts AES-256-GCM. The key is the raw SHA-256 of @p cipher_key.
 * Encryption is not available: encrypt() returns
 * PUBNUB_ERR_NOT_SUPPORTED and encrypt_size() returns 0.
 *
 * @param cipher_key NUL-terminated cipher key string.
 * @param alloc      Allocator for state allocation; NULL falls back to
 *                   compiled-in default.
 * @return Cryptor instance, or NULL on failure.
 */
pubnub_crypto_provider_t*
pn_mbedtls_cryptor_aes_gcm_create(const char*                  cipher_key,
                                  pubnub_allocator_provider_t* alloc);

/**
 * @brief Destroy an mbedTLS-backed cryptor instance.
 *
 * Frees DRBG/entropy state and securely zeros key material. NULL-safe.
 *
 * @param cryptor Instance to destroy, or NULL (no-op).
 */
void pn_mbedtls_cryptor_destroy(pubnub_crypto_provider_t* cryptor);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_MBEDTLS_FACTORIES_H */

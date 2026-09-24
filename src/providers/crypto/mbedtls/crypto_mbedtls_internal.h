/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CRYPTO_MBEDTLS_INTERNAL_H
#define PN_CRYPTO_MBEDTLS_INTERNAL_H

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <stdint.h>

/**
 * @brief Shared state for mbedTLS-backed cryptor instances.
 *
 * Both ACRH and legacy cryptors use this layout. The `base` field is
 * first so the struct can be cast to/from `pubnub_crypto_provider_t*`.
 */
typedef struct pn_mbedtls_cryptor_state {
    /** Provider vtable (first member enables cast to base pointer). */
    pubnub_crypto_provider_t base;
    /** Derived AES-256 key (32 bytes). */
    uint8_t key[32];
    /** Legacy only: 1 = random IV per encrypt, 0 = static IV. */
    int use_random_iv;
    /** CTR-DRBG context for random IV generation. */
    mbedtls_ctr_drbg_context drbg;
    /** Entropy source backing the DRBG. */
    mbedtls_entropy_context entropy;
    /** Allocator stored at creation for use by destroy. */
    pubnub_allocator_provider_t* alloc;
} pn_mbedtls_cryptor_state_t;

/** @brief AES-256 block size in bytes. */
#define PN_AES_BLOCK_SIZE 16

/** @brief AES-256 key size in bytes. */
#define PN_AES_KEY_SIZE 32

/** @brief HMAC-SHA256 output size in bytes. */
#define PN_HMAC_SHA256_SIZE 32

/** @brief SHA-256 digest size in bytes. */
#define PN_SHA256_DIGEST_SIZE 32

/**
 * @brief Derive AES-256 key for ACRH algorithm.
 *
 * Computes raw SHA-256 of cipher_key and writes 32 bytes to out_key.
 *
 * @param cipher_key NUL-terminated cipher key string.
 * @param out_key    Output buffer (must be at least 32 bytes).
 * @return PUBNUB_OK on success, PUBNUB_ERR_CRYPTO on failure.
 */
pubnub_res_t pn_mbedtls_derive_key_acrh(const char* cipher_key, uint8_t* out_key);

/**
 * @brief Derive AES-256 key for legacy algorithm.
 *
 * Computes SHA-256 of cipher_key, hex-encodes the digest, then takes
 * the first 32 hex characters as the key bytes.
 *
 * @param cipher_key NUL-terminated cipher key string.
 * @param out_key    Output buffer (must be at least 32 bytes).
 * @return PUBNUB_OK on success, PUBNUB_ERR_CRYPTO on failure.
 */
pubnub_res_t pn_mbedtls_derive_key_legacy(const char* cipher_key, uint8_t* out_key);

/**
 * @brief Compute HMAC-SHA256 using mbedTLS md API.
 *
 * @param self       Provider instance (unused internally, for vtable).
 * @param key        Signing key.
 * @param key_len    Key length in bytes.
 * @param data       Data to sign.
 * @param data_len   Data length in bytes.
 * @param output     Output buffer (at least 32 bytes).
 * @param output_len On entry: buffer size. On exit: 32.
 * @return PUBNUB_OK on success, PUBNUB_ERR_CRYPTO on failure.
 */
pubnub_res_t pn_mbedtls_hmac_sha256(pubnub_crypto_provider_t* self,
                                    const uint8_t*            key,
                                    size_t                    key_len,
                                    const uint8_t*            data,
                                    size_t                    data_len,
                                    uint8_t*                  output,
                                    size_t*                   output_len);

/**
 * @brief Securely zero a memory buffer via mbedtls_platform_zeroize.
 *
 * @param buf  Buffer to zero.
 * @param len  Length in bytes.
 */
void pn_mbedtls_secure_zero(void* buf, size_t len);

/**
 * @brief Initialize entropy and CTR-DRBG contexts in the state struct.
 *
 * @param state Pre-allocated state with uninitialized drbg/entropy.
 * @return 0 on success, non-zero on seeding failure.
 */
int pn_mbedtls_drbg_init(pn_mbedtls_cryptor_state_t* state);

/**
 * @brief Free entropy and CTR-DRBG contexts in the state struct.
 *
 * @param state State whose drbg/entropy are to be freed.
 */
void pn_mbedtls_drbg_free(pn_mbedtls_cryptor_state_t* state);

/**
 * @brief Populate the ACRH cryptor vtable on a pre-allocated state.
 *
 * Sets identifier to "ACRH", wires encrypt/decrypt/hmac functions,
 * and forces use_random_iv=1.
 *
 * @param state Pre-allocated and zero-initialized state struct.
 */
void pn_mbedtls_acrh_populate_vtable(pn_mbedtls_cryptor_state_t* state);

/**
 * @brief Populate the legacy cryptor vtable on a pre-allocated state.
 *
 * Sets identifier to {0,0,0,0} and wires encrypt/decrypt/hmac.
 *
 * @param state         Pre-allocated and zero-initialized state struct.
 * @param use_random_iv 1 = random IV per encrypt, 0 = static IV.
 */
void pn_mbedtls_legacy_populate_vtable(pn_mbedtls_cryptor_state_t* state,
                                       int use_random_iv);

#endif /* PN_CRYPTO_MBEDTLS_INTERNAL_H */

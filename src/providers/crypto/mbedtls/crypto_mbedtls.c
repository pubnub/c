/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_mbedtls_internal.h"
#include "mbedtls_factories.h"

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

#include <stddef.h>

/* Forward declarations for public API symbols (defined here, consumed
 * by the crypto feature module in a separate library). */
pubnub_crypto_provider_t* pn_crypto_default(void); // NOLINT(misc-use-internal-linkage)
pubnub_crypto_provider_t* pubnub_cryptor_aes_cbc_create( // NOLINT(misc-use-internal-linkage)
    const char*                  cipher_key,
    pubnub_allocator_provider_t* alloc);
pubnub_crypto_provider_t* pubnub_cryptor_legacy_create( // NOLINT(misc-use-internal-linkage)
    const char*                  cipher_key,
    int                          use_random_iv,
    pubnub_allocator_provider_t* alloc);
void pubnub_cryptor_destroy(pubnub_crypto_provider_t* cryptor); // NOLINT(misc-use-internal-linkage)

/**
 * @brief Static singleton provider for pn_crypto_default().
 *
 * Provides HMAC-SHA256 for PAM signing. Encrypt/decrypt are NULL
 * because payload crypto uses per-module cryptor instances, not the
 * compiled-in default.
 */
static pubnub_crypto_provider_t pn_mbedtls_default = {
    .identifier   = {0, 0, 0, 0},
    .encrypt_size = NULL,
    .encrypt      = NULL,
    .decrypt      = NULL,
    .hmac_sha256  = pn_mbedtls_hmac_sha256,
    .init         = NULL,
    .deinit       = NULL,
};

pubnub_crypto_provider_t* pn_crypto_default(void)
{
    return &pn_mbedtls_default;
}

pubnub_crypto_provider_t* pubnub_cryptor_aes_cbc_create(const char* cipher_key,
                                                        pubnub_allocator_provider_t* alloc)
{
    return pn_mbedtls_cryptor_aes_cbc_create(cipher_key, alloc);
}

pubnub_crypto_provider_t* pubnub_cryptor_legacy_create(const char* cipher_key,
                                                       int use_random_iv,
                                                       pubnub_allocator_provider_t* alloc)
{
    return pn_mbedtls_cryptor_legacy_create(cipher_key, use_random_iv, alloc);
}

void pubnub_cryptor_destroy(pubnub_crypto_provider_t* cryptor)
{
    pn_mbedtls_cryptor_destroy(cryptor);
}

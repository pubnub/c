/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_mbedtls_internal.h"
#include "mbedtls_factories.h"

#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

#include <stddef.h>
#include <string.h>

/** @brief Resolve allocator: fall back to compiled-in default. */
pubnub_allocator_provider_t* pn_allocator_default(void);

/**
 * @brief Shared creation logic for ACRH factory.
 */
static pubnub_crypto_provider_t*
pn_mbedtls_create_acrh(const char* cipher_key, pubnub_allocator_provider_t* alloc)
{
    if (NULL == cipher_key) {
        return NULL;
    }
    if (NULL == alloc) {
        alloc = pn_allocator_default();
    }
    if (NULL == alloc) {
        return NULL;
    }

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)PN_ALLOC(
        alloc, sizeof(pn_mbedtls_cryptor_state_t), 0);
    if (NULL == state) {
        return NULL;
    }

    memset(state, 0, sizeof(*state));
    state->alloc = alloc;

    if (PUBNUB_OK != pn_mbedtls_derive_key_acrh(cipher_key, state->key)) {
        PN_FREE(alloc, state);
        return NULL;
    }

    if (0 != pn_mbedtls_drbg_init(state)) {
        pn_mbedtls_secure_zero(state->key, sizeof(state->key));
        PN_FREE(alloc, state);
        return NULL;
    }

    pn_mbedtls_acrh_populate_vtable(state);

    return &state->base;
}

/**
 * @brief Shared creation logic for legacy factory.
 */
static pubnub_crypto_provider_t*
pn_mbedtls_create_legacy(const char*                  cipher_key,
                         int                          use_random_iv,
                         pubnub_allocator_provider_t* alloc)
{
    if (NULL == cipher_key) {
        return NULL;
    }
    if (NULL == alloc) {
        alloc = pn_allocator_default();
    }
    if (NULL == alloc) {
        return NULL;
    }

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)PN_ALLOC(
        alloc, sizeof(pn_mbedtls_cryptor_state_t), 0);
    if (NULL == state) {
        return NULL;
    }

    memset(state, 0, sizeof(*state));
    state->alloc = alloc;

    if (PUBNUB_OK != pn_mbedtls_derive_key_legacy(cipher_key, state->key)) {
        PN_FREE(alloc, state);
        return NULL;
    }

    if (use_random_iv) {
        if (0 != pn_mbedtls_drbg_init(state)) {
            pn_mbedtls_secure_zero(state->key, sizeof(state->key));
            PN_FREE(alloc, state);
            return NULL;
        }
    }

    pn_mbedtls_legacy_populate_vtable(state, use_random_iv);

    return &state->base;
}

/**
 * @brief Shared destroy logic.
 */
static void pn_mbedtls_destroy(pubnub_crypto_provider_t* cryptor)
{
    if (NULL == cryptor) {
        return;
    }

    pn_mbedtls_cryptor_state_t*  state = (pn_mbedtls_cryptor_state_t*)cryptor;
    pubnub_allocator_provider_t* alloc = state->alloc;
    if (NULL == alloc) {
        return;
    }

    /* Tear down DRBG state. */
    pn_mbedtls_drbg_free(state);

    /* Securely zero key material before freeing. */
    pn_mbedtls_secure_zero(state->key, sizeof(state->key));

    PN_FREE(alloc, state);
}

pubnub_crypto_provider_t*
pn_mbedtls_cryptor_aes_cbc_create(const char*                  cipher_key,
                                  pubnub_allocator_provider_t* alloc)
{
    return pn_mbedtls_create_acrh(cipher_key, alloc);
}

pubnub_crypto_provider_t*
pn_mbedtls_cryptor_legacy_create(const char*                  cipher_key,
                                 int                          use_random_iv,
                                 pubnub_allocator_provider_t* alloc)
{
    return pn_mbedtls_create_legacy(cipher_key, use_random_iv, alloc);
}

void pn_mbedtls_cryptor_destroy(pubnub_crypto_provider_t* cryptor)
{
    pn_mbedtls_destroy(cryptor);
}

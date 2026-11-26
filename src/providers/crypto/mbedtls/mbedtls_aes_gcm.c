/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_mbedtls_internal.h"

#include "pubnub/error.h"

#if defined(MBEDTLS_GCM_C)
#include <mbedtls/gcm.h>
#endif

#include <string.h>

/** @brief AES-GCM nonce carried in the PNED metadata. */
#define PN_GCM_NONCE_SIZE 12

/** @brief AES-GCM authentication tag appended to the ciphertext. */
#define PN_GCM_TAG_SIZE 16

static size_t pn_acgm_encrypt_size(pubnub_crypto_provider_t* self,
                                   size_t                    plaintext_len)
{
    (void)self;
    (void)plaintext_len;

    /* AES-256-GCM encryption is not available. */
    return 0;
}

static pubnub_res_t pn_acgm_encrypt(pubnub_crypto_provider_t* self,
                                    const uint8_t*            input,
                                    size_t                    input_len,
                                    pubnub_encrypted_data_t*  output)
{
    (void)self;
    (void)input;
    (void)input_len;
    (void)output;

    /* AES-256-GCM encryption is not available. */
    return PUBNUB_ERR_NOT_SUPPORTED;
}

static pubnub_res_t pn_acgm_decrypt(pubnub_crypto_provider_t*      self,
                                    const pubnub_encrypted_data_t* input,
                                    uint8_t*                       output,
                                    size_t*                        output_len)
{
#if !defined(MBEDTLS_GCM_C)
    (void)self;
    (void)input;
    (void)output;
    (void)output_len;

    /*
     * mbedtls_gcm_* exists only when the mbedTLS configuration enables
     * MBEDTLS_GCM_C. CONFIG_PUBNUB_ENABLE_CRYPTO selects that symbol
     * and, under PSA, CONFIG_MBEDTLS_LEGACY_CRYPTO_C and
     * CONFIG_PSA_WANT_ALG_GCM. A configuration that still omits
     * MBEDTLS_GCM_C builds; ACGM decryption returns an error.
     * AES-CBC is unaffected.
     */
    return PUBNUB_ERR_NOT_SUPPORTED ;
#else
    if (NULL == self || NULL == input || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* Nonce is the 12-byte metadata. The tag is the last 16 body bytes. */
    if (NULL == input->metadata || PN_GCM_NONCE_SIZE != input->metadata_len) {
        return PUBNUB_ERR_CRYPTO;
    }
    if (NULL == input->data || input->data_len < PN_GCM_TAG_SIZE) {
        return PUBNUB_ERR_CRYPTO;
    }

    size_t plain_len = input->data_len - PN_GCM_TAG_SIZE;
    if (*output_len < plain_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)self;

    uint8_t tag[PN_GCM_TAG_SIZE];
    memcpy(tag, input->data + plain_len, PN_GCM_TAG_SIZE);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    pubnub_res_t rc = PUBNUB_ERR_CRYPTO;

    if (0
        != mbedtls_gcm_setkey(
            &gcm, MBEDTLS_CIPHER_ID_AES, state->key, PN_AES_KEY_SIZE * 8)) {
        goto cleanup;
    }

    /*
     * Ciphertext only; additional authenticated data is empty. A body of
     * exactly 16 bytes is an empty plaintext plus the tag. Output must
     * not alias the ciphertext.
     */
    if (0
        != mbedtls_gcm_auth_decrypt(&gcm,
                                    plain_len,
                                    input->metadata,
                                    PN_GCM_NONCE_SIZE,
                                    NULL,
                                    0,
                                    tag,
                                    PN_GCM_TAG_SIZE,
                                    input->data,
                                    output)) {
        goto cleanup;
    }

    *output_len = plain_len;
    rc          = PUBNUB_OK;

cleanup:
    mbedtls_gcm_free(&gcm);
    pn_mbedtls_secure_zero(tag, sizeof(tag));
    if (PUBNUB_OK != rc && plain_len > 0) {
        /* Drop plaintext written before the tag check failed. */
        pn_mbedtls_secure_zero(output, plain_len);
    }

    return rc;
#endif
}

void pn_mbedtls_acgm_populate_vtable(pn_mbedtls_cryptor_state_t* state)
{
    state->base.identifier[0] = 'A';
    state->base.identifier[1] = 'C';
    state->base.identifier[2] = 'G';
    state->base.identifier[3] = 'M';
    state->base.encrypt_size  = pn_acgm_encrypt_size;
    state->base.encrypt       = pn_acgm_encrypt;
    state->base.decrypt       = pn_acgm_decrypt;
    state->base.hmac_sha256   = pn_mbedtls_hmac_sha256;
    state->base.init          = NULL;
    state->base.deinit        = NULL;
    state->use_random_iv      = 0;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_openssl_internal.h"

#include "pubnub/error.h"

#include <openssl/evp.h>

#include <limits.h>
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

    /* EVP update lengths are int; reject a body that does not fit. */
    if (input->data_len > (size_t)INT_MAX) {
        return PUBNUB_ERR_CRYPTO;
    }

    size_t plain_len = input->data_len - PN_GCM_TAG_SIZE;
    if (*output_len < plain_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    pn_openssl_cryptor_state_t* state = (pn_openssl_cryptor_state_t*)self;

    uint8_t tag[PN_GCM_TAG_SIZE];
    memcpy(tag, input->data + plain_len, PN_GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        OPENSSL_cleanse(tag, sizeof(tag));
        return PUBNUB_ERR_CRYPTO;
    }

    pubnub_res_t rc      = PUBNUB_ERR_CRYPTO;
    int          out_len = 0;
    int          fin_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        goto cleanup;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PN_GCM_NONCE_SIZE, NULL)) {
        goto cleanup;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, state->key, input->metadata)) {
        goto cleanup;
    }

    /*
     * Ciphertext only; additional authenticated data is empty. A body of
     * exactly 16 bytes is an empty plaintext plus the tag.
     */
    if (1 != EVP_DecryptUpdate(ctx, output, &out_len, input->data, (int)plain_len)) {
        goto cleanup;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PN_GCM_TAG_SIZE, tag)) {
        goto cleanup;
    }

    /* DecryptFinal verifies the authentication tag. */
    if (1 != EVP_DecryptFinal_ex(ctx, output + out_len, &fin_len)) {
        goto cleanup;
    }

    *output_len = (size_t)out_len + (size_t)fin_len;
    rc          = PUBNUB_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(tag, sizeof(tag));
    if (PUBNUB_OK != rc && plain_len > 0) {
        /* Drop plaintext written before the tag check failed. */
        OPENSSL_cleanse(output, plain_len);
    }

    return rc;
}

void pn_openssl_acgm_populate_vtable(pn_openssl_cryptor_state_t* state)
{
    state->base.identifier[0] = 'A';
    state->base.identifier[1] = 'C';
    state->base.identifier[2] = 'G';
    state->base.identifier[3] = 'M';
    state->base.encrypt_size  = pn_acgm_encrypt_size;
    state->base.encrypt       = pn_acgm_encrypt;
    state->base.decrypt       = pn_acgm_decrypt;
    state->base.hmac_sha256   = pn_openssl_hmac_sha256;
    state->base.init          = NULL;
    state->base.deinit        = NULL;
    state->use_random_iv      = 0;
}

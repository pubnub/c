/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_openssl_internal.h"

#include "pubnub/error.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

/** @brief Static IV used by legacy cryptor when use_random_iv is 0. */
static const uint8_t pn_legacy_static_iv[PN_AES_BLOCK_SIZE] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5'};

static size_t pn_legacy_encrypt_size(pubnub_crypto_provider_t* self,
                                     size_t                    plaintext_len)
{
    pn_openssl_cryptor_state_t* state = (pn_openssl_cryptor_state_t*)self;

    /*
     * Ciphertext: plaintext rounded up to block boundary (PKCS#7).
     * Random IV mode: 16-byte IV prepended to ciphertext in data output.
     */
    size_t ciphertext_len = plaintext_len + PN_AES_BLOCK_SIZE;

    if (state->use_random_iv) {
        return ciphertext_len + PN_AES_BLOCK_SIZE;
    }

    return ciphertext_len;
}

static pubnub_res_t pn_legacy_encrypt(pubnub_crypto_provider_t* self,
                                      const uint8_t*            input,
                                      size_t                    input_len,
                                      pubnub_encrypted_data_t*  output)
{
    if (NULL == self || NULL == input || NULL == output) {
        return PUBNUB_ERR_CRYPTO;
    }

    pn_openssl_cryptor_state_t* state = (pn_openssl_cryptor_state_t*)self;

    uint8_t iv[PN_AES_BLOCK_SIZE];
    size_t  data_offset = 0;

    if (state->use_random_iv) {
        /* Generate random IV and prepend to output data. */
        if (1 != RAND_bytes(iv, PN_AES_BLOCK_SIZE)) {
            return PUBNUB_ERR_CRYPTO;
        }
        memcpy(output->data, iv, PN_AES_BLOCK_SIZE);
        data_offset = PN_AES_BLOCK_SIZE;
    } else {
        memcpy(iv, pn_legacy_static_iv, PN_AES_BLOCK_SIZE);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        OPENSSL_cleanse(iv, sizeof(iv));
        return PUBNUB_ERR_CRYPTO;
    }

    pubnub_res_t rc        = PUBNUB_ERR_CRYPTO;
    int          out_len   = 0;
    int          final_len = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, state->key, iv)) {
        goto cleanup;
    }

    if (1
        != EVP_EncryptUpdate(
            ctx, output->data + data_offset, &out_len, input, (int)input_len)) {
        goto cleanup;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, output->data + data_offset + out_len, &final_len)) {
        goto cleanup;
    }

    output->data_len     = data_offset + (size_t)out_len + (size_t)final_len;
    output->metadata     = NULL;
    output->metadata_len = 0;

    rc = PUBNUB_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(iv, sizeof(iv));

    return rc;
}

static pubnub_res_t pn_legacy_decrypt(pubnub_crypto_provider_t*      self,
                                      const pubnub_encrypted_data_t* input,
                                      uint8_t*                       output,
                                      size_t*                        output_len)
{
    if (NULL == self || NULL == input || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (0 == input->data_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    pn_openssl_cryptor_state_t* state = (pn_openssl_cryptor_state_t*)self;

    const uint8_t* iv             = NULL;
    const uint8_t* ciphertext     = NULL;
    size_t         ciphertext_len = 0;

    /*
     * IV resolution order per spec section 5.2:
     * 1. Non-NULL metadata of 16 bytes (cross-format interop).
     * 2. Random IV mode: first 16 bytes of data are IV.
     * 3. Static IV mode: use fixed "0123456789012345".
     */
    if (NULL != input->metadata && PN_AES_BLOCK_SIZE == input->metadata_len) {
        iv             = input->metadata;
        ciphertext     = input->data;
        ciphertext_len = input->data_len;
    } else if (state->use_random_iv) {
        if (input->data_len <= PN_AES_BLOCK_SIZE) {
            return PUBNUB_ERR_CRYPTO;
        }
        iv             = input->data;
        ciphertext     = input->data + PN_AES_BLOCK_SIZE;
        ciphertext_len = input->data_len - PN_AES_BLOCK_SIZE;
    } else {
        iv             = pn_legacy_static_iv;
        ciphertext     = input->data;
        ciphertext_len = input->data_len;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return PUBNUB_ERR_CRYPTO;
    }

    pubnub_res_t rc        = PUBNUB_ERR_CRYPTO;
    int          out_len   = 0;
    int          final_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, state->key, iv)) {
        goto cleanup;
    }

    if (1 != EVP_DecryptUpdate(ctx, output, &out_len, ciphertext, (int)ciphertext_len)) {
        goto cleanup;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, output + out_len, &final_len)) {
        goto cleanup;
    }

    *output_len = (size_t)out_len + (size_t)final_len;
    rc          = PUBNUB_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    return rc;
}

void pn_openssl_legacy_populate_vtable(pn_openssl_cryptor_state_t* state,
                                       int use_random_iv)
{
    state->base.identifier[0] = 0;
    state->base.identifier[1] = 0;
    state->base.identifier[2] = 0;
    state->base.identifier[3] = 0;
    state->base.encrypt_size  = pn_legacy_encrypt_size;
    state->base.encrypt       = pn_legacy_encrypt;
    state->base.decrypt       = pn_legacy_decrypt;
    state->base.hmac_sha256   = pn_openssl_hmac_sha256;
    state->base.init          = NULL;
    state->base.deinit        = NULL;
    state->use_random_iv      = use_random_iv;
}

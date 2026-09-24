/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_mbedtls_internal.h"

#include "pubnub/error.h"

#include <mbedtls/cipher.h>

#include <string.h>

/** @brief Static IV used by legacy cryptor when use_random_iv is 0. */
static const uint8_t pn_legacy_static_iv[PN_AES_BLOCK_SIZE] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5'};

static size_t pn_legacy_encrypt_size(pubnub_crypto_provider_t* self,
                                     size_t                    plaintext_len)
{
    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)self;

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

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)self;

    uint8_t iv[PN_AES_BLOCK_SIZE];
    size_t  data_offset = 0;

    if (state->use_random_iv) {
        /* Generate random IV and prepend to output data. */
        if (0 != mbedtls_ctr_drbg_random(&state->drbg, iv, PN_AES_BLOCK_SIZE)) {
            return PUBNUB_ERR_CRYPTO;
        }
        memcpy(output->data, iv, PN_AES_BLOCK_SIZE);
        data_offset = PN_AES_BLOCK_SIZE;
    } else {
        memcpy(iv, pn_legacy_static_iv, PN_AES_BLOCK_SIZE);
    }

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    pubnub_res_t rc = PUBNUB_ERR_CRYPTO;

    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if (NULL == cipher_info) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_setup(&ctx, cipher_info)) {
        goto cleanup;
    }

    if (0
        != mbedtls_cipher_setkey(
            &ctx, state->key, PN_AES_KEY_SIZE * 8, MBEDTLS_ENCRYPT)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_set_iv(&ctx, iv, PN_AES_BLOCK_SIZE)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_reset(&ctx)) {
        goto cleanup;
    }

    size_t out_len   = 0;
    size_t final_len = 0;

    if (0
        != mbedtls_cipher_update(
            &ctx, input, input_len, output->data + data_offset, &out_len)) {
        goto cleanup;
    }

    if (0
        != mbedtls_cipher_finish(
            &ctx, output->data + data_offset + out_len, &final_len)) {
        goto cleanup;
    }

    output->data_len     = data_offset + out_len + final_len;
    output->metadata     = NULL;
    output->metadata_len = 0;

    rc = PUBNUB_OK;

cleanup:
    mbedtls_cipher_free(&ctx);
    pn_mbedtls_secure_zero(iv, sizeof(iv));

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

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)self;

    const uint8_t* iv             = NULL;
    const uint8_t* ciphertext     = NULL;
    size_t         ciphertext_len = 0;

    /*
     * IV resolution order:
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

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    pubnub_res_t rc = PUBNUB_ERR_CRYPTO;

    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if (NULL == cipher_info) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_setup(&ctx, cipher_info)) {
        goto cleanup;
    }

    if (0
        != mbedtls_cipher_setkey(
            &ctx, state->key, PN_AES_KEY_SIZE * 8, MBEDTLS_DECRYPT)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_set_iv(&ctx, iv, PN_AES_BLOCK_SIZE)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_reset(&ctx)) {
        goto cleanup;
    }

    size_t out_len   = 0;
    size_t final_len = 0;

    if (0 != mbedtls_cipher_update(&ctx, ciphertext, ciphertext_len, output, &out_len)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_finish(&ctx, output + out_len, &final_len)) {
        goto cleanup;
    }

    *output_len = out_len + final_len;
    rc          = PUBNUB_OK;

cleanup:
    mbedtls_cipher_free(&ctx);

    return rc;
}

void pn_mbedtls_legacy_populate_vtable(pn_mbedtls_cryptor_state_t* state,
                                       int use_random_iv)
{
    state->base.identifier[0] = 0;
    state->base.identifier[1] = 0;
    state->base.identifier[2] = 0;
    state->base.identifier[3] = 0;
    state->base.encrypt_size  = pn_legacy_encrypt_size;
    state->base.encrypt       = pn_legacy_encrypt;
    state->base.decrypt       = pn_legacy_decrypt;
    state->base.hmac_sha256   = pn_mbedtls_hmac_sha256;
    state->base.init          = NULL;
    state->base.deinit        = NULL;
    state->use_random_iv      = use_random_iv;
}

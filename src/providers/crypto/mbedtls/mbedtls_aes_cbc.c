/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_mbedtls_internal.h"

#include "pubnub/error.h"

#include <mbedtls/cipher.h>

#include <string.h>

static size_t pn_acrh_encrypt_size(pubnub_crypto_provider_t* self,
                                   size_t                    plaintext_len)
{
    (void)self;

    /*
     * AES-256-CBC with PKCS#7 padding: output is always rounded up to
     * the next block boundary. Worst case adds a full block of padding.
     */
    return plaintext_len + PN_AES_BLOCK_SIZE;
}

static pubnub_res_t pn_acrh_encrypt(pubnub_crypto_provider_t* self,
                                    const uint8_t*            input,
                                    size_t                    input_len,
                                    pubnub_encrypted_data_t*  output)
{
    if (NULL == self || NULL == input || NULL == output) {
        return PUBNUB_ERR_CRYPTO;
    }

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)self;

    /* Generate random 16-byte IV via CTR-DRBG. */
    uint8_t iv[PN_AES_BLOCK_SIZE];
    if (0 != mbedtls_ctr_drbg_random(&state->drbg, iv, PN_AES_BLOCK_SIZE)) {
        return PUBNUB_ERR_CRYPTO;
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

    if (0 != mbedtls_cipher_update(&ctx, input, input_len, output->data, &out_len)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_finish(&ctx, output->data + out_len, &final_len)) {
        goto cleanup;
    }

    output->data_len = out_len + final_len;

    /* Metadata = IV (16 bytes). */
    if (NULL != output->metadata) {
        memcpy(output->metadata, iv, PN_AES_BLOCK_SIZE);
        output->metadata_len = PN_AES_BLOCK_SIZE;
    }

    rc = PUBNUB_OK;

cleanup:
    mbedtls_cipher_free(&ctx);
    pn_mbedtls_secure_zero(iv, sizeof(iv));

    return rc;
}

static pubnub_res_t pn_acrh_decrypt(pubnub_crypto_provider_t*      self,
                                    const pubnub_encrypted_data_t* input,
                                    uint8_t*                       output,
                                    size_t*                        output_len)
{
    if (NULL == self || NULL == input || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* IV must come from metadata (16 bytes). */
    if (NULL == input->metadata || PN_AES_BLOCK_SIZE != input->metadata_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (0 == input->data_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    pn_mbedtls_cryptor_state_t* state = (pn_mbedtls_cryptor_state_t*)self;

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

    if (0 != mbedtls_cipher_set_iv(&ctx, input->metadata, PN_AES_BLOCK_SIZE)) {
        goto cleanup;
    }

    if (0 != mbedtls_cipher_reset(&ctx)) {
        goto cleanup;
    }

    size_t out_len   = 0;
    size_t final_len = 0;

    if (0 != mbedtls_cipher_update(&ctx, input->data, input->data_len, output, &out_len)) {
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

void pn_mbedtls_acrh_populate_vtable(pn_mbedtls_cryptor_state_t* state)
{
    state->base.identifier[0] = 'A';
    state->base.identifier[1] = 'C';
    state->base.identifier[2] = 'R';
    state->base.identifier[3] = 'H';
    state->base.encrypt_size  = pn_acrh_encrypt_size;
    state->base.encrypt       = pn_acrh_encrypt;
    state->base.decrypt       = pn_acrh_decrypt;
    state->base.hmac_sha256   = pn_mbedtls_hmac_sha256;
    state->base.init          = NULL;
    state->base.deinit        = NULL;
    state->use_random_iv      = 1;
}

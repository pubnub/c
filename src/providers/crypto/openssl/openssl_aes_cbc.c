/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_openssl_internal.h"

#include "pubnub/error.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

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

    pn_openssl_cryptor_state_t* state = (pn_openssl_cryptor_state_t*)self;

    /* Generate random 16-byte IV. */
    uint8_t iv[PN_AES_BLOCK_SIZE];
    if (1 != RAND_bytes(iv, PN_AES_BLOCK_SIZE)) {
        return PUBNUB_ERR_CRYPTO;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return PUBNUB_ERR_CRYPTO;
    }

    pubnub_res_t rc        = PUBNUB_ERR_CRYPTO;
    int          out_len   = 0;
    int          final_len = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, state->key, iv)) {
        goto cleanup;
    }

    if (1 != EVP_EncryptUpdate(ctx, output->data, &out_len, input, (int)input_len)) {
        goto cleanup;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, output->data + out_len, &final_len)) {
        goto cleanup;
    }

    output->data_len = (size_t)out_len + (size_t)final_len;

    /* Metadata = IV (16 bytes). */
    if (NULL != output->metadata) {
        memcpy(output->metadata, iv, PN_AES_BLOCK_SIZE);
        output->metadata_len = PN_AES_BLOCK_SIZE;
    }

    rc = PUBNUB_OK;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(iv, sizeof(iv));

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

    pn_openssl_cryptor_state_t* state = (pn_openssl_cryptor_state_t*)self;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return PUBNUB_ERR_CRYPTO;
    }

    pubnub_res_t rc        = PUBNUB_ERR_CRYPTO;
    int          out_len   = 0;
    int          final_len = 0;

    if (1
        != EVP_DecryptInit_ex(
            ctx, EVP_aes_256_cbc(), NULL, state->key, input->metadata)) {
        goto cleanup;
    }

    if (1 != EVP_DecryptUpdate(ctx, output, &out_len, input->data, (int)input->data_len)) {
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

void pn_openssl_acrh_populate_vtable(pn_openssl_cryptor_state_t* state)
{
    state->base.identifier[0] = 'A';
    state->base.identifier[1] = 'C';
    state->base.identifier[2] = 'R';
    state->base.identifier[3] = 'H';
    state->base.encrypt_size  = pn_acrh_encrypt_size;
    state->base.encrypt       = pn_acrh_encrypt;
    state->base.decrypt       = pn_acrh_decrypt;
    state->base.hmac_sha256   = pn_openssl_hmac_sha256;
    state->base.init          = NULL;
    state->base.deinit        = NULL;
    state->use_random_iv      = 1;
}

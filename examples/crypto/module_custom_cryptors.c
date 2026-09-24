/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/module_custom_cryptors.c
 * @brief Assemble a crypto module from cryptors you create yourself, and
 *        implement the crypto provider vtable.
 *
 * Two snippets live here:
 *
 *   cryptoModuleCustomCryptors -- pubnub_crypto_module_create() with an
 *       explicit default cryptor plus a fallback array. Unlike the named
 *       factories, this module does NOT own the cryptors, so the caller
 *       destroys them after destroying the module.
 *
 *   cryptoCustomCryptorVtable -- a minimal pubnub_crypto_provider_t
 *       implementation. The XOR "cipher" below is a placeholder for the
 *       vtable shape only. It is NOT secure and must never ship.
 *
 * Build: cmake --build build/full --target example_crypto_module_custom_cryptors
 * Run:   ./build/full/examples/crypto/example_crypto_module_custom_cryptors
 */

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// snippet.cryptoCustomCryptorVtable

/* Extend pubnub_crypto_provider_t by making the vtable the first member,
 * then cast `self` back to recover your own state. */
typedef struct demo_cryptor {
    pubnub_crypto_provider_t base;
    uint8_t                  key;
} demo_cryptor_t;

/* Worst-case output size for a given plaintext length. The SDK calls this
 * before encrypt() so it can size buffers without allocating. */
static size_t demo_encrypt_size(pubnub_crypto_provider_t* self, size_t plaintext_len)
{
    (void)self;
    return plaintext_len;
}

static pubnub_res_t demo_encrypt(pubnub_crypto_provider_t* self,
                                 const uint8_t*            input,
                                 size_t                    input_len,
                                 pubnub_encrypted_data_t*  output)
{
    demo_cryptor_t* me = (demo_cryptor_t*)self;

    if (NULL == output || NULL == output->data || output->data_len < input_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < input_len; i++) {
        output->data[i] = (uint8_t)(input[i] ^ me->key);
    }
    /* Report what was actually written. Set metadata_len when the
     * algorithm emits an IV or nonce; this one does not. */
    output->data_len     = input_len;
    output->metadata_len = 0;
    return PUBNUB_OK;
}

static pubnub_res_t demo_decrypt(pubnub_crypto_provider_t*      self,
                                 const pubnub_encrypted_data_t* input,
                                 uint8_t*                       output,
                                 size_t*                        output_len)
{
    demo_cryptor_t* me = (demo_cryptor_t*)self;

    if (NULL == input || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    /* output_len is in/out: capacity on entry, bytes written on exit. */
    if (*output_len < input->data_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < input->data_len; i++) {
        output[i] = (uint8_t)(input->data[i] ^ me->key);
    }
    *output_len = input->data_len;
    return PUBNUB_OK;
}

/* The 4-byte identifier is how the module picks a fallback cryptor on
 * decrypt, so it must be unique across every cryptor you register.
 * encrypt_size, encrypt, and decrypt are required. hmac_sha256 is only
 * needed when this cryptor also signs PAM requests, and init/deinit are
 * optional per-context lifecycle hooks. */
static demo_cryptor_t s_demo_cryptor = {
    .base.identifier   = {'D', 'E', 'M', 'O'},
    .base.encrypt_size = demo_encrypt_size,
    .base.encrypt      = demo_encrypt,
    .base.decrypt      = demo_decrypt,
    .base.hmac_sha256  = NULL,
    .base.init         = NULL,
    .base.deinit       = NULL,
    .key               = 0x5AU,
};

// snippet.end

// snippet.cryptoModuleCustomCryptors

int main(void)
{
    /* 1. Build the cryptors yourself. This reproduces the
     * ACRH-default / legacy-fallback pairing that
     * pubnub_crypto_module_aes_cbc() creates automatically, and adds a
     * third cryptor of our own. */
    pubnub_crypto_provider_t* acrh =
        pubnub_cryptor_aes_cbc_create("my-cipher-key", NULL);
    if (NULL == acrh) {
        printf("Failed to create the ACRH cryptor\n");
        return EXIT_FAILURE;
    }

    pubnub_crypto_provider_t* legacy =
        pubnub_cryptor_legacy_create("my-cipher-key", 1, NULL);
    if (NULL == legacy) {
        printf("Failed to create the legacy cryptor\n");
        pubnub_cryptor_destroy(acrh);
        return EXIT_FAILURE;
    }

    /* 2. `others` is consulted on decrypt only, matched by identifier.
     * Its length must not exceed PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS
     * or the factory returns NULL. */
    pubnub_crypto_provider_t* fallbacks[] = {legacy, &s_demo_cryptor.base};

    pubnub_crypto_module_t* module = pubnub_crypto_module_create(
        acrh, fallbacks, sizeof(fallbacks) / sizeof(fallbacks[0]), NULL);
    if (NULL == module) {
        printf("Failed to create the crypto module\n");
        pubnub_cryptor_destroy(legacy);
        pubnub_cryptor_destroy(acrh);
        return EXIT_FAILURE;
    }

    /* 3. Use it exactly like a factory-built module: attach it to
     * pubnub_config_t::crypto_module, or call the encrypt/decrypt
     * helpers directly. */
    const char*  plaintext  = "{\"text\":\"custom cryptor set\"}";
    uint8_t*     cipher     = NULL;
    size_t       cipher_len = 0;
    pubnub_res_t rc         = pubnub_crypto_module_encrypt(
        module, (const uint8_t*)plaintext, strlen(plaintext), &cipher, &cipher_len);
    if (PUBNUB_OK == rc) {
        printf("Encrypted with the default cryptor: %zu bytes\n", cipher_len);
        pubnub_crypto_module_free(module, cipher);
    } else {
        printf("Encrypt failed: %s\n", pubnub_res_str(rc));
    }

    /* 4. Teardown order matters. pubnub_crypto_module_create() borrows
     * the cryptors, so destroy the module first, then each cryptor.
     * s_demo_cryptor is static storage and needs no destructor. */
    pubnub_crypto_module_destroy(module);
    pubnub_cryptor_destroy(legacy);
    pubnub_cryptor_destroy(acrh);
    return EXIT_SUCCESS;
}

// snippet.end

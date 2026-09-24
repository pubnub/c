/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/module_legacy.c
 * @brief Create a legacy-default crypto module and round-trip a payload.
 *
 * The legacy module encrypts with the pre-ACRH cryptor (identifier
 * {0,0,0,0}) so that older SDKs and 128-bit-key deployments can still
 * read the ciphertext. It keeps an ACRH fallback for decryption, so it
 * reads data produced by both generations.
 *
 * Use this only for backwards compatibility. New deployments should use
 * pubnub_crypto_module_aes_cbc(). See migrate_legacy.c for the
 * transition path.
 *
 * Build: cmake --build build/full --target example_crypto_module_legacy
 * Run:   ./build/full/examples/crypto/example_crypto_module_legacy
 */

// snippet.cryptoModuleLegacy

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char* plaintext = "{\"text\":\"legacy payload\"}";

    /* 1. Create a legacy-default module. use_random_iv = 1 prepends a
     * fresh 16-byte IV to every ciphertext; 0 uses the static IV
     * "0123456789012345", which older c-core releases expect. */
    pubnub_crypto_module_t* legacy =
        pubnub_crypto_module_legacy("my-cipher-key", 1, NULL);
    if (NULL == legacy) {
        printf("Failed to create legacy crypto module\n");
        return EXIT_FAILURE;
    }

    /* 2. Encrypt. Legacy output carries no PNED header — it is raw
     * ciphertext, optionally prefixed with the random IV. */
    uint8_t*     cipher     = NULL;
    size_t       cipher_len = 0;
    pubnub_res_t rc         = pubnub_crypto_module_encrypt(
        legacy, (const uint8_t*)plaintext, strlen(plaintext), &cipher, &cipher_len);
    if (PUBNUB_OK != rc) {
        printf("Encrypt failed: %s\n", pubnub_res_str(rc));
        pubnub_crypto_module_destroy(legacy);
        return EXIT_FAILURE;
    }
    printf("Encrypted %zu bytes into %zu bytes\n", strlen(plaintext), cipher_len);

    /* 3. Decrypt. The module tries its default legacy cryptor first,
     * then the ACRH fallback, so it also reads data written by
     * pubnub_crypto_module_aes_cbc(). */
    uint8_t* plain     = NULL;
    size_t   plain_len = 0;
    rc = pubnub_crypto_module_decrypt(legacy, cipher, cipher_len, &plain, &plain_len);
    if (PUBNUB_OK == rc) {
        printf("Decrypted: %.*s\n", (int)plain_len, (const char*)plain);
    } else {
        printf("Decrypt failed: %s\n", pubnub_res_str(rc));
    }

    /* 4. Free both buffers through the module that produced them, then
     * destroy the module. The factory-created cryptors are destroyed
     * with it and their key material is zeroed. */
    pubnub_crypto_module_free(legacy, plain);
    pubnub_crypto_module_free(legacy, cipher);
    pubnub_crypto_module_destroy(legacy);
    return EXIT_SUCCESS;
}

// snippet.end

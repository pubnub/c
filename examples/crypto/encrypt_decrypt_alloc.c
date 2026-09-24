/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/encrypt_decrypt_alloc.c
 * @brief Encrypt and decrypt into SDK-allocated buffers.
 *
 * The allocating variants are the convenient choice on hosted targets:
 * the module sizes the output for you. Every buffer they hand back must
 * be returned with pubnub_crypto_module_free(), using the same module
 * that produced it, because the module's allocator owns the memory.
 *
 * Build: cmake --build build/full --target example_crypto_encrypt_decrypt_alloc
 * Run:   ./build/full/examples/crypto/example_crypto_encrypt_decrypt_alloc
 */

// snippet.cryptoEncryptDecryptAlloc

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char*  plaintext = "{\"text\":\"allocated round trip\"}";
    const size_t plain_len = strlen(plaintext);

    pubnub_crypto_module_t* crypto =
        pubnub_crypto_module_aes_cbc("my-cipher-key", 1, NULL);
    if (NULL == crypto) {
        printf("Failed to create crypto module\n");
        return EXIT_FAILURE;
    }

    /* 1. Encrypt. The module allocates the output and reports its length.
     * No encrypt_size() call is needed. */
    uint8_t*     cipher     = NULL;
    size_t       cipher_len = 0;
    pubnub_res_t rc         = pubnub_crypto_module_encrypt(
        crypto, (const uint8_t*)plaintext, plain_len, &cipher, &cipher_len);
    if (PUBNUB_OK != rc) {
        /* PUBNUB_ERR_OUT_OF_MEMORY or PUBNUB_ERR_CRYPTO. */
        printf("Encrypt failed: %s\n", pubnub_res_str(rc));
        pubnub_crypto_module_destroy(crypto);
        return EXIT_FAILURE;
    }
    printf("Encrypted %zu bytes into %zu bytes\n", plain_len, cipher_len);

    /* 2. Decrypt. The blob carries the PNED header, so the module knows
     * which cryptor produced it and picks the matching one. */
    uint8_t* plain   = NULL;
    size_t   out_len = 0;
    rc = pubnub_crypto_module_decrypt(crypto, cipher, cipher_len, &plain, &out_len);
    if (PUBNUB_OK == rc) {
        /* The plaintext is not NUL-terminated — always print or copy it
         * using out_len. */
        printf("Round trip: %.*s\n", (int)out_len, (const char*)plain);
    } else {
        printf("Decrypt failed: %s\n", pubnub_res_str(rc));
    }

    /* 3. Free through the module, not free(). Both calls are NULL-safe,
     * so they are correct even on the decrypt-failure path. */
    pubnub_crypto_module_free(crypto, plain);
    pubnub_crypto_module_free(crypto, cipher);
    pubnub_crypto_module_destroy(crypto);
    return EXIT_SUCCESS;
}

// snippet.end

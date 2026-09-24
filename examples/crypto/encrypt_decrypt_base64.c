/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/encrypt_decrypt_base64.c
 * @brief Encrypt to base64 text and decrypt back.
 *
 * Use the base64 pair when the ciphertext has to travel through a
 * text-only channel: a JSON string field, an HTTP header, a log line, or
 * App Context custom metadata. The output is a NUL-terminated C string.
 *
 * Build: cmake --build build/full --target example_crypto_encrypt_decrypt_base64
 * Run:   ./build/full/examples/crypto/example_crypto_encrypt_decrypt_base64
 */

// snippet.cryptoEncryptDecryptBase64

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char*  plaintext = "{\"text\":\"base64 friendly\"}";
    const size_t plain_len = strlen(plaintext);

    pubnub_crypto_module_t* crypto =
        pubnub_crypto_module_aes_cbc("my-cipher-key", 1, NULL);
    if (NULL == crypto) {
        printf("Failed to create crypto module\n");
        return EXIT_FAILURE;
    }

    /* 1. Optional: pre-flight the size when you need to budget memory.
     * The value includes the NUL terminator. */
    printf("base64 worst case for %zu bytes: %zu bytes\n",
           plain_len,
           pubnub_crypto_module_encrypted_base64_size(crypto, plain_len));

    /* 2. Encrypt and base64-encode in one step. */
    char*        b64     = NULL;
    size_t       b64_len = 0;
    pubnub_res_t rc      = pubnub_crypto_module_encrypt_to_base64(
        crypto, (const uint8_t*)plaintext, plain_len, &b64, &b64_len);
    if (PUBNUB_OK != rc) {
        printf("Encrypt failed: %s\n", pubnub_res_str(rc));
        pubnub_crypto_module_destroy(crypto);
        return EXIT_FAILURE;
    }
    printf("base64 ciphertext (%zu chars): %s\n", b64_len, b64);

    /* 3. Decode and decrypt in one step. */
    uint8_t* plain   = NULL;
    size_t   out_len = 0;
    rc               = pubnub_crypto_module_decrypt_from_base64(
        crypto, b64, b64_len, &plain, &out_len);
    if (PUBNUB_OK == rc) {
        printf("Round trip: %.*s\n", (int)out_len, (const char*)plain);
    } else {
        printf("Decrypt failed: %s\n", pubnub_res_str(rc));
    }

    /* 4. Both outputs came from the module's allocator. */
    pubnub_crypto_module_free(crypto, plain);
    pubnub_crypto_module_free(crypto, b64);
    pubnub_crypto_module_destroy(crypto);
    return EXIT_SUCCESS;
}

// snippet.end

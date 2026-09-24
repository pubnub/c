/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/encrypt_decrypt_buf.c
 * @brief Encrypt and decrypt into caller-owned fixed-size buffers.
 *
 * The _buf variants never allocate, which makes them the ones to use on
 * no-heap targets. You size the buffer up front with
 * pubnub_crypto_module_encrypt_size() and the module writes into it.
 *
 * Build: cmake --build build/full --target example_crypto_encrypt_decrypt_buf
 * Run:   ./build/full/examples/crypto/example_crypto_encrypt_decrypt_buf
 */

// snippet.cryptoEncryptDecryptBuf

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Worst-case ciphertext for this example's plaintext. On a real embedded
 * target, size this from pubnub_crypto_module_encrypt_size() for your
 * largest expected payload and assert it at compile time. */
#define CIPHER_CAP 256

int main(void)
{
    const char*  plaintext = "{\"text\":\"no allocation anywhere\"}";
    const size_t plain_len = strlen(plaintext);

    pubnub_crypto_module_t* crypto =
        pubnub_crypto_module_aes_cbc("my-cipher-key", 1, NULL);
    if (NULL == crypto) {
        printf("Failed to create crypto module\n");
        return EXIT_FAILURE;
    }

    /* 1. Ask how much room the ciphertext needs. This covers the PNED
     * header, the algorithm metadata (IV), and the padded ciphertext. */
    const size_t needed = pubnub_crypto_module_encrypt_size(crypto, plain_len);
    printf("%zu plaintext bytes need %zu ciphertext bytes\n", plain_len, needed);
    if (0 == needed || needed > CIPHER_CAP) {
        printf("CIPHER_CAP is too small for this payload\n");
        pubnub_crypto_module_destroy(crypto);
        return EXIT_FAILURE;
    }

    /* 2. Encrypt into the caller's buffer. output_len receives the
     * number of bytes actually written, which is <= needed. */
    uint8_t      cipher[CIPHER_CAP];
    size_t       cipher_len = 0;
    pubnub_res_t rc         = pubnub_crypto_module_encrypt_buf(
        crypto, (const uint8_t*)plaintext, plain_len, cipher, sizeof(cipher), &cipher_len);
    if (PUBNUB_OK != rc) {
        /* PUBNUB_ERR_BUFFER_TOO_SMALL means grow the buffer.
         * PUBNUB_ERR_CRYPTO means the backend failed. */
        printf("Encrypt failed: %s\n", pubnub_res_str(rc));
        pubnub_crypto_module_destroy(crypto);
        return EXIT_FAILURE;
    }
    printf("Wrote %zu ciphertext bytes\n", cipher_len);

    /* 3. Decrypt back. The decrypt buffer must be at least as large as
     * the ciphertext, so reusing the ciphertext length as the capacity
     * is always safe. */
    uint8_t plain[CIPHER_CAP];
    size_t  out_len = 0;
    rc              = pubnub_crypto_module_decrypt_buf(
        crypto, cipher, cipher_len, plain, cipher_len, &out_len);
    if (PUBNUB_OK == rc) {
        printf("Round trip: %.*s\n", (int)out_len, (const char*)plain);
    } else {
        printf("Decrypt failed: %s\n", pubnub_res_str(rc));
    }

    /* 4. Nothing to free — the buffers are ours. */
    pubnub_crypto_module_destroy(crypto);
    return EXIT_SUCCESS;
}

// snippet.end

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/migrate_legacy.c
 * @brief Move a deployment from the legacy cryptor to AES-CBC (ACRH)
 *        without re-encrypting stored data.
 *
 * Encryption always uses the module's default cryptor. Decryption may
 * use the default cryptor or any of its fallbacks, matched on the 4-byte
 * identifier. Both named factories pair the two generations
 * automatically, so an ACRH-default module still reads every message a
 * legacy-default deployment wrote under the same cipher key.
 *
 * Build: cmake --build build/full --target example_crypto_migrate_legacy
 * Run:   ./build/full/examples/crypto/example_crypto_migrate_legacy
 */

// snippet.cryptoMigrateLegacy

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char* cipher_key = "my-cipher-key";
    const char* payload    = "message stored under the legacy default";
    int         status     = EXIT_FAILURE;

    uint8_t* stored        = NULL;
    size_t   stored_len    = 0;
    uint8_t* recovered     = NULL;
    size_t   recovered_len = 0;

    /* 1. The old deployment: legacy is the default cryptor, so this is
     * what produced the ciphertext already sitting in Message
     * Persistence, in a file, or in App Context custom metadata. */
    pubnub_crypto_module_t* old_module =
        pubnub_crypto_module_legacy(cipher_key, 1, NULL);
    if (NULL == old_module) {
        printf("Failed to create the legacy module\n");
        return EXIT_FAILURE;
    }

    pubnub_res_t rc = pubnub_crypto_module_encrypt(
        old_module, (const uint8_t*)payload, strlen(payload), &stored, &stored_len);
    if (PUBNUB_OK != rc) {
        printf("Legacy encrypt failed: %s\n", pubnub_res_str(rc));
        goto cleanup_old;
    }
    printf("Legacy ciphertext: %zu bytes\n", stored_len);

    /* 2. The new deployment: ACRH is now the default cryptor. New
     * messages are written in the ACRH format from here on. */
    pubnub_crypto_module_t* new_module =
        pubnub_crypto_module_aes_cbc(cipher_key, 1, NULL);
    if (NULL == new_module) {
        printf("Failed to create the AES-CBC module\n");
        goto cleanup_old;
    }

    /* 3. The new module reads the old bytes. Legacy ciphertext carries
     * no PNED header, so the module resolves it to the cryptor with the
     * all-zero legacy identifier, which the factory registered as a
     * fallback. Nothing had to be re-encrypted. */
    rc = pubnub_crypto_module_decrypt(
        new_module, stored, stored_len, &recovered, &recovered_len);
    if (PUBNUB_OK == rc) {
        printf("Recovered with the ACRH default: %.*s\n",
               (int)recovered_len,
               (const char*)recovered);
        status = EXIT_SUCCESS;
    } else {
        /* PUBNUB_ERR_CRYPTO here means no registered cryptor claimed the
         * blob, which in practice means a cipher-key mismatch. */
        printf("Decrypt failed: %s\n", pubnub_res_str(rc));
    }

    /* 4. Free each buffer through the module that produced it. */
    pubnub_crypto_module_free(new_module, recovered);
    pubnub_crypto_module_destroy(new_module);
cleanup_old:
    pubnub_crypto_module_free(old_module, stored);
    pubnub_crypto_module_destroy(old_module);
    return status;
}

// snippet.end

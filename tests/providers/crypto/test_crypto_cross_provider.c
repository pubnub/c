/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Cross-provider interoperability tests.
 *
 * Links both OpenSSL and mbedTLS OBJECT libraries simultaneously.
 * Uses backend-prefixed factory functions to create instances of each
 * and verifies encrypt/decrypt interop (OpenSSL encrypt -> mbedTLS
 * decrypt, and vice versa).
 */

#include "openssl_factories.h"
#include "mbedtls_factories.h"

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

#include "support/test_allocator.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#define TEST_CIPHER_KEY "enigma"
#define TEST_PLAINTEXT  "Hello, cross-provider PubNub crypto!"
#define BUF_SIZE        512

static void test_openssl_acrh_encrypt_mbedtls_decrypt(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    ossl =
        pn_openssl_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    pubnub_crypto_provider_t* mbed =
        pn_mbedtls_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    assert_non_null(ossl);
    assert_non_null(mbed);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    uint8_t                 data_buf[BUF_SIZE];
    uint8_t                 meta_buf[16];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = meta_buf,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, ossl->encrypt(ossl, plaintext, plaintext_len, &enc));

    uint8_t dec_buf[BUF_SIZE];
    size_t  dec_len = sizeof(dec_buf);
    assert_int_equal(PUBNUB_OK, mbed->decrypt(mbed, &enc, dec_buf, &dec_len));
    assert_int_equal(plaintext_len, dec_len);
    assert_memory_equal(plaintext, dec_buf, dec_len);

    pn_openssl_cryptor_destroy(ossl);
    pn_mbedtls_cryptor_destroy(mbed);
}

static void test_mbedtls_acrh_encrypt_openssl_decrypt(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    mbed =
        pn_mbedtls_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    pubnub_crypto_provider_t* ossl =
        pn_openssl_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    assert_non_null(mbed);
    assert_non_null(ossl);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    uint8_t                 data_buf[BUF_SIZE];
    uint8_t                 meta_buf[16];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = meta_buf,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, mbed->encrypt(mbed, plaintext, plaintext_len, &enc));

    uint8_t dec_buf[BUF_SIZE];
    size_t  dec_len = sizeof(dec_buf);
    assert_int_equal(PUBNUB_OK, ossl->decrypt(ossl, &enc, dec_buf, &dec_len));
    assert_int_equal(plaintext_len, dec_len);
    assert_memory_equal(plaintext, dec_buf, dec_len);

    pn_mbedtls_cryptor_destroy(mbed);
    pn_openssl_cryptor_destroy(ossl);
}

static void test_openssl_legacy_random_encrypt_mbedtls_decrypt(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    ossl =
        pn_openssl_cryptor_legacy_create(TEST_CIPHER_KEY, 1, alloc);
    pubnub_crypto_provider_t* mbed =
        pn_mbedtls_cryptor_legacy_create(TEST_CIPHER_KEY, 1, alloc);
    assert_non_null(ossl);
    assert_non_null(mbed);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    uint8_t                 data_buf[BUF_SIZE];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = NULL,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, ossl->encrypt(ossl, plaintext, plaintext_len, &enc));

    uint8_t dec_buf[BUF_SIZE];
    size_t  dec_len = sizeof(dec_buf);
    assert_int_equal(PUBNUB_OK, mbed->decrypt(mbed, &enc, dec_buf, &dec_len));
    assert_int_equal(plaintext_len, dec_len);
    assert_memory_equal(plaintext, dec_buf, dec_len);

    pn_openssl_cryptor_destroy(ossl);
    pn_mbedtls_cryptor_destroy(mbed);
}

static void test_mbedtls_legacy_random_encrypt_openssl_decrypt(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    mbed =
        pn_mbedtls_cryptor_legacy_create(TEST_CIPHER_KEY, 1, alloc);
    pubnub_crypto_provider_t* ossl =
        pn_openssl_cryptor_legacy_create(TEST_CIPHER_KEY, 1, alloc);
    assert_non_null(mbed);
    assert_non_null(ossl);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    uint8_t                 data_buf[BUF_SIZE];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = NULL,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, mbed->encrypt(mbed, plaintext, plaintext_len, &enc));

    uint8_t dec_buf[BUF_SIZE];
    size_t  dec_len = sizeof(dec_buf);
    assert_int_equal(PUBNUB_OK, ossl->decrypt(ossl, &enc, dec_buf, &dec_len));
    assert_int_equal(plaintext_len, dec_len);
    assert_memory_equal(plaintext, dec_buf, dec_len);

    pn_mbedtls_cryptor_destroy(mbed);
    pn_openssl_cryptor_destroy(ossl);
}

static void test_openssl_legacy_static_encrypt_mbedtls_decrypt(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    ossl =
        pn_openssl_cryptor_legacy_create(TEST_CIPHER_KEY, 0, alloc);
    pubnub_crypto_provider_t* mbed =
        pn_mbedtls_cryptor_legacy_create(TEST_CIPHER_KEY, 0, alloc);
    assert_non_null(ossl);
    assert_non_null(mbed);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    uint8_t                 data_buf[BUF_SIZE];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = NULL,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, ossl->encrypt(ossl, plaintext, plaintext_len, &enc));

    uint8_t dec_buf[BUF_SIZE];
    size_t  dec_len = sizeof(dec_buf);
    assert_int_equal(PUBNUB_OK, mbed->decrypt(mbed, &enc, dec_buf, &dec_len));
    assert_int_equal(plaintext_len, dec_len);
    assert_memory_equal(plaintext, dec_buf, dec_len);

    pn_openssl_cryptor_destroy(ossl);
    pn_mbedtls_cryptor_destroy(mbed);
}

static void test_mbedtls_legacy_static_encrypt_openssl_decrypt(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    mbed =
        pn_mbedtls_cryptor_legacy_create(TEST_CIPHER_KEY, 0, alloc);
    pubnub_crypto_provider_t* ossl =
        pn_openssl_cryptor_legacy_create(TEST_CIPHER_KEY, 0, alloc);
    assert_non_null(mbed);
    assert_non_null(ossl);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    uint8_t                 data_buf[BUF_SIZE];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = NULL,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, mbed->encrypt(mbed, plaintext, plaintext_len, &enc));

    uint8_t dec_buf[BUF_SIZE];
    size_t  dec_len = sizeof(dec_buf);
    assert_int_equal(PUBNUB_OK, ossl->decrypt(ossl, &enc, dec_buf, &dec_len));
    assert_int_equal(plaintext_len, dec_len);
    assert_memory_equal(plaintext, dec_buf, dec_len);

    pn_mbedtls_cryptor_destroy(mbed);
    pn_openssl_cryptor_destroy(ossl);
}

static void test_hmac_sha256_parity(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    ossl =
        pn_openssl_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    pubnub_crypto_provider_t* mbed =
        pn_mbedtls_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    assert_non_null(ossl);
    assert_non_null(mbed);

    const uint8_t key[]  = "signing-key";
    const uint8_t data[] = "data-to-sign";

    uint8_t ossl_out[32];
    size_t  ossl_len = sizeof(ossl_out);
    uint8_t mbed_out[32];
    size_t  mbed_len = sizeof(mbed_out);

    assert_int_equal(PUBNUB_OK,
                     ossl->hmac_sha256(ossl,
                                       key,
                                       strlen((const char*)key),
                                       data,
                                       strlen((const char*)data),
                                       ossl_out,
                                       &ossl_len));
    assert_int_equal(PUBNUB_OK,
                     mbed->hmac_sha256(mbed,
                                       key,
                                       strlen((const char*)key),
                                       data,
                                       strlen((const char*)data),
                                       mbed_out,
                                       &mbed_len));

    assert_int_equal(32, ossl_len);
    assert_int_equal(32, mbed_len);
    assert_memory_equal(ossl_out, mbed_out, 32);

    pn_openssl_cryptor_destroy(ossl);
    pn_mbedtls_cryptor_destroy(mbed);
}

static void test_key_derivation_parity(void** state)
{
    (void)state;

    /*
     * Both backends derive the same key from the same cipher_key.
     * Verify by encrypting with a static IV (legacy, use_random_iv=0)
     * and comparing ciphertext byte-for-byte.
     */
    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    ossl =
        pn_openssl_cryptor_legacy_create(TEST_CIPHER_KEY, 0, alloc);
    pubnub_crypto_provider_t* mbed =
        pn_mbedtls_cryptor_legacy_create(TEST_CIPHER_KEY, 0, alloc);
    assert_non_null(ossl);
    assert_non_null(mbed);

    const uint8_t* plaintext     = (const uint8_t*)"key-derivation-test";
    size_t         plaintext_len = strlen((const char*)plaintext);

    uint8_t                 data1[BUF_SIZE];
    pubnub_encrypted_data_t enc1 = {
        .data         = data1,
        .data_len     = 0,
        .metadata     = NULL,
        .metadata_len = 0,
    };

    uint8_t                 data2[BUF_SIZE];
    pubnub_encrypted_data_t enc2 = {
        .data         = data2,
        .data_len     = 0,
        .metadata     = NULL,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK,
                     ossl->encrypt(ossl, plaintext, plaintext_len, &enc1));
    assert_int_equal(PUBNUB_OK,
                     mbed->encrypt(mbed, plaintext, plaintext_len, &enc2));

    /* Same key + same IV + same plaintext = identical ciphertext. */
    assert_int_equal(enc1.data_len, enc2.data_len);
    assert_memory_equal(enc1.data, enc2.data, enc1.data_len);

    pn_openssl_cryptor_destroy(ossl);
    pn_mbedtls_cryptor_destroy(mbed);
}

static void test_cross_ciphertext_opacity(void** state)
{
    (void)state;

    pubnub_allocator_provider_t* alloc = pn_test_allocator();
    pubnub_crypto_provider_t*    ossl =
        pn_openssl_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    pubnub_crypto_provider_t* mbed =
        pn_mbedtls_cryptor_aes_cbc_create(TEST_CIPHER_KEY, alloc);
    assert_non_null(ossl);
    assert_non_null(mbed);

    const uint8_t* plaintext     = (const uint8_t*)TEST_PLAINTEXT;
    size_t         plaintext_len = strlen(TEST_PLAINTEXT);

    /* Encrypt with OpenSSL, scan ciphertext for plaintext fragments. */
    uint8_t                 data_buf[BUF_SIZE];
    uint8_t                 meta_buf[16];
    pubnub_encrypted_data_t enc = {
        .data         = data_buf,
        .data_len     = 0,
        .metadata     = meta_buf,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK, ossl->encrypt(ossl, plaintext, plaintext_len, &enc));

    for (size_t i = 0; i + 4 <= plaintext_len; ++i) {
        for (size_t j = 0; j + 4 <= enc.data_len; ++j) {
            assert_true(0 != memcmp(plaintext + i, enc.data + j, 4));
        }
    }

    /* Encrypt with mbedTLS, scan ciphertext. */
    uint8_t                 data_buf2[BUF_SIZE];
    uint8_t                 meta_buf2[16];
    pubnub_encrypted_data_t enc2 = {
        .data         = data_buf2,
        .data_len     = 0,
        .metadata     = meta_buf2,
        .metadata_len = 0,
    };

    assert_int_equal(PUBNUB_OK,
                     mbed->encrypt(mbed, plaintext, plaintext_len, &enc2));

    for (size_t i = 0; i + 4 <= plaintext_len; ++i) {
        for (size_t j = 0; j + 4 <= enc2.data_len; ++j) {
            assert_true(0 != memcmp(plaintext + i, enc2.data + j, 4));
        }
    }

    pn_openssl_cryptor_destroy(ossl);
    pn_mbedtls_cryptor_destroy(mbed);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_openssl_acrh_encrypt_mbedtls_decrypt),
        cmocka_unit_test(test_mbedtls_acrh_encrypt_openssl_decrypt),
        cmocka_unit_test(test_openssl_legacy_random_encrypt_mbedtls_decrypt),
        cmocka_unit_test(test_mbedtls_legacy_random_encrypt_openssl_decrypt),
        cmocka_unit_test(test_openssl_legacy_static_encrypt_mbedtls_decrypt),
        cmocka_unit_test(test_mbedtls_legacy_static_encrypt_openssl_decrypt),
        cmocka_unit_test(test_hmac_sha256_parity),
        cmocka_unit_test(test_key_derivation_parity),
        cmocka_unit_test(test_cross_ciphertext_opacity),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

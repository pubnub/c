/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/error.h"
#include "pubnub/features/crypto.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

static void* stub_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void stub_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_alloc = {
    .alloc       = stub_alloc,
    .realloc     = NULL,
    .free        = stub_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static const char* const TEST_KEY = "enigma";

static const uint8_t TEST_PLAINTEXT[] = "Hello, PubNub crypto module!";
#define TEST_PLAINTEXT_LEN (sizeof(TEST_PLAINTEXT) - 1)

static void module_aes_cbc_create_destroy(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    assert_non_null(module);

    pubnub_crypto_provider_t* def = pubnub_crypto_module_default_cryptor(module);
    assert_non_null(def);

    /* ACRH identifier is "ACRH" (0x41 0x43 0x52 0x48). */
    assert_int_equal(def->identifier[0], 0x41);
    assert_int_equal(def->identifier[1], 0x43);
    assert_int_equal(def->identifier[2], 0x52);
    assert_int_equal(def->identifier[3], 0x48);

    pubnub_crypto_module_destroy(module);
}

static void module_legacy_create_destroy(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_legacy(TEST_KEY, 1, &s_alloc);
    assert_non_null(module);

    pubnub_crypto_provider_t* def = pubnub_crypto_module_default_cryptor(module);
    assert_non_null(def);

    /* Legacy identifier is {0, 0, 0, 0}. */
    assert_int_equal(def->identifier[0], 0);
    assert_int_equal(def->identifier[1], 0);
    assert_int_equal(def->identifier[2], 0);
    assert_int_equal(def->identifier[3], 0);

    pubnub_crypto_module_destroy(module);
}

static void module_encrypt_decrypt_roundtrip_acrh(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    assert_non_null(module);

    size_t enc_size = pubnub_crypto_module_encrypt_size(module, TEST_PLAINTEXT_LEN);
    assert_true(enc_size > 0);

    uint8_t* enc_buf = (uint8_t*)malloc(enc_size);
    assert_non_null(enc_buf);

    size_t       enc_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt_buf(
        module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, enc_buf, enc_size, &enc_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_true(enc_len > 0);
    assert_true(enc_len <= enc_size);

    /* Encrypted output must differ from plaintext. */
    assert_true(enc_len != TEST_PLAINTEXT_LEN
                || 0 != memcmp(enc_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN));

    /* Decrypt. */
    uint8_t dec_buf[256];
    size_t  dec_len = 0;
    res             = pubnub_crypto_module_decrypt_buf(
        module, enc_buf, enc_len, dec_buf, sizeof(dec_buf), &dec_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(dec_len, TEST_PLAINTEXT_LEN);
    assert_memory_equal(dec_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN);

    free(enc_buf);
    pubnub_crypto_module_destroy(module);
}

static void module_encrypt_decrypt_roundtrip_legacy_random_iv(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_legacy(TEST_KEY, 1, &s_alloc);
    assert_non_null(module);

    size_t enc_size = pubnub_crypto_module_encrypt_size(module, TEST_PLAINTEXT_LEN);
    assert_true(enc_size > 0);

    uint8_t* enc_buf = (uint8_t*)malloc(enc_size);
    assert_non_null(enc_buf);

    size_t       enc_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt_buf(
        module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, enc_buf, enc_size, &enc_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_true(enc_len > 0);

    uint8_t dec_buf[256];
    size_t  dec_len = 0;
    res             = pubnub_crypto_module_decrypt_buf(
        module, enc_buf, enc_len, dec_buf, sizeof(dec_buf), &dec_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(dec_len, TEST_PLAINTEXT_LEN);
    assert_memory_equal(dec_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN);

    free(enc_buf);
    pubnub_crypto_module_destroy(module);
}

static void module_encrypt_decrypt_roundtrip_legacy_static_iv(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_legacy(TEST_KEY, 0, &s_alloc);
    assert_non_null(module);

    size_t enc_size = pubnub_crypto_module_encrypt_size(module, TEST_PLAINTEXT_LEN);
    assert_true(enc_size > 0);

    uint8_t* enc_buf = (uint8_t*)malloc(enc_size);
    assert_non_null(enc_buf);

    size_t       enc_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt_buf(
        module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, enc_buf, enc_size, &enc_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_true(enc_len > 0);

    uint8_t dec_buf[256];
    size_t  dec_len = 0;
    res             = pubnub_crypto_module_decrypt_buf(
        module, enc_buf, enc_len, dec_buf, sizeof(dec_buf), &dec_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(dec_len, TEST_PLAINTEXT_LEN);
    assert_memory_equal(dec_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN);

    free(enc_buf);
    pubnub_crypto_module_destroy(module);
}

static void module_acrh_encrypt_legacy_decrypt(void** state)
{
    (void)state;

    /* Encrypt with ACRH module. */
    pubnub_crypto_module_t* acrh_module =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    assert_non_null(acrh_module);

    uint8_t*     enc_buf = NULL;
    size_t       enc_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt(
        acrh_module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, &enc_buf, &enc_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_non_null(enc_buf);

    /* Decrypt with legacy module (ACRH is its fallback). */
    pubnub_crypto_module_t* legacy_module =
        pubnub_crypto_module_legacy(TEST_KEY, 1, &s_alloc);
    assert_non_null(legacy_module);

    uint8_t* dec_buf = NULL;
    size_t   dec_len = 0;
    res              = pubnub_crypto_module_decrypt(
        legacy_module, enc_buf, enc_len, &dec_buf, &dec_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(dec_len, TEST_PLAINTEXT_LEN);
    assert_memory_equal(dec_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN);

    pubnub_crypto_module_free(legacy_module, dec_buf);
    pubnub_crypto_module_free(acrh_module, enc_buf);
    pubnub_crypto_module_destroy(legacy_module);
    pubnub_crypto_module_destroy(acrh_module);
}

static void module_legacy_encrypt_acrh_decrypt(void** state)
{
    (void)state;

    /* Encrypt with legacy module. */
    pubnub_crypto_module_t* legacy_module =
        pubnub_crypto_module_legacy(TEST_KEY, 1, &s_alloc);
    assert_non_null(legacy_module);

    uint8_t*     enc_buf = NULL;
    size_t       enc_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt(
        legacy_module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, &enc_buf, &enc_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_non_null(enc_buf);

    /* Decrypt with ACRH module (legacy is its fallback). */
    pubnub_crypto_module_t* acrh_module =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    assert_non_null(acrh_module);

    uint8_t* dec_buf = NULL;
    size_t   dec_len = 0;
    res              = pubnub_crypto_module_decrypt(
        acrh_module, enc_buf, enc_len, &dec_buf, &dec_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(dec_len, TEST_PLAINTEXT_LEN);
    assert_memory_equal(dec_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN);

    pubnub_crypto_module_free(acrh_module, dec_buf);
    pubnub_crypto_module_free(legacy_module, enc_buf);
    pubnub_crypto_module_destroy(acrh_module);
    pubnub_crypto_module_destroy(legacy_module);
}

static void module_encrypt_to_base64_decrypt_from_base64(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    assert_non_null(module);

    char*        b64     = NULL;
    size_t       b64_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt_to_base64(
        module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, &b64, &b64_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_non_null(b64);
    assert_true(b64_len > 0);

    /* Verify NUL termination. */
    assert_int_equal(b64[b64_len], '\0');

    /* Decrypt from base64. */
    uint8_t* dec_buf = NULL;
    size_t   dec_len = 0;
    res              = pubnub_crypto_module_decrypt_from_base64(
        module, b64, b64_len, &dec_buf, &dec_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(dec_len, TEST_PLAINTEXT_LEN);
    assert_memory_equal(dec_buf, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN);

    pubnub_crypto_module_free(module, dec_buf);
    pubnub_crypto_module_free(module, b64);
    pubnub_crypto_module_destroy(module);
}

static void module_decrypt_unknown_identifier_fails(void** state)
{
    (void)state;

    /* Create a module with only ACRH (no legacy fallback). */
    pubnub_crypto_provider_t* acrh =
        pubnub_cryptor_aes_cbc_create(TEST_KEY, &s_alloc);
    assert_non_null(acrh);

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_create(acrh, NULL, 0, &s_alloc);
    assert_non_null(module);

    /* Forge a PNED header with an unknown identifier "ZZZZ". */
    uint8_t fake_blob[64];
    memset(fake_blob, 0, sizeof(fake_blob));

    /* Manually write a minimal PNED header:
     *   sentinel "PNED" (4) + version 1 (1) + identifier "ZZZZ" (4)
     *   + metadata_len 16 (1) = 10 bytes header prefix
     *   + 16 bytes metadata + at least 16 bytes ciphertext */
    fake_blob[0] = 0x50; /* P */
    fake_blob[1] = 0x4E; /* N */
    fake_blob[2] = 0x45; /* E */
    fake_blob[3] = 0x44; /* D */
    fake_blob[4] = 0x01; /* version 1 */
    fake_blob[5] = 'Z';
    fake_blob[6] = 'Z';
    fake_blob[7] = 'Z';
    fake_blob[8] = 'Z';
    fake_blob[9] = 16; /* metadata_len = 16 */
    /* 10..25 = fake metadata (16 bytes) */
    /* 26..41 = fake ciphertext (16 bytes) */

    uint8_t      dec_buf[64];
    size_t       dec_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_decrypt_buf(
        module, fake_blob, 42, dec_buf, sizeof(dec_buf), &dec_len);
    assert_int_equal(res, PUBNUB_ERR_CRYPTO);

    pubnub_crypto_module_destroy(module);
    pubnub_cryptor_destroy(acrh);
}

static void module_encrypt_size_correct(void** state)
{
    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    assert_non_null(module);

    size_t reported_size =
        pubnub_crypto_module_encrypt_size(module, TEST_PLAINTEXT_LEN);
    assert_true(reported_size > 0);

    uint8_t* enc_buf = (uint8_t*)malloc(reported_size);
    assert_non_null(enc_buf);

    size_t       enc_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt_buf(
        module, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, enc_buf, reported_size, &enc_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_true(enc_len <= reported_size);

    free(enc_buf);
    pubnub_crypto_module_destroy(module);
}

static void module_null_module_returns_error(void** state)
{
    (void)state;

    /* encrypt_size returns 0 on NULL module. */
    size_t size = pubnub_crypto_module_encrypt_size(NULL, 10);
    assert_int_equal(size, 0);

    /* encrypt_buf returns error on NULL module. */
    uint8_t      buf[32];
    size_t       out_len = 0;
    pubnub_res_t res     = pubnub_crypto_module_encrypt_buf(
        NULL, TEST_PLAINTEXT, TEST_PLAINTEXT_LEN, buf, sizeof(buf), &out_len);
    assert_int_equal(res, PUBNUB_ERR_INVALID_ARGUMENT);

    /* decrypt_buf returns error on NULL module. */
    res = pubnub_crypto_module_decrypt_buf(
        NULL, buf, sizeof(buf), buf, sizeof(buf), &out_len);
    assert_int_equal(res, PUBNUB_ERR_INVALID_ARGUMENT);

    /* default_cryptor returns NULL on NULL module. */
    pubnub_crypto_provider_t* def = pubnub_crypto_module_default_cryptor(NULL);
    assert_null(def);

    /* destroy is NULL-safe. */
    pubnub_crypto_module_destroy(NULL);
}

/* ─── Cross-SDK compatibility vectors (from PHP SDK via Python test suite) ─── */

static void cross_sdk_php_legacy_static_iv_decrypt(void** state)
{
    (void)state;

    /* Vector from Python SDK test_php_encrypted_crosscheck (PHP SDK):
     * key="myCipherKey", plaintext="PHP can backwards Legacy static"
     * base64: "KGc+SNJD7mIveY+KNIL/L9ZzAjC0dCJCju+HXRwSW2k=" */
    pubnub_crypto_module_t* module =
        pubnub_crypto_module_legacy("myCipherKey", 0, &s_alloc);
    assert_non_null(module);

    const char   b64[]        = "KGc+SNJD7mIveY+KNIL/L9ZzAjC0dCJCju+HXRwSW2k=";
    const char*  expected     = "PHP can backwards Legacy static";
    const size_t expected_len = strlen(expected);

    uint8_t* output     = NULL;
    size_t   output_len = 0;

    pubnub_res_t res = pubnub_crypto_module_decrypt_from_base64(
        module, b64, strlen(b64), &output, &output_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(output_len, expected_len);
    assert_memory_equal(output, expected, expected_len);

    pubnub_crypto_module_free(module, output);
    pubnub_crypto_module_destroy(module);
}

static void cross_sdk_php_legacy_random_iv_decrypt(void** state)
{
    (void)state;

    /* Vector from Python SDK test_php_encrypted_crosscheck (PHP SDK):
     * key="myCipherKey", plaintext="PHP can backwards Legacy random"
     * base64: "PXjHv0L05kgj0mqIE9s7n4LDPrLtjnfamMoHyiMoL0R1uzSMsYp7dDfqEWrnoaqS"
     * (random IV prepended to ciphertext, no PNED header) */
    pubnub_crypto_module_t* module =
        pubnub_crypto_module_legacy("myCipherKey", 1, &s_alloc);
    assert_non_null(module);

    const char b64[] =
        "PXjHv0L05kgj0mqIE9s7n4LDPrLtjnfamMoHyiMoL0R1uzSMsYp7dDfqEWrnoaqS";
    const char*  expected     = "PHP can backwards Legacy random";
    const size_t expected_len = strlen(expected);

    uint8_t* output     = NULL;
    size_t   output_len = 0;

    pubnub_res_t res = pubnub_crypto_module_decrypt_from_base64(
        module, b64, strlen(b64), &output, &output_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(output_len, expected_len);
    assert_memory_equal(output, expected, expected_len);

    pubnub_crypto_module_free(module, output);
    pubnub_crypto_module_destroy(module);
}

static void cross_sdk_php_acrh_decrypt(void** state)
{
    (void)state;

    /* Vector from Python SDK test_php_encrypted_crosscheck (PHP SDK):
     * key="myCipherKey"
     * plaintext="PHP can into space with headers and aes cbc and other shiny
     * stuff" base64 contains PNED header + ACRH ciphertext */
    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc("myCipherKey", 1, &s_alloc);
    assert_non_null(module);

    const char b64[] =
        "UE5FRAFBQ1JIEHvl3cY3RYsHnbKm6VR51XG/Y7HodnkumKHxo+mrsxbIjZvFpVuILQ"
        "0oZysVwjNsDNMKiMfZteoJ8P1/mvPmbuQKLErBzS2l7vEohCwbmAJODPR2yNhJGB89"
        "89reTZ7Y7Q==";
    const char* expected =
        "PHP can into space with headers and aes cbc and other shiny stuff";
    const size_t expected_len = strlen(expected);

    uint8_t* output     = NULL;
    size_t   output_len = 0;

    pubnub_res_t res = pubnub_crypto_module_decrypt_from_base64(
        module, b64, strlen(b64), &output, &output_len);
    assert_int_equal(res, PUBNUB_OK);
    assert_int_equal(output_len, expected_len);
    assert_memory_equal(output, expected, expected_len);

    pubnub_crypto_module_free(module, output);
    pubnub_crypto_module_destroy(module);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(module_aes_cbc_create_destroy),
        cmocka_unit_test(module_legacy_create_destroy),
        cmocka_unit_test(module_encrypt_decrypt_roundtrip_acrh),
        cmocka_unit_test(module_encrypt_decrypt_roundtrip_legacy_random_iv),
        cmocka_unit_test(module_encrypt_decrypt_roundtrip_legacy_static_iv),
        cmocka_unit_test(module_acrh_encrypt_legacy_decrypt),
        cmocka_unit_test(module_legacy_encrypt_acrh_decrypt),
        cmocka_unit_test(module_encrypt_to_base64_decrypt_from_base64),
        cmocka_unit_test(module_decrypt_unknown_identifier_fails),
        cmocka_unit_test(module_encrypt_size_correct),
        cmocka_unit_test(module_null_module_returns_error),
        cmocka_unit_test(cross_sdk_php_legacy_static_iv_decrypt),
        cmocka_unit_test(cross_sdk_php_legacy_random_iv_decrypt),
        cmocka_unit_test(cross_sdk_php_acrh_decrypt),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

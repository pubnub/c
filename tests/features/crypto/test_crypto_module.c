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

#include "core/protocol_common/pn_base64.h"

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

    /* Decrypt with the legacy module (ACRH and ACGM are its fallbacks). */
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

    /* Decrypt with the AES-CBC module (legacy and ACGM are its fallbacks). */
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

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Returns the decoded length, or (size_t)-1 when the hex is invalid. */
static size_t hex_decode(const char* hex, uint8_t* out, size_t cap)
{
    size_t n;
    size_t i;

    if (NULL == hex || '\0' == hex[0]) {
        return 0;
    }

    n = strlen(hex);
    if (0 != (n % 2) || (n / 2) > cap) {
        return (size_t)-1;
    }

    for (i = 0; i < n; i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return (size_t)-1;
        }
        out[i / 2] = (uint8_t)((unsigned)hi << 4 | (unsigned)lo);
    }

    return n / 2;
}

/* UTF-8 for "ключ 🔑 key", NUL-terminated. Kept as bytes so the source
 * file encoding cannot change the cipher key. */
static const uint8_t GCM_UNICODE_KEY[] = {
    0xD0,
    0xBA,
    0xD0,
    0xBB,
    0xD1,
    0x8E,
    0xD1,
    0x87,
    0x20,
    0xF0,
    0x9F,
    0x94,
    0x91,
    0x20,
    0x6B,
    0x65,
    0x79,
    0x00,
};

/*
 * Known AES-256-GCM (ACGM) PNED payloads. The metadata is the nonce
 * and the tag follows the ciphertext. plain_hex is empty when the
 * plaintext is empty.
 */
static const struct {
    const char*    key;
    const uint8_t* key_bytes;
    const char*    payload_hex;
    const char*    plain_hex;
} GCM_VECTORS[] = {
    {"enigma",
     NULL,            "504e4544014143474d0c0102030405060708090a0b0cea1b5780788b593294f898dabd1d"
     "02d7219c77218ad262c4a9aecc",           "48656c6c6f20776f726c64"          },
    {"enigma",
     NULL,            "504e4544014143474d0c111111111111111111111111d138fbfc4bd0c337e29d9f2c98a5"
     "dd072360f4433e2979f440fc7827b3",       "68c3a96c6c6f20e4bda0e5a5bd"      },
    {"myCipherKey",
     NULL,            "504e4544014143474d0c000102030405060708090a0bc411f0f18fefca7becf7235b4d09"
     "b970d4d56d19",                         "00ff7f80"                        },
    {"enigma",
     NULL,            "504e4544014143474d0cffffffffffffffffffffffff0d54b73ce2509d4e7655043f5b10"
     "3cb4f1e78738a73a2f56109813955359b4784774de1954f835d4d739805631c5cdcc3467"
     "607259",                               "7b2274657874223a2248656c6c6f2c20e4b896e7958c2120f09f8c8d222c226e223a3432"
     "7d"                                                        },
    {"enigma",
     NULL,            "504e4544014143474d0c8f5a2d1b6e9c4ef0a37d83b9fd24a488008bd084305aaee605b3"
     "49028c21b92d48f4dd5c71e99dce881c2ec9", "30313233343536373839616263646566"},
    {"enigma",
     NULL,            "504e4544014143474d0cffffffffffffffffffffffff0d54b73ce2509d4e7655043f5b10"
     "3cb4f1e78738a73a2f56109813955359b4784774de19050b4f14f7a439a859ac6c327856"
     "fe1af874bbe888945c603004176ddab22578e407663346d307669e83fa4c9a8b13743a07"
     "a21b7f",                               "7b2274657874223a2248656c6c6f2c20e4b896e7958c2120f09f8c8d222c226e223a3432"
     "2c226c697374223a5b312c322c335d2c226e6573746564223a7b226f6b223a747275657d"
     "7d"                                                        },
    {NULL,
     GCM_UNICODE_KEY, "504e4544014143474d0c000000000000000000000000326052d9ff1b757ed8810f5d6f87"
     "a7c021920eb09b82e47049efecf5094f6f5837691e9fb66539dfc47d434cc01b783527c4"
     "d62ae2d8163043f86dc7ac405b90971ceaa07134add2be50dfd60f8390572d9b05255f30"
     "97614e888fcca4",            "4c696e65206f6e650a094c696e652074776f2077697468202271756f7465732220262073"
     "796d626f6c73203c3e2f5c20e28094207370616e73207365766572616c2041455320626c"
     "6f636b732e"                             },
    {"customKey",
     NULL,            "504e4544014143474d0ca1a2a3a4a5a6a7a8a9aaabacfbeef1ccce8f5a09087348786b99"
     "b75076",                               "61"                              },
    /* Empty plaintext: the body is the 16-byte tag and nothing else. */
    {"enigma",
     NULL,            "504e4544014143474d0c090807060504030201000102d2cc905e1cc396312f67a8be4c17"
     "fb43",                                 ""                                },
};

static const char* gcm_vector_key(size_t index)
{
    if (NULL != GCM_VECTORS[index].key) {
        return GCM_VECTORS[index].key;
    }
    return (const char*)GCM_VECTORS[index].key_bytes;
}

static void module_decrypts_aes_gcm_vectors(void** state)
{
    size_t i;

    (void)state;

    for (i = 0; i < sizeof(GCM_VECTORS) / sizeof(GCM_VECTORS[0]); ++i) {
        uint8_t payload[512];
        uint8_t plain[256];
        size_t  payload_len =
            hex_decode(GCM_VECTORS[i].payload_hex, payload, sizeof(payload));
        size_t plain_len =
            hex_decode(GCM_VECTORS[i].plain_hex, plain, sizeof(plain));
        const char*             key = gcm_vector_key(i);
        pubnub_crypto_module_t* modules[2];
        size_t                  m;

        assert_true(payload_len != (size_t)-1);
        assert_true(plain_len != (size_t)-1);
        assert_true(payload_len > 0);

        modules[0] = pubnub_crypto_module_aes_cbc(key, 1, &s_alloc);
        modules[1] = pubnub_crypto_module_legacy(key, 0, &s_alloc);
        assert_non_null(modules[0]);
        assert_non_null(modules[1]);

        for (m = 0; m < 2; ++m) {
            uint8_t* dec     = (uint8_t*)malloc(payload_len);
            size_t   dec_len = 0;
            char     b64[700];
            size_t   b64_len;
            uint8_t* b64_dec     = NULL;
            size_t   b64_dec_len = 0;

            assert_non_null(dec);
            assert_int_equal(
                PUBNUB_OK,
                pubnub_crypto_module_decrypt_buf(
                    modules[m], payload, payload_len, dec, payload_len, &dec_len));
            assert_int_equal(plain_len, dec_len);
            if (plain_len > 0) {
                assert_memory_equal(plain, dec, plain_len);
            }
            free(dec);

            b64_len = pn_base64_encoded_len(payload_len);
            assert_true(b64_len <= sizeof(b64));
            assert_int_equal(
                PUBNUB_OK,
                pn_base64_encode(payload, payload_len, b64, sizeof(b64)));
            assert_int_equal(
                PUBNUB_OK,
                pubnub_crypto_module_decrypt_from_base64(
                    modules[m], b64, b64_len - 1, &b64_dec, &b64_dec_len));
            assert_int_equal(plain_len, b64_dec_len);
            if (plain_len > 0) {
                assert_memory_equal(plain, b64_dec, plain_len);
            }
            pubnub_crypto_module_free(modules[m], b64_dec);
        }

        pubnub_crypto_module_destroy(modules[0]);
        pubnub_crypto_module_destroy(modules[1]);
    }
}

static void module_encrypt_does_not_use_aes_gcm(void** state)
{
    (void)state;

    const uint8_t plaintext[] = "Hello world";
    uint8_t*      enc         = NULL;
    size_t        enc_len     = 0;

    pubnub_crypto_module_t* cbc =
        pubnub_crypto_module_aes_cbc(TEST_KEY, 1, &s_alloc);
    pubnub_crypto_module_t* legacy =
        pubnub_crypto_module_legacy(TEST_KEY, 1, &s_alloc);
    assert_non_null(cbc);
    assert_non_null(legacy);

    assert_int_equal(PUBNUB_OK,
                     pubnub_crypto_module_encrypt(
                         cbc, plaintext, sizeof(plaintext) - 1, &enc, &enc_len));
    assert_true(enc_len >= 9);
    assert_memory_equal("PNED", enc, 4);
    assert_memory_equal("ACRH", enc + 5, 4);
    pubnub_crypto_module_free(cbc, enc);

    enc     = NULL;
    enc_len = 0;
    assert_int_equal(PUBNUB_OK,
                     pubnub_crypto_module_encrypt(
                         legacy, plaintext, sizeof(plaintext) - 1, &enc, &enc_len));
    assert_true(enc_len >= 4);
    assert_true(0 != memcmp(enc, "PNED", 4));
    pubnub_crypto_module_free(legacy, enc);

    pubnub_crypto_module_destroy(cbc);
    pubnub_crypto_module_destroy(legacy);
}

static void module_aes_gcm_rejects_bad_payloads(void** state)
{
    (void)state;

    /* Known ACGM payload for key "enigma", plaintext "Hello world". */
    const char* hello_hex = "504e4544014143474d0c0102030405060708090a0b0cea1b57"
                            "80788b593294f898dabd1d"
                            "02d7219c77218ad262c4a9aecc";
    uint8_t     payload[128];
    size_t      payload_len = hex_decode(hello_hex, payload, sizeof(payload));
    uint8_t     dec[128];
    size_t      dec_len = 0;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc("enigma", 1, &s_alloc);
    pubnub_crypto_module_t* wrong =
        pubnub_crypto_module_legacy("other-key", 1, &s_alloc);
    assert_true(payload_len != (size_t)-1);
    assert_non_null(module);
    assert_non_null(wrong);

    payload[payload_len - 1] ^= 0xff;
    assert_int_equal(PUBNUB_ERR_CRYPTO,
                     pubnub_crypto_module_decrypt_buf(
                         module, payload, payload_len, dec, sizeof(dec), &dec_len));
    payload[payload_len - 1] ^= 0xff;

    assert_int_equal(PUBNUB_ERR_CRYPTO,
                     pubnub_crypto_module_decrypt_buf(
                         wrong, payload, payload_len, dec, sizeof(dec), &dec_len));

    /* Metadata length byte sits at offset 9. 11 is not the GCM nonce size. */
    payload[9] = 11;
    assert_int_equal(PUBNUB_ERR_CRYPTO,
                     pubnub_crypto_module_decrypt_buf(
                         module, payload, payload_len, dec, sizeof(dec), &dec_len));
    payload[9] = 12;

    /* Header is 22 bytes. 15 body bytes is shorter than the 16-byte tag. */
    assert_int_equal(PUBNUB_ERR_CRYPTO,
                     pubnub_crypto_module_decrypt_buf(
                         module, payload, 22 + 15, dec, sizeof(dec), &dec_len));

    pubnub_crypto_module_destroy(wrong);
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
        cmocka_unit_test(module_decrypts_aes_gcm_vectors),
        cmocka_unit_test(module_encrypt_does_not_use_aes_gcm),
        cmocka_unit_test(module_aes_gcm_rejects_bad_payloads),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

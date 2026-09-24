/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_mbedtls_internal.h"

#include "pubnub/error.h"

#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

#include <string.h>

/**
 * @brief Compute SHA-256 via the md API (portable across mbedTLS 2.x and 3.x).
 *
 * mbedTLS 2.x `mbedtls_sha256()` returns void; 3.x returns int. Using
 * `mbedtls_md()` avoids the incompatibility.
 */
static int pn_mbedtls_sha256(const unsigned char* input,
                             size_t               len,
                             unsigned char*       output)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (NULL == info) {
        return -1;
    }

    return mbedtls_md(info, input, len, output);
}

pubnub_res_t pn_mbedtls_derive_key_acrh(const char* cipher_key, uint8_t* out_key)
{
    unsigned char digest[PN_SHA256_DIGEST_SIZE];

    if (NULL == cipher_key || NULL == out_key) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (0
        != pn_mbedtls_sha256(
            (const unsigned char*)cipher_key, strlen(cipher_key), digest)) {
        return PUBNUB_ERR_CRYPTO;
    }

    memcpy(out_key, digest, PN_AES_KEY_SIZE);
    mbedtls_platform_zeroize(digest, sizeof(digest));

    return PUBNUB_OK;
}

pubnub_res_t pn_mbedtls_derive_key_legacy(const char* cipher_key, uint8_t* out_key)
{
    static const char hex_table[] = "0123456789abcdef";
    unsigned char     digest[PN_SHA256_DIGEST_SIZE];
    char              hex_str[PN_SHA256_DIGEST_SIZE * 2];
    size_t            i;

    if (NULL == cipher_key || NULL == out_key) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (0
        != pn_mbedtls_sha256(
            (const unsigned char*)cipher_key, strlen(cipher_key), digest)) {
        return PUBNUB_ERR_CRYPTO;
    }

    /*
     * Legacy key derivation: hex-encode the SHA-256 digest, then use
     * the first 32 hex characters as raw key bytes. This matches the
     * behavior of older PubNub SDKs (JS < v7.2, Java legacy).
     */
    for (i = 0; i < PN_SHA256_DIGEST_SIZE; ++i) {
        hex_str[i * 2]     = hex_table[(digest[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = hex_table[digest[i] & 0x0F];
    }

    /* Take first 32 hex characters as the AES key bytes. */
    memcpy(out_key, hex_str, PN_AES_KEY_SIZE);

    mbedtls_platform_zeroize(digest, sizeof(digest));
    mbedtls_platform_zeroize(hex_str, sizeof(hex_str));

    return PUBNUB_OK;
}

pubnub_res_t pn_mbedtls_hmac_sha256(pubnub_crypto_provider_t* self,
                                    const uint8_t*            key,
                                    size_t                    key_len,
                                    const uint8_t*            data,
                                    size_t                    data_len,
                                    uint8_t*                  output,
                                    size_t*                   output_len)
{
    const mbedtls_md_info_t* md_info;
    int                      rc;

    (void)self;

    if (NULL == key || NULL == data || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (*output_len < PN_HMAC_SHA256_SIZE) {
        return PUBNUB_ERR_CRYPTO;
    }

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (NULL == md_info) {
        return PUBNUB_ERR_CRYPTO;
    }

    rc = mbedtls_md_hmac(md_info, key, key_len, data, data_len, output);
    if (0 != rc) {
        return PUBNUB_ERR_CRYPTO;
    }

    *output_len = PN_HMAC_SHA256_SIZE;

    return PUBNUB_OK;
}

void pn_mbedtls_secure_zero(void* buf, size_t len)
{
    if (NULL != buf && len > 0) {
        mbedtls_platform_zeroize(buf, len);
    }
}

int pn_mbedtls_drbg_init(pn_mbedtls_cryptor_state_t* state)
{
    int rc;

    if (NULL == state) {
        return -1;
    }

    mbedtls_entropy_init(&state->entropy);
    mbedtls_ctr_drbg_init(&state->drbg);

    rc = mbedtls_ctr_drbg_seed(
        &state->drbg, mbedtls_entropy_func, &state->entropy, NULL, 0);
    if (0 != rc) {
        mbedtls_ctr_drbg_free(&state->drbg);
        mbedtls_entropy_free(&state->entropy);
        return rc;
    }

    return 0;
}

void pn_mbedtls_drbg_free(pn_mbedtls_cryptor_state_t* state)
{
    if (NULL == state) {
        return;
    }

    mbedtls_ctr_drbg_free(&state->drbg);
    mbedtls_entropy_free(&state->entropy);
}

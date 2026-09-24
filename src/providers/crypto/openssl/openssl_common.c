/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_openssl_internal.h"

#include "pubnub/error.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <limits.h>
#include <string.h>

pubnub_res_t pn_openssl_derive_key_acrh(const char* cipher_key, uint8_t* out_key)
{
    unsigned char digest[PN_SHA256_DIGEST_SIZE];

    if (NULL == cipher_key || NULL == out_key) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (NULL
        == SHA256((const unsigned char*)cipher_key, strlen(cipher_key), digest)) {
        return PUBNUB_ERR_CRYPTO;
    }

    memcpy(out_key, digest, PN_AES_KEY_SIZE);
    OPENSSL_cleanse(digest, sizeof(digest));

    return PUBNUB_OK;
}

pubnub_res_t pn_openssl_derive_key_legacy(const char* cipher_key, uint8_t* out_key)
{
    static const char hex_table[] = "0123456789abcdef";
    unsigned char     digest[PN_SHA256_DIGEST_SIZE];
    char              hex_str[PN_SHA256_DIGEST_SIZE * 2];
    size_t            i;

    if (NULL == cipher_key || NULL == out_key) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (NULL
        == SHA256((const unsigned char*)cipher_key, strlen(cipher_key), digest)) {
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

    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(hex_str, sizeof(hex_str));

    return PUBNUB_OK;
}

pubnub_res_t pn_openssl_hmac_sha256(pubnub_crypto_provider_t* self,
                                    const uint8_t*            key,
                                    size_t                    key_len,
                                    const uint8_t*            data,
                                    size_t                    data_len,
                                    uint8_t*                  output,
                                    size_t*                   output_len)
{
    unsigned int   hmac_len = 0;
    unsigned char* result;

    (void)self;

    if (NULL == key || NULL == data || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    if (*output_len < PN_HMAC_SHA256_SIZE) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* OpenSSL HMAC() takes key length as int; reject oversized keys. */
    if (key_len > (size_t)INT_MAX) {
        return PUBNUB_ERR_CRYPTO;
    }

    result =
        HMAC(EVP_sha256(), key, (int)key_len, data, data_len, output, &hmac_len);
    if (NULL == result) {
        return PUBNUB_ERR_CRYPTO;
    }

    *output_len = hmac_len;

    return PUBNUB_OK;
}

void pn_openssl_secure_zero(void* buf, size_t len)
{
    if (NULL != buf && len > 0) {
        OPENSSL_cleanse(buf, len);
    }
}

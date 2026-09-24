/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "crypto_internal.h"
#include "crypto_header.h"

#include "pubnub/error.h"
#include "pubnub/features/crypto.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"

#include "core/protocol_common/pn_base64.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief Resolve allocator: fall back to compiled-in default. */
pubnub_allocator_provider_t* pn_allocator_default(void);

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_crypto_provider_t*
pubnub_cryptor_aes_cbc_create(const char*                  cipher_key,
                              pubnub_allocator_provider_t* alloc);
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_crypto_provider_t*
pubnub_cryptor_legacy_create(const char*                  cipher_key,
                             int                          use_random_iv,
                             pubnub_allocator_provider_t* alloc);
// NOLINTNEXTLINE(misc-use-internal-linkage)
void pubnub_cryptor_destroy(pubnub_crypto_provider_t* cryptor);

#define PN_ACRH_METADATA_LEN 16

static const uint8_t pn_legacy_identifier[4] = {0, 0, 0, 0};

/**
 * @brief Check whether identifier represents the legacy cryptor.
 */
static int pn_is_legacy_identifier(const uint8_t identifier[4])
{
    return 0 == memcmp(identifier, pn_legacy_identifier, 4);
}

/**
 * @brief Find a cryptor matching identifier; checks default first,
 *        then fallbacks.
 */
static pubnub_crypto_provider_t* pn_find_cryptor(pubnub_crypto_module_t* module,
                                                 const uint8_t identifier[4])
{
    size_t i;

    if (0 == memcmp(module->default_cryptor->identifier, identifier, 4)) {
        return module->default_cryptor;
    }

    for (i = 0; i < module->others_count; ++i) {
        if (0 == memcmp(module->others[i]->identifier, identifier, 4)) {
            return module->others[i];
        }
    }

    return NULL;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_crypto_module_t* pubnub_crypto_module_aes_cbc(const char* cipher_key,
                                                     int         use_random_iv,
                                                     pubnub_allocator_provider_t* alloc)
{
    if (NULL == cipher_key) {
        return NULL;
    }
    if (NULL == alloc) {
        alloc = pn_allocator_default();
    }
    if (NULL == alloc) {
        return NULL;
    }

    pubnub_crypto_provider_t* acrh =
        pubnub_cryptor_aes_cbc_create(cipher_key, alloc);
    if (NULL == acrh) {
        return NULL;
    }

    pubnub_crypto_provider_t* legacy =
        pubnub_cryptor_legacy_create(cipher_key, use_random_iv, alloc);
    if (NULL == legacy) {
        pubnub_cryptor_destroy(acrh);
        return NULL;
    }

    pubnub_crypto_module_t* module =
        (pubnub_crypto_module_t*)PN_ALLOC(alloc, sizeof(pubnub_crypto_module_t), 0);
    if (NULL == module) {
        pubnub_cryptor_destroy(legacy);
        pubnub_cryptor_destroy(acrh);
        return NULL;
    }

    memset(module, 0, sizeof(*module));
    module->default_cryptor = acrh;
    module->others[0]       = legacy;
    module->others_count    = 1;
    module->owns_cryptors   = 1;
    module->alloc           = alloc;
    return module;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_crypto_module_t* pubnub_crypto_module_legacy(const char* cipher_key,
                                                    int         use_random_iv,
                                                    pubnub_allocator_provider_t* alloc)
{
    if (NULL == cipher_key) {
        return NULL;
    }
    if (NULL == alloc) {
        alloc = pn_allocator_default();
    }
    if (NULL == alloc) {
        return NULL;
    }

    pubnub_crypto_provider_t* legacy =
        pubnub_cryptor_legacy_create(cipher_key, use_random_iv, alloc);
    if (NULL == legacy) {
        return NULL;
    }

    /* ACRH fallback for decrypting modern-format messages. */
    pubnub_crypto_provider_t* acrh =
        pubnub_cryptor_aes_cbc_create(cipher_key, alloc);
    if (NULL == acrh) {
        pubnub_cryptor_destroy(legacy);
        return NULL;
    }

    pubnub_crypto_module_t* module =
        (pubnub_crypto_module_t*)PN_ALLOC(alloc, sizeof(pubnub_crypto_module_t), 0);
    if (NULL == module) {
        pubnub_cryptor_destroy(acrh);
        pubnub_cryptor_destroy(legacy);
        return NULL;
    }

    memset(module, 0, sizeof(*module));
    module->default_cryptor = legacy;
    module->others[0]       = acrh;
    module->others_count    = 1;
    module->owns_cryptors   = 1;
    module->alloc           = alloc;

    return module;
}

pubnub_crypto_module_t*
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_crypto_module_create(pubnub_crypto_provider_t*    default_cryptor,
                            pubnub_crypto_provider_t**   others,
                            size_t                       others_count,
                            pubnub_allocator_provider_t* alloc)
{
    if (NULL == default_cryptor) {
        return NULL;
    }
    if (NULL == alloc) {
        alloc = pn_allocator_default();
    }
    if (NULL == alloc) {
        return NULL;
    }
    if (others_count > PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS) {
        return NULL;
    }
    if (others_count > 0 && NULL == others) {
        return NULL;
    }

    pubnub_crypto_module_t* module =
        (pubnub_crypto_module_t*)PN_ALLOC(alloc, sizeof(pubnub_crypto_module_t), 0);
    if (NULL == module) {
        return NULL;
    }

    memset(module, 0, sizeof(*module));
    module->default_cryptor = default_cryptor;
    {
        size_t i;
        for (i = 0; i < others_count; ++i) {
            module->others[i] = others[i];
        }
    }
    module->others_count  = others_count;
    module->owns_cryptors = 0;
    module->alloc         = alloc;

    return module;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void pubnub_crypto_module_destroy(pubnub_crypto_module_t* module)
{
    if (NULL == module) {
        return;
    }

    pubnub_allocator_provider_t* alloc = module->alloc;
    if (NULL == alloc) {
        return;
    }

    if (module->owns_cryptors) {
        size_t i;
        pubnub_cryptor_destroy(module->default_cryptor);
        for (i = 0; i < module->others_count; ++i) {
            pubnub_cryptor_destroy(module->others[i]);
        }
    }

    PN_FREE(alloc, module);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
size_t pubnub_crypto_module_encrypt_size(pubnub_crypto_module_t* module,
                                         size_t                  input_len)
{
    if (NULL == module || NULL == module->default_cryptor) {
        return 0;
    }
    if (NULL == module->default_cryptor->encrypt_size) {
        return 0;
    }

    size_t ciphertext_size =
        module->default_cryptor->encrypt_size(module->default_cryptor, input_len);
    if (0 == ciphertext_size) {
        return 0;
    }

    /* Legacy cryptor: no PNED header. Output is ciphertext only. */
    if (pn_is_legacy_identifier(module->default_cryptor->identifier)) {
        return ciphertext_size;
    }

    /* Non-legacy: PNED header prefix + metadata + ciphertext. */
    size_t header_size = pn_crypto_header_size(PN_ACRH_METADATA_LEN);

    return header_size + ciphertext_size;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
size_t pubnub_crypto_module_encrypted_base64_size(pubnub_crypto_module_t* module,
                                                  size_t input_len)
{
    size_t raw_size = pubnub_crypto_module_encrypt_size(module, input_len);
    if (0 == raw_size) {
        return 0;
    }

    return pn_base64_encoded_len(raw_size);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pubnub_crypto_module_encrypt_buf(pubnub_crypto_module_t* module,
                                              const uint8_t*          input,
                                              size_t                  input_len,
                                              uint8_t*                output,
                                              size_t  output_cap,
                                              size_t* output_len)
{
    if (NULL == module || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == input && 0 != input_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *output_len = 0;

    pubnub_crypto_provider_t* cryptor = module->default_cryptor;
    if (NULL == cryptor || NULL == cryptor->encrypt
        || NULL == cryptor->encrypt_size) {
        return PUBNUB_ERR_CRYPTO;
    }

    size_t needed = pubnub_crypto_module_encrypt_size(module, input_len);
    if (0 == needed) {
        return PUBNUB_ERR_CRYPTO;
    }
    if (output_cap < needed) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    int is_legacy = pn_is_legacy_identifier(cryptor->identifier);

    if (is_legacy) {
        /* Legacy: encrypt directly into output (IV may be prepended
         * by the cryptor itself). No PNED header. */
        pubnub_encrypted_data_t enc = {
            .data         = output,
            .data_len     = output_cap,
            .metadata     = NULL,
            .metadata_len = 0,
        };

        pubnub_res_t res = cryptor->encrypt(cryptor, input, input_len, &enc);
        if (PUBNUB_OK != res) {
            return res;
        }

        *output_len = enc.data_len;
        return PUBNUB_OK;
    }

    /* Non-legacy (ACRH): serialize PNED header + metadata + ciphertext. */
    uint8_t iv_buf[PN_ACRH_METADATA_LEN];

    size_t header_prefix_size = pn_crypto_header_serialize(
        cryptor->identifier, PN_ACRH_METADATA_LEN, output, output_cap);
    if (0 == header_prefix_size) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    /* Encrypt into the buffer region after header + metadata. */
    size_t data_offset = header_prefix_size + PN_ACRH_METADATA_LEN;

    pubnub_encrypted_data_t enc = {
        .data         = output + data_offset,
        .data_len     = output_cap - data_offset,
        .metadata     = iv_buf,
        .metadata_len = PN_ACRH_METADATA_LEN,
    };

    pubnub_res_t res = cryptor->encrypt(cryptor, input, input_len, &enc);
    if (PUBNUB_OK != res) {
        return res;
    }

    /* Copy metadata (IV) into the gap between header prefix and
     * ciphertext. */
    memcpy(output + header_prefix_size, iv_buf, PN_ACRH_METADATA_LEN);

    *output_len = header_prefix_size + PN_ACRH_METADATA_LEN + enc.data_len;
    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pubnub_crypto_module_decrypt_buf(pubnub_crypto_module_t* module,
                                              const uint8_t*          input,
                                              size_t                  input_len,
                                              uint8_t*                output,
                                              size_t  output_cap,
                                              size_t* output_len)
{
    if (NULL == module || NULL == output || NULL == output_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == input || 0 == input_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *output_len = 0;

    /* Plaintext is always <= ciphertext; reject undersized buffers. */
    if (output_cap < input_len) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    pubnub_crypto_provider_t* cryptor = NULL;
    pubnub_encrypted_data_t   enc;
    memset(&enc, 0, sizeof(enc));

    if (pn_crypto_header_is_present(input, input_len)) {
        /* PNED header present: parse and dispatch by identifier. */
        pn_crypto_header_t header;
        pubnub_res_t res = pn_crypto_header_parse(input, input_len, &header);
        if (PUBNUB_OK != res) {
            return PUBNUB_ERR_CRYPTO;
        }

        cryptor = pn_find_cryptor(module, header.identifier);
        if (NULL == cryptor) {
            return PUBNUB_ERR_CRYPTO;
        }

        /* Metadata sits between the header prefix and ciphertext. */
        size_t prefix_len = header.header_len - header.metadata_len;
        enc.metadata =
            (uint8_t*)(input + prefix_len); /* NOLINT: const-cast for borrowed pointer */
        enc.metadata_len = header.metadata_len;

        enc.data     = (uint8_t*)(input + header.header_len);
        enc.data_len = input_len - header.header_len;
    } else {
        /* No PNED header: legacy format. Pass entire blob as data. */
        cryptor = pn_find_cryptor(module, pn_legacy_identifier);
        if (NULL == cryptor) {
            return PUBNUB_ERR_CRYPTO;
        }

        enc.data = (uint8_t*)input; /* NOLINT: const-cast for borrowed pointer */
        enc.data_len     = input_len;
        enc.metadata     = NULL;
        enc.metadata_len = 0;
    }

    if (NULL == cryptor->decrypt) {
        return PUBNUB_ERR_CRYPTO;
    }

    size_t       dec_len = output_cap;
    pubnub_res_t res     = cryptor->decrypt(cryptor, &enc, output, &dec_len);
    if (PUBNUB_OK != res) {
        return res;
    }

    *output_len = dec_len;
    return PUBNUB_OK;
}

pubnub_res_t pn_crypto_module_encrypt(pubnub_crypto_module_t*      module,
                                      const uint8_t*               input,
                                      size_t                       input_len,
                                      uint8_t**                    output,
                                      size_t*                      output_len,
                                      pubnub_allocator_provider_t* alloc)
{
    if (NULL == output || NULL == output_len || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *output     = NULL;
    *output_len = 0;

    size_t needed = pubnub_crypto_module_encrypt_size(module, input_len);
    if (0 == needed) {
        return PUBNUB_ERR_CRYPTO;
    }

    uint8_t* buf = (uint8_t*)PN_ALLOC(alloc, needed, 1);
    if (NULL == buf) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    size_t       actual = 0;
    pubnub_res_t res    = pubnub_crypto_module_encrypt_buf(
        module, input, input_len, buf, needed, &actual);
    if (PUBNUB_OK != res) {
        PN_FREE(alloc, buf);
        return res;
    }

    *output     = buf;
    *output_len = actual;
    return PUBNUB_OK;
}

pubnub_res_t pn_crypto_module_decrypt(pubnub_crypto_module_t*      module,
                                      const uint8_t*               input,
                                      size_t                       input_len,
                                      uint8_t**                    output,
                                      size_t*                      output_len,
                                      pubnub_allocator_provider_t* alloc)
{
    if (NULL == output || NULL == output_len || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *output     = NULL;
    *output_len = 0;

    /* Plaintext is always <= ciphertext size; allocate input_len. */
    uint8_t* buf = (uint8_t*)PN_ALLOC(alloc, input_len, 1);
    if (NULL == buf) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    size_t       actual = 0;
    pubnub_res_t res    = pubnub_crypto_module_decrypt_buf(
        module, input, input_len, buf, input_len, &actual);
    if (PUBNUB_OK != res) {
        PN_FREE(alloc, buf);
        return res;
    }

    *output     = buf;
    *output_len = actual;
    return PUBNUB_OK;
}

pubnub_res_t pn_crypto_module_encrypt_to_base64(pubnub_crypto_module_t* module,
                                                const uint8_t*          input,
                                                size_t  input_len,
                                                char**  out_base64,
                                                size_t* out_len,
                                                pubnub_allocator_provider_t* alloc)
{
    if (NULL == out_base64 || NULL == out_len || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_base64 = NULL;
    *out_len    = 0;

    /* Step 1: encrypt to binary. */
    uint8_t*     enc_buf = NULL;
    size_t       enc_len = 0;
    pubnub_res_t res     = pn_crypto_module_encrypt(
        module, input, input_len, &enc_buf, &enc_len, alloc);
    if (PUBNUB_OK != res) {
        return res;
    }

    /* Step 2: base64-encode. */
    size_t b64_size = pn_base64_encoded_len(enc_len);
    char*  b64_buf  = (char*)PN_ALLOC(alloc, b64_size, 1);
    if (NULL == b64_buf) {
        PN_FREE(alloc, enc_buf);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    res = pn_base64_encode(enc_buf, enc_len, b64_buf, b64_size);
    PN_FREE(alloc, enc_buf);

    if (PUBNUB_OK != res) {
        PN_FREE(alloc, b64_buf);
        return res;
    }

    *out_base64 = b64_buf;
    /* Length excludes NUL terminator. */
    *out_len = b64_size - 1;
    return PUBNUB_OK;
}

pubnub_res_t pn_crypto_module_decrypt_from_base64(pubnub_crypto_module_t* module,
                                                  const char* base64,
                                                  size_t      base64_len,
                                                  uint8_t**   output,
                                                  size_t*     output_len,
                                                  pubnub_allocator_provider_t* alloc)
{
    if (NULL == output || NULL == output_len || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == base64 || 0 == base64_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *output     = NULL;
    *output_len = 0;

    /* Step 1: base64-decode. */
    size_t   dec_max = pn_base64_decoded_max_len(base64_len);
    uint8_t* dec_buf = (uint8_t*)PN_ALLOC(alloc, dec_max, 1);
    if (NULL == dec_buf) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    size_t       dec_len = 0;
    pubnub_res_t res =
        pn_base64_decode(base64, base64_len, dec_buf, dec_max, &dec_len);
    if (PUBNUB_OK != res) {
        PN_FREE(alloc, dec_buf);
        return PUBNUB_ERR_CRYPTO;
    }

    /* Step 2: decrypt the binary blob. */
    uint8_t* plain_buf = NULL;
    size_t   plain_len = 0;
    res                = pn_crypto_module_decrypt(
        module, dec_buf, dec_len, &plain_buf, &plain_len, alloc);
    PN_FREE(alloc, dec_buf);

    if (PUBNUB_OK != res) {
        return res;
    }

    *output     = plain_buf;
    *output_len = plain_len;
    return PUBNUB_OK;
}

pubnub_crypto_provider_t*
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_crypto_module_default_cryptor(pubnub_crypto_module_t* module)
{
    if (NULL == module) {
        return NULL;
    }
    return module->default_cryptor;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pubnub_crypto_module_encrypt(pubnub_crypto_module_t* module,
                                          const uint8_t*          input,
                                          size_t                  input_len,
                                          uint8_t**               output,
                                          size_t*                 output_len)
{
    if (NULL == module) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_crypto_module_encrypt(
        module, input, input_len, output, output_len, module->alloc);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pubnub_crypto_module_decrypt(pubnub_crypto_module_t* module,
                                          const uint8_t*          input,
                                          size_t                  input_len,
                                          uint8_t**               output,
                                          size_t*                 output_len)
{
    if (NULL == module) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_crypto_module_decrypt(
        module, input, input_len, output, output_len, module->alloc);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pubnub_crypto_module_encrypt_to_base64(pubnub_crypto_module_t* module,
                                                    const uint8_t* input,
                                                    size_t         input_len,
                                                    char**         out_base64,
                                                    size_t*        out_len)
{
    if (NULL == module) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_crypto_module_encrypt_to_base64(
        module, input, input_len, out_base64, out_len, module->alloc);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pubnub_crypto_module_decrypt_from_base64(pubnub_crypto_module_t* module,
                                                      const char* base64,
                                                      size_t      base64_len,
                                                      uint8_t**   output,
                                                      size_t*     output_len)
{
    if (NULL == module) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_crypto_module_decrypt_from_base64(
        module, base64, base64_len, output, output_len, module->alloc);
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void pubnub_crypto_module_free(pubnub_crypto_module_t* module, void* ptr)
{
    if (NULL == module || NULL == ptr || NULL == module->alloc) {
        return;
    }
    PN_FREE(module->alloc, ptr);
}

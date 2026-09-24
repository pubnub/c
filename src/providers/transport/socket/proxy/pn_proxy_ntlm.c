/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_proxy_ntlm.h"

#include "pn_proxy_md4.h"
#include "pn_proxy_md5.h"

#include <string.h>

/* NTLM signature (8 bytes including the trailing NUL). */
static const uint8_t ntlm_signature[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'};

/* NTLMv2 negotiate flags for Type 1. */
#define PN_NTLM_NEGOTIATE_UNICODE       0x00000001U
#define PN_NTLM_NEGOTIATE_OEM           0x00000002U
#define PN_NTLM_REQUEST_TARGET          0x00000004U
#define PN_NTLM_NEGOTIATE_NTLM          0x00000200U
#define PN_NTLM_NEGOTIATE_ALWAYS_SIGN   0x00008000U
#define PN_NTLM_NEGOTIATE_EXTENDED_SESS 0x00080000U

/** @brief Type 1 fixed negotiate flags. */
#define PN_NTLM_TYPE1_FLAGS                            \
    (PN_NTLM_NEGOTIATE_UNICODE | PN_NTLM_NEGOTIATE_OEM \
     | PN_NTLM_REQUEST_TARGET | PN_NTLM_NEGOTIATE_NTLM \
     | PN_NTLM_NEGOTIATE_ALWAYS_SIGN | PN_NTLM_NEGOTIATE_EXTENDED_SESS)

/** @brief Write a uint32_t in little-endian. */
static void ntlm_write_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)((v >> 24) & 0xffU);
}

/** @brief Write a uint16_t in little-endian. */
static void ntlm_write_u16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
}

/** @brief Read a uint32_t in little-endian. */
static uint32_t ntlm_read_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/** @brief Read a uint16_t in little-endian. */
static uint16_t ntlm_read_u16(const uint8_t* p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/**
 * @brief Compute HMAC-MD5 using the existing MD5 streaming wrapper.
 *
 * Standard HMAC construction per RFC 2104.
 */
static void ntlm_hmac_md5(const uint8_t* key,
                          size_t         key_len,
                          const uint8_t* data,
                          size_t         data_len,
                          uint8_t        digest[16])
{
    uint8_t key_block[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[16];

    memset(key_block, 0, sizeof(key_block));

    if (key_len > 64) {
        pn_proxy_md5_ctx_t ctx;
        pn_proxy_md5_init(&ctx);
        pn_proxy_md5_update(&ctx, key, key_len);
        pn_proxy_md5_final(&ctx, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < 64; ++i) {
        ipad[i] = key_block[i] ^ 0x36U;
        opad[i] = key_block[i] ^ 0x5cU;
    }

    /* Inner hash: H(K xor ipad || data) */
    pn_proxy_md5_ctx_t ctx;
    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, ipad, 64);
    pn_proxy_md5_update(&ctx, data, data_len);
    pn_proxy_md5_final(&ctx, inner);

    /* Outer hash: H(K xor opad || inner) */
    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, opad, 64);
    pn_proxy_md5_update(&ctx, inner, 16);
    pn_proxy_md5_final(&ctx, digest);

    /* Scrub intermediate secrets (ipad/opad encode key XOR constant). */
    volatile uint8_t* vp = (volatile uint8_t*)key_block;
    for (int i = 0; i < 64; ++i) {
        vp[i] = 0;
    }
    vp = (volatile uint8_t*)ipad;
    for (int i = 0; i < 64; ++i) {
        vp[i] = 0;
    }
    vp = (volatile uint8_t*)opad;
    for (int i = 0; i < 64; ++i) {
        vp[i] = 0;
    }
    vp = (volatile uint8_t*)inner;
    for (int i = 0; i < 16; ++i) {
        vp[i] = 0;
    }
}

/**
 * @brief HMAC-MD5 with two data segments (avoids concatenation buffer).
 *
 * Computes HMAC-MD5(key, data1 || data2).
 */
static void ntlm_hmac_md5_two(const uint8_t* key,
                              size_t         key_len,
                              const uint8_t* data1,
                              size_t         data1_len,
                              const uint8_t* data2,
                              size_t         data2_len,
                              uint8_t        digest[16])
{
    uint8_t key_block[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[16];

    memset(key_block, 0, sizeof(key_block));

    if (key_len > 64) {
        pn_proxy_md5_ctx_t ctx;
        pn_proxy_md5_init(&ctx);
        pn_proxy_md5_update(&ctx, key, key_len);
        pn_proxy_md5_final(&ctx, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < 64; ++i) {
        ipad[i] = key_block[i] ^ 0x36U;
        opad[i] = key_block[i] ^ 0x5cU;
    }

    pn_proxy_md5_ctx_t ctx;
    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, ipad, 64);
    pn_proxy_md5_update(&ctx, data1, data1_len);
    pn_proxy_md5_update(&ctx, data2, data2_len);
    pn_proxy_md5_final(&ctx, inner);

    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, opad, 64);
    pn_proxy_md5_update(&ctx, inner, 16);
    pn_proxy_md5_final(&ctx, digest);

    volatile uint8_t* vp = (volatile uint8_t*)key_block;
    for (int i = 0; i < 64; ++i) {
        vp[i] = 0;
    }
    vp = (volatile uint8_t*)ipad;
    for (int i = 0; i < 64; ++i) {
        vp[i] = 0;
    }
    vp = (volatile uint8_t*)opad;
    for (int i = 0; i < 64; ++i) {
        vp[i] = 0;
    }
    vp = (volatile uint8_t*)inner;
    for (int i = 0; i < 16; ++i) {
        vp[i] = 0;
    }
}

/**
 * @brief Convert ASCII string to UTF-16LE in-place.
 *
 * Each ASCII byte becomes two bytes: [char, 0x00].
 *
 * @return Number of bytes written (2 * len).
 */
static size_t ntlm_ascii_to_utf16le(const char* src, size_t len, uint8_t* dst, size_t dst_cap)
{
    if (len * 2 > dst_cap) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        dst[i * 2]     = (uint8_t)src[i];
        dst[i * 2 + 1] = 0;
    }
    return len * 2;
}

/**
 * @brief Convert ASCII char to uppercase.
 */
static char ntlm_toupper(char c)
{
    if (c >= 'a' && c <= 'z') {
        return (char)(c - 32);
    }
    return c;
}

size_t pn_ntlm_type1_build(uint8_t* output, size_t out_cap)
{
    /* Type 1 message is 32 bytes (fixed, no domain/workstation). */
    if (NULL == output || out_cap < 32) {
        return 0;
    }

    memset(output, 0, 32);

    /* Signature */
    memcpy(output, ntlm_signature, 8);

    /* Type indicator: 1 */
    ntlm_write_u32(output + 8, 1);

    /* Flags */
    ntlm_write_u32(output + 12, PN_NTLM_TYPE1_FLAGS);

    /* Domain name fields (len, max_len, offset) — all zero (empty). */
    /* Workstation fields — all zero (empty). */
    /* Offsets 16..31 are already zeroed. */

    return 32;
}

int pn_ntlm_type2_parse(const uint8_t* data, size_t len, pn_ntlm_type2_t* out)
{
    if (NULL == data || NULL == out) {
        return -1;
    }

    /* Minimum Type 2 size: signature(8) + type(4) + target_name(8) +
     * flags(4) + challenge(8) = 32 bytes. */
    if (len < 32) {
        return -1;
    }

    /* Verify NTLMSSP signature. */
    if (0 != memcmp(data, ntlm_signature, 8)) {
        return -1;
    }

    /* Verify type indicator is 2. */
    if (2 != ntlm_read_u32(data + 8)) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Flags at offset 20. */
    out->flags = ntlm_read_u32(data + 20);

    /* Server challenge at offset 24 (8 bytes). */
    memcpy(out->server_challenge, data + 24, 8);

    /* TargetName security buffer at offsets 12-19 (len:2, maxlen:2, offset:4).
     * Strip UTF-16LE null high-bytes to recover the ASCII domain name.
     * If any high byte is non-zero the domain falls back to "" silently. */
    {
        uint16_t tn_len    = ntlm_read_u16(data + 12);
        uint32_t tn_offset = ntlm_read_u32(data + 16);

        if (tn_len > 0 && tn_offset <= (uint32_t)len
            && (uint32_t)tn_len <= (uint32_t)len - tn_offset) {
            size_t char_count = tn_len / 2U;
            if (char_count > sizeof(out->target_name) - 1U) {
                char_count = sizeof(out->target_name) - 1U;
            }
            size_t i;
            int    valid = 1;
            for (i = 0; i < char_count; ++i) {
                uint8_t lo = data[tn_offset + i * 2U];
                uint8_t hi = data[tn_offset + i * 2U + 1U];
                if (0 != hi) {
                    valid = 0;
                    break;
                }
                out->target_name[i] = (char)lo;
            }
            if (valid) {
                out->target_name[char_count] = '\0';
                out->target_name_len         = char_count;
            }
            /* On non-ASCII: target_name stays "" from memset above. */
        }
    }

    /* Target info: only present if message is at least 48 bytes
     * (the target info fields start at offset 40). */
    if (len >= 48) {
        uint16_t ti_len    = ntlm_read_u16(data + 40);
        uint32_t ti_offset = ntlm_read_u32(data + 44);

        if (ti_len > 0 && ti_offset <= len && ti_len <= len - ti_offset) {
            out->target_info     = data + ti_offset;
            out->target_info_len = ti_len;
        }
    }

    return 0;
}

/**
 * @brief Compute NT hash: MD4(UTF-16LE(password)).
 *
 * @return 0 on success, -1 if password exceeds internal buffer.
 */
static int ntlm_compute_nt_hash(const char* password, uint8_t nt_hash[16])
{
    size_t  pwd_len = strlen(password);
    uint8_t pwd_utf16[256];

    if (pwd_len > sizeof(pwd_utf16) / 2) {
        return -1;
    }

    size_t utf16_len =
        ntlm_ascii_to_utf16le(password, pwd_len, pwd_utf16, sizeof(pwd_utf16));
    pn_proxy_md4(pwd_utf16, utf16_len, nt_hash);

    volatile uint8_t* vp = (volatile uint8_t*)pwd_utf16;
    for (size_t i = 0; i < sizeof(pwd_utf16); ++i) {
        vp[i] = 0;
    }
    return 0;
}

/**
 * @brief Compute NTLMv2 hash: HMAC-MD5(NT_hash, UTF16LE(UPPER(user) + domain)).
 *
 * @return 0 on success, -1 if username+domain exceeds internal buffer.
 */
static int ntlm_compute_ntlmv2_hash(const uint8_t nt_hash[16],
                                    const char*   username,
                                    const char*   domain,
                                    uint8_t       ntlmv2_hash[16])
{
    size_t  uname_len  = strlen(username);
    size_t  domain_len = strlen(domain);
    uint8_t user_domain[512];
    size_t  ud_offset = 0;

    if ((uname_len + domain_len) * 2 > sizeof(user_domain)) {
        return -1;
    }

    /* Uppercase username to UTF-16LE. */
    for (size_t i = 0; i < uname_len; ++i) {
        user_domain[ud_offset]     = (uint8_t)ntlm_toupper(username[i]);
        user_domain[ud_offset + 1] = 0;
        ud_offset += 2;
    }

    /* Domain to UTF-16LE (case-preserved). */
    for (size_t i = 0; i < domain_len; ++i) {
        user_domain[ud_offset]     = (uint8_t)domain[i];
        user_domain[ud_offset + 1] = 0;
        ud_offset += 2;
    }

    ntlm_hmac_md5(nt_hash, 16, user_domain, ud_offset, ntlmv2_hash);

    volatile uint8_t* vp = (volatile uint8_t*)user_domain;
    for (size_t i = 0; i < sizeof(user_domain); ++i) {
        vp[i] = 0;
    }
    return 0;
}

/**
 * @brief Build the NTLMv2 blob (client challenge + timestamp + target info).
 *
 * @return Blob size in bytes, or 0 if output buffer is too small.
 */
static size_t ntlm_build_blob(const pn_ntlm_type2_t* type2,
                              const uint8_t          client_challenge[8],
                              uint64_t               timestamp,
                              uint8_t*               out,
                              size_t                 cap)
{
    size_t ti_len   = (size_t)type2->target_info_len;
    size_t blob_len = 28 + ti_len + 4;

    if (blob_len > cap) {
        return 0;
    }

    memset(out, 0, blob_len);
    out[0] = 0x01; /* RespType */
    out[1] = 0x01; /* HiRespType */

    /* Timestamp at offset 8 (8 bytes, little-endian). */
    out[8]  = (uint8_t)(timestamp & 0xffU);
    out[9]  = (uint8_t)((timestamp >> 8) & 0xffU);
    out[10] = (uint8_t)((timestamp >> 16) & 0xffU);
    out[11] = (uint8_t)((timestamp >> 24) & 0xffU);
    out[12] = (uint8_t)((timestamp >> 32) & 0xffU);
    out[13] = (uint8_t)((timestamp >> 40) & 0xffU);
    out[14] = (uint8_t)((timestamp >> 48) & 0xffU);
    out[15] = (uint8_t)((timestamp >> 56) & 0xffU);

    /* Client challenge at offset 16. */
    memcpy(out + 16, client_challenge, 8);

    /* Target info at offset 28. */
    if (ti_len > 0 && NULL != type2->target_info) {
        memcpy(out + 28, type2->target_info, ti_len);
    }

    return blob_len;
}

size_t pn_ntlm_type3_build(const pn_ntlm_type2_t* type2,
                           const char*            username,
                           const char*            password,
                           const char*            domain,
                           const uint8_t          client_challenge[8],
                           uint64_t               timestamp,
                           uint8_t*               output,
                           size_t                 out_cap)
{
    if (NULL == type2 || NULL == username || NULL == password || NULL == domain
        || NULL == client_challenge || NULL == output) {
        return 0;
    }

    size_t uname_len  = strlen(username);
    size_t domain_len = strlen(domain);

    /* Step 1: NT hash = MD4(UTF-16LE(password)). */
    uint8_t nt_hash[16];
    if (0 != ntlm_compute_nt_hash(password, nt_hash)) {
        return 0;
    }

    /* Step 2: NTLMv2 hash = HMAC-MD5(NT_hash, UTF16LE(UPPER(user)+domain)). */
    uint8_t ntlmv2_hash[16];
    if (0 != ntlm_compute_ntlmv2_hash(nt_hash, username, domain, ntlmv2_hash)) {
        volatile uint8_t* vp = (volatile uint8_t*)nt_hash;
        for (int i = 0; i < 16; ++i) {
            vp[i] = 0;
        }
        return 0;
    }

    /* Scrub NT hash — no longer needed. */
    {
        volatile uint8_t* vp = (volatile uint8_t*)nt_hash;
        for (int i = 0; i < 16; ++i) {
            vp[i] = 0;
        }
    }

    /* Step 3: Build the NTLMv2 blob. */
    uint8_t blob[384];
    size_t  blob_len =
        ntlm_build_blob(type2, client_challenge, timestamp, blob, sizeof(blob));
    if (0 == blob_len) {
        volatile uint8_t* vp = (volatile uint8_t*)ntlmv2_hash;
        for (int i = 0; i < 16; ++i) {
            vp[i] = 0;
        }
        return 0;
    }

    /* Step 4: NTProofStr = HMAC-MD5(NTLMv2_hash, server_challenge || blob). */
    uint8_t nt_proof_str[16];
    ntlm_hmac_md5_two(
        ntlmv2_hash, 16, type2->server_challenge, 8, blob, blob_len, nt_proof_str);

    /* Scrub NTLMv2 hash. */
    {
        volatile uint8_t* vp = (volatile uint8_t*)ntlmv2_hash;
        for (int i = 0; i < 16; ++i) {
            vp[i] = 0;
        }
    }

    /* NT response = NTProofStr(16) + blob. */
    size_t nt_response_len = 16 + blob_len;

    /* Payload field sizes (all UTF-16LE). */
    uint16_t domain_field_len   = (uint16_t)(domain_len * 2);
    uint16_t username_field_len = (uint16_t)(uname_len * 2);
    uint16_t nt_resp_field_len  = (uint16_t)nt_response_len;
    uint16_t lm_resp_field_len  = 24;

    /* Type 3 header is 72 bytes (standard layout with flags). */
    uint32_t payload_offset = 72;
    size_t   total_size     = (size_t)payload_offset + lm_resp_field_len
                      + nt_resp_field_len + domain_field_len + username_field_len;

    if (total_size > out_cap || total_size > PN_NTLM_MAX_MSG_SIZE) {
        return 0;
    }

    memset(output, 0, total_size);

    /* Header. */
    memcpy(output, ntlm_signature, 8);
    ntlm_write_u32(output + 8, 3);

    /* Security buffer offsets (payload order: LM, NT, domain, username). */
    uint32_t lm_offset     = payload_offset;
    uint32_t nt_offset     = lm_offset + lm_resp_field_len;
    uint32_t domain_offset = nt_offset + nt_resp_field_len;
    uint32_t user_offset   = domain_offset + domain_field_len;

    /* LM Response security buffer: offset 12. */
    ntlm_write_u16(output + 12, lm_resp_field_len);
    ntlm_write_u16(output + 14, lm_resp_field_len);
    ntlm_write_u32(output + 16, lm_offset);

    /* NT Response security buffer: offset 20. */
    ntlm_write_u16(output + 20, nt_resp_field_len);
    ntlm_write_u16(output + 22, nt_resp_field_len);
    ntlm_write_u32(output + 24, nt_offset);

    /* Domain security buffer: offset 28. */
    ntlm_write_u16(output + 28, domain_field_len);
    ntlm_write_u16(output + 30, domain_field_len);
    ntlm_write_u32(output + 32, domain_offset);

    /* Username security buffer: offset 36. */
    ntlm_write_u16(output + 36, username_field_len);
    ntlm_write_u16(output + 38, username_field_len);
    ntlm_write_u32(output + 40, user_offset);

    /* Workstation security buffer: offset 44 (empty). */
    ntlm_write_u16(output + 44, 0);
    ntlm_write_u16(output + 46, 0);
    ntlm_write_u32(output + 48, (uint32_t)total_size);

    /* Encrypted random session key: offset 52 (empty). */
    ntlm_write_u16(output + 52, 0);
    ntlm_write_u16(output + 54, 0);
    ntlm_write_u32(output + 56, (uint32_t)total_size);

    /* Negotiate flags: offset 60. */
    ntlm_write_u32(output + 60, PN_NTLM_TYPE1_FLAGS);

    /* Payload: NT response = NTProofStr + blob. */
    memcpy(output + nt_offset, nt_proof_str, 16);
    memcpy(output + nt_offset + 16, blob, blob_len);

    /* Payload: domain (UTF-16LE). */
    ntlm_ascii_to_utf16le(
        domain, domain_len, output + domain_offset, total_size - domain_offset);

    /* Payload: username (UTF-16LE). */
    ntlm_ascii_to_utf16le(
        username, uname_len, output + user_offset, total_size - user_offset);

    /* Scrub remaining intermediate secrets. */
    {
        volatile uint8_t* vp = (volatile uint8_t*)nt_proof_str;
        for (int i = 0; i < 16; ++i) {
            vp[i] = 0;
        }
        vp = (volatile uint8_t*)blob;
        for (size_t i = 0; i < blob_len; ++i) {
            vp[i] = 0;
        }
    }

    return total_size;
}

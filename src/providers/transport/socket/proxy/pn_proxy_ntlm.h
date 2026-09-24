/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief NTLM authentication message generation for HTTP proxy tunneling.
 *
 * Implements NTLMv2 challenge-response protocol (Type 1/2/3 messages).
 * Only ASCII username/password/domain are supported; non-ASCII
 * credentials require full Unicode conversion which is out of scope.
 */

#ifndef PN_PROXY_NTLM_H
#define PN_PROXY_NTLM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Maximum NTLM message size (Type 3 can reach ~400 bytes). */
#define PN_NTLM_MAX_MSG_SIZE 512

/**
 * @brief Parsed NTLM Type 2 (Challenge) message fields.
 */
typedef struct pn_ntlm_type2 {
    /** Server challenge (8 bytes, always present). */
    uint8_t server_challenge[8];
    /** Negotiate flags from the server. */
    uint32_t flags;
    /** Pointer into the original Type 2 buffer (borrowed). */
    const uint8_t* target_info;
    /** Length of target_info in bytes. */
    uint16_t target_info_len;
    /**
     * NetBIOS domain name from the TargetName security buffer, converted
     * from UTF-16LE to ASCII. Empty string when absent or when any code
     * unit has a non-zero high byte (non-ASCII domain name).
     */
    char target_name[64];
    /** Length of target_name excluding the NUL terminator. */
    size_t target_name_len;
} pn_ntlm_type2_t;

/**
 * @brief Generate an NTLM Type 1 (Negotiate) message.
 *
 * The Type 1 message announces client capabilities. It uses a fixed
 * flag set suitable for NTLMv2 authentication with HTTP proxies.
 *
 * @param output   Buffer for the binary message.
 * @param out_cap  Buffer capacity in bytes.
 * @return Bytes written, or 0 if the buffer is too small.
 */
size_t pn_ntlm_type1_build(uint8_t* output, size_t out_cap);

/**
 * @brief Parse an NTLM Type 2 (Challenge) message.
 *
 * Extracts server challenge, negotiate flags, and target info from
 * the binary Type 2 message. The target_info pointer in @p out
 * references memory within @p data (borrowed, not copied).
 *
 * @param data  Binary Type 2 message.
 * @param len   Message length in bytes.
 * @param out   Parsed result.
 * @return 0 on success, -1 on malformed message.
 */
int pn_ntlm_type2_parse(const uint8_t* data, size_t len, pn_ntlm_type2_t* out);

/**
 * @brief Generate an NTLM Type 3 (Authenticate) message.
 *
 * Computes the NTLMv2 response using the parsed server challenge and
 * the user's credentials. All intermediate key material is zeroed
 * before returning.
 *
 * @param type2             Parsed Type 2 challenge.
 * @param username          Username (NUL-terminated, ASCII only).
 * @param password          Password (NUL-terminated, ASCII only).
 * @param domain            Domain (NUL-terminated, may be empty "").
 * @param client_challenge  8 random bytes from the platform provider.
 * @param timestamp         Windows FILETIME (100ns intervals since
 *                          1601-01-01). Pass 0 if unavailable.
 * @param output            Buffer for the binary message.
 * @param out_cap           Buffer capacity in bytes.
 * @return Bytes written, or 0 on failure.
 */
size_t pn_ntlm_type3_build(const pn_ntlm_type2_t* type2,
                           const char*            username,
                           const char*            password,
                           const char*            domain,
                           const uint8_t          client_challenge[8],
                           uint64_t               timestamp,
                           uint8_t*               output,
                           size_t                 out_cap);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PROXY_NTLM_H */

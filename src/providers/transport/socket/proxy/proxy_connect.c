/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "proxy_connect.h"

#include "connection_fsm_internal.h"
#include "providers/transport/socket/platform/pn_socket_platform_ops.h"
#include "transport_socket_internal.h"

#include "core/pn_format.h"
#include "core/protocol_common/pn_base64.h"

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"

#include <string.h>

#if PUBNUB_ENABLE_PROXY
#include "pn_proxy_md5.h"
#include "pn_proxy_ntlm.h"
#endif

/** @brief Internal state for the CONNECT negotiation FSM. */
typedef enum {
    PN_PROXY_CONNECT_SEND_REQUEST = 0,
    PN_PROXY_CONNECT_RECV_RESPONSE,
    PN_PROXY_CONNECT_SEND_AUTH_REQUEST,
    PN_PROXY_CONNECT_RECV_AUTH_RESPONSE
} pn_proxy_connect_state_t;

/** @brief Maximum CONNECT request size (host + auth header + framing).
 *  NTLM Type 3 base64 can reach ~700 bytes with CONNECT framing. */
#ifndef PN_PROXY_CONNECT_BUF_SIZE
#define PN_PROXY_CONNECT_BUF_SIZE 768
#endif

/** @brief Maximum proxy response buffer (status line + headers). */
#ifndef PN_PROXY_RESPONSE_BUF_SIZE
#define PN_PROXY_RESPONSE_BUF_SIZE 512
#endif

/** @brief Maximum realm length from Proxy-Authenticate header. */
#define PN_PROXY_DIGEST_REALM_SIZE 64

/** @brief Maximum nonce length from Proxy-Authenticate header. */
#define PN_PROXY_DIGEST_NONCE_SIZE 128

/** @brief Maximum qop value length ("auth" or empty). */
#define PN_PROXY_DIGEST_QOP_SIZE 16

/**
 * @brief Per-connection proxy negotiation session.
 *
 * Allocated when negotiate_start is called, freed on COMPLETE/ERROR/cancel.
 * Holds per-negotiation buffers and progress state. Eliminates shared-state
 * races when PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS >= 2.
 */
typedef struct pn_proxy_connect_session {
    /** CONNECT request buffer. */
    char request_buf[PN_PROXY_CONNECT_BUF_SIZE];
    /** Total length of the CONNECT request. */
    uint16_t request_len;
    /** Bytes of request already sent. */
    uint16_t request_sent;

    /** Response buffer (enlarged for Digest challenge headers). */
    char response_buf[PN_PROXY_RESPONSE_BUF_SIZE];
    /** Bytes of response received so far. */
    uint16_t response_len;

    /** Current negotiation sub-state. */
    uint8_t state;

    /** Target hostname for CONNECT (needed for Digest auth retry). */
    char target_host[PUBNUB_CFG_MAX_HOSTNAME_LEN];
    /** Target port for CONNECT (needed for Digest auth retry). */
    uint16_t target_port;

    /** Digest auth challenge: realm from Proxy-Authenticate header. */
    char realm[PN_PROXY_DIGEST_REALM_SIZE];
    /** Digest auth challenge: nonce from Proxy-Authenticate header. */
    char nonce[PN_PROXY_DIGEST_NONCE_SIZE];
    /** Digest auth challenge: qop from Proxy-Authenticate header. */
    char qop[PN_PROXY_DIGEST_QOP_SIZE];
    /** Client-generated nonce (8 hex chars + NUL). */
    char cnonce[9];

    /** NTLM: decoded Type 2 challenge message. */
    uint8_t ntlm_type2_buf[256];
    /** NTLM: length of decoded Type 2 message. */
    uint16_t ntlm_type2_len;
} pn_proxy_connect_session_t;

#include "pubnub/pubnub_compat.h"
PUBNUB_STATIC_ASSERT(
    sizeof(pn_proxy_connect_session_t) <= PN_PROXY_CONNECT_SESSION_SIZE,
    "PN_PROXY_CONNECT_SESSION_SIZE must accommodate session struct");

/**
 * @brief HTTP CONNECT proxy module (stateless, singleton-safe).
 *
 * Holds only the vtable and config reference. All per-negotiation state
 * is in pn_proxy_connect_session_t. Multiple connections can negotiate
 * simultaneously without interference.
 */
typedef struct pn_proxy_connect_module {
    /** Vtable (must be first member for pn_proxy_module_t* cast). */
    pn_proxy_module_t base;

    /** Configuration reference (must remain valid for module lifetime). */
    const pn_proxy_config_t* config;

    /** Allocator for session alloc/free. */
    struct pubnub_allocator_provider* allocator;
} pn_proxy_connect_module_t;

/**
 * @brief Find the end of HTTP headers (\r\n\r\n) in the response.
 *
 * @return Pointer past the terminator, or NULL if not yet found.
 */
static const char* proxy_find_header_end(const char* buf, size_t len)
{
    if (len < 4) {
        return NULL;
    }
    for (size_t i = 0; i <= len - 4; ++i) {
        if ('\r' == buf[i] && '\n' == buf[i + 1] && '\r' == buf[i + 2]
            && '\n' == buf[i + 3]) {
            return &buf[i + 4];
        }
    }
    return NULL;
}

/**
 * @brief Parse the HTTP status code from the response status line.
 *
 * Expects "HTTP/1.x NNN ...". Returns the 3-digit status code,
 * or 0 if the line is malformed.
 */
static int proxy_parse_status_code(const char* buf, size_t len)
{
    if (len < 12) {
        return 0;
    }
    if (0 != memcmp(buf, "HTTP/1.", 7)) {
        return 0;
    }

    const char* space = (const char*)memchr(buf, ' ', len);
    if (NULL == space) {
        return 0;
    }

    const char* code_start = space + 1;
    size_t      remaining  = len - (size_t)(code_start - buf);
    if (remaining < 3) {
        return 0;
    }
    if (code_start[0] < '0' || code_start[0] > '9' || code_start[1] < '0'
        || code_start[1] > '9' || code_start[2] < '0' || code_start[2] > '9') {
        return 0;
    }

    return (code_start[0] - '0') * 100 + (code_start[1] - '0') * 10
         + (code_start[2] - '0');
}

/**
 * @brief Build the initial CONNECT request (no auth or Basic auth).
 *
 * Uses the session's response_buf as scratch space for base64 encoding
 * during Basic auth (it's unused during request building, zeroed when
 * entering the receive state).
 *
 * @return Number of bytes written, or 0 on failure.
 */
static uint16_t proxy_build_request(pn_proxy_connect_session_t* session,
                                    const pn_proxy_config_t*    config,
                                    const char*                 target_host,
                                    uint16_t                    target_port)
{
    int written = pn_snprintf(session->request_buf,
                              sizeof(session->request_buf),
                              "CONNECT %s:%u HTTP/1.1\r\n"
                              "Host: %s:%u\r\n",
                              target_host,
                              (unsigned)target_port,
                              target_host,
                              (unsigned)target_port);
    if (written < 0 || (size_t)written >= sizeof(session->request_buf)) {
        return 0;
    }

    size_t offset = (size_t)written;

    /* Append Proxy-Authorization if Basic auth is configured. */
    if (PN_PROXY_AUTH_BASIC == config->auth_type && NULL != config->username
        && NULL != config->password) {
        size_t ulen     = strlen(config->username);
        size_t plen     = strlen(config->password);
        size_t cred_len = ulen + 1 + plen;

        if (cred_len >= sizeof(session->response_buf)) {
            return 0;
        }
        memcpy(session->response_buf, config->username, ulen);
        session->response_buf[ulen] = ':';
        memcpy(session->response_buf + ulen + 1, config->password, plen);

        size_t       b64_needed = pn_base64_encoded_len(cred_len);
        pubnub_res_t res;

        if (cred_len + b64_needed >= sizeof(session->response_buf)) {
            return 0;
        }
        res = pn_base64_encode((const uint8_t*)session->response_buf,
                               cred_len,
                               session->response_buf + cred_len,
                               sizeof(session->response_buf) - cred_len);
        if (PUBNUB_OK != res) {
            return 0;
        }

        int auth_written = pn_snprintf(session->request_buf + offset,
                                       sizeof(session->request_buf) - offset,
                                       "Proxy-Authorization: Basic %s\r\n",
                                       session->response_buf + cred_len);
        if (auth_written < 0
            || (size_t)auth_written >= sizeof(session->request_buf) - offset) {
            return 0;
        }
        offset += (size_t)auth_written;
    }

    /* Append final CRLF to terminate headers. */
    if (offset + 2 >= sizeof(session->request_buf)) {
        return 0;
    }
    session->request_buf[offset]     = '\r';
    session->request_buf[offset + 1] = '\n';
    offset += 2;

    return (uint16_t)offset;
}

#if PUBNUB_ENABLE_PROXY

/**
 * @brief Bundled parameters for Digest authentication computation.
 *
 * Groups credentials and challenge fields to keep
 * proxy_compute_digest_response within the 8-parameter limit.
 */
typedef struct pn_digest_auth_params {
    const char* username;
    const char* password;
    const char* realm;
    const char* nonce;
    const char* nc_str;
    const char* cnonce;
    const char* qop;
} pn_digest_auth_params_t;

/**
 * @brief Convert a 16-byte MD5 digest to a 32-char lowercase hex string.
 */
static void proxy_md5_hex(const uint8_t digest[16], char hex[33])
{
    static const char table[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i) {
        hex[i * 2]     = table[digest[i] >> 4];
        hex[i * 2 + 1] = table[digest[i] & 0x0f];
    }
    hex[32] = '\0';
}

/**
 * @brief Generate a cnonce from 4 random bytes via the platform provider.
 *
 * Produces 8 hex characters stored in session->cnonce.
 *
 * @return 0 on success; non-zero when no random source is available or
 *         the platform RNG fails. Callers must abort the exchange on
 *         failure rather than send an all-zero cnonce.
 */
static int proxy_generate_cnonce(pn_proxy_connect_session_t* session,
                                 pn_socket_transport_t*      transport)
{
    static const char table[] = "0123456789abcdef";
    uint8_t           raw[4]  = {0};
    size_t            i;

    if (NULL == transport->platform || NULL == transport->platform->random_bytes) {
        return -1;
    }
    if (0 != transport->platform->random_bytes(transport->platform, raw, sizeof(raw))) {
        return -1;
    }

    for (i = 0; i < 4; ++i) {
        session->cnonce[i * 2]     = table[raw[i] >> 4];
        session->cnonce[i * 2 + 1] = table[raw[i] & 0x0f];
    }
    session->cnonce[8] = '\0';

    return 0;
}

/**
 * @brief Compute the Digest auth response hash (RFC 7616, MD5).
 *
 * HA1 = MD5(username:realm:password)
 * HA2 = MD5(method:uri)
 * If qop="auth": response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
 * If no qop:     response = MD5(HA1:nonce:HA2)
 */
static void proxy_compute_digest_response(const pn_digest_auth_params_t* auth,
                                          const char*                    method,
                                          const char*                    uri,
                                          char response_hex[33])
{
    pn_proxy_md5_ctx_t ctx;
    uint8_t            digest[16];
    char               ha1[33];
    char               ha2[33];

    /* HA1 = MD5(username:realm:password) */
    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, (const uint8_t*)auth->username, strlen(auth->username));
    pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
    pn_proxy_md5_update(&ctx, (const uint8_t*)auth->realm, strlen(auth->realm));
    pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
    pn_proxy_md5_update(&ctx, (const uint8_t*)auth->password, strlen(auth->password));
    pn_proxy_md5_final(&ctx, digest);
    proxy_md5_hex(digest, ha1);

    /* HA2 = MD5(method:uri) */
    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, (const uint8_t*)method, strlen(method));
    pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
    pn_proxy_md5_update(&ctx, (const uint8_t*)uri, strlen(uri));
    pn_proxy_md5_final(&ctx, digest);
    proxy_md5_hex(digest, ha2);

    /* response = MD5(HA1:nonce[:nc:cnonce:qop]:HA2) */
    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, (const uint8_t*)ha1, 32);
    pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
    pn_proxy_md5_update(&ctx, (const uint8_t*)auth->nonce, strlen(auth->nonce));
    if ('\0' != auth->qop[0]) {
        pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
        pn_proxy_md5_update(&ctx, (const uint8_t*)auth->nc_str, strlen(auth->nc_str));
        pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
        pn_proxy_md5_update(&ctx, (const uint8_t*)auth->cnonce, strlen(auth->cnonce));
        pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
        pn_proxy_md5_update(&ctx, (const uint8_t*)auth->qop, strlen(auth->qop));
    }
    pn_proxy_md5_update(&ctx, (const uint8_t*)":", 1);
    pn_proxy_md5_update(&ctx, (const uint8_t*)ha2, 32);
    pn_proxy_md5_final(&ctx, digest);
    proxy_md5_hex(digest, response_hex);

    /* Scrub intermediate secrets from stack (HA1 is credential-equivalent). */
    volatile uint8_t* p = (volatile uint8_t*)ha1;
    for (size_t i = 0; i < sizeof(ha1); ++i) {
        p[i] = 0;
    }
    p = (volatile uint8_t*)ha2;
    for (size_t i = 0; i < sizeof(ha2); ++i) {
        p[i] = 0;
    }
    p = (volatile uint8_t*)digest;
    for (size_t i = 0; i < sizeof(digest); ++i) {
        p[i] = 0;
    }
}

/**
 * @brief Extract a value from a Digest challenge key=value pair.
 *
 * Searches for `key=` (case-insensitive) in the header data. Copies
 * the unquoted value into dst (up to dst_size-1 chars + NUL).
 *
 * @return 1 if found, 0 otherwise.
 */
static int proxy_extract_digest_param(const char* header,
                                      size_t      header_len,
                                      const char* key,
                                      char*       dst,
                                      size_t      dst_size)
{
    size_t key_len = strlen(key);
    dst[0]         = '\0';

    for (size_t i = 0; i + key_len + 1 < header_len; ++i) {
        /* Case-insensitive key match followed by '='. */
        int match = 1;
        for (size_t k = 0; k < key_len; ++k) {
            char a = header[i + k];
            char b = key[k];
            if (a >= 'A' && a <= 'Z') {
                a = (char)(a + 32);
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char)(b + 32);
            }
            if (a != b) {
                match = 0;
                break;
            }
        }
        if (!match || '=' != header[i + key_len]) {
            continue;
        }

        /* Ensure key is preceded by separator or start of data. */
        if (i > 0) {
            char prev = header[i - 1];
            if (' ' != prev && ',' != prev && '\t' != prev) {
                continue;
            }
        }

        const char* val_start = header + i + key_len + 1;
        size_t      rem       = header_len - (i + key_len + 1);

        int    quoted = (rem > 0 && '"' == val_start[0]);
        size_t vi     = quoted ? 1 : 0;
        size_t di     = 0;

        while (vi < rem && di < dst_size - 1) {
            char ch = val_start[vi];
            if (quoted) {
                if ('"' == ch) {
                    break;
                }
            } else {
                if (',' == ch || ' ' == ch || '\r' == ch || '\t' == ch) {
                    break;
                }
            }
            dst[di++] = ch;
            ++vi;
        }
        dst[di] = '\0';
        return 1;
    }
    return 0;
}

/**
 * @brief Parse Proxy-Authenticate: Digest challenge from the 407 response.
 *
 * Extracts realm, nonce, and qop from the first Digest challenge found.
 *
 * @return 1 if a valid Digest challenge was parsed, 0 otherwise.
 */
static int proxy_parse_digest_challenge(pn_proxy_connect_session_t* session)
{
    const char* search    = "proxy-authenticate:";
    size_t      slen      = 19;
    const char* buf       = session->response_buf;
    size_t      total_len = (size_t)session->response_len;
    const char* hdr       = NULL;

    /* Find the header (case-insensitive). */
    for (size_t i = 0; i + slen < total_len; ++i) {
        int match = 1;
        for (size_t j = 0; j < slen; ++j) {
            char a = buf[i + j];
            if (a >= 'A' && a <= 'Z') {
                a = (char)(a + 32);
            }
            if (a != search[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            hdr = buf + i + slen;
            break;
        }
    }

    if (NULL == hdr) {
        return 0;
    }

    /* Skip whitespace after colon. */
    while (hdr < buf + total_len && (' ' == *hdr || '\t' == *hdr)) {
        ++hdr;
    }

    /* Verify "Digest" scheme. */
    size_t hdr_remaining = (size_t)(buf + total_len - hdr);
    if (hdr_remaining < 7) {
        return 0;
    }
    char scheme[7];
    for (int i = 0; i < 6; ++i) {
        scheme[i] = hdr[i];
        if (scheme[i] >= 'A' && scheme[i] <= 'Z') {
            scheme[i] = (char)(scheme[i] + 32);
        }
    }
    scheme[6] = '\0';
    if (0 != memcmp(scheme, "digest", 6)) {
        return 0;
    }

    /* Find the end of this header line. */
    const char* line_end = (const char*)memchr(hdr, '\r', hdr_remaining);
    if (NULL == line_end) {
        line_end = buf + total_len;
    }
    size_t params_len = (size_t)(line_end - hdr);

    /* Extract realm, nonce, qop. */
    int got_realm = proxy_extract_digest_param(
        hdr, params_len, "realm", session->realm, sizeof(session->realm));
    int got_nonce = proxy_extract_digest_param(
        hdr, params_len, "nonce", session->nonce, sizeof(session->nonce));
    proxy_extract_digest_param(
        hdr, params_len, "qop", session->qop, sizeof(session->qop));

    return (got_realm && got_nonce) ? 1 : 0;
}

/**
 * @brief Build the Digest-authenticated CONNECT retry request.
 *
 * @return Number of bytes written, or 0 on failure.
 */
static uint16_t proxy_build_digest_request(pn_proxy_connect_session_t* session,
                                           const pn_proxy_config_t*    config)
{
    /* URI for CONNECT Digest is "host:port". */
    char uri[PUBNUB_CFG_MAX_HOSTNAME_LEN + 8];
    int  uri_len = pn_snprintf(
        uri, sizeof(uri), "%s:%u", session->target_host, (unsigned)session->target_port);
    if (uri_len < 0 || (size_t)uri_len >= sizeof(uri)) {
        return 0;
    }

    /* Compute Digest response hash. */
    char                          response_hex[33];
    const pn_digest_auth_params_t auth = {.username = config->username,
                                          .password = config->password,
                                          .realm    = session->realm,
                                          .nonce    = session->nonce,
                                          .nc_str   = "00000001",
                                          .cnonce   = session->cnonce,
                                          .qop      = session->qop};
    proxy_compute_digest_response(&auth, "CONNECT", uri, response_hex);

    /* Format the full request with Digest auth header. */
    int written;
    if ('\0' != session->qop[0]) {
        written = pn_snprintf(session->request_buf,
                              sizeof(session->request_buf),
                              "CONNECT %s HTTP/1.1\r\n"
                              "Host: %s\r\n"
                              "Proxy-Authorization: Digest "
                              "username=\"%s\", "
                              "realm=\"%s\", "
                              "nonce=\"%s\", "
                              "uri=\"%s\", "
                              "response=\"%s\", "
                              "qop=%s, "
                              "nc=00000001, "
                              "cnonce=\"%s\"\r\n"
                              "\r\n",
                              uri,
                              uri,
                              config->username,
                              session->realm,
                              session->nonce,
                              uri,
                              response_hex,
                              session->qop,
                              session->cnonce);
    } else {
        written = pn_snprintf(session->request_buf,
                              sizeof(session->request_buf),
                              "CONNECT %s HTTP/1.1\r\n"
                              "Host: %s\r\n"
                              "Proxy-Authorization: Digest "
                              "username=\"%s\", "
                              "realm=\"%s\", "
                              "nonce=\"%s\", "
                              "uri=\"%s\", "
                              "response=\"%s\"\r\n"
                              "\r\n",
                              uri,
                              uri,
                              config->username,
                              session->realm,
                              session->nonce,
                              uri,
                              response_hex);
    }

    if (written < 0 || (size_t)written >= sizeof(session->request_buf)) {
        return 0;
    }

    return (uint16_t)written;
}

/**
 * @brief Build CONNECT request with NTLM Type 1 negotiate message.
 *
 * @return Number of bytes written to request_buf, or 0 on failure.
 */
static uint16_t proxy_build_ntlm_type1_request(pn_proxy_connect_session_t* session,
                                               const char* target_host,
                                               uint16_t    target_port)
{
    uint8_t type1_msg[64];
    size_t  type1_len = pn_ntlm_type1_build(type1_msg, sizeof(type1_msg));
    if (0 == type1_len) {
        return 0;
    }

    /* Base64-encode Type 1 into response_buf as scratch. */
    size_t b64_needed = pn_base64_encoded_len(type1_len);
    if (b64_needed > sizeof(session->response_buf)) {
        return 0;
    }

    pubnub_res_t res = pn_base64_encode(
        type1_msg, type1_len, session->response_buf, sizeof(session->response_buf));
    if (PUBNUB_OK != res) {
        return 0;
    }

    int written = pn_snprintf(session->request_buf,
                              sizeof(session->request_buf),
                              "CONNECT %s:%u HTTP/1.1\r\n"
                              "Host: %s:%u\r\n"
                              "Proxy-Authorization: NTLM %s\r\n"
                              "\r\n",
                              target_host,
                              (unsigned)target_port,
                              target_host,
                              (unsigned)target_port,
                              session->response_buf);
    if (written < 0 || (size_t)written >= sizeof(session->request_buf)) {
        return 0;
    }

    return (uint16_t)written;
}

/**
 * @brief Extract and decode the NTLM Type 2 challenge from a 407 response.
 *
 * Finds "Proxy-Authenticate: NTLM <base64>" header, decodes the binary
 * Type 2 message into session->ntlm_type2_buf.
 *
 * @return 1 if a valid NTLM challenge was decoded, 0 otherwise.
 */
static int proxy_parse_ntlm_challenge(pn_proxy_connect_session_t* session)
{
    const char* search    = "proxy-authenticate:";
    size_t      slen      = 19;
    const char* buf       = session->response_buf;
    size_t      total_len = (size_t)session->response_len;
    const char* hdr       = NULL;

    /* Find the Proxy-Authenticate header (case-insensitive).
     * For NTLM, there may be multiple Proxy-Authenticate headers
     * (e.g., one for Negotiate, one for NTLM). Find the NTLM one. */
    for (size_t i = 0; i + slen < total_len; ++i) {
        int match = 1;
        for (size_t j = 0; j < slen; ++j) {
            char a = buf[i + j];
            if (a >= 'A' && a <= 'Z') {
                a = (char)(a + 32);
            }
            if (a != search[j]) {
                match = 0;
                break;
            }
        }
        if (!match) {
            continue;
        }

        const char* candidate = buf + i + slen;

        /* Skip whitespace. */
        while (candidate < buf + total_len
               && (' ' == *candidate || '\t' == *candidate)) {
            ++candidate;
        }

        /* Check for "NTLM " scheme (case-insensitive). */
        size_t remaining = (size_t)(buf + total_len - candidate);
        if (remaining < 5) {
            continue;
        }

        char scheme[5];
        for (int k = 0; k < 4; ++k) {
            scheme[k] = candidate[k];
            if (scheme[k] >= 'A' && scheme[k] <= 'Z') {
                scheme[k] = (char)(scheme[k] + 32);
            }
        }
        scheme[4] = '\0';
        if (0 != memcmp(scheme, "ntlm", 4)) {
            continue;
        }
        if (' ' != candidate[4] && '\r' != candidate[4]) {
            continue;
        }

        hdr = candidate + 5;
        break;
    }

    if (NULL == hdr) {
        return 0;
    }

    /* Skip whitespace before the base64 data. */
    while (hdr < buf + total_len && (' ' == *hdr || '\t' == *hdr)) {
        ++hdr;
    }

    /* Find end of base64 data (up to CR or end of buffer). */
    const char* b64_end = hdr;
    while (b64_end < buf + total_len && '\r' != *b64_end && '\n' != *b64_end
           && ' ' != *b64_end) {
        ++b64_end;
    }

    size_t b64_len = (size_t)(b64_end - hdr);
    if (0 == b64_len) {
        return 0;
    }

    /* Decode base64 into ntlm_type2_buf. */
    size_t       decoded_len = 0;
    pubnub_res_t res         = pn_base64_decode(hdr,
                                        b64_len,
                                        session->ntlm_type2_buf,
                                        sizeof(session->ntlm_type2_buf),
                                        &decoded_len);
    if (PUBNUB_OK != res || 0 == decoded_len) {
        return 0;
    }

    session->ntlm_type2_len = (uint16_t)decoded_len;
    return 1;
}

/**
 * @brief Build CONNECT request with NTLM Type 3 authenticate message.
 *
 * Parses the previously-decoded Type 2 challenge, computes the NTLMv2
 * response, and assembles the Type 3 message.
 *
 * @return Number of bytes written to request_buf, or 0 on failure.
 */
static uint16_t proxy_build_ntlm_type3_request(pn_proxy_connect_session_t* session,
                                               const pn_proxy_config_t* config,
                                               pn_socket_transport_t* transport)
{
    /* Parse Type 2 message. */
    pn_ntlm_type2_t type2;
    if (0
        != pn_ntlm_type2_parse(
            session->ntlm_type2_buf, session->ntlm_type2_len, &type2)) {
        return 0;
    }

    /* Generate 8-byte client challenge from platform random. A failed or
     * absent RNG must abort the exchange - an all-zero challenge would
     * cripple the NTLMv2 response. */
    uint8_t client_challenge[8] = {0};
    if (NULL == transport->platform || NULL == transport->platform->random_bytes) {
        return 0;
    }
    if (0
        != transport->platform->random_bytes(
            transport->platform, client_challenge, sizeof(client_challenge))) {
        return 0;
    }

    /* NTLMv2 blob timestamp: 0 is universally accepted by proxies.
     * monotonic_ms is not epoch-anchored on most platforms and would
     * produce an incorrect FILETIME that some proxies reject. */
    uint64_t timestamp = 0;

    /* Domain auto-discovered from the Type 2 TargetName security buffer. */
    uint8_t type3_msg[PN_NTLM_MAX_MSG_SIZE];
    size_t  type3_len = pn_ntlm_type3_build(&type2,
                                           config->username,
                                           config->password,
                                           type2.target_name,
                                           client_challenge,
                                           timestamp,
                                           type3_msg,
                                           sizeof(type3_msg));
    if (0 == type3_len) {
        return 0;
    }

    /* Base64-encode Type 3 into response_buf as scratch. */
    size_t b64_needed = pn_base64_encoded_len(type3_len);
    if (b64_needed > sizeof(session->response_buf)) {
        return 0;
    }

    pubnub_res_t res = pn_base64_encode(
        type3_msg, type3_len, session->response_buf, sizeof(session->response_buf));
    if (PUBNUB_OK != res) {
        return 0;
    }

    /* Build the CONNECT request with NTLM Type 3 auth. */
    int written = pn_snprintf(session->request_buf,
                              sizeof(session->request_buf),
                              "CONNECT %s:%u HTTP/1.1\r\n"
                              "Host: %s:%u\r\n"
                              "Proxy-Authorization: NTLM %s\r\n"
                              "\r\n",
                              session->target_host,
                              (unsigned)session->target_port,
                              session->target_host,
                              (unsigned)session->target_port,
                              session->response_buf);
    if (written < 0 || (size_t)written >= sizeof(session->request_buf)) {
        return 0;
    }

    return (uint16_t)written;
}

#endif /* PUBNUB_ENABLE_PROXY */

/**
 * @brief Send data from request_buf, advancing request_sent.
 *
 * @return PN_PROXY_IN_PROGRESS while sending, PN_PROXY_ERROR on failure.
 */
static pn_proxy_result_t proxy_do_send(pn_proxy_connect_session_t* session,
                                       pn_socket_connection_t*     conn,
                                       pn_socket_transport_t*      transport,
                                       uint8_t                     next_state)
{
    size_t remaining = (size_t)(session->request_len - session->request_sent);
    int    rc        = transport->ops->socket_send(
        transport->ops,
        conn->socket,
        (const uint8_t*)(session->request_buf + session->request_sent),
        remaining);

    if (rc > 0) {
        session->request_sent += (uint16_t)rc;
        if (session->request_sent >= session->request_len) {
            session->state        = next_state;
            session->response_len = 0;
            memset(session->response_buf, 0, sizeof(session->response_buf));
        }
        return PN_PROXY_IN_PROGRESS;
    }

    if (0 == rc) {
        return PN_PROXY_IN_PROGRESS;
    }

    return PN_PROXY_ERROR;
}

/**
 * @brief Receive data into response_buf until headers are complete.
 *
 * @param[out] out_status  Parsed HTTP status code when headers complete.
 * @return 1 if headers complete, 0 if still reading, -1 on error.
 */
static int proxy_do_recv(pn_proxy_connect_session_t* session,
                         pn_socket_connection_t*     conn,
                         pn_socket_transport_t*      transport,
                         int*                        out_status)
{
    size_t space = (size_t)(PN_PROXY_RESPONSE_BUF_SIZE - session->response_len);
    if (0 == space) {
        return -1;
    }

    int rc = transport->ops->socket_recv(
        transport->ops,
        conn->socket,
        (uint8_t*)(session->response_buf + session->response_len),
        space);

    if (rc > 0) {
        session->response_len += (uint16_t)rc;

        const char* end = proxy_find_header_end(session->response_buf,
                                                (size_t)session->response_len);
        if (NULL == end) {
            return 0;
        }

        *out_status = proxy_parse_status_code(session->response_buf,
                                              (size_t)session->response_len);
        return 1;
    }

    if (0 == rc) {
        return 0;
    }

    return -1;
}

static pn_proxy_result_t proxy_connect_negotiate_start(struct pn_proxy_module* self,
                                                       pn_socket_connection_t* conn,
                                                       pn_socket_transport_t* transport,
                                                       const char* target_host,
                                                       uint16_t    target_port)
{
    (void)transport;

    if (NULL == self || NULL == conn || NULL == target_host) {
        return PN_PROXY_ERROR;
    }

    pn_proxy_connect_module_t* module = (pn_proxy_connect_module_t*)self;

    /* Allocate per-connection session. */
    pn_proxy_connect_session_t* session = (pn_proxy_connect_session_t*)PN_ALLOC(
        module->allocator, sizeof(pn_proxy_connect_session_t), 8);
    if (NULL == session) {
        return PN_PROXY_ERROR;
    }
    memset(session, 0, sizeof(*session));

    /* Store target for potential Digest auth retry. */
    size_t host_len = strlen(target_host);
    if (host_len >= sizeof(session->target_host)) {
        PN_FREE(module->allocator, session);
        return PN_PROXY_ERROR;
    }
    memcpy(session->target_host, target_host, host_len + 1);
    session->target_port = target_port;

    /* For Digest auth, send initial CONNECT without credentials
     * to provoke a 407 with the server's nonce challenge. */
    if (PN_PROXY_AUTH_DIGEST == module->config->auth_type) {
        int written = pn_snprintf(session->request_buf,
                                  sizeof(session->request_buf),
                                  "CONNECT %s:%u HTTP/1.1\r\n"
                                  "Host: %s:%u\r\n"
                                  "\r\n",
                                  target_host,
                                  (unsigned)target_port,
                                  target_host,
                                  (unsigned)target_port);
        if (written < 0 || (size_t)written >= sizeof(session->request_buf)) {
            PN_FREE(module->allocator, session);
            return PN_PROXY_ERROR;
        }
        session->request_len = (uint16_t)written;
#if PUBNUB_ENABLE_PROXY
    } else if (PN_PROXY_AUTH_NTLM == module->config->auth_type) {
        /* NTLM Round 1: send CONNECT with Type 1 negotiate. */
        session->request_len =
            proxy_build_ntlm_type1_request(session, target_host, target_port);
        if (0 == session->request_len) {
            PN_FREE(module->allocator, session);
            return PN_PROXY_ERROR;
        }
#endif
    } else {
        /* Build CONNECT request (no auth or Basic auth). */
        session->request_len =
            proxy_build_request(session, module->config, target_host, target_port);
        if (0 == session->request_len) {
            PN_FREE(module->allocator, session);
            return PN_PROXY_ERROR;
        }
    }

    session->request_sent = 0;
    session->response_len = 0;
    session->state        = PN_PROXY_CONNECT_SEND_REQUEST;

    conn->proxy_session = session;

    return PN_PROXY_IN_PROGRESS;
}

#if PUBNUB_ENABLE_PROXY
/**
 * @brief Handle a 407 Proxy Authentication Required response.
 *
 * Parses the challenge (Digest or NTLM), builds the authenticated
 * retry request, and transitions the session to SEND_AUTH_REQUEST.
 *
 * @return PN_PROXY_IN_PROGRESS on success, PN_PROXY_ERROR on failure.
 */
static pn_proxy_result_t
proxy_handle_407_challenge(pn_proxy_connect_session_t* session,
                           pn_proxy_connect_module_t*  module,
                           pn_socket_transport_t*      transport)
{
    if (NULL == module->config->username || NULL == module->config->password) {
        return PN_PROXY_ERROR;
    }

    if (PN_PROXY_AUTH_DIGEST == module->config->auth_type) {
        if (!proxy_parse_digest_challenge(session)) {
            return PN_PROXY_ERROR;
        }

        if (0 != proxy_generate_cnonce(session, transport)) {
            return PN_PROXY_ERROR;
        }

        session->request_len = proxy_build_digest_request(session, module->config);
        if (0 == session->request_len) {
            return PN_PROXY_ERROR;
        }
    } else if (PN_PROXY_AUTH_NTLM == module->config->auth_type) {
        if (!proxy_parse_ntlm_challenge(session)) {
            return PN_PROXY_ERROR;
        }

        session->request_len =
            proxy_build_ntlm_type3_request(session, module->config, transport);
        if (0 == session->request_len) {
            return PN_PROXY_ERROR;
        }
    } else {
        return PN_PROXY_ERROR;
    }

    session->request_sent = 0;
    session->state        = PN_PROXY_CONNECT_SEND_AUTH_REQUEST;
    return PN_PROXY_IN_PROGRESS;
}
#endif /* PUBNUB_ENABLE_PROXY */

static pn_proxy_result_t proxy_connect_negotiate_tick(struct pn_proxy_module* self,
                                                      pn_socket_connection_t* conn,
                                                      pn_socket_transport_t* transport)
{
    if (NULL == conn || NULL == transport || NULL == conn->proxy_session) {
        return PN_PROXY_ERROR;
    }

    pn_proxy_connect_session_t* session =
        (pn_proxy_connect_session_t*)conn->proxy_session;

    switch ((pn_proxy_connect_state_t)session->state) {
    case PN_PROXY_CONNECT_SEND_REQUEST:
        return proxy_do_send(session, conn, transport, PN_PROXY_CONNECT_RECV_RESPONSE);

    case PN_PROXY_CONNECT_RECV_RESPONSE: {
        int status = 0;
        int rc     = proxy_do_recv(session, conn, transport, &status);
        if (0 == rc) {
            return PN_PROXY_IN_PROGRESS;
        }
        if (rc < 0) {
            return PN_PROXY_ERROR;
        }

        if (200 == status) {
            return PN_PROXY_COMPLETE;
        }

#if PUBNUB_ENABLE_PROXY
        if (407 == status) {
            return proxy_handle_407_challenge(
                session, (pn_proxy_connect_module_t*)self, transport);
        }
#else
        (void)self;
#endif /* PUBNUB_ENABLE_PROXY */

        return PN_PROXY_ERROR;
    }

    case PN_PROXY_CONNECT_SEND_AUTH_REQUEST:
        return proxy_do_send(
            session, conn, transport, PN_PROXY_CONNECT_RECV_AUTH_RESPONSE);

    case PN_PROXY_CONNECT_RECV_AUTH_RESPONSE: {
        int status = 0;
        int rc     = proxy_do_recv(session, conn, transport, &status);
        if (0 == rc) {
            return PN_PROXY_IN_PROGRESS;
        }
        if (rc < 0) {
            return PN_PROXY_ERROR;
        }

        if (200 == status) {
            return PN_PROXY_COMPLETE;
        }

        return PN_PROXY_ERROR;
    }

    default: break;
    }

    return PN_PROXY_ERROR;
}

static void proxy_connect_destroy(struct pn_proxy_module*           self,
                                  struct pubnub_allocator_provider* allocator)
{
    if (NULL == self || NULL == allocator) {
        return;
    }
    PN_FREE(allocator, self);
}

pn_proxy_module_t* pn_proxy_connect_create(const pn_proxy_config_t* config,
                                           struct pubnub_allocator_provider* allocator)
{
    if (NULL == config || NULL == allocator) {
        return NULL;
    }

    pn_proxy_connect_module_t* module = (pn_proxy_connect_module_t*)PN_ALLOC(
        allocator, sizeof(pn_proxy_connect_module_t), 8);
    if (NULL == module) {
        return NULL;
    }
    memset(module, 0, sizeof(*module));

    module->config    = config;
    module->allocator = allocator;

    module->base.negotiate_start = proxy_connect_negotiate_start;
    module->base.negotiate_tick  = proxy_connect_negotiate_tick;
    module->base.destroy         = proxy_connect_destroy;

    return &module->base;
}

void pn_proxy_connect_session_destroy(void* session,
                                      struct pubnub_allocator_provider* allocator)
{
    volatile uint8_t* p;
    size_t            i;

    if (NULL == session) {
        return;
    }
    /* sizeof is exact; PN_PROXY_CONNECT_SESSION_SIZE is an upper bound.
     * Scrub even without a free hook: arena allocators linger until reset. */
    p = (volatile uint8_t*)session;
    for (i = 0; i < sizeof(pn_proxy_connect_session_t); ++i) {
        p[i] = 0;
    }
    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, session);
    }
}

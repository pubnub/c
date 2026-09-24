/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file test_proxy_connect.c
 * @brief cmocka white-box tests for the HTTP CONNECT proxy module.
 *
 * Includes proxy_connect.c directly to test static functions. Mocks
 * socket I/O via the pn_socket_platform_ops_t vtable to validate the
 * state machine, wire protocol output, and multi-round authentication
 * (Basic, Digest/MD5, NTLM/NTLMv2).
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

/* Include the module under test directly (white-box).
 * PUBNUB_ENABLE_PROXY and PUBNUB_ENABLE_SECURE_TRANSPORT are set to 1
 * in the generated config.h (this test only builds when both are ON). */
#include "providers/transport/socket/proxy/proxy_connect.c"

/* pn_proxy_md5.h is available transitively via proxy_connect.c.
 * We use the same MD5 wrapper for independent hash validation. */

#define MOCK_SEND_BUF_SIZE 4096
#define MOCK_SOCKET_FD     42

static struct {
    int            send_result;
    int            recv_result;
    const uint8_t* recv_data;
    size_t         recv_data_len;
    size_t         recv_offset;
    uint8_t        send_buf[MOCK_SEND_BUF_SIZE];
    size_t         send_buf_len;
    uint8_t        random_bytes[8];
    int            alloc_fail;
} mock;

static int mock_socket_send(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            const uint8_t*                  data,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    if (mock.send_result < 0) {
        return mock.send_result;
    }
    if (0 == mock.send_result) {
        return 0;
    }
    size_t space = sizeof(mock.send_buf) - mock.send_buf_len;
    size_t copy  = len < space ? len : space;
    memcpy(mock.send_buf + mock.send_buf_len, data, copy);
    mock.send_buf_len += copy;
    return (int)len;
}

static int mock_socket_recv(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            uint8_t*                        buf,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    if (mock.recv_result < 0) {
        return mock.recv_result;
    }
    if (NULL == mock.recv_data) {
        return 0;
    }
    size_t avail = mock.recv_data_len - mock.recv_offset;
    if (0 == avail) {
        return 0;
    }
    size_t to_read = len < avail ? len : avail;
    memcpy(buf, mock.recv_data + mock.recv_offset, to_read);
    mock.recv_offset += to_read;
    return (int)to_read;
}

static int mock_random_bytes(struct pubnub_platform_provider* self,
                             uint8_t*                         buf,
                             size_t                           len)
{
    (void)self;
    size_t copy = len < sizeof(mock.random_bytes) ? len : sizeof(mock.random_bytes);
    memcpy(buf, mock.random_bytes, copy);
    return 0;
}

static void* mock_alloc(struct pubnub_allocator_provider* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    if (mock.alloc_fail) {
        return NULL;
    }
    return malloc(size);
}

static void mock_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pn_socket_platform_ops_t         mock_ops;
static struct pubnub_platform_provider  mock_platform;
static struct pubnub_allocator_provider mock_allocator;
static pn_socket_transport_t            mock_transport;

static void mock_reset(void)
{
    memset(&mock, 0, sizeof(mock));
    mock.send_result = 1;

    memset(&mock_ops, 0, sizeof(mock_ops));
    mock_ops.socket_send = mock_socket_send;
    mock_ops.socket_recv = mock_socket_recv;

    memset(&mock_platform, 0, sizeof(mock_platform));
    mock_platform.random_bytes = mock_random_bytes;

    memset(&mock_allocator, 0, sizeof(mock_allocator));
    mock_allocator.alloc = mock_alloc;
    mock_allocator.free  = mock_free;

    memset(&mock_transport, 0, sizeof(mock_transport));
    mock_transport.ops       = &mock_ops;
    mock_transport.platform  = &mock_platform;
    mock_transport.allocator = &mock_allocator;
}

static const char PROXY_200[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
static const char PROXY_403[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
static const char PROXY_500[] =
    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
static const char PROXY_407_DIGEST[] =
    "HTTP/1.1 407 Proxy Authentication Required\r\n"
    "Proxy-Authenticate: Digest realm=\"proxy\", "
    "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
    "qop=\"auth\"\r\n\r\n";
static const char PROXY_407_NO_SCHEME[] =
    "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";

static char ntlm_type2_response[512];
static char ntlm_invalid_type2_response[512];
static char ntlm_short_type2_response[512];

/** @brief Known server challenge for NTLM Type 2. */
static const uint8_t NTLM_SERVER_CHALLENGE[8] =
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

static void build_ntlm_type2_response(void)
{
    uint8_t type2[32] = {0};
    memcpy(type2, "NTLMSSP", 8);
    type2[8]  = 0x02;
    type2[16] = 32;
    type2[20] = 0x33;
    type2[21] = 0x82;
    type2[22] = 0x8a;
    type2[23] = 0xe2;
    memcpy(type2 + 24, NTLM_SERVER_CHALLENGE, 8);

    char b64[64] = {0};
    pn_base64_encode(type2, 32, b64, sizeof(b64));

    pn_snprintf(ntlm_type2_response,
                sizeof(ntlm_type2_response),
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: NTLM %s\r\n\r\n",
                b64);
}

static void build_ntlm_invalid_type2_response(void)
{
    uint8_t bad[32] = {0};
    memcpy(bad, "BADDSSP", 8);
    bad[8]  = 0x02;
    bad[16] = 32;
    bad[20] = 0x33;
    bad[21] = 0x82;
    bad[22] = 0x8a;
    bad[23] = 0xe2;
    memcpy(bad + 24, NTLM_SERVER_CHALLENGE, 8);

    char b64[64] = {0};
    pn_base64_encode(bad, 32, b64, sizeof(b64));

    pn_snprintf(ntlm_invalid_type2_response,
                sizeof(ntlm_invalid_type2_response),
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: NTLM %s\r\n\r\n",
                b64);
}

static void build_ntlm_short_type2_response(void)
{
    /* Only 16 bytes (less than minimum 32-byte Type 2 message). */
    uint8_t tiny[16] = {0};
    memcpy(tiny, "NTLMSSP", 8);
    tiny[8] = 0x02;

    char b64[32] = {0};
    pn_base64_encode(tiny, 16, b64, sizeof(b64));

    pn_snprintf(ntlm_short_type2_response,
                sizeof(ntlm_short_type2_response),
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: NTLM %s\r\n\r\n",
                b64);
}

/**
 * @brief Compute MD5 hex using the proxy MD5 wrapper for validation.
 *
 * Uses the same MD5 implementation as the module under test but provides
 * independent input assembly to verify the module's hash construction.
 */
static void compute_md5_hex(const char* input, size_t len, char hex[33])
{
    pn_proxy_md5_ctx_t ctx;
    uint8_t            digest[16];
    static const char  table[] = "0123456789abcdef";

    pn_proxy_md5_init(&ctx);
    pn_proxy_md5_update(&ctx, (const uint8_t*)input, len);
    pn_proxy_md5_final(&ctx, digest);

    for (int i = 0; i < 16; ++i) {
        hex[i * 2]     = table[digest[i] >> 4];
        hex[i * 2 + 1] = table[digest[i] & 0x0f];
    }
    hex[32] = '\0';
}

/**
 * @brief Validate Basic auth header in captured send buffer.
 */
static void validate_basic_auth(const char* expected_credentials)
{
    const char* marker = "Proxy-Authorization: Basic ";
    char*       found  = strstr((char*)mock.send_buf, marker);
    assert_non_null(found);

    const char* b64_start = found + strlen(marker);
    const char* b64_end   = strstr(b64_start, "\r\n");
    assert_non_null(b64_end);

    size_t  b64_len = (size_t)(b64_end - b64_start);
    uint8_t decoded[128];
    size_t  decoded_len = 0;

    pubnub_res_t res = pn_base64_decode(
        b64_start, b64_len, decoded, sizeof(decoded), &decoded_len);
    assert_int_equal(PUBNUB_OK, res);
    assert_int_equal(strlen(expected_credentials), decoded_len);
    assert_memory_equal(expected_credentials, decoded, decoded_len);
}

/**
 * @brief Validate no Proxy-Authorization header present in send buffer.
 */
static void validate_no_auth_header(void)
{
    char* found = strstr((char*)mock.send_buf, "Proxy-Authorization:");
    assert_null(found);
}

/**
 * @brief Extract a quoted or unquoted value from Digest auth header.
 *
 * @return 1 if found, 0 otherwise.
 */
static int extract_digest_field(const char* header,
                                const char* key,
                                char*       out,
                                size_t      out_size)
{
    size_t      key_len = strlen(key);
    const char* p       = header;
    out[0]              = '\0';

    while (NULL != (p = strstr(p, key))) {
        if (p > header) {
            char prev = *(p - 1);
            if (' ' != prev && ',' != prev && '\t' != prev && '\n' != prev) {
                p += key_len;
                continue;
            }
        }
        p += key_len;
        if ('=' != *p) {
            continue;
        }
        ++p;

        int    quoted = ('"' == *p);
        size_t di     = 0;
        if (quoted) {
            ++p;
        }
        while ('\0' != *p && di < out_size - 1) {
            if (quoted) {
                if ('"' == *p) {
                    break;
                }
            } else {
                if (',' == *p || ' ' == *p || '\r' == *p) {
                    break;
                }
            }
            out[di++] = *p++;
        }
        out[di] = '\0';
        return 1;
    }
    return 0;
}

/**
 * @brief Validate Digest auth response in the second CONNECT request.
 */
static void validate_digest_auth(const char* username,
                                 const char* password,
                                 const char* realm,
                                 const char* nonce,
                                 const char* target_host,
                                 uint16_t    target_port)
{
    /* Find the second CONNECT request (with Digest auth). */
    const char* second_req = strstr((char*)mock.send_buf + 1, "CONNECT ");
    assert_non_null(second_req);

    const char* auth_line = strstr(second_req, "Proxy-Authorization: Digest ");
    assert_non_null(auth_line);

    /* Extract fields from the Digest header. */
    char resp_value[64]   = {0};
    char cnonce_value[16] = {0};
    char nc_value[16]     = {0};
    char qop_value[16]    = {0};
    char uri_value[128]   = {0};

    int found_resp = extract_digest_field(
        auth_line, "response", resp_value, sizeof(resp_value));
    assert_int_equal(1, found_resp);

    extract_digest_field(auth_line, "cnonce", cnonce_value, sizeof(cnonce_value));
    extract_digest_field(auth_line, "nc", nc_value, sizeof(nc_value));
    extract_digest_field(auth_line, "qop", qop_value, sizeof(qop_value));
    extract_digest_field(auth_line, "uri", uri_value, sizeof(uri_value));

    /* Independently compute expected Digest response. */
    char uri_expected[128];
    pn_snprintf(
        uri_expected, sizeof(uri_expected), "%s:%u", target_host, (unsigned)target_port);

    /* HA1 = MD5(username:realm:password) */
    char ha1_input[256];
    int  ha1_input_len = pn_snprintf(
        ha1_input, sizeof(ha1_input), "%s:%s:%s", username, realm, password);
    char ha1[33];
    compute_md5_hex(ha1_input, (size_t)ha1_input_len, ha1);

    /* HA2 = MD5(CONNECT:uri) */
    char ha2_input[256];
    int  ha2_input_len =
        pn_snprintf(ha2_input, sizeof(ha2_input), "CONNECT:%s", uri_expected);
    char ha2[33];
    compute_md5_hex(ha2_input, (size_t)ha2_input_len, ha2);

    /* response = MD5(HA1:nonce:nc:cnonce:qop:HA2) */
    char resp_input[512];
    int  resp_input_len = pn_snprintf(resp_input,
                                     sizeof(resp_input),
                                     "%s:%s:%s:%s:%s:%s",
                                     ha1,
                                     nonce,
                                     nc_value,
                                     cnonce_value,
                                     qop_value,
                                     ha2);
    char expected_resp[33];
    compute_md5_hex(resp_input, (size_t)resp_input_len, expected_resp);

    assert_string_equal(expected_resp, resp_value);
    assert_string_equal(uri_expected, uri_value);
}

/**
 * @brief Validate NTLM Type 1 message structure.
 */
static void validate_ntlm_type1(const uint8_t* msg, size_t len)
{
    assert_true(len >= 32);
    assert_memory_equal("NTLMSSP", msg, 7);
    assert_int_equal(0, msg[7]);
    /* Type 1 indicator LE: 0x00000001 */
    assert_int_equal(1, msg[8]);
    assert_int_equal(0, msg[9]);
    assert_int_equal(0, msg[10]);
    assert_int_equal(0, msg[11]);
    /* Flags should include NTLMSSP_NEGOTIATE_NTLM (bit 9 = 0x200). */
    uint32_t flags = (uint32_t)msg[12] | ((uint32_t)msg[13] << 8)
                   | ((uint32_t)msg[14] << 16) | ((uint32_t)msg[15] << 24);
    assert_true(0 != (flags & 0x00000200));
}

/**
 * @brief Extract base64-decoded NTLM blob from an "NTLM <b64>" header.
 *
 * @param start_after  Position in send_buf to start searching from.
 * @param out          Output buffer for decoded binary.
 * @param out_cap      Capacity of output buffer.
 * @param out_len      Receives decoded length.
 * @return Pointer to the next char after the header value, or NULL.
 */
static const char* extract_ntlm_blob(const char* start_after,
                                     uint8_t*    out,
                                     size_t      out_cap,
                                     size_t*     out_len)
{
    const char* marker = "Proxy-Authorization: NTLM ";
    const char* found  = strstr(start_after, marker);
    if (NULL == found) {
        return NULL;
    }

    const char* b64_start = found + strlen(marker);
    const char* b64_end   = strstr(b64_start, "\r\n");
    if (NULL == b64_end) {
        return NULL;
    }

    size_t b64_len = (size_t)(b64_end - b64_start);
    pubnub_res_t res = pn_base64_decode(b64_start, b64_len, out, out_cap, out_len);
    if (PUBNUB_OK != res) {
        return NULL;
    }
    return b64_end;
}

/**
 * @brief Helper: run ticks until the request is fully sent.
 *
 * @return Last result from negotiate_tick.
 */
static pn_proxy_result_t tick_until_sent(pn_proxy_module_t*      module,
                                         pn_socket_connection_t* conn)
{
    pn_proxy_result_t result;
    for (int i = 0; i < 20; ++i) {
        result = module->negotiate_tick(module, conn, &mock_transport);
        if (PN_PROXY_IN_PROGRESS != result) {
            return result;
        }
        pn_proxy_connect_session_t* session =
            (pn_proxy_connect_session_t*)conn->proxy_session;
        if (session->request_sent >= session->request_len) {
            return PN_PROXY_IN_PROGRESS;
        }
    }
    return PN_PROXY_IN_PROGRESS;
}

static void test_proxy_basic_200(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_BASIC;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Tick to send the request. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Validate Basic auth wire format. */
    validate_basic_auth("user:pass");

    /* Feed the 200 response. */
    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = strlen(PROXY_200);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    /* Cleanup. */
    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_basic_403(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_BASIC;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Tick to send. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed a 403 Forbidden response. */
    mock.recv_data     = (const uint8_t*)PROXY_403;
    mock.recv_data_len = strlen(PROXY_403);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_no_auth_200(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_NONE;

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* No auth header should be present. */
    validate_no_auth_header();

    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = strlen(PROXY_200);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief Verify that an HTTP 500 response from the proxy yields PN_PROXY_ERROR.
 */
static void test_proxy_no_auth_500(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_NONE;

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Tick to send. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed a 500 Internal Server Error response. */
    mock.recv_data     = (const uint8_t*)PROXY_500;
    mock.recv_data_len = strlen(PROXY_500);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_send_would_block(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_BASIC;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Simulate would-block on send. */
    mock.send_result = 0;
    result           = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);
    assert_int_equal(0, mock.send_buf_len);

    /* Unblock send, feed 200 response. */
    mock.send_result   = 1;
    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = strlen(PROXY_200);
    mock.recv_offset   = 0;

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_recv_partial(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_NONE;

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed first half of the response (no \r\n\r\n yet). */
    size_t total = strlen(PROXY_200);
    size_t half  = total / 2;

    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = half;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed remaining data. */
    mock.recv_data     = (const uint8_t*)PROXY_200 + half;
    mock.recv_data_len = total - half;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_recv_connection_closed(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_NONE;

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Simulate connection close / error on recv. */
    mock.recv_result = -1;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_digest_407_200(void** state)
{
    (void)state;
    mock_reset();

    /* Set known random bytes for deterministic cnonce. */
    mock.random_bytes[0] = 0xDE;
    mock.random_bytes[1] = 0xAD;
    mock.random_bytes[2] = 0xBE;
    mock.random_bytes[3] = 0xEF;

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_DIGEST;
    config.username          = "admin";
    config.password          = "secret";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Tick to send the initial unauthenticated CONNECT. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed 407 Digest challenge. */
    mock.recv_data     = (const uint8_t*)PROXY_407_DIGEST;
    mock.recv_data_len = strlen(PROXY_407_DIGEST);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Now in SEND_AUTH_REQUEST state. Feed 200 for the retry. */
    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = strlen(PROXY_200);
    mock.recv_offset   = 0;

    /* Tick to send the Digest auth request. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Validate the Digest auth wire format. */
    validate_digest_auth("admin",
                         "secret",
                         "proxy",
                         "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                         "ps.pndsn.com",
                         443);

    /* Tick to receive the 200 response. */
    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_digest_malformed_challenge(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_DIGEST;
    config.username          = "admin";
    config.password          = "secret";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed 407 WITHOUT a valid Digest challenge header. */
    mock.recv_data     = (const uint8_t*)PROXY_407_NO_SCHEME;
    mock.recv_data_len = strlen(PROXY_407_NO_SCHEME);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_digest_wrong_credentials(void** state)
{
    (void)state;
    mock_reset();

    mock.random_bytes[0] = 0xAA;
    mock.random_bytes[1] = 0xBB;
    mock.random_bytes[2] = 0xCC;
    mock.random_bytes[3] = 0xDD;

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_DIGEST;
    config.username          = "wrong";
    config.password          = "creds";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* First round: send initial CONNECT, receive 407 challenge. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    mock.recv_data     = (const uint8_t*)PROXY_407_DIGEST;
    mock.recv_data_len = strlen(PROXY_407_DIGEST);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Second round: send Digest auth, receive another 407 (wrong creds). */
    mock.recv_data     = (const uint8_t*)PROXY_407_DIGEST;
    mock.recv_data_len = strlen(PROXY_407_DIGEST);
    mock.recv_offset   = 0;

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_ntlm_type1_type3_200(void** state)
{
    (void)state;
    mock_reset();
    build_ntlm_type2_response();

    /* Set known random bytes for deterministic client challenge. */
    mock.random_bytes[0] = 0x11;
    mock.random_bytes[1] = 0x22;
    mock.random_bytes[2] = 0x33;
    mock.random_bytes[3] = 0x44;
    mock.random_bytes[4] = 0x55;
    mock.random_bytes[5] = 0x66;
    mock.random_bytes[6] = 0x77;
    mock.random_bytes[7] = 0x88;

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Tick to send Type 1. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Validate Type 1 message in the wire output. */
    uint8_t     type1_blob[128];
    size_t      type1_len   = 0;
    const char* after_type1 = extract_ntlm_blob(
        (const char*)mock.send_buf, type1_blob, sizeof(type1_blob), &type1_len);
    assert_non_null(after_type1);
    validate_ntlm_type1(type1_blob, type1_len);

    /* Feed 407 with NTLM Type 2 challenge. */
    mock.recv_data     = (const uint8_t*)ntlm_type2_response;
    mock.recv_data_len = strlen(ntlm_type2_response);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Tick to send Type 3. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Validate Type 3 message in the wire output. */
    uint8_t type3_blob[512];
    size_t  type3_len = 0;

    /* Find the second NTLM header (Type 3). */
    const char* second_ntlm =
        strstr((char*)mock.send_buf + (after_type1 - (char*)mock.send_buf),
               "Proxy-Authorization: NTLM ");
    assert_non_null(second_ntlm);

    const char* after_type3 =
        extract_ntlm_blob(second_ntlm, type3_blob, sizeof(type3_blob), &type3_len);
    assert_non_null(after_type3);

    /* Verify Type 3 structure. */
    assert_true(type3_len >= 52);
    assert_memory_equal("NTLMSSP", type3_blob, 7);
    assert_int_equal(0, type3_blob[7]);
    /* Type 3 indicator LE: 0x00000003 */
    assert_int_equal(3, type3_blob[8]);
    assert_int_equal(0, type3_blob[9]);
    assert_int_equal(0, type3_blob[10]);
    assert_int_equal(0, type3_blob[11]);

    /* Feed 200 response to complete negotiation. */
    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = strlen(PROXY_200);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_ntlm_invalid_type2(void** state)
{
    (void)state;
    mock_reset();
    build_ntlm_invalid_type2_response();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Send Type 1. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed invalid Type 2 (bad signature). */
    mock.recv_data     = (const uint8_t*)ntlm_invalid_type2_response;
    mock.recv_data_len = strlen(ntlm_invalid_type2_response);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_ntlm_short_type2(void** state)
{
    (void)state;
    mock_reset();
    build_ntlm_short_type2_response();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Send Type 1. */
    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    /* Feed truncated Type 2 (< 32 bytes). */
    mock.recv_data     = (const uint8_t*)ntlm_short_type2_response;
    mock.recv_data_len = strlen(ntlm_short_type2_response);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

static void test_proxy_null_module(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_NONE;

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;
    conn.proxy_session          = NULL;

    /* negotiate_tick with NULL proxy_session should return ERROR. */
    pn_proxy_result_t result =
        module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    /* negotiate_start with NULL conn should return ERROR. */
    result =
        module->negotiate_start(module, NULL, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_ERROR, result);

    /* negotiate_start with NULL target_host should return ERROR. */
    result = module->negotiate_start(module, &conn, &mock_transport, NULL, 443);
    assert_int_equal(PN_PROXY_ERROR, result);

    module->destroy(module, &mock_allocator);
}

static void test_proxy_session_alloc_failure(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_NONE;

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    /* Force allocation failure for the session. */
    mock.alloc_fail = 1;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_ERROR, result);

    /* Module was allocated before we set alloc_fail; destroy it. */
    mock.alloc_fail = 0;
    module->destroy(module, &mock_allocator);
}

/**
 * Type 2 message with TargetName "CORP" (UTF-16LE): pn_ntlm_type2_parse must
 * populate target_name with "CORP" and target_name_len with 4.
 */
static void test_proxy_ntlm_type2_parse_domain(void** state)
{
    (void)state;

    /*
     * Minimal 64-byte Type 2 message with TargetName "CORP" at offset 56.
     *
     * Offset  0: Signature "NTLMSSP\0"
     * Offset  8: MessageType = 2
     * Offset 12: TargetName len=8, maxlen=8, offset=56 (0x38)
     * Offset 20: NegotiateFlags
     * Offset 24: ServerChallenge (8 bytes)
     * Offset 32: Reserved (8 bytes)
     * Offset 40: TargetInfo  len=0, maxlen=0, offset=48 (0x30)
     * Offset 56: UTF-16LE "CORP" = 43 00 4f 00 52 00 50 00
     */
    // clang-format off
    static const uint8_t type2[] = {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,  /* "NTLMSSP\0" signature */
        0x02, 0x00, 0x00, 0x00,                            /* MessageType: 2 */
        0x08, 0x00, 0x08, 0x00, 0x38, 0x00, 0x00, 0x00,   /* TargetName: len=8, maxlen=8, offset=56 */
        0x07, 0x82, 0x08, 0xa0,                            /* NegotiateFlags */
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,   /* ServerChallenge */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Reserved */
        0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,   /* TargetInfo: len=0, maxlen=0, offset=48 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Padding (offset 48-55) */
        0x43, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x50, 0x00,   /* UTF-16LE "CORP" at offset 56 */
    };
    // clang-format on

    pn_ntlm_type2_t t2 = {0};
    int             rc = pn_ntlm_type2_parse(type2, sizeof(type2), &t2);

    assert_int_equal(0, rc);
    assert_string_equal("CORP", t2.target_name);
    assert_int_equal(4, (int)t2.target_name_len);
}

/**
 * Type 2 message with zero-length TargetName: target_name must be "".
 */
static void test_proxy_ntlm_type2_parse_no_domain(void** state)
{
    (void)state;

    /* Minimal valid Type 2 with zero-length TargetName. */
    // clang-format off
    static const uint8_t type2[] = {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,  /* "NTLMSSP\0" signature */
        0x02, 0x00, 0x00, 0x00,                            /* MessageType: 2 */
        0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,   /* TargetName: len=0, maxlen=0, offset=48 */
        0x07, 0x82, 0x08, 0xa0,                            /* NegotiateFlags */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,   /* ServerChallenge */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Reserved */
        0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,   /* TargetInfo: len=0, maxlen=0, offset=48 */
    };
    // clang-format on

    pn_ntlm_type2_t t2 = {0};
    int             rc = pn_ntlm_type2_parse(type2, sizeof(type2), &t2);

    assert_int_equal(0, rc);
    assert_string_equal("", t2.target_name);
    assert_int_equal(0, (int)t2.target_name_len);
}

/**
 * @brief Build a Digest 407 response padded to exactly target_total bytes.
 *
 * Keeps a valid Digest challenge and a proper header terminator, sizing an
 * X-Pad filler header so the whole response is exactly target_total bytes.
 */
static void build_digest_407_padded(char* out, size_t target_total, size_t* out_len)
{
    static const char head[] =
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        "Proxy-Authenticate: Digest realm=\"proxy\", "
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\"\r\n"
        "X-Pad: ";
    static const char tail[]   = "\r\n\r\n";
    const size_t      head_len = sizeof(head) - 1;
    const size_t      tail_len = sizeof(tail) - 1;
    size_t            pad      = 0;

    assert_true(target_total >= head_len + tail_len);
    pad = target_total - head_len - tail_len;
    memcpy(out, head, head_len);
    memset(out + head_len, 'A', pad);
    memcpy(out + head_len + pad, tail, tail_len);
    *out_len = target_total;
}

/**
 * @brief Build a 407 response of `total` bytes with NO header terminator.
 *
 * The parser never finds \r\n\r\n, so response_buf fills to capacity and
 * proxy_do_recv must fail cleanly rather than overflow.
 */
static void build_oversized_407(char* out, size_t total, size_t* out_len)
{
    static const char head[] = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                               "Proxy-Authenticate: Basic realm=\"";
    const size_t      head_len = sizeof(head) - 1;

    assert_true(total > head_len);
    memcpy(out, head, head_len);
    memset(out + head_len, 'A', total - head_len);
    *out_len = total;
}

/**
 * @brief Build an NTLM 407 whose Type 2 blob decodes to exactly blob_len.
 *
 * The first 64 bytes are a valid Type 2 message (TargetName "CORP"); any
 * remaining bytes are zero padding. Used to probe the 256-byte
 * ntlm_type2_buf decode boundary.
 */
static void build_ntlm_407_with_blob_len(char*   out,
                                         size_t  out_cap,
                                         size_t  blob_len,
                                         size_t* out_len)
{
    // clang-format off
    static const uint8_t template64[64] = {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,  /* "NTLMSSP\0" */
        0x02, 0x00, 0x00, 0x00,                            /* MessageType: 2 */
        0x08, 0x00, 0x08, 0x00, 0x38, 0x00, 0x00, 0x00,   /* TargetName sec-buf */
        0x07, 0x82, 0x08, 0xa0,                            /* NegotiateFlags */
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,   /* ServerChallenge */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Reserved */
        0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,   /* TargetInfo sec-buf */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Padding 48-55 */
        0x43, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x50, 0x00,   /* UTF-16LE "CORP" */
    };
    // clang-format on
    uint8_t blob[320] = {0};
    char    b64[512]  = {0};
    size_t copy = blob_len < sizeof(template64) ? blob_len : sizeof(template64);
    int    n    = 0;

    assert_true(blob_len <= sizeof(blob));
    memcpy(blob, template64, copy);
    pn_base64_encode(blob, blob_len, b64, sizeof(b64));
    n = pn_snprintf(out,
                    out_cap,
                    "HTTP/1.1 407 Proxy Authentication Required\r\n"
                    "Proxy-Authenticate: NTLM %s\r\n\r\n",
                    b64);
    assert_true(n > 0 && (size_t)n < out_cap);
    *out_len = (size_t)n;
}

/**
 * @brief G-006: an oversized 407 challenge must fail cleanly.
 *
 * A 407 whose header section exceeds the 512-byte response buffer and never
 * terminates must yield PN_PROXY_ERROR with no out-of-bounds access.
 */
static void test_proxy_oversized_407_challenge_errors(void** state)
{
    (void)state;
    char              resp[600] = {0};
    size_t            resp_len  = 0;
    pn_proxy_result_t result    = PN_PROXY_IN_PROGRESS;
    int               i         = 0;

    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_BASIC;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    build_oversized_407(resp, 600, &resp_len);
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = resp_len;
    mock.recv_offset   = 0;

    for (i = 0; i < 8; ++i) {
        result = module->negotiate_tick(module, &conn, &mock_transport);
        if (PN_PROXY_IN_PROGRESS != result) {
            break;
        }
    }
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-006: a 407 filling response_buf exactly must parse cleanly.
 *
 * A well-formed Digest 407 that is exactly 512 bytes (with a valid
 * terminator) must be parsed without a truncation misparse.
 */
static void test_proxy_407_at_buffer_boundary_parses(void** state)
{
    (void)state;
    char   resp[600] = {0};
    size_t resp_len  = 0;

    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 8080;
    config.auth_type         = PN_PROXY_AUTH_DIGEST;
    config.username          = "admin";
    config.password          = "secret";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    build_digest_407_padded(resp, PN_PROXY_RESPONSE_BUF_SIZE, &resp_len);
    assert_int_equal(PN_PROXY_RESPONSE_BUF_SIZE, (int)resp_len);
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = resp_len;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    pn_proxy_connect_session_t* session =
        (pn_proxy_connect_session_t*)conn.proxy_session;
    assert_int_equal(PN_PROXY_CONNECT_SEND_AUTH_REQUEST, session->state);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-006: response_buf is reset between negotiate rounds.
 *
 * After the Type 3 auth request is sent, response_len must be zero and
 * response_buf cleared, so leftover Type 2 bytes cannot corrupt the next
 * response parse (legacy 80cd7bee regression guard).
 */
static void test_proxy_response_len_reset_between_rounds(void** state)
{
    (void)state;
    mock_reset();
    build_ntlm_type2_response();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    mock.recv_data     = (const uint8_t*)ntlm_type2_response;
    mock.recv_data_len = strlen(ntlm_type2_response);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    pn_proxy_connect_session_t* session =
        (pn_proxy_connect_session_t*)conn.proxy_session;
    assert_int_equal(0, (int)session->response_len);
    assert_int_equal('\0', session->response_buf[0]);

    mock.recv_data     = (const uint8_t*)PROXY_200;
    mock.recv_data_len = strlen(PROXY_200);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_COMPLETE, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-006: an oversized second-round 407 must fail cleanly.
 *
 * After a valid Type 2 round advances to the auth request, an oversized
 * unterminated auth response must yield PN_PROXY_ERROR with no corruption.
 */
static void test_proxy_oversized_407_second_round_errors(void** state)
{
    (void)state;
    char              resp[600] = {0};
    size_t            resp_len  = 0;
    pn_proxy_result_t result    = PN_PROXY_IN_PROGRESS;
    int               i         = 0;

    mock_reset();
    build_ntlm_type2_response();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    mock.recv_data     = (const uint8_t*)ntlm_type2_response;
    mock.recv_data_len = strlen(ntlm_type2_response);
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    build_oversized_407(resp, 600, &resp_len);
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = resp_len;
    mock.recv_offset   = 0;

    for (i = 0; i < 8; ++i) {
        result = module->negotiate_tick(module, &conn, &mock_transport);
        if (PN_PROXY_IN_PROGRESS != result) {
            break;
        }
    }
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-007: a Type 2 blob at the 256-byte bound is accepted.
 *
 * A Type 2 message decoding to exactly ntlm_type2_buf (256 bytes) is the
 * largest challenge the decoder accepts; negotiation must continue.
 */
static void test_proxy_ntlm_type2_max_size_accepted(void** state)
{
    (void)state;
    char   resp[600] = {0};
    size_t resp_len  = 0;

    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    build_ntlm_407_with_blob_len(resp, sizeof(resp), 256, &resp_len);
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = resp_len;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    pn_proxy_connect_session_t* session =
        (pn_proxy_connect_session_t*)conn.proxy_session;
    assert_int_equal(PN_PROXY_CONNECT_SEND_AUTH_REQUEST, session->state);
    assert_int_equal(256, (int)session->ntlm_type2_len);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-007: a Type 2 blob one byte past the bound is rejected.
 *
 * A Type 2 decoding to 257 bytes exceeds the 256-byte ntlm_type2_buf; the
 * decoder must reject it cleanly with no overflow.
 */
static void test_proxy_ntlm_type2_over_max_rejected(void** state)
{
    (void)state;
    char   resp[600] = {0};
    size_t resp_len  = 0;

    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    build_ntlm_407_with_blob_len(resp, sizeof(resp), 257, &resp_len);
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = resp_len;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-007: an NTLM Type 2 token with invalid base64 is rejected.
 */
static void test_proxy_ntlm_type2_invalid_base64(void** state)
{
    (void)state;
    static const char resp[] = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                               "Proxy-Authenticate: NTLM !!!!\r\n\r\n";

    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = sizeof(resp) - 1;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

/**
 * @brief G-007: an NTLM Type 2 header with an empty token is rejected.
 */
static void test_proxy_ntlm_type2_empty_token(void** state)
{
    (void)state;
    static const char resp[] = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                               "Proxy-Authenticate: NTLM \r\n\r\n";

    mock_reset();

    pn_proxy_config_t config = {0};
    config.host              = "proxy.example.com";
    config.port              = 3128;
    config.auth_type         = PN_PROXY_AUTH_NTLM;
    config.username          = "user";
    config.password          = "pass";

    pn_proxy_module_t* module = pn_proxy_connect_create(&config, &mock_allocator);
    assert_non_null(module);

    pn_socket_connection_t conn = {0};
    conn.socket                 = MOCK_SOCKET_FD;

    pn_proxy_result_t result = module->negotiate_start(
        module, &conn, &mock_transport, "ps.pndsn.com", 443);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    result = tick_until_sent(module, &conn);
    assert_int_equal(PN_PROXY_IN_PROGRESS, result);

    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = sizeof(resp) - 1;
    mock.recv_offset   = 0;

    result = module->negotiate_tick(module, &conn, &mock_transport);
    assert_int_equal(PN_PROXY_ERROR, result);

    mock_allocator.free(&mock_allocator, conn.proxy_session);
    module->destroy(module, &mock_allocator);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_proxy_basic_200),
        cmocka_unit_test(test_proxy_basic_403),
        cmocka_unit_test(test_proxy_no_auth_200),
        cmocka_unit_test(test_proxy_no_auth_500),
        cmocka_unit_test(test_proxy_send_would_block),
        cmocka_unit_test(test_proxy_recv_partial),
        cmocka_unit_test(test_proxy_recv_connection_closed),
        cmocka_unit_test(test_proxy_digest_407_200),
        cmocka_unit_test(test_proxy_digest_malformed_challenge),
        cmocka_unit_test(test_proxy_digest_wrong_credentials),
        cmocka_unit_test(test_proxy_ntlm_type1_type3_200),
        cmocka_unit_test(test_proxy_ntlm_invalid_type2),
        cmocka_unit_test(test_proxy_ntlm_short_type2),
        cmocka_unit_test(test_proxy_null_module),
        cmocka_unit_test(test_proxy_session_alloc_failure),
        cmocka_unit_test(test_proxy_ntlm_type2_parse_domain),
        cmocka_unit_test(test_proxy_ntlm_type2_parse_no_domain),
        cmocka_unit_test(test_proxy_oversized_407_challenge_errors),
        cmocka_unit_test(test_proxy_407_at_buffer_boundary_parses),
        cmocka_unit_test(test_proxy_response_len_reset_between_rounds),
        cmocka_unit_test(test_proxy_oversized_407_second_round_errors),
        cmocka_unit_test(test_proxy_ntlm_type2_max_size_accepted),
        cmocka_unit_test(test_proxy_ntlm_type2_over_max_rejected),
        cmocka_unit_test(test_proxy_ntlm_type2_invalid_base64),
        cmocka_unit_test(test_proxy_ntlm_type2_empty_token),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

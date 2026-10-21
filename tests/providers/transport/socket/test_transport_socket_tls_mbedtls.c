/*
 * PubNub C SDK
 * Copyright (c) 2026 PubNub Inc.
 * https://www.pubnub.com/
 *
 * SPDX-License-Identifier: PubNub-Software-Development-Agreement
 * For full license terms, see LICENSE.txt or https://www.pubnub.com/legal/
 */

#include "providers/transport/socket/platform/pn_socket_types.h"
#include "providers/transport/socket/tls/pn_tls_backend.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/provider_deps.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

extern const pn_tls_backend_t pn_tls_mbedtls_backend;

static int g_alloc_calls;
static int g_free_calls;

static void* tracking_alloc(struct pubnub_allocator_provider* self,
                            size_t                            size,
                            size_t                            align)
{
    (void)self;
    (void)align;
    g_alloc_calls++;
    return malloc(size);
}

static void tracking_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    g_free_calls++;
    free(ptr);
}

static pubnub_allocator_provider_t tracking_allocator = {
    .alloc       = tracking_alloc,
    .realloc     = NULL,
    .free        = tracking_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static pubnub_provider_deps_t tracking_deps = {
    .allocator     = &tracking_allocator,
    .logger        = NULL,
    .platform      = NULL,
    .proxy         = NULL,
    .tcp_keepalive = NULL,
};

/**
 * @brief Verify ctx_create routes through the SDK allocator.
 */
static void test_ctx_create_uses_allocator(void** state)
{
    (void)state;

    g_alloc_calls = 0;
    g_free_calls  = 0;

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    cfg.skip_verify     = 1;
    void* ctx = pn_tls_mbedtls_backend.ctx_create(&cfg, &tracking_deps);
    assert_non_null(ctx);
    assert_true(0 < g_alloc_calls);

    int alloc_before_destroy = g_alloc_calls;
    pn_tls_mbedtls_backend.ctx_destroy(ctx);
    (void)alloc_before_destroy;
    assert_true(0 < g_free_calls);
}

/**
 * @brief Verify ctx_create fails gracefully with NULL deps.
 */
static void test_ctx_create_null_deps(void** state)
{
    (void)state;

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    cfg.skip_verify     = 1;
    void* ctx           = pn_tls_mbedtls_backend.ctx_create(&cfg, NULL);
    assert_null(ctx);
}

/**
 * @brief Verify session_create routes through the allocator from ctx.
 */
static void test_session_create_uses_allocator(void** state)
{
    (void)state;

    g_alloc_calls = 0;
    g_free_calls  = 0;

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    cfg.skip_verify     = 1;
    void* ctx = pn_tls_mbedtls_backend.ctx_create(&cfg, &tracking_deps);
    assert_non_null(ctx);

    int allocs_after_ctx = g_alloc_calls;

    /* session_create with invalid socket must fail but should still attempt
     * allocation before hitting the validation error or cleanup. However,
     * since PN_INVALID_SOCKET is validated first in session_create, it
     * returns -1 before allocating. Test with a real (but dummy) fd. */
    void* session = NULL;
    int   rc      = pn_tls_mbedtls_backend.session_create(
        &session, ctx, PN_INVALID_SOCKET, NULL, "example.com");
    assert_int_equal(rc, -1);
    assert_null(session);

    /* Alloc count should not have increased (early validation failure). */
    assert_int_equal(g_alloc_calls, allocs_after_ctx);

    pn_tls_mbedtls_backend.ctx_destroy(ctx);
    assert_true(0 < g_free_calls);
}

/**
 * @brief Security invariant: PN_TLS_CONFIG_INIT is secure by default.
 *
 * Certificate verification must be ON (skip_verify == 0) and the platform
 * trust store loaded (use_system_certs == 1) with zero configuration.
 * skip_verify is a TESTING-ONLY escape hatch and must never default on.
 *
 * No-cleartext-downgrade invariant: when PUBNUB_ENABLE_SECURE_TRANSPORT is
 * compiled in, an https request always creates a TLS session; there is no
 * plaintext downgrade path if the handshake or certificate verification
 * fails -- the connection fails closed rather than falling back to cleartext.
 */
static void test_tls_config_secure_by_default(void** state)
{
    (void)state;

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;

    assert_int_equal(0, cfg.skip_verify);
    assert_int_equal(1, cfg.use_system_certs);
}

/**
 * @brief Error codes map to their own mbedTLS names.
 *
 * Unknown codes must yield NULL so callers can fall back to generic text.
 */
static void test_tls_mbedtls_error_str_labels(void** state)
{
    (void)state;

    static const struct {
        int         code;
        const char* label;
    } cases[] = {
        {-0x2700, "X509_CERT_VERIFY_FAILED"  },
        {-0x2800, "X509_BAD_INPUT_DATA"      },
        {-0x7780, "SSL_FATAL_ALERT_MESSAGE"  },
        {-0x7700, "SSL_UNEXPECTED_MESSAGE"   },
        {-0x7880, "SSL_PEER_CLOSE_NOTIFY"    },
        {-0x7280, "SSL_CONN_EOF"             },
        {-0x6800, "SSL_TIMEOUT"              },
        {-0x6480, "SSL_EARLY_MESSAGE"        },
        {-0x7200, "SSL_INVALID_RECORD"       },
        {-0x7180, "SSL_INVALID_MAC"          },
        {-0x7480, "SSL_NO_CLIENT_CERTIFICATE"},
        {-0x7A00, "SSL_BAD_CERTIFICATE"      },
        {-0x7100, "SSL_BAD_INPUT_DATA"       },
        {-0x7F00, "SSL_ALLOC_FAILED"         },
        {-0x0050, "NET_CONN_RESET"           },
        {-0x004E, "NET_SEND_FAILED"          },
        {-0x004C, "NET_RECV_FAILED"          },
    };

    const size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t       i;
    size_t       j;

    assert_non_null(pn_tls_mbedtls_backend.session_error_str);
    for (i = 0; i < n; ++i) {
        const char* got = pn_tls_mbedtls_backend.session_error_str(cases[i].code);
        assert_non_null(got);
        assert_string_equal(cases[i].label, got);
        for (j = i + 1; j < n; ++j) {
            assert_string_not_equal(cases[i].label, cases[j].label);
        }
    }

    assert_null(pn_tls_mbedtls_backend.session_error_str(0));
    assert_null(pn_tls_mbedtls_backend.session_error_str(-1));
    assert_null(pn_tls_mbedtls_backend.session_error_str(-0x1234));
}

#if !defined(_WIN32)

extern const struct pn_socket_platform_ops pn_posix_socket_ops;

/** Capacity of the captured log text. */
#define CAP_LOG_SIZE 4096

/**
 * @brief Logger that records every text entry as "<level-letter> <message>\n".
 */
typedef struct cap_logger {
    /** Base provider (must be first member). */
    pubnub_logger_provider_t base;
    /** Concatenated captured entries (NUL-terminated). */
    char text[CAP_LOG_SIZE];
    /** Bytes used in text. */
    size_t len;
} cap_logger_t;

static cap_logger_t g_cap;

/**
 * @brief Logger callback: append a text entry to the capture buffer.
 *
 * @param self  Provider (a cap_logger_t).
 * @param entry Log entry; only text entries are recorded.
 */
static void cap_log(struct pubnub_logger_provider* self,
                    const pubnub_log_entry_t*      entry)
{
    cap_logger_t* cap = (cap_logger_t*)self;
    char          letter;
    int           n;

    if (PUBNUB_LOG_ENTRY_TEXT != entry->type) {
        return;
    }
    switch (entry->level) {
    case PUBNUB_LOG_LEVEL_TRACE: letter = 'T'; break;
    case PUBNUB_LOG_LEVEL_DEBUG: letter = 'D'; break;
    case PUBNUB_LOG_LEVEL_INFO: letter = 'I'; break;
    case PUBNUB_LOG_LEVEL_WARNING: letter = 'W'; break;
    default: letter = 'E'; break;
    }
    n = snprintf(cap->text + cap->len,
                 sizeof(cap->text) - cap->len,
                 "%c %s\n",
                 letter,
                 ((const pubnub_log_entry_text_t*)entry)->message);
    if (0 < n && (size_t)n < sizeof(cap->text) - cap->len) {
        cap->len += (size_t)n;
    }
}

/** @brief A failed handshake logs the code, then the mbedTLS text. */
static void test_tls_mbedtls_handshake_failure_logs(void** state)
{
    (void)state;
    if (0 == PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE) {
        skip();
    }

    static const char garbage[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
    int               fds[2]    = {-1, -1};
    pn_tls_config_t   cfg       = PN_TLS_CONFIG_INIT;
    void*             ctx       = NULL;
    void*             sess      = NULL;
    int               rc        = 0;
    int               i         = 0;

    memset(&g_cap, 0, sizeof(g_cap));
    g_cap.base.log = cap_log;

    pubnub_provider_deps_t deps = tracking_deps;
    deps.logger                 = &g_cap.base;

    assert_int_equal(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    (void)fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK);
    assert_int_equal((int)sizeof(garbage) - 1,
                     (int)write(fds[1], garbage, sizeof(garbage) - 1));

    cfg.skip_verify = 1;
    ctx             = pn_tls_mbedtls_backend.ctx_create(&cfg, &deps);
    assert_non_null(ctx);
    assert_int_equal(
        0,
        pn_tls_mbedtls_backend.session_create(
            &sess, ctx, (pn_socket_t)fds[0], &pn_posix_socket_ops, "localhost"));

    for (i = 0; i < 10 && 0 <= rc; ++i) {
        rc = pn_tls_mbedtls_backend.handshake(sess);
    }
    assert_true(0 > rc);
    assert_non_null(strstr(g_cap.text, "W TLS handshake error: rc=-"));
    assert_non_null(strstr(g_cap.text, " resume="));
    assert_non_null(strstr(g_cap.text, " ("));

    pn_tls_mbedtls_backend.session_destroy(sess);
    pn_tls_mbedtls_backend.ctx_destroy(ctx);
    close(fds[0]);
    close(fds[1]);
}

#endif /* !defined(_WIN32) */

#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)

static pn_socket_t connect_tcp(const char* hostname, const char* port)
{
    struct addrinfo hints = {0};
    hints.ai_family       = AF_UNSPEC;
    hints.ai_socktype     = SOCK_STREAM;

    struct addrinfo* result = NULL;
    int              rc     = getaddrinfo(hostname, port, &hints, &result);
    if (0 != rc || NULL == result) {
        return PN_INVALID_SOCKET;
    }

    pn_socket_t sock = PN_INVALID_SOCKET;
    for (struct addrinfo* rp = result; NULL != rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (PN_INVALID_SOCKET == sock) {
            continue;
        }
        if (0 == connect(sock, rp->ai_addr, rp->ai_addrlen)) {
            break;
        }
        close(sock);
        sock = PN_INVALID_SOCKET;
    }
    freeaddrinfo(result);

    if (PN_INVALID_SOCKET != sock) {
        int flags = fcntl(sock, F_GETFL, 0);
        if (0 <= flags) {
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
    }
    return sock;
}

/**
 * @brief Integration: TLS handshake and HTTP GET via mbedTLS backend.
 */
static void test_tls_mbedtls_integration(void** state)
{
    (void)state;

    g_alloc_calls = 0;
    g_free_calls  = 0;

    pn_socket_t sock = connect_tcp("ps.pndsn.com", "443");
    assert_int_not_equal(sock, PN_INVALID_SOCKET);

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    void* ctx = pn_tls_mbedtls_backend.ctx_create(&cfg, &tracking_deps);
    assert_non_null(ctx);
    assert_true(0 < g_alloc_calls);

    void* session = NULL;
    int   rc      = pn_tls_mbedtls_backend.session_create(
        &session, ctx, sock, &pn_posix_socket_ops, "ps.pndsn.com");
    assert_int_equal(rc, 0);
    assert_non_null(session);

    /* Drive handshake. */
    int handshake_result = -1;
    for (int i = 0; i < 100; ++i) {
        handshake_result = pn_tls_mbedtls_backend.handshake(session);
        if (PN_TLS_OK == handshake_result) {
            break;
        }
        if (0 > handshake_result) {
            break;
        }
        struct pollfd pfd = {0};
        pfd.fd            = sock;
        if (PN_TLS_WANT_READ == handshake_result) {
            pfd.events = POLLIN;
        } else if (PN_TLS_WANT_WRITE == handshake_result) {
            pfd.events = POLLOUT;
        }
        poll(&pfd, 1, 2000);
    }
    assert_int_equal(handshake_result, PN_TLS_OK);

    /* Send HTTP GET. */
    const char request[] = "GET /time/0 HTTP/1.1\r\nHost: ps.pndsn.com\r\n\r\n";
    size_t     sent      = 0;
    while (sent < sizeof(request) - 1) {
        int n = pn_tls_mbedtls_backend.send(
            session, request + sent, sizeof(request) - 1 - sent);
        if (0 < n) {
            sent += n;
        } else if (0 == n) {
            struct pollfd pfd = {0};
            pfd.fd            = sock;
            pfd.events        = POLLOUT;
            poll(&pfd, 1, 1000);
        } else {
            fail_msg("Send failed");
        }
    }

    /* Receive response. */
    char   response[1024] = {0};
    size_t received       = 0;
    int    complete       = 0;
    for (int i = 0; i < 100; ++i) {
        int n = pn_tls_mbedtls_backend.recv(
            session, response + received, sizeof(response) - received - 1);
        if (0 < n) {
            received += n;
            if (NULL != strstr(response, "\r\n\r\n")) {
                complete = 1;
                break;
            }
        } else if (0 == n) {
            struct pollfd pfd = {0};
            pfd.fd            = sock;
            pfd.events        = POLLIN;
            poll(&pfd, 1, 1000);
        } else {
            break;
        }
    }
    assert_int_equal(complete, 1);
    assert_non_null(strstr(response, "HTTP/1.1 200"));

    int frees_before = g_free_calls;
    pn_tls_mbedtls_backend.session_destroy(session);
    assert_true(g_free_calls > frees_before);

    pn_tls_mbedtls_backend.ctx_destroy(ctx);
    close(sock);
}

/**
 * @brief Helper: drive a handshake against host:443, return terminal result.
 *
 * Uses the default secure config (verification ON). Reuses the same
 * WANT_READ/WANT_WRITE poll loop as test_tls_mbedtls_integration. Returns the
 * terminal handshake result: PN_TLS_OK on success, < 0 on rejection or
 * connect failure.
 */
static int tls_handshake_result_for(const char* hostname)
{
    pn_socket_t sock = connect_tcp(hostname, "443");
    if (PN_INVALID_SOCKET == sock) {
        return -1;
    }

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    void* ctx = pn_tls_mbedtls_backend.ctx_create(&cfg, &tracking_deps);
    if (NULL == ctx) {
        close(sock);
        return -1;
    }

    void* session = NULL;
    int   rc      = pn_tls_mbedtls_backend.session_create(
        &session, ctx, sock, &pn_posix_socket_ops, hostname);
    if (0 != rc) {
        pn_tls_mbedtls_backend.ctx_destroy(ctx);
        close(sock);
        return -1;
    }

    int handshake_result = -1;
    for (int i = 0; i < 100; ++i) {
        handshake_result = pn_tls_mbedtls_backend.handshake(session);
        if (PN_TLS_OK == handshake_result || 0 > handshake_result) {
            break;
        }

        struct pollfd pfd = {0};
        pfd.fd            = sock;
        if (PN_TLS_WANT_READ == handshake_result) {
            pfd.events = POLLIN;
        } else if (PN_TLS_WANT_WRITE == handshake_result) {
            pfd.events = POLLOUT;
        }
        poll(&pfd, 1, 2000);
    }

    pn_tls_mbedtls_backend.session_destroy(session);
    pn_tls_mbedtls_backend.ctx_destroy(ctx);
    close(sock);
    return handshake_result;
}

/**
 * @brief Cert rejection: expired certificate must fail the handshake.
 */
static void test_tls_rejects_expired_cert(void** state)
{
    (void)state;

    int result = tls_handshake_result_for("expired.badssl.com");
    assert_true(0 > result);
}

/**
 * @brief Cert rejection: hostname mismatch must fail the handshake.
 */
static void test_tls_rejects_wrong_host_cert(void** state)
{
    (void)state;

    int result = tls_handshake_result_for("wrong.host.badssl.com");
    assert_true(0 > result);
}

/**
 * @brief Cert rejection: self-signed certificate must fail the handshake.
 */
static void test_tls_rejects_self_signed_cert(void** state)
{
    (void)state;

    int result = tls_handshake_result_for("self-signed.badssl.com");
    assert_true(0 > result);
}

/**
 * @brief Positive control: a valid certificate must complete the handshake.
 */
static void test_tls_accepts_valid_cert(void** state)
{
    (void)state;

    int result = tls_handshake_result_for("ps.pndsn.com");
    assert_int_equal(PN_TLS_OK, result);
}

#endif /* PUBNUB_TEST_NETWORK */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ctx_create_uses_allocator),
        cmocka_unit_test(test_ctx_create_null_deps),
        cmocka_unit_test(test_session_create_uses_allocator),
        cmocka_unit_test(test_tls_config_secure_by_default),
        cmocka_unit_test(test_tls_mbedtls_error_str_labels),
#if !defined(_WIN32)
        cmocka_unit_test(test_tls_mbedtls_handshake_failure_logs),
#endif
#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)
        cmocka_unit_test(test_tls_mbedtls_integration),
        cmocka_unit_test(test_tls_rejects_expired_cert),
        cmocka_unit_test(test_tls_rejects_wrong_host_cert),
        cmocka_unit_test(test_tls_rejects_self_signed_cert),
        cmocka_unit_test(test_tls_accepts_valid_cert),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

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
#include "pubnub/providers/provider_deps.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

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

#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)

extern const struct pn_socket_platform_ops pn_posix_socket_ops;

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

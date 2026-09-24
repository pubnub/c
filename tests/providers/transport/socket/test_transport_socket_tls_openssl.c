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

/* Network-free regression tests drive the backend over a socketpair against
 * an in-process TLS peer, and inspect the OpenSSL thread error queue directly
 * (POSIX + OpenSSL only). */
#if !defined(_WIN32)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)
#include <netdb.h>
#endif

/* Forward declaration of the OpenSSL backend. */
extern const pn_tls_backend_t pn_tls_openssl_backend;

static void* stub_alloc(struct pubnub_allocator_provider* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void stub_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t stub_allocator = {
    .alloc       = stub_alloc,
    .realloc     = NULL,
    .free        = stub_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static pubnub_provider_deps_t test_deps = {
    .allocator     = &stub_allocator,
    .logger        = NULL,
    .platform      = NULL,
    .proxy         = NULL,
    .tcp_keepalive = NULL,
};

/**
 * @brief Unit test: create and destroy TLS context with defaults.
 */
static void test_ctx_create_destroy(void** state)
{
    (void)state;

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;

    void* ctx = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    assert_non_null(ctx);

    pn_tls_openssl_backend.ctx_destroy(ctx);
}

/**
 * @brief Unit test: session_create with invalid socket.
 */
static void test_session_create_invalid_fd(void** state)
{
    (void)state;

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    void*           ctx = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    assert_non_null(ctx);

    void* session = NULL;
    int   rc      = pn_tls_openssl_backend.session_create(
        &session, ctx, PN_INVALID_SOCKET, NULL, "example.com");
    assert_int_equal(rc, -1);
    assert_null(session);

    pn_tls_openssl_backend.ctx_destroy(ctx);
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

#if !defined(_WIN32)

/**
 * @brief Seed the current thread's OpenSSL error queue with a stale error.
 *
 * Reproduces the production leak: SSL_shutdown on an SSL still in handshake
 * init queues SSL_R_SHUTDOWN_WHILE_IN_INIT, and SSL_free does not clear it,
 * so the entry survives on the thread until explicitly cleared.
 */
static void seed_stale_thread_error(void)
{
    SSL_CTX* tmp_ctx = SSL_CTX_new(TLS_client_method());
    if (NULL != tmp_ctx) {
        SSL* tmp_ssl = SSL_new(tmp_ctx);
        if (NULL != tmp_ssl) {
            SSL_set_connect_state(tmp_ssl);
            /* Depends on OpenSSL 3.x queueing SSL_R_SHUTDOWN_WHILE_IN_INIT
             * when SSL_shutdown runs on a session still in handshake init. */
            (void)SSL_shutdown(tmp_ssl);
            SSL_free(tmp_ssl);
        }
        SSL_CTX_free(tmp_ctx);
    }
}

/**
 * @brief Create a socketpair with both ends set non-blocking.
 *
 * @param fds Output array of two socket descriptors.
 * @return 0 on success, -1 on failure.
 */
static int make_nonblocking_pair(int fds[2])
{
    int i;
    if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        int flags = fcntl(fds[i], F_GETFL, 0);
        if (0 <= flags) {
            (void)fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
        }
    }
    return 0;
}

/**
 * @brief Generate a throwaway EC key + self-signed certificate for the peer.
 *
 * The offline TLS peer needs a credential; certificate verification is
 * disabled on the client side, so any self-signed leaf is sufficient.
 *
 * @param out_key Receives the generated key pair (caller frees).
 * @param out_crt Receives the self-signed certificate (caller frees).
 * @return 0 on success, -1 on failure.
 */
static int make_self_signed(EVP_PKEY** out_key, X509** out_crt)
{
    EVP_PKEY_CTX* pctx = NULL;
    EVP_PKEY*     key  = NULL;
    X509*         crt  = NULL;
    X509_NAME*    name = NULL;

    *out_key = NULL;
    *out_crt = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (NULL == pctx) {
        return -1;
    }

    if (0 >= EVP_PKEY_keygen_init(pctx)
        || 0 >= EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)
        || 0 >= EVP_PKEY_keygen(pctx, &key)) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    crt = X509_new();
    if (NULL == crt) {
        EVP_PKEY_free(key);
        return -1;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_getm_notBefore(crt), 0);
    X509_gmtime_adj(X509_getm_notAfter(crt), 3600);
    X509_set_pubkey(crt, key);

    name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(crt, name);

    if (0 == X509_sign(crt, key, EVP_sha256())) {
        X509_free(crt);
        EVP_PKEY_free(key);
        return -1;
    }

    *out_key = key;
    *out_crt = crt;
    return 0;
}

/**
 * @brief Drive a client (backend) and server (raw OpenSSL) handshake to
 *        completion over a local socketpair.
 *
 * @param client_session Backend session on client_fd.
 * @param server_ssl     Raw OpenSSL server SSL on server_fd.
 * @param client_fd      Client socket descriptor.
 * @param server_fd      Server socket descriptor.
 * @return 0 when both sides complete, -1 on error or timeout.
 */
static int drive_offline_handshake(void* client_session,
                                   SSL*  server_ssl,
                                   int   client_fd,
                                   int   server_fd)
{
    int client_done = 0;
    int server_done = 0;
    int i;

    for (i = 0; i < 200; ++i) {
        struct pollfd pfds[2] = {{0}, {0}};
        if (0 == client_done) {
            int r = pn_tls_openssl_backend.handshake(client_session);
            if (PN_TLS_OK == r) {
                client_done = 1;
            } else if (0 > r) {
                return -1;
            }
        }
        if (0 == server_done) {
            int r = SSL_accept(server_ssl);
            if (1 == r) {
                server_done = 1;
            } else {
                int e = SSL_get_error(server_ssl, r);
                if (SSL_ERROR_WANT_READ != e && SSL_ERROR_WANT_WRITE != e) {
                    return -1;
                }
            }
        }
        if (0 != client_done && 0 != server_done) {
            return 0;
        }

        pfds[0].fd     = client_fd;
        pfds[0].events = POLLIN | POLLOUT;
        pfds[1].fd     = server_fd;
        pfds[1].events = POLLIN | POLLOUT;
        (void)poll(pfds, 2, 100);
    }
    return -1;
}

/**
 * @brief Regression: a stale thread error queue must not poison recv.
 *
 * After a completed handshake, a benign would-block SSL_read must be reported
 * as would-block (0). A stale ERR_LIB_SSL entry left on the thread queue by a
 * prior session's SSL_shutdown must not make SSL_get_error() report a hard
 * error (-2). Fails on the unfixed backend, which peeks the stale entry,
 * returns -2, and stores the stale error code.
 */
static void test_recv_ignores_stale_thread_error(void** state)
{
    (void)state;

    int fds[2] = {-1, -1};
    assert_int_equal(0, make_nonblocking_pair(fds));

    EVP_PKEY* key = NULL;
    X509*     crt = NULL;
    assert_int_equal(0, make_self_signed(&key, &crt));

    SSL_CTX* server_ctx = SSL_CTX_new(TLS_server_method());
    assert_non_null(server_ctx);
    assert_int_equal(1, SSL_CTX_use_certificate(server_ctx, crt));
    assert_int_equal(1, SSL_CTX_use_PrivateKey(server_ctx, key));
    /* Force TLS 1.2 and suppress session tickets so the client's first
     * post-handshake read is a pure would-block (no ticket-processing state
     * machine that would clear the thread error queue on its own). This
     * mirrors the production path where a benign would-block read is
     * misclassified by a stale queue entry. */
    (void)SSL_CTX_set_max_proto_version(server_ctx, TLS1_2_VERSION);
    (void)SSL_CTX_set_options(server_ctx, SSL_OP_NO_TICKET);

    SSL* server_ssl = SSL_new(server_ctx);
    assert_non_null(server_ssl);
    assert_int_equal(1, SSL_set_fd(server_ssl, fds[1]));
    SSL_set_accept_state(server_ssl);

    /* Client side: disable verification so the throwaway leaf is accepted. */
    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    cfg.skip_verify     = 1;
    void* ctx           = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    assert_non_null(ctx);

    void* session = NULL;
    int   rc      = pn_tls_openssl_backend.session_create(
        &session, ctx, (pn_socket_t)fds[0], NULL, "localhost");
    assert_int_equal(0, rc);
    assert_non_null(session);

    assert_int_equal(
        0, drive_offline_handshake(session, server_ssl, fds[0], fds[1]));

    /* Poison the thread error queue, then read post-handshake with no data
     * pending on the wire: this must classify as would-block, not a hard
     * error, regardless of the stale entry. */
    ERR_clear_error();
    seed_stale_thread_error();
    unsigned long seeded = ERR_peek_error();
    assert_int_not_equal(0, seeded);

    char buf[64] = {0};
    int  n       = pn_tls_openssl_backend.recv(session, buf, sizeof(buf));

    assert_int_equal(0, n);
    assert_int_not_equal((int)seeded,
                         pn_tls_openssl_backend.get_session_error(session));
    assert_int_equal(0, pn_tls_openssl_backend.get_session_error(session));

    pn_tls_openssl_backend.session_destroy(session);
    pn_tls_openssl_backend.ctx_destroy(ctx);
    SSL_free(server_ssl);
    SSL_CTX_free(server_ctx);
    X509_free(crt);
    EVP_PKEY_free(key);
    ERR_clear_error();
    close(fds[0]);
    close(fds[1]);
}

/**
 * @brief Regression: session_destroy must not leak an error onto the thread.
 *
 * Destroying a session still in handshake init runs a best-effort
 * SSL_shutdown that queues SSL_R_SHUTDOWN_WHILE_IN_INIT. The thread error
 * queue must be empty afterwards so the next TLS operation on this thread
 * classifies correctly. Fails on the unfixed backend, which leaves the
 * shutdown error queued.
 */
static void test_session_destroy_clears_thread_error(void** state)
{
    (void)state;

    int fds[2] = {-1, -1};
    assert_int_equal(0, make_nonblocking_pair(fds));

    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    void*           ctx = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    assert_non_null(ctx);

    void* session = NULL;
    int   rc      = pn_tls_openssl_backend.session_create(
        &session, ctx, (pn_socket_t)fds[0], NULL, "example.com");
    assert_int_equal(0, rc);
    assert_non_null(session);

    /* Session is still in handshake init (no handshake driven). */
    ERR_clear_error();
    pn_tls_openssl_backend.session_destroy(session);

    assert_int_equal(0, ERR_peek_error());

    pn_tls_openssl_backend.ctx_destroy(ctx);
    ERR_clear_error();
    close(fds[0]);
    close(fds[1]);
}

/** SIGPIPE observation flag, raised by the test signal handler. */
static volatile sig_atomic_t g_sigpipe = 0;

/**
 * @brief SIGPIPE handler that records delivery without terminating the test.
 *
 * @param signum Delivered signal number (unused).
 */
static void sigpipe_flag_handler(int signum)
{
    (void)signum;
    g_sigpipe = 1;
}

/**
 * @brief Regression: a broken-pipe write through the custom BIO must not
 *        raise SIGPIPE.
 *
 * The C3 fix replaced SSL_set_fd with a custom source/sink BIO whose write
 * path uses send(..., MSG_NOSIGNAL) instead of the OS write(). Writing into a
 * connection whose peer has just sent RST must therefore surface a clean
 * error, not a process-terminating SIGPIPE. This drives a completed TLS
 * session over a socketpair, forces the server end to reset with SO_LINGER=0,
 * then pushes data through the dead connection: the backend send must report
 * an error while SIGPIPE is never delivered.
 */
static void tls_openssl_should_not_raise_sigpipe_on_rst(void** state)
{
    (void)state;

    struct sigaction sa_new     = {0};
    struct sigaction sa_old     = {0};
    struct linger    lg         = {0};
    int              fds[2]     = {-1, -1};
    EVP_PKEY*        key        = NULL;
    X509*            crt        = NULL;
    SSL_CTX*         server_ctx = NULL;
    SSL*             server_ssl = NULL;
    void*            ctx        = NULL;
    void*            session    = NULL;
    pn_tls_config_t  cfg        = PN_TLS_CONFIG_INIT;
    char             payload[4096];
    int              saw_error = 0;
    int              rc        = 0;
    int              i         = 0;

    g_sigpipe         = 0;
    sa_new.sa_handler = sigpipe_flag_handler;
    sigemptyset(&sa_new.sa_mask);
    assert_int_equal(0, sigaction(SIGPIPE, &sa_new, &sa_old));

    assert_int_equal(0, make_nonblocking_pair(fds));
    assert_int_equal(0, make_self_signed(&key, &crt));

    server_ctx = SSL_CTX_new(TLS_server_method());
    assert_non_null(server_ctx);
    assert_int_equal(1, SSL_CTX_use_certificate(server_ctx, crt));
    assert_int_equal(1, SSL_CTX_use_PrivateKey(server_ctx, key));

    server_ssl = SSL_new(server_ctx);
    assert_non_null(server_ssl);
    assert_int_equal(1, SSL_set_fd(server_ssl, fds[1]));
    SSL_set_accept_state(server_ssl);

    cfg.skip_verify = 1;
    ctx             = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    assert_non_null(ctx);

    rc = pn_tls_openssl_backend.session_create(
        &session, ctx, (pn_socket_t)fds[0], NULL, "localhost");
    assert_int_equal(0, rc);
    assert_non_null(session);

    assert_int_equal(
        0, drive_offline_handshake(session, server_ssl, fds[0], fds[1]));

    /* SO_LINGER with a zero timeout makes close() discard the send buffer and
     * reset the connection instead of draining it gracefully. */
    lg.l_onoff  = 1;
    lg.l_linger = 0;
    (void)setsockopt(fds[1], SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    /* SSL_set_fd binds the fd with BIO_NOCLOSE, so SSL_free leaves fds[1]
     * open; the explicit close() is what tears down the peer. */
    SSL_free(server_ssl);
    server_ssl = NULL;
    close(fds[1]);
    fds[1] = -1;

    /* Push several records into the dead connection. The first send may still
     * be buffered locally; a subsequent one hits the broken pipe. Without
     * MSG_NOSIGNAL the failing write would deliver SIGPIPE before returning. */
    memset(payload, 'x', sizeof(payload));
    for (i = 0; i < 100 && 0 == saw_error; ++i) {
        int n = pn_tls_openssl_backend.send(session, payload, sizeof(payload));
        if (0 > n) {
            saw_error = 1;
        }
    }

    assert_int_equal(0, (int)g_sigpipe);
    assert_int_equal(1, saw_error);

    pn_tls_openssl_backend.session_destroy(session);
    pn_tls_openssl_backend.ctx_destroy(ctx);
    SSL_CTX_free(server_ctx);
    X509_free(crt);
    EVP_PKEY_free(key);
    ERR_clear_error();
    close(fds[0]);
    (void)sigaction(SIGPIPE, &sa_old, NULL);
}

#endif /* !defined(_WIN32) */

#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)

/**
 * @brief Helper: connect TCP socket to host:port.
 *
 * @param hostname Server hostname.
 * @param port     Server port.
 * @return Connected socket, or PN_INVALID_SOCKET on failure.
 */
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

    /* Set non-blocking. */
    if (PN_INVALID_SOCKET != sock) {
        int flags = fcntl(sock, F_GETFL, 0);
        if (0 <= flags) {
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
    }

    return sock;
}

/**
 * @brief Integration test: TLS handshake and HTTP GET to ps.pndsn.com:443.
 */
static void test_tls_integration(void** state)
{
    (void)state;

    /* Connect TCP socket. */
    pn_socket_t sock = connect_tcp("ps.pndsn.com", "443");
    assert_int_not_equal(sock, PN_INVALID_SOCKET);

    /* Create TLS context with system certs. */
    pn_tls_config_t cfg = PN_TLS_CONFIG_INIT;
    void*           ctx = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    assert_non_null(ctx);

    /* Create TLS session. */
    void* session = NULL;
    int   rc      = pn_tls_openssl_backend.session_create(
        &session, ctx, sock, NULL, "ps.pndsn.com");
    assert_int_equal(rc, 0);
    assert_non_null(session);

    /* Drive handshake. */
    int handshake_result = -1;
    for (int i = 0; i < 100; ++i) {
        handshake_result = pn_tls_openssl_backend.handshake(session);
        if (PN_TLS_OK == handshake_result) {
            break;
        }
        if (0 > handshake_result) {
            break;
        }

        /* Poll for readiness. */
        struct pollfd pfd = {0};
        pfd.fd            = sock;
        if (PN_TLS_WANT_READ == handshake_result) {
            pfd.events = POLLIN;
        } else if (PN_TLS_WANT_WRITE == handshake_result) {
            pfd.events = POLLOUT;
        }
        poll(&pfd, 1, 1000);
    }
    assert_int_equal(handshake_result, PN_TLS_OK);

    /* Send HTTP GET. */
    const char request[] = "GET /time/0 HTTP/1.1\r\nHost: ps.pndsn.com\r\n\r\n";
    size_t     sent      = 0;
    while (sent < sizeof(request) - 1) {
        int n = pn_tls_openssl_backend.send(
            session, request + sent, sizeof(request) - 1 - sent);
        if (0 < n) {
            sent += n;
        } else if (0 == n) {
            /* Would block; poll for write. */
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
        int n = pn_tls_openssl_backend.recv(
            session, response + received, sizeof(response) - received - 1);
        if (0 < n) {
            received += n;
            /* Check for end of headers. */
            if (NULL != strstr(response, "\r\n\r\n")) {
                complete = 1;
                break;
            }
        } else if (0 == n) {
            /* Would block; poll for read. */
            struct pollfd pfd = {0};
            pfd.fd            = sock;
            pfd.events        = POLLIN;
            poll(&pfd, 1, 1000);
        } else {
            break;
        }
    }
    assert_int_equal(complete, 1);
    assert_true(0 < received);

    /* Verify status 200. */
    assert_non_null(strstr(response, "HTTP/1.1 200"));

    /* Cleanup. */
    pn_tls_openssl_backend.session_destroy(session);
    pn_tls_openssl_backend.ctx_destroy(ctx);
    close(sock);
}

/**
 * @brief Helper: drive a handshake against host:443, return terminal result.
 *
 * Uses the default secure config (verification ON). Reuses the same
 * WANT_READ/WANT_WRITE poll loop as test_tls_integration. Returns the
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
    void*           ctx = pn_tls_openssl_backend.ctx_create(&cfg, &test_deps);
    if (NULL == ctx) {
        close(sock);
        return -1;
    }

    void* session = NULL;
    int   rc =
        pn_tls_openssl_backend.session_create(&session, ctx, sock, NULL, hostname);
    if (0 != rc) {
        pn_tls_openssl_backend.ctx_destroy(ctx);
        close(sock);
        return -1;
    }

    int handshake_result = -1;
    for (int i = 0; i < 100; ++i) {
        handshake_result = pn_tls_openssl_backend.handshake(session);
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
        poll(&pfd, 1, 1000);
    }

    pn_tls_openssl_backend.session_destroy(session);
    pn_tls_openssl_backend.ctx_destroy(ctx);
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
        cmocka_unit_test(test_ctx_create_destroy),
        cmocka_unit_test(test_session_create_invalid_fd),
        cmocka_unit_test(test_tls_config_secure_by_default),
#if !defined(_WIN32)
        cmocka_unit_test(test_recv_ignores_stale_thread_error),
        cmocka_unit_test(test_session_destroy_clears_thread_error),
        cmocka_unit_test(tls_openssl_should_not_raise_sigpipe_on_rst),
#endif
#if defined(PUBNUB_TEST_NETWORK) && !defined(_WIN32)
        cmocka_unit_test(test_tls_integration),
        cmocka_unit_test(test_tls_rejects_expired_cert),
        cmocka_unit_test(test_tls_rejects_wrong_host_cert),
        cmocka_unit_test(test_tls_rejects_self_signed_cert),
        cmocka_unit_test(test_tls_accepts_valid_cert),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

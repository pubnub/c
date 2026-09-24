/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TLS_BACKEND_H
#define PN_TLS_BACKEND_H

#include "certs/pn_tls_cert_loader.h"
#include "providers/transport/socket/platform/pn_socket_types.h"
#include <stddef.h>
#include <stdint.h>

struct pubnub_provider_deps;
struct pn_socket_platform_ops;

/** @brief TLS handshake/I/O return codes. */
#define PN_TLS_OK         0 /**< Operation complete. */
#define PN_TLS_WANT_READ  1 /**< Socket must be readable to continue. */
#define PN_TLS_WANT_WRITE 2 /**< Socket must be writable to continue. */
/* < 0 = error */

/** @brief TLS protocol version. */
#define PN_TLS_1_2 0
#define PN_TLS_1_3 1

/**
 * @brief TLS configuration (transport-internal).
 *
 * Configures certificate verification, session resumption, and protocol
 * constraints for a long-lived TLS context. Passed once at context creation.
 */
typedef struct pn_tls_config {
    const char* ca_file; /**< Path to CA cert file (PEM). */
    const char* ca_path; /**< Path to CA cert directory. */
    const char* ca_pem;  /**< Inline PEM CA cert string. */
    /**
     * 1 = load the platform's built-in CA trust store.
     *
     * Supported platforms and cert sources:
     *   - Linux / FreeBSD: /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu),
     *     /etc/pki/tls/certs/ca-bundle.crt (RHEL/CentOS),
     *     /etc/ssl/cert.pem (Alpine)
     *   - macOS: /etc/ssl/cert.pem or Homebrew cert bundles
     *   - Windows: Windows Certificate Store (CertOpenSystemStoreA "ROOT")
     *   - ESP32 (ESP-IDF): esp_crt_bundle_attach() via
     *     CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
     *   - Zephyr: not yet implemented - provide ca_pem in transport config
     *
     * On unsupported targets the flag is ignored. Context creation will
     * succeed only if ca_file, ca_pem, or skip_verify is also set.
     */
    uint8_t use_system_certs;
    uint8_t session_reuse; /**< 1 = enable TLS session
                                resumption. */
    uint8_t min_version;   /**< @brief Minimum TLS version floor.
                                Best-effort: if the requested
                                version is unavailable, falls back
                                to the highest available. */
    uint8_t skip_verify;   /**< TESTING ONLY: skip hostname verify. */
    /**
     * Platform certificate loader callback. NULL means use the
     * compiled-in platform default (selected by CMake). Set to a custom
     * function to override for non-standard cert stores.
     */
    pn_tls_system_cert_fn_t system_cert_loader;
    /** Opaque pointer passed to system_cert_loader. May be NULL. */
    void* system_cert_user_data;
} pn_tls_config_t;

#define PN_TLS_CONFIG_INIT {NULL, NULL, NULL, 1, 1, PN_TLS_1_2, 0, NULL, NULL}

/**
 * @brief TLS backend vtable (transport-internal).
 *
 * Provides pluggable TLS implementations (OpenSSL, mbedTLS, Schannel).
 * Selected at compile time via PN_SOCKET_TLS_BACKEND. The socket transport
 * calls these functions for TLS context/session management and encrypted I/O.
 *
 * Context is long-lived (one per transport instance). Sessions are
 * per-TCP connection. All I/O is non-blocking — handshake/send/recv return
 * PN_TLS_WANT_READ or PN_TLS_WANT_WRITE when the socket is not ready.
 *
 * All callbacks are NOT thread-safe; the transport serializes calls
 * per-socket.
 */
typedef struct pn_tls_backend {
    /**
     * @brief Create a long-lived TLS context.
     *
     * @param cfg  Configuration. Pointer lifetime must exceed context lifetime
     *             (may be stack or config-owned).
     * @param deps Provider dependencies (allocator, logger, platform). The
     *             allocator pointer is always non-NULL and must be used for
     *             all heap allocation within the backend.
     * @return Opaque context pointer, or NULL on failure.
     */
    void* (*ctx_create)(const pn_tls_config_t*             cfg,
                        const struct pubnub_provider_deps* deps);

    /**
     * @brief Destroy a TLS context.
     *
     * Safe to call with NULL.
     *
     * @param ctx Context from ctx_create, or NULL.
     */
    void (*ctx_destroy)(void* ctx);

    /**
     * @brief Create a TLS session for a connected socket.
     *
     * Prepares the session for handshake. The socket must be connected and
     * non-blocking before calling.
     *
     * @param out_session Output session pointer. Must be non-NULL.
     * @param ctx         Context from ctx_create.
     * @param sock        Connected TCP socket.
     * @param ops         Platform socket operations vtable. Stored for the
     *                    session lifetime — the pointer must remain valid
     *                    until session_destroy is called. Used by TLS BIO
     *                    callbacks to route I/O through the platform
     *                    abstraction instead of calling POSIX send()/recv()
     *                    directly.
     * @param hostname    Server hostname for SNI and verification.
     * @return 0 on success, <0 on error. On success, caller owns out_session
     *         and must pass it to all subsequent calls for this socket.
     */
    int (*session_create)(void**                               out_session,
                          void*                                ctx,
                          pn_socket_t                          sock,
                          const struct pn_socket_platform_ops* ops,
                          const char*                          hostname);

    /**
     * @brief Drive TLS handshake (non-blocking).
     *
     * Call repeatedly until completion. Each call advances the handshake
     * state until all steps finish or an I/O wait or error occurs.
     *
     * @param session Session from session_create.
     * @return PN_TLS_OK when handshake complete, PN_TLS_WANT_READ/WRITE if
     *         socket must be checked for readiness before next call, <0 on
     *         error.
     */
    int (*handshake)(void* session);

    /**
     * @brief Send data over TLS (non-blocking).
     *
     * @param session Session from session_create.
     * @param buf     Buffer to send (may be NULL if len == 0).
     * @param len     Bytes to send.
     * @return >0 bytes sent (may be less than len), 0 if send would block
     *         (call when socket is writable), <0 on error (including peer
     *         close).
     */
    int (*send)(void* session, const void* buf, size_t len);

    /**
     * @brief Receive data over TLS (non-blocking).
     *
     * @param session Session from session_create.
     * @param buf     Output buffer.
     * @param len     Capacity of buf.
     * @return >0 bytes received, 0 if receive would block (call when socket
     *         is readable), -1 if peer closed cleanly, <-1 on error.
     */
    int (*recv)(void* session, void* buf, size_t len);

    /**
     * @brief Destroy a TLS session (performs shutdown).
     *
     * Does NOT close the underlying socket; caller manages socket lifetime.
     * Safe to call with NULL.
     *
     * @param session Session from session_create, or NULL.
     */
    void (*session_destroy)(void* session);

    /**
     * @brief Return the last session-level error code.
     *
     * Returns the numeric error from the most recent failed session
     * operation (handshake, send, or recv). Returns 0 if no error is
     * stored. May be NULL — not all backends implement error tracking.
     *
     * @param session Session from session_create.
     * @return Backend-specific error code, or 0 if none.
     */
    int (*get_session_error)(void* session);

    /**
     * @brief Map a backend error code to a short static string.
     *
     * Returns a short human-readable label for the error code (e.g.
     * "X509_CERT_VERIFY_FAILED"). The returned pointer is a static
     * string literal — callers MUST NOT free it. May be NULL, or may
     * return NULL for unknown codes.
     *
     * @param error_code Code from get_session_error.
     * @return Static label, or NULL for unknown codes.
     */
    const char* (*session_error_str)(int error_code);
} pn_tls_backend_t;

#endif /* PN_TLS_BACKEND_H */

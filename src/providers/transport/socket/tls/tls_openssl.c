/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_backend.h"

#include "certs/pn_tls_cert_loader.h"
#include "pubnub/config.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/provider_deps.h"
#include "core/pn_string.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#endif

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
/**
 * @brief One hostname-indexed TLS session cache entry.
 */
typedef struct pn_tls_ssl_session_entry {
    /** Cached session object (owned; freed on eviction/destroy). */
    SSL_SESSION* session;
    /** Host key used to match subsequent connections. */
    char hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN + 1];
    /** 1 = slot holds a valid cached session. */
    uint8_t valid;
} pn_tls_ssl_session_entry_t;
#endif

/**
 * @brief OpenSSL context wrapper.
 *
 * Wraps the long-lived SSL_CTX with an optional hostname-indexed session
 * cache used to resume TLS sessions across connections to the same host.
 *
 * The session cache is accessed exclusively from the transport poll thread;
 * no locking is required.
 */
struct pn_openssl_ctx {
    SSL_CTX*                       ssl_ctx; /**< OpenSSL context handle. */
    struct pubnub_logger_provider* logger;  /**< Logger (may be NULL). */
    uint8_t session_reuse; /**< 1 = manual session cache active. */
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    pn_tls_ssl_session_entry_t session_cache[PUBNUB_CFG_TLS_SESSION_CACHE_SIZE];
#endif
};

/**
 * @brief Per-connection OpenSSL session wrapper.
 *
 * Wraps the bare SSL pointer with error tracking for diagnostics and, when
 * session caching is enabled, a back-pointer to the owning context plus the
 * connection hostname used as the cache key.
 */
struct pn_openssl_session {
    SSL*          ssl;          /**< OpenSSL session handle. */
    unsigned long last_error;   /**< Last ERR_get_error() value. */
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    struct pn_openssl_ctx* ctx; /**< Owning context (for cache access). */
    char    hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN + 1]; /**< Connection host. */
    uint8_t resume_attempted; /**< 1 = a cached session was applied. */
#endif
};

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
static void pn_tls_ssl_session_cache_store(struct pn_openssl_ctx* ctx,
                                           const char*            hostname,
                                           SSL_SESSION*           new_sess);
static pn_tls_ssl_session_entry_t*
pn_tls_ssl_session_cache_lookup(struct pn_openssl_ctx* ctx, const char* hostname);
static void pn_tls_ssl_session_cache_invalidate(struct pn_openssl_ctx* ctx,
                                                const char* hostname);

/**
 * @brief Find a valid cache entry for a hostname.
 *
 * @param ctx      Owning context.
 * @param hostname Host key to match.
 * @return Pointer to the matching valid entry, or NULL if none.
 */
static pn_tls_ssl_session_entry_t*
pn_tls_ssl_session_cache_lookup(struct pn_openssl_ctx* ctx, const char* hostname)
{
    int i;

    if (NULL == ctx || NULL == hostname) {
        return NULL;
    }

    for (i = 0; i < PUBNUB_CFG_TLS_SESSION_CACHE_SIZE; ++i) {
        pn_tls_ssl_session_entry_t* e = &ctx->session_cache[i];
        if (0 != e->valid
            && 0 == strncmp(e->hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN)) {
            return e;
        }
    }

    return NULL;
}

/**
 * @brief Store a session for a hostname, taking ownership of @p new_sess.
 *
 * Updates the existing slot for the host if present; otherwise fills the first
 * free slot; otherwise FIFO-evicts slot 0. The previously held session in the
 * reused/evicted slot is freed.
 *
 * @param ctx      Owning context.
 * @param hostname Host key.
 * @param new_sess Session to store (ownership transferred; freed on any early
 *                 return).
 */
static void pn_tls_ssl_session_cache_store(struct pn_openssl_ctx* ctx,
                                           const char*            hostname,
                                           SSL_SESSION*           new_sess)
{
    int i;
    int free_slot = -1;

    if (NULL == ctx || NULL == hostname || NULL == new_sess) {
        SSL_SESSION_free(new_sess);
        return;
    }

#ifdef PN_DEBUG_SOCKET_OPS
    PUBNUB_LOG(ctx->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "TLS cache store: session captured host=%s",
               hostname);
#endif

    for (i = 0; i < PUBNUB_CFG_TLS_SESSION_CACHE_SIZE; ++i) {
        pn_tls_ssl_session_entry_t* e = &ctx->session_cache[i];
        if (0 != e->valid) {
            if (0 == strncmp(e->hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN)) {
                SSL_SESSION_free(e->session);
                e->session = new_sess;
#ifdef PN_DEBUG_SOCKET_OPS
                PUBNUB_LOG(ctx->logger,
                           PUBNUB_LOG_LEVEL_DEBUG,
                           "TLS cache: session stored for host=%s slot=%d",
                           hostname,
                           i);
#endif
                return;
            }
        } else if (-1 == free_slot) {
            free_slot = i;
        }
    }

    if (-1 != free_slot) {
        pn_tls_ssl_session_entry_t* e = &ctx->session_cache[free_slot];
        e->session                    = new_sess;
        pn_strlcpy(e->hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN + 1);
        e->valid = 1;
#ifdef PN_DEBUG_SOCKET_OPS
        PUBNUB_LOG(ctx->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "TLS cache: session stored for host=%s slot=%d",
                   hostname,
                   free_slot);
#endif
        return;
    }

    SSL_SESSION_free(ctx->session_cache[0].session);
    ctx->session_cache[0].session = new_sess;
    pn_strlcpy(ctx->session_cache[0].hostname,
               hostname,
               PUBNUB_CFG_MAX_HOSTNAME_LEN + 1);
    ctx->session_cache[0].valid = 1;
#ifdef PN_DEBUG_SOCKET_OPS
    PUBNUB_LOG(ctx->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "TLS cache: session stored for host=%s slot=%d",
               hostname,
               0);
#endif
}

/**
 * @brief Drop a cached session for a hostname.
 *
 * Frees the stored session and clears the slot. Used when a resume attempt
 * fails so a stale session is not offered again.
 *
 * @param ctx      Owning context.
 * @param hostname Host key.
 */
static void pn_tls_ssl_session_cache_invalidate(struct pn_openssl_ctx* ctx,
                                                const char*            hostname)
{
    pn_tls_ssl_session_entry_t* e;

    if (NULL == ctx || NULL == hostname) {
        return;
    }

    e = pn_tls_ssl_session_cache_lookup(ctx, hostname);
    if (NULL != e) {
        SSL_SESSION_free(e->session);
        e->session = NULL;
        e->valid   = 0;
    }
}
#endif /* PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0 */

/**
 * @brief Create a TLS context with OpenSSL.
 *
 * Configures certificate verification, minimum protocol version, session
 * reuse, and SNI. Caller owns the returned context and must pass it to
 * ctx_destroy when done.
 *
 * OpenSSL manages its own heap internally; only the logger is taken from deps
 * (deps and its logger may both be NULL).
 *
 * @param cfg  Configuration (must outlive context).
 * @param deps Provider dependencies; only deps->logger is used (may be NULL).
 * @return Opaque pn_openssl_ctx pointer, or NULL on failure.
 */
static void* pn_tls_openssl_ctx_create(const pn_tls_config_t*             cfg,
                                       const struct pubnub_provider_deps* deps)
{
    struct pn_openssl_ctx* pctx = NULL;
    if (NULL == cfg) {
        return NULL;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (NULL == ctx) {
        return NULL;
    }

    /* Set minimum TLS version. */
    int min_version = TLS1_2_VERSION;
    if (PN_TLS_1_3 == cfg->min_version) {
#ifdef TLS1_3_VERSION
        min_version = TLS1_3_VERSION;
#else
        /* TLS 1.3 is best-effort: if OpenSSL was compiled without TLS 1.3
         * support (pre-1.1.1), we silently fall back to TLS 1.2. The caller
         * accepts this by the min_version contract being a floor, not exact. */
        min_version = TLS1_2_VERSION;
#endif
    }
    if (1 != SSL_CTX_set_min_proto_version(ctx, min_version)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load certificates. */
    int loaded = 0;
    if (NULL != cfg->ca_file || NULL != cfg->ca_path) {
        if (1 != SSL_CTX_load_verify_locations(ctx, cfg->ca_file, cfg->ca_path)) {
            SSL_CTX_free(ctx);
            return NULL;
        }
        loaded = 1;
    }

    if (NULL != cfg->ca_pem) {
        BIO* bio = BIO_new_mem_buf(cfg->ca_pem, -1);
        if (NULL == bio) {
            SSL_CTX_free(ctx);
            return NULL;
        }

        X509_STORE* store      = SSL_CTX_get_cert_store(ctx);
        X509*       cert       = NULL;
        int         cert_count = 0;
        while (NULL != (cert = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
            if (1 != X509_STORE_add_cert(store, cert)) {
                X509_free(cert);
                BIO_free(bio);
                SSL_CTX_free(ctx);
                return NULL;
            }
            X509_free(cert);
            cert_count++;
        }
        BIO_free(bio);
        if (0 < cert_count) {
            loaded = 1;
        }
    }

    if (0 != cfg->use_system_certs) {
        pn_tls_system_cert_fn_t loader = cfg->system_cert_loader;
        if (NULL == loader) {
            loader = pn_tls_get_default_cert_loader();
        }
        if (NULL != loader) {
            if (0 == loader(ctx, NULL, cfg->system_cert_user_data)) {
                loaded = 1;
            }
        }
        if (0 == loaded) {
            /* Fallback: let OpenSSL search its compiled-in default paths. */
            (void)SSL_CTX_set_default_verify_paths(ctx);
        }
    }

    /* Set verify mode (unless skip_verify). */
    if (0 == cfg->skip_verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Disable the internal OpenSSL session cache only when session_reuse is off;
     * when on, our external cache gates operations via pctx->session_reuse. */
    if (0 == cfg->session_reuse) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }

    pctx = (struct pn_openssl_ctx*)malloc(sizeof(*pctx));
    if (NULL == pctx) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    memset(pctx, 0, sizeof(*pctx));
    pctx->ssl_ctx       = ctx;
    pctx->logger        = (NULL != deps) ? deps->logger : NULL;
    pctx->session_reuse = (0 != cfg->session_reuse) ? 1 : 0;
    return pctx;
}

/**
 * @brief Destroy an OpenSSL TLS context.
 *
 * @param ctx pn_openssl_ctx from ctx_create, or NULL.
 */
static void pn_tls_openssl_ctx_destroy(void* ctx)
{
    if (NULL == ctx) {
        return;
    }

    struct pn_openssl_ctx* pctx = (struct pn_openssl_ctx*)ctx;
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    {
        int i;
        for (i = 0; i < PUBNUB_CFG_TLS_SESSION_CACHE_SIZE; ++i) {
            if (0 != pctx->session_cache[i].valid) {
                SSL_SESSION_free(pctx->session_cache[i].session);
                pctx->session_cache[i].session = NULL;
                pctx->session_cache[i].valid   = 0;
            }
        }
    }
#endif
    SSL_CTX_free(pctx->ssl_ctx);
    free(pctx);
}

#ifndef _WIN32
#ifndef MSG_NOSIGNAL
/* macOS lacks MSG_NOSIGNAL; SIGPIPE is already suppressed there via
 * SO_NOSIGPIPE set at socket creation (posix_socket_ops.c, __APPLE__), so a
 * zero flag passed to send() is a safe no-op on that platform. */
#define MSG_NOSIGNAL 0
#endif

/* Process-lifetime custom BIO_METHOD; created once on first use. Standard
 * OpenSSL practice for a derived socket method — intentionally never freed. */
static BIO_METHOD* s_nosigpipe_bio_method = NULL;

/**
 * @brief Read the socket fd stored on a custom nosigpipe BIO.
 *
 * The fd is stored in the BIO data slot by pn_tls_openssl_bio_ctrl on
 * BIO_C_SET_FD; a value of 0 is a legitimate fd and reads back unambiguously.
 *
 * @param bio Custom socket BIO.
 * @return Stored socket fd.
 */
static int pn_tls_openssl_bio_fd(BIO* bio)
{
    return (int)(intptr_t)BIO_get_data(bio);
}

/**
 * @brief Socket write that never raises SIGPIPE.
 *
 * Replaces the default socket BIO write (which uses write(2) and can raise
 * SIGPIPE when the peer has sent RST mid-write) with send(2) carrying
 * MSG_NOSIGNAL. Retry classification mirrors the stock socket BIO so
 * non-blocking would-block conditions are surfaced to OpenSSL unchanged.
 *
 * @param bio Custom socket BIO holding the connected fd.
 * @param buf Bytes to write.
 * @param len Byte count (BIO write contract: int, may be <= 0).
 * @return Bytes written (>0), or <=0 with retry flags set on would-block.
 */
static int pn_tls_openssl_bio_write(BIO* bio, const char* buf, int len)
{
    int fd = pn_tls_openssl_bio_fd(bio);
    int rc;

    if (NULL == buf || 0 >= len) {
        return 0;
    }

    BIO_clear_retry_flags(bio);
    rc = (int)send(fd, buf, (size_t)len, MSG_NOSIGNAL);
    if (0 >= rc && 0 != BIO_sock_should_retry(rc)) {
        BIO_set_retry_write(bio);
    }
    return rc;
}

/**
 * @brief Socket read for the custom nosigpipe BIO.
 *
 * Mirrors the stock socket BIO read; provided because the read method cannot
 * be borrowed from BIO_s_socket() without the getters deprecated in OpenSSL
 * 3.5. A return of 0 signals a clean peer close (no retry flag set).
 *
 * @param bio Custom socket BIO holding the connected fd.
 * @param buf Output buffer.
 * @param len Capacity (BIO read contract: int, may be <= 0).
 * @return Bytes read (>0), 0 on clean close, or <0 with retry flags on
 *         would-block.
 */
static int pn_tls_openssl_bio_read(BIO* bio, char* buf, int len)
{
    int fd = pn_tls_openssl_bio_fd(bio);
    int rc;

    if (NULL == buf || 0 >= len) {
        return 0;
    }

    BIO_clear_retry_flags(bio);
    rc = (int)recv(fd, buf, (size_t)len, 0);
    if (0 > rc && 0 != BIO_sock_should_retry(rc)) {
        BIO_set_retry_read(bio);
    }
    return rc;
}

/**
 * @brief Control operations for the custom nosigpipe BIO.
 *
 * Implements the minimal fd-binding subset the SSL layer needs: fd get/set,
 * flush, and dup. The socket is always bound BIO_NOCLOSE (the transport owns
 * its lifetime), so close-flag queries report no ownership.
 *
 * @param bio  Custom socket BIO.
 * @param cmd  BIO_C_/BIO_CTRL_ command.
 * @param larg Long argument (unused).
 * @param ptr  Command-specific pointer (int* for fd get/set).
 * @return Command-specific result; 1 for handled no-op commands, 0 otherwise.
 */
static long pn_tls_openssl_bio_ctrl(BIO* bio, int cmd, long larg, void* ptr)
{
    long ret = 1;

    (void)larg;
    switch (cmd) {
    case BIO_C_SET_FD:
        BIO_set_data(bio, (void*)(intptr_t)(*(int*)ptr)); /* NOLINT(performance-no-int-to-ptr) */
        BIO_set_init(bio, 1);
        break;
    case BIO_C_GET_FD:
        if (0 == BIO_get_init(bio)) {
            ret = -1;
            break;
        }
        {
            int fd = pn_tls_openssl_bio_fd(bio);
            if (NULL != ptr) {
                *(int*)ptr = fd;
            }
            ret = fd;
        }
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = 0; /* Always BIO_NOCLOSE: transport owns the socket. */
        break;
    case BIO_CTRL_SET_CLOSE:
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DUP: ret = 1; break;
    default: ret = 0; break;
    }
    return ret;
}

/**
 * @brief Initialize a freshly allocated custom nosigpipe BIO.
 *
 * @param bio BIO being created.
 * @return 1 always.
 */
static int pn_tls_openssl_bio_create(BIO* bio)
{
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    BIO_set_flags(bio, 0);
    return 1;
}

/**
 * @brief Tear down a custom nosigpipe BIO.
 *
 * Does not close the socket (always bound BIO_NOCLOSE); the transport owns
 * the fd lifetime.
 *
 * @param bio BIO being destroyed, or NULL.
 * @return 1 on success, 0 if bio is NULL.
 */
static int pn_tls_openssl_bio_destroy(BIO* bio)
{
    if (NULL == bio) {
        return 0;
    }
    BIO_set_init(bio, 0);
    return 1;
}

/**
 * @brief Get (lazily creating) the SIGPIPE-safe socket BIO method.
 *
 * A self-contained source/sink BIO method whose write path uses send() with
 * MSG_NOSIGNAL. It is not derived from BIO_s_socket() because the method
 * getters needed to borrow the stock read/ctrl were deprecated in OpenSSL
 * 3.5; the fd-binding subset is reimplemented here instead. Concurrent
 * first-use from multiple poll threads (one per context) is benign: the
 * pointer store is pointer-aligned and effectively atomic, and the worst
 * case is a one-time unreachable BIO_METHOD leak if two threads race on
 * first init.
 *
 * @return Shared BIO_METHOD, or NULL on allocation failure.
 */
static BIO_METHOD* pn_tls_openssl_nosigpipe_method(void)
{
    if (NULL == s_nosigpipe_bio_method) {
        BIO_METHOD* m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
                                     "pubnub nosigpipe socket");
        if (NULL == m) {
            return NULL;
        }
        BIO_meth_set_write(m, pn_tls_openssl_bio_write);
        BIO_meth_set_read(m, pn_tls_openssl_bio_read);
        BIO_meth_set_ctrl(m, pn_tls_openssl_bio_ctrl);
        BIO_meth_set_create(m, pn_tls_openssl_bio_create);
        BIO_meth_set_destroy(m, pn_tls_openssl_bio_destroy);
        s_nosigpipe_bio_method = m;
    }
    return s_nosigpipe_bio_method;
}
#endif /* !_WIN32 */

/**
 * @brief Create an OpenSSL TLS session for a connected socket.
 *
 * Prepares the session for handshake. Caller must pass a connected, non-
 * blocking socket. Sets SNI and hostname verification. When session caching
 * is enabled and a cached session exists for the hostname, it is applied so
 * the handshake can resume.
 *
 * @param out_session Output session pointer (must be non-NULL).
 * @param ctx         pn_openssl_ctx from ctx_create.
 * @param sock        Connected TCP socket.
 * @param ops         Platform socket operations vtable (unused by OpenSSL).
 * @param hostname    Server hostname for SNI and verification.
 * @return 0 on success, -1 on error.
 */
static int pn_tls_openssl_session_create(void**      out_session,
                                         void*       ctx,
                                         pn_socket_t sock,
                                         const struct pn_socket_platform_ops* ops,
                                         const char* hostname)
{
    (void)ops;
    if (NULL == out_session || NULL == ctx || PN_INVALID_SOCKET == sock
        || NULL == hostname) {
        return -1;
    }
    *out_session = NULL;

    struct pn_openssl_ctx* pctx = (struct pn_openssl_ctx*)ctx;
    SSL*                   ssl  = SSL_new(pctx->ssl_ctx);
    if (NULL == ssl) {
        return -1;
    }

#ifdef _WIN32
    BIO* bio = BIO_new_socket((int)sock, BIO_NOCLOSE);
    if (NULL == bio) {
        SSL_free(ssl);
        return -1;
    }
    SSL_set_bio(ssl, bio, bio);
#else
    {
        BIO_METHOD* method = pn_tls_openssl_nosigpipe_method();
        BIO*        bio    = (NULL != method) ? BIO_new(method) : NULL;
        if (NULL == bio) {
            SSL_free(ssl);
            return -1;
        }
        BIO_set_fd(bio, (int)sock, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);
    }
#endif

    /* Set SNI hostname. */
    if (1 != SSL_set_tlsext_host_name(ssl, hostname)) {
        SSL_free(ssl);
        return -1;
    }

    /* Set hostname verification (OpenSSL 1.1.0+). */
    if (1 != SSL_set1_host(ssl, hostname)) {
        SSL_free(ssl);
        return -1;
    }

    /* Mark as client. */
    SSL_set_connect_state(ssl);

    struct pn_openssl_session* sess =
        (struct pn_openssl_session*)malloc(sizeof(*sess));
    if (NULL == sess) {
        SSL_free(ssl);
        return -1;
    }

    sess->ssl        = ssl;
    sess->last_error = 0;
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    sess->ctx              = pctx;
    sess->resume_attempted = 0;
    pn_strlcpy(sess->hostname, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN + 1);
    if (0 != pctx->session_reuse) {
        pn_tls_ssl_session_entry_t* cached =
            pn_tls_ssl_session_cache_lookup(pctx, hostname);
#ifdef PN_DEBUG_SOCKET_OPS
        PUBNUB_LOG(pctx->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "TLS cache lookup: host=%s found=%d",
                   hostname,
                   NULL != cached ? 1 : 0);
#endif
        if (NULL != cached) {
            SSL_set_session(sess->ssl, cached->session);
#ifdef PN_DEBUG_SOCKET_OPS
            PUBNUB_LOG(pctx->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "TLS cache: applying cached session for host=%s",
                       hostname);
#endif
            sess->resume_attempted = 1;
        }
    }
#endif
    *out_session = sess;
    return 0;
}

/**
 * @brief Drive TLS handshake (non-blocking).
 *
 * Call repeatedly until PN_TLS_OK. Returns PN_TLS_WANT_READ or
 * PN_TLS_WANT_WRITE when the socket must be polled for readiness. On success
 * the negotiated session is cached (when caching is enabled); on failure after
 * a resume attempt the stale cached session is invalidated.
 *
 * @param session pn_openssl_session from session_create.
 * @return PN_TLS_OK when handshake complete, PN_TLS_WANT_READ/WRITE if socket
 *         must be checked for readiness, -1 on error.
 */
static int pn_tls_openssl_handshake(void* session)
{
    if (NULL == session) {
        return -1;
    }

    struct pn_openssl_session* sess = (struct pn_openssl_session*)session;
    int                        rc;
    /* OpenSSL requires an empty thread error queue before the operation so
     * SSL_get_error() classifies the result from this call alone; a stale
     * entry left by a prior session would be misread as SSL_ERROR_SSL. */
    ERR_clear_error();
    rc = SSL_connect(sess->ssl);
    if (1 == rc) {
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
#ifdef PN_DEBUG_SOCKET_OPS
        PUBNUB_LOG(sess->ctx->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "TLS handshake OK: host=%s resume_attempted=%d",
                   sess->hostname,
                   (int)sess->resume_attempted);
#endif
        if (0 != sess->ctx->session_reuse) {
            SSL_SESSION* new_sess = SSL_get1_session(sess->ssl);
            if (NULL != new_sess) {
                pn_tls_ssl_session_cache_store(sess->ctx, sess->hostname, new_sess);
            }
        }
#endif
        return PN_TLS_OK;
    }

    int err = SSL_get_error(sess->ssl, rc);
    if (SSL_ERROR_WANT_READ == err) {
        return PN_TLS_WANT_READ;
    }
    if (SSL_ERROR_WANT_WRITE == err) {
        return PN_TLS_WANT_WRITE;
    }

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    if (0 != sess->resume_attempted && NULL != sess->ctx) {
        pn_tls_ssl_session_cache_invalidate(sess->ctx, sess->hostname);
        sess->resume_attempted = 0;
    }
#endif
    sess->last_error = ERR_get_error();
    return -1;
}

/**
 * @brief Send data over TLS (non-blocking).
 *
 * @param session pn_openssl_session from session_create.
 * @param buf     Buffer to send.
 * @param len     Bytes to send.
 * @return >0 bytes sent (may be less than len), 0 if send would block,
 *         -1 if peer closed cleanly, <-1 on error.
 */
static int pn_tls_openssl_send(void* session, const void* buf, size_t len)
{
    if (NULL == session || (NULL == buf && 0 != len)) {
        return -1;
    }

    struct pn_openssl_session* sess = (struct pn_openssl_session*)session;
    int                        rc;
    /* Clear the thread error queue so SSL_get_error() reflects only this
     * write; a stale entry would be misread as SSL_ERROR_SSL. */
    ERR_clear_error();
    rc = SSL_write(sess->ssl, buf, (int)len);
    if (0 < rc) {
        return rc;
    }

    int err = SSL_get_error(sess->ssl, rc);
    if (SSL_ERROR_WANT_WRITE == err || SSL_ERROR_WANT_READ == err) {
        return 0;
    }
    if (SSL_ERROR_ZERO_RETURN == err) {
        return -1;
    }

    sess->last_error = ERR_get_error();
    return -2;
}

/**
 * @brief Receive data over TLS (non-blocking).
 *
 * @param session pn_openssl_session from session_create.
 * @param buf     Output buffer.
 * @param len     Capacity of buf.
 * @return >0 bytes received, 0 if receive would block, -1 if peer closed
 *         cleanly, <-1 on error.
 */
static int pn_tls_openssl_recv(void* session, void* buf, size_t len)
{
    if (NULL == session || NULL == buf || 0 == len) {
        return -1;
    }

    struct pn_openssl_session* sess = (struct pn_openssl_session*)session;
    int                        rc;
    /* Clear the thread error queue so SSL_get_error() reflects only this
     * read. Without this a benign would-block read is misclassified as
     * SSL_ERROR_SSL when a prior session left a stale entry queued. */
    ERR_clear_error();
    rc = SSL_read(sess->ssl, buf, (int)len);
    if (0 < rc) {
        return rc;
    }

    int err = SSL_get_error(sess->ssl, rc);
    if (SSL_ERROR_WANT_READ == err || SSL_ERROR_WANT_WRITE == err) {
        return 0;
    }
    if (SSL_ERROR_ZERO_RETURN == err) {
        return -1;
    }

    sess->last_error = ERR_get_error();
    return -2;
}

/**
 * @brief Destroy an OpenSSL TLS session.
 *
 * Performs best-effort shutdown. Does NOT close the underlying socket (caller
 * manages socket lifetime). The session cache lives in the context, so nothing
 * cache-related is freed here.
 *
 * @param session pn_openssl_session from session_create, or NULL.
 */
static void pn_tls_openssl_session_destroy(void* session)
{
    if (NULL != session) {
        struct pn_openssl_session* sess = (struct pn_openssl_session*)session;
        /* Best-effort shutdown; ignore errors. On an in-init SSL this queues
         * SSL_R_SHUTDOWN_WHILE_IN_INIT, and SSL_free does not clear it, so
         * clear the thread queue to keep it from poisoning the next
         * operation on this thread. */
        SSL_shutdown(sess->ssl);
        ERR_clear_error();
        SSL_free(sess->ssl);
        sess->ssl = NULL;
        free(sess);
    }
}

static int pn_tls_openssl_get_session_error(void* session)
{
    if (NULL == session) {
        return 0;
    }
    return (int)((struct pn_openssl_session*)session)->last_error;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_tls_backend_t pn_tls_openssl_backend = {
    .ctx_create        = pn_tls_openssl_ctx_create,
    .ctx_destroy       = pn_tls_openssl_ctx_destroy,
    .session_create    = pn_tls_openssl_session_create,
    .session_destroy   = pn_tls_openssl_session_destroy,
    .handshake         = pn_tls_openssl_handshake,
    .send              = pn_tls_openssl_send,
    .recv              = pn_tls_openssl_recv,
    .get_session_error = pn_tls_openssl_get_session_error,
    .session_error_str = NULL,
};

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_backend.h"

#include "certs/pn_tls_cert_loader.h"
#include "core/pn_format.h"
#include "core/pn_string.h"
#include "providers/transport/socket/platform/pn_socket_platform_ops.h"
#include "pubnub/config.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/pubnub_compat.h"

#include <mbedtls/version.h>
/* MBEDTLS_ALLOW_PRIVATE_ACCESS must be defined before ssl.h so the session
 * ticket fields (ticket / ticket_len) are reachable on mbedTLS 3.x. */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#else
#include <psa/crypto.h>
/* Error code for pn_psa_rng return; defined in mbedtls/entropy.h which
 * is excluded when ENTROPY_C is disabled. Use the raw value (-0x003C)
 * so the PSA path compiles without transitive-include dependencies. */
#ifndef MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
#define MBEDTLS_ERR_ENTROPY_SOURCE_FAILED -0x003C
#endif
#endif

#include <string.h>

/* MBEDTLS_SSL_VERSION_TLS1_2 was added in mbedTLS 3.x; on 2.x use the
 * raw protocol version constant directly. */
#ifndef MBEDTLS_SSL_VERSION_TLS1_2
#define MBEDTLS_SSL_VERSION_TLS1_2 0x0303
#endif

/* Net-layer error codes live in mbedtls/net_sockets.h, which this backend
 * does not include (it drives its own socket ops). Provide guarded
 * fallbacks so recv_cb can report resets/failures without the transitive
 * include, mirroring the MBEDTLS_ERR_ENTROPY_SOURCE_FAILED pattern above. */
#ifndef MBEDTLS_ERR_NET_CONN_RESET
#define MBEDTLS_ERR_NET_CONN_RESET -0x0050
#endif
#ifndef MBEDTLS_ERR_NET_RECV_FAILED
#define MBEDTLS_ERR_NET_RECV_FAILED -0x004C
#endif

/* config.h defines this inside the socket-transport guard; keep a safe
 * default so the backend still compiles standalone. 0 disables caching. */
#ifndef PUBNUB_CFG_TLS_SESSION_CACHE_SIZE
#define PUBNUB_CFG_TLS_SESSION_CACHE_SIZE 2
#endif

/* Maximum session-ticket bytes copied into a cache entry's fixed buffer.
 * Larger tickets are dropped; session-ID resumption still applies. */
#ifndef PN_TLS_SESSION_TICKET_MAX_SIZE
#define PN_TLS_SESSION_TICKET_MAX_SIZE 256
#endif

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
/**
 * @brief One hostname-indexed TLS session cache entry.
 *
 * The mbedTLS session may reference a malloc'd session ticket. On store the
 * ticket is relocated into @c ticket_buf so the entry owns no persistent heap
 * allocation, which matters on embedded no-heap profiles.
 */
typedef struct pn_tls_session_entry {
    /** Cached session (owned; freed on eviction/destroy). */
    mbedtls_ssl_session session;
    /** Fixed storage the session ticket is copied into. */
    uint8_t ticket_buf[PN_TLS_SESSION_TICKET_MAX_SIZE];
    /** Host key used to match subsequent connections. */
    char host[PUBNUB_CFG_MAX_HOSTNAME_LEN + 1];
    /** 1 = slot holds a valid cached session. */
    uint8_t valid;
} pn_tls_session_entry_t;
#endif

/**
 * @brief Long-lived mbedTLS context.
 *
 * One per transport instance. Holds configuration, CA chain, and RNG state.
 */
struct pn_mbedtls_ctx {
    mbedtls_ssl_config conf;                /**< SSL config (client mode). */
    mbedtls_x509_crt   ca_chain;            /**< Certificate authority chain. */
#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_context ctr_drbg;      /**< Random generator. */
    mbedtls_entropy_context  entropy;       /**< Entropy source. */
#endif
    pubnub_allocator_provider_t* allocator; /**< SDK allocator for heap ops. */
    struct pubnub_logger_provider* logger;  /**< Logger (may be NULL). */
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    /** Hostname-indexed session cache for TLS resumption. */
    pn_tls_session_entry_t session_cache[PUBNUB_CFG_TLS_SESSION_CACHE_SIZE];
    /** Cached copy of cfg->session_reuse (1 = resumption enabled). */
    uint8_t session_reuse;
#endif
};

/**
 * @brief Per-connection mbedTLS session.
 *
 * Holds SSL state and socket reference for one TCP connection.
 */
struct pn_mbedtls_session {
    mbedtls_ssl_context             ssl;    /**< SSL session state. */
    pn_socket_t                     sock;   /**< Socket for BIO callbacks. */
    const pn_socket_platform_ops_t* ops;    /**< Platform I/O vtable. */
    pubnub_allocator_provider_t* allocator; /**< SDK allocator for heap ops. */
    struct pubnub_logger_provider* logger;  /**< Logger (may be NULL). */
    int                            last_error; /**< Last mbedTLS error code. */
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    struct pn_mbedtls_ctx* mctx; /**< Owning context (for cache access). */
    char    host[PUBNUB_CFG_MAX_HOSTNAME_LEN + 1]; /**< Connection host key. */
    uint8_t resume_attempted; /**< 1 = a cached session was applied. */
#endif
};

/* pn_mbedtls_ctx is the long-lived struct; runtime heap cost of
 * mbedtls_ssl_setup is an additional ~4-6KB per session, not captured
 * by sizeof. mbedTLS 3.x ssl_config alone is ~1.5KB on 64-bit. The
 * session cache adds one entry per configured slot; the per-entry
 * allowance below tracks the real entry composition so the ceiling
 * holds for any hostname length, cache size, or mbedTLS version. */
/* The tight bound only applies to the 32-bit embedded no-heap arena target
 * the reservation was computed for: PUBNUB_CFG_ARENA_POOL_SIZE is defined in
 * every profile, so gate on PUBNUB_CFG_NO_HEAP (only the embedded profile sets
 * it) AND 32-bit pointers. On a 64-bit host the struct is naturally larger
 * (wider pointers / mbedtls_ssl_session), so the loose ceiling applies there. */
#if PUBNUB_CFG_NO_HEAP && (__SIZEOF_POINTER__ == 4)
/* 3584 = PN_ARENA_BOUND_TLS_CTX from cmake/arena.cmake; matches the Zone B
 * budget reserved for this struct. Fires if the struct grows past it. */
PUBNUB_STATIC_ASSERT(sizeof(struct pn_mbedtls_ctx) <= 3584,
                     "pn_mbedtls_ctx exceeds arena TLS-ctx budget; "
                     "raise PN_ARENA_BOUND_TLS_CTX in cmake/arena.cmake");
#elif PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
PUBNUB_STATIC_ASSERT(sizeof(struct pn_mbedtls_ctx)
                         < 8192
                               + PUBNUB_CFG_TLS_SESSION_CACHE_SIZE
                                     * (sizeof(mbedtls_ssl_session)
                                        + PN_TLS_SESSION_TICKET_MAX_SIZE
                                        + PUBNUB_CFG_MAX_HOSTNAME_LEN + 64),
                     "mbedTLS context struct exceeds expected size");
#else
PUBNUB_STATIC_ASSERT(sizeof(struct pn_mbedtls_ctx) < 8192,
                     "mbedTLS context struct exceeds expected size");
#endif

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
/**
 * @brief Find a valid cache entry for a hostname.
 *
 * @param mctx Owning context.
 * @param host Host key to match.
 * @return Pointer to the matching valid entry, or NULL if none.
 */
static pn_tls_session_entry_t* pn_tls_mbedtls_cache_lookup(struct pn_mbedtls_ctx* mctx,
                                                           const char* host)
{
    int i;

    if (NULL == mctx || NULL == host) {
        return NULL;
    }

    for (i = 0; i < PUBNUB_CFG_TLS_SESSION_CACHE_SIZE; ++i) {
        pn_tls_session_entry_t* e = &mctx->session_cache[i];
        if (0 != e->valid
            && 0 == strncmp(e->host, host, PUBNUB_CFG_MAX_HOSTNAME_LEN)) {
            return e;
        }
    }

    return NULL;
}

/**
 * @brief Free a stored cache entry's session and mark the slot free.
 *
 * A stored session's ticket field points into the entry's fixed @c ticket_buf,
 * not the heap, so it is detached before the mbedTLS free to avoid freeing
 * non-heap storage. Any heap-owned peer certificate the session holds is
 * released by mbedtls_ssl_session_free.
 *
 * @param e Cache entry to release (must be non-NULL).
 */
static void pn_tls_mbedtls_entry_release(pn_tls_session_entry_t* e)
{
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    e->session.ticket     = NULL;
    e->session.ticket_len = 0;
#endif
    mbedtls_ssl_session_free(&e->session);
    e->valid = 0;
}

/**
 * @brief Store the negotiated session for a hostname.
 *
 * Snapshots the session from @p ssl and relocates any heap-allocated session
 * ticket into the entry's fixed @c ticket_buf so the entry owns no persistent
 * heap ticket. Updates the existing slot for the host if present; otherwise
 * fills the first free slot; otherwise FIFO-evicts slot 0. Any session already
 * held by the chosen slot is released first.
 *
 * @param mctx Owning context.
 * @param host Host key.
 * @param ssl  Completed SSL context to snapshot.
 */
static void pn_tls_mbedtls_cache_store(struct pn_mbedtls_ctx*     mctx,
                                       const char*                host,
                                       const mbedtls_ssl_context* ssl)
{
    mbedtls_ssl_session     tmp_session;
    pn_tls_session_entry_t* slot      = NULL;
    int                     free_slot = -1;
    int                     i;
    int                     rc;

    if (NULL == mctx || NULL == host || NULL == ssl) {
        return;
    }

    mbedtls_ssl_session_init(&tmp_session);
    rc = mbedtls_ssl_get_session(ssl, &tmp_session);
#ifdef PN_DEBUG_SOCKET_OPS
    PUBNUB_LOG(mctx->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "TLS cache store: get_session rc=%d host=%s",
               rc,
               host);
#endif
    if (0 != rc) {
        mbedtls_ssl_session_free(&tmp_session);
        return;
    }

    /* Select the slot: existing host match, else first free, else evict 0. */
    for (i = 0; i < PUBNUB_CFG_TLS_SESSION_CACHE_SIZE; ++i) {
        pn_tls_session_entry_t* e = &mctx->session_cache[i];
        if (0 != e->valid) {
            if (0 == strncmp(e->host, host, PUBNUB_CFG_MAX_HOSTNAME_LEN)) {
                slot = e;
                break;
            }
        } else if (-1 == free_slot) {
            free_slot = i;
        }
    }
    if (NULL == slot) {
        slot = (-1 != free_slot) ? &mctx->session_cache[free_slot]
                                 : &mctx->session_cache[0];
    }
    if (0 != slot->valid) {
        pn_tls_mbedtls_entry_release(slot);
    }

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    /* Relocate the heap ticket into the entry's fixed buffer. A ticket that
     * does not fit is dropped entirely (a truncated ticket is unusable);
     * session-ID resumption still applies. */
    if (NULL != tmp_session.ticket && tmp_session.ticket_len > 0) {
#ifdef PN_DEBUG_SOCKET_OPS
        PUBNUB_LOG(mctx->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "TLS cache store: ticket_len=%u (max=%u) host=%s",
                   (unsigned)tmp_session.ticket_len,
                   (unsigned)PN_TLS_SESSION_TICKET_MAX_SIZE,
                   host);
#endif
        if (tmp_session.ticket_len <= PN_TLS_SESSION_TICKET_MAX_SIZE) {
            size_t copy_len = tmp_session.ticket_len;
            memcpy(slot->ticket_buf, tmp_session.ticket, copy_len);
            mbedtls_platform_zeroize(tmp_session.ticket, tmp_session.ticket_len);
            mbedtls_free(tmp_session.ticket);
            tmp_session.ticket     = slot->ticket_buf;
            tmp_session.ticket_len = copy_len;
        } else {
            mbedtls_platform_zeroize(tmp_session.ticket, tmp_session.ticket_len);
            mbedtls_free(tmp_session.ticket);
            tmp_session.ticket     = NULL;
            tmp_session.ticket_len = 0;
        }
    }
#endif

    slot->session = tmp_session;
    pn_strlcpy(slot->host, host, PUBNUB_CFG_MAX_HOSTNAME_LEN + 1);
#ifdef PN_DEBUG_SOCKET_OPS
    PUBNUB_LOG(mctx->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "TLS cache: session stored for host=%s slot=%d",
               host,
               (int)(slot - mctx->session_cache));
#endif
    slot->valid = 1;
}

/**
 * @brief Drop a cached session for a hostname.
 *
 * Used when a resume attempt fails so a stale session is not offered again.
 *
 * @param mctx Owning context.
 * @param host Host key.
 */
static void pn_tls_mbedtls_cache_invalidate(struct pn_mbedtls_ctx* mctx,
                                            const char*            host)
{
    pn_tls_session_entry_t* e;

    if (NULL == mctx || NULL == host) {
        return;
    }

    e = pn_tls_mbedtls_cache_lookup(mctx, host);
    if (NULL != e) {
        pn_tls_mbedtls_entry_release(e);
    }
}
#endif /* PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0 */

#if !(defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C))
/**
 * @brief PSA-backed RNG callback for mbedTLS ssl_conf_rng.
 *
 * Used on platforms (e.g. NCS/Zephyr with PSA crypto) that disable the
 * legacy ENTROPY_C/CTR_DRBG_C modules.
 */
static int pn_psa_rng(void* ctx, unsigned char* buf, size_t len)
{
    (void)ctx;
    psa_status_t st = psa_generate_random(buf, len);
    return (PSA_SUCCESS == st) ? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}
#endif

/**
 * @brief Custom send callback for mbedTLS (non-blocking).
 *
 * Routes I/O through the platform ops vtable instead of calling POSIX
 * send() directly. This enables mbedTLS on platforms without POSIX
 * socket names (e.g. Zephyr RTOS).
 *
 * @param ctx Session (struct pn_mbedtls_session*).
 * @param buf Data to send.
 * @param len Bytes to send.
 * @return Bytes sent, or mbedTLS error code.
 */
static int pn_mbedtls_send_cb(void* ctx, const unsigned char* buf, size_t len)
{
    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)ctx;
    int rc = sess->ops->socket_send(sess->ops, sess->sock, buf, len);
    /* socket_send: >0 bytes sent, 0 would-block, <-1 error. */
    if (rc > 0) {
        return rc;
    }
    if (0 == rc) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    PUBNUB_LOG(sess->logger,
               PUBNUB_LOG_LEVEL_WARNING,
               "TLS send_cb: socket_send error rc=%d",
               rc);
    return -0x004E; /* MBEDTLS_ERR_NET_SEND_FAILED */
}

/**
 * @brief Custom recv callback for mbedTLS (non-blocking).
 *
 * Routes I/O through the platform ops vtable instead of calling POSIX
 * recv() directly.
 *
 * @param ctx Session (struct pn_mbedtls_session*).
 * @param buf Output buffer.
 * @param len Buffer capacity.
 * @return Bytes received, or mbedTLS error code.
 */
static int pn_mbedtls_recv_cb(void* ctx, unsigned char* buf, size_t len)
{
    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)ctx;
    int rc = sess->ops->socket_recv(sess->ops, sess->sock, buf, len);
    /* socket_recv: >0 bytes, 0 would-block, -1 peer closed, <-1 error. */
    if (rc > 0) {
        return rc;
    }
    if (0 == rc) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (-1 == rc) {
        /* Raw TCP FIN with no TLS close_notify alert. Report an
         * unexpected reset so mbedTLS surfaces a truncated close-delimited
         * body as an error instead of a clean close. A genuine TLS
         * close_notify is detected by mbedTLS itself from the decrypted
         * alert record, not synthesized here. */
        return MBEDTLS_ERR_NET_CONN_RESET;
    }
    PUBNUB_LOG(sess->logger,
               PUBNUB_LOG_LEVEL_WARNING,
               "TLS recv_cb: socket_recv error rc=%d",
               rc);
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

/**
 * @brief Create a TLS context with mbedTLS.
 *
 * Configures certificate verification, minimum protocol version, session reuse,
 * and RNG. Caller owns the returned context and must pass it to ctx_destroy
 * when done.
 *
 * @param cfg  Configuration (must outlive context).
 * @param deps Provider dependencies (allocator must be non-NULL).
 * @return Opaque struct pn_mbedtls_ctx pointer, or NULL on failure.
 */
static void* pn_tls_mbedtls_ctx_create(const pn_tls_config_t*             cfg,
                                       const struct pubnub_provider_deps* deps)
{
    if (NULL == cfg || NULL == deps || NULL == deps->allocator) {
        return NULL;
    }

    pubnub_allocator_provider_t* alloc = deps->allocator;
    struct pn_mbedtls_ctx*       mctx =
        (struct pn_mbedtls_ctx*)PN_ALLOC(alloc, sizeof(*mctx), sizeof(void*));
    if (NULL == mctx) {
        return NULL;
    }

    /* Zero-initialize all structures. */
    memset(mctx, 0, sizeof(*mctx));
    mctx->allocator = alloc;
    mctx->logger    = deps->logger;
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    mctx->session_reuse = (0 != cfg->session_reuse) ? 1 : 0;
#endif
    mbedtls_ssl_config_init(&mctx->conf);
    mbedtls_x509_crt_init(&mctx->ca_chain);

#if !(defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C))
    /* PSA must be initialized for psa_generate_random(). On Zephyr this
     * is handled by SYS_INIT; on bare-metal targets the call is
     * idempotent (safe to call multiple times). */
    if (PSA_SUCCESS != psa_crypto_init()) {
        PN_FREE(alloc, mctx);
        return NULL;
    }
#else
    mbedtls_entropy_init(&mctx->entropy);
    mbedtls_ctr_drbg_init(&mctx->ctr_drbg);

    /* Seed RNG. */
    const char* pers = "pubnub-mbedtls";
    if (0
        != mbedtls_ctr_drbg_seed(&mctx->ctr_drbg,
                                 mbedtls_entropy_func,
                                 &mctx->entropy,
                                 (const unsigned char*)pers,
                                 strlen(pers))) {
        goto error;
    }
#endif

    /* Configure SSL defaults (client, stream, default preset). */
    if (0
        != mbedtls_ssl_config_defaults(&mctx->conf,
                                       MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT)) {
        goto error;
    }

    /* Set minimum TLS version. API differs between 2.x and 3.x; version is
     * detected via MBEDTLS_VERSION_NUMBER because MBEDTLS_SSL_VERSION_TLS1_3
     * is an enum (not a #define) on 3.x — #ifdef on it is always false. */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    {
        mbedtls_ssl_protocol_version min_version = MBEDTLS_SSL_VERSION_TLS1_2;
        if (PN_TLS_1_3 == cfg->min_version) {
            /* The enum is always declared on 3.x; the handshake fails at
             * runtime if TLS 1.3 support was not compiled in. */
            min_version = MBEDTLS_SSL_VERSION_TLS1_3;
        }
        mbedtls_ssl_conf_min_tls_version(&mctx->conf, min_version);
    }
#else
    {
        /* mbedTLS 2.x: enforce the floor via the legacy min-version API
         * rather than relying on the library default. */
        int min_minor = MBEDTLS_SSL_MINOR_VERSION_3; /* TLS 1.2 */
#if defined(MBEDTLS_SSL_MINOR_VERSION_4)
        if (PN_TLS_1_3 == cfg->min_version) {
            min_minor = MBEDTLS_SSL_MINOR_VERSION_4; /* TLS 1.3 */
        }
#endif
        mbedtls_ssl_conf_min_version(
            &mctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3, min_minor);
    }
#endif

    /* Load certificates. */
    int loaded = 0;

#ifdef MBEDTLS_FS_IO
    if (NULL != cfg->ca_file) {
        if (0 != mbedtls_x509_crt_parse_file(&mctx->ca_chain, cfg->ca_file)) {
            goto error;
        }
        loaded = 1;
    }
#else
    (void)cfg->ca_file;
#endif

    if (NULL != cfg->ca_pem) {
        size_t pem_len = strlen(cfg->ca_pem);
        if (0
            != mbedtls_x509_crt_parse(
                &mctx->ca_chain, (const unsigned char*)cfg->ca_pem, pem_len + 1)) {
            goto error;
        }
        loaded = 1;
    }

    if (0 != cfg->use_system_certs) {
        pn_tls_system_cert_fn_t loader = cfg->system_cert_loader;
        if (NULL == loader) {
            loader = pn_tls_get_default_cert_loader();
        }
        if (NULL != loader) {
            if (0 == loader(&mctx->ca_chain, &mctx->conf, cfg->system_cert_user_data)) {
                loaded = 1;
            }
        }
    }

    /* Fail if no certs loaded at all (unless skip_verify). */
    if (0 == loaded && 0 == cfg->skip_verify) {
        goto error;
    }

    /* Set auth mode. */
    int auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
    if (0 != cfg->skip_verify) {
        auth_mode = MBEDTLS_SSL_VERIFY_NONE;
    }
    mbedtls_ssl_conf_authmode(&mctx->conf, auth_mode);

    /* Attach CA chain. */
    mbedtls_ssl_conf_ca_chain(&mctx->conf, &mctx->ca_chain, NULL);

    /* Set RNG. */
#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ssl_conf_rng(&mctx->conf, mbedtls_ctr_drbg_random, &mctx->ctr_drbg);
#else
    mbedtls_ssl_conf_rng(&mctx->conf, pn_psa_rng, NULL);
#endif

    /* Session resumption is enabled by default in mbedTLS. */
#if defined(MBEDTLS_SSL_SESSION_TICKETS_C)
    if (0 == cfg->session_reuse) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
        mbedtls_ssl_conf_session_tickets(&mctx->conf,
                                         MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#else
        mbedtls_ssl_conf_session_tickets(&mctx->conf, 0);
#endif
    }
#endif /* MBEDTLS_SSL_SESSION_TICKETS_C */

    return mctx;

error:
    mbedtls_x509_crt_free(&mctx->ca_chain);
    mbedtls_ssl_config_free(&mctx->conf);
#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_free(&mctx->ctr_drbg);
    mbedtls_entropy_free(&mctx->entropy);
#endif
    PN_FREE(mctx->allocator, mctx);
    return NULL;
}

/**
 * @brief Destroy an mbedTLS TLS context.
 *
 * @param ctx struct pn_mbedtls_ctx from ctx_create, or NULL.
 */
static void pn_tls_mbedtls_ctx_destroy(void* ctx)
{
    if (NULL == ctx) {
        return;
    }

    struct pn_mbedtls_ctx* mctx = (struct pn_mbedtls_ctx*)ctx;
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    {
        int i;
        for (i = 0; i < PUBNUB_CFG_TLS_SESSION_CACHE_SIZE; ++i) {
            if (0 != mctx->session_cache[i].valid) {
                pn_tls_mbedtls_entry_release(&mctx->session_cache[i]);
            }
        }
    }
#endif
    mbedtls_x509_crt_free(&mctx->ca_chain);
    mbedtls_ssl_config_free(&mctx->conf);
#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_free(&mctx->ctr_drbg);
    mbedtls_entropy_free(&mctx->entropy);
#endif
    PN_FREE(mctx->allocator, mctx);
}

/**
 * @brief Create an mbedTLS TLS session for a connected socket.
 *
 * Prepares the session for handshake. Caller must pass a connected, non-
 * blocking socket. Sets SNI and hostname verification.
 *
 * @param out_session Output session pointer (must be non-NULL).
 * @param ctx         struct pn_mbedtls_ctx from ctx_create.
 * @param sock        Connected TCP socket.
 * @param ops         Platform socket operations vtable.
 * @param hostname    Server hostname for SNI and verification.
 * @return 0 on success, -1 on error.
 */
static int pn_tls_mbedtls_session_create(void**      out_session,
                                         void*       ctx,
                                         pn_socket_t sock,
                                         const struct pn_socket_platform_ops* ops,
                                         const char* hostname)
{
    if (NULL == out_session || NULL == ctx || PN_INVALID_SOCKET == sock
        || NULL == ops || NULL == hostname) {
        return -1;
    }

    struct pn_mbedtls_ctx* mctx = (struct pn_mbedtls_ctx*)ctx;

    PUBNUB_LOG(mctx->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "TLS session create: sizeof(pn_mbedtls_session)=%u",
               (unsigned)sizeof(struct pn_mbedtls_session));

    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)PN_ALLOC(
        mctx->allocator, sizeof(*sess), sizeof(void*));
    if (NULL == sess) {
        PUBNUB_LOG(mctx->logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "TLS session alloc failed: requested %u bytes",
                   (unsigned)sizeof(struct pn_mbedtls_session));
        return -1;
    }

    sess->sock       = sock;
    sess->ops        = ops;
    sess->allocator  = mctx->allocator;
    sess->logger     = mctx->logger;
    sess->last_error = 0;
    mbedtls_ssl_init(&sess->ssl);

    /* Attach config. */
    int setup_rc = mbedtls_ssl_setup(&sess->ssl, &mctx->conf);
    if (0 != setup_rc) {
        char errbuf[64];
        mbedtls_strerror(setup_rc, errbuf, sizeof(errbuf));
        PUBNUB_LOG(mctx->logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "TLS ssl_setup error: rc=%d (%s)",
                   setup_rc,
                   errbuf);
        sess->last_error = setup_rc;
        mbedtls_ssl_free(&sess->ssl);
        PN_FREE(mctx->allocator, sess);
        return -1;
    }

    /* Set SNI hostname. */
    int sni_rc = mbedtls_ssl_set_hostname(&sess->ssl, hostname);
    if (0 != sni_rc) {
        char errbuf[64];
        mbedtls_strerror(sni_rc, errbuf, sizeof(errbuf));
        PUBNUB_LOG(mctx->logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "TLS set_hostname error: rc=%d (%s)",
                   sni_rc,
                   errbuf);
        sess->last_error = sni_rc;
        mbedtls_ssl_free(&sess->ssl);
        PN_FREE(mctx->allocator, sess);
        return -1;
    }

    /* Set custom BIO callbacks. */
    mbedtls_ssl_set_bio(
        &sess->ssl, sess, pn_mbedtls_send_cb, pn_mbedtls_recv_cb, NULL);

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    sess->mctx             = mctx;
    sess->resume_attempted = 0;
    pn_strlcpy(sess->host, hostname, PUBNUB_CFG_MAX_HOSTNAME_LEN + 1);
    if (0 != mctx->session_reuse) {
        pn_tls_session_entry_t* cached =
            pn_tls_mbedtls_cache_lookup(mctx, hostname);
#ifdef PN_DEBUG_SOCKET_OPS
        PUBNUB_LOG(mctx->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "TLS cache lookup: host=%s found=%d",
                   hostname,
                   NULL != cached ? 1 : 0);
#endif
        if (NULL != cached) {
            int set_rc = mbedtls_ssl_set_session(&sess->ssl, &cached->session);
#ifdef PN_DEBUG_SOCKET_OPS
            PUBNUB_LOG(mctx->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "TLS cache: applying cached session for host=%s rc=%d",
                       hostname,
                       set_rc);
#endif
            if (0 == set_rc) {
                sess->resume_attempted = 1;
            }
        }
    }
#endif

    *out_session = sess;
    return 0;
}

/** @brief Drive TLS handshake (non-blocking).
 *
 * Call repeatedly until PN_TLS_OK. Returns PN_TLS_WANT_READ or
 * PN_TLS_WANT_WRITE when the socket must be polled for readiness.
 *
 * @note Stack usage: ~2-3KB during handshake (mbedTLS record buffers +
 *       BIO callbacks). FreeRTOS tasks must have at least 4KB stack.
 *
 * @param session struct pn_mbedtls_session from session_create.
 * @return PN_TLS_OK when handshake complete, PN_TLS_WANT_READ/WRITE if socket
 *         must be checked for readiness, -1 on error.
 */
static int pn_tls_mbedtls_handshake(void* session)
{
    if (NULL == session) {
        return -1;
    }

    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)session;
    int                        rc   = mbedtls_ssl_handshake(&sess->ssl);
    if (0 == rc) {
#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
#ifdef PN_DEBUG_SOCKET_OPS
        if (NULL != sess->mctx) {
            PUBNUB_LOG(sess->mctx->logger,
                       PUBNUB_LOG_LEVEL_DEBUG,
                       "TLS handshake OK: host=%s resume_attempted=%d",
                       sess->host,
                       (int)sess->resume_attempted);
        }
#endif
        if (NULL != sess->mctx && 0 != sess->mctx->session_reuse) {
            pn_tls_mbedtls_cache_store(sess->mctx, sess->host, &sess->ssl);
        }
#endif
        return PN_TLS_OK;
    }

    if (MBEDTLS_ERR_SSL_WANT_READ == rc) {
        return PN_TLS_WANT_READ;
    }
    if (MBEDTLS_ERR_SSL_WANT_WRITE == rc) {
        return PN_TLS_WANT_WRITE;
    }

#if PUBNUB_CFG_TLS_SESSION_CACHE_SIZE > 0
    if (0 != sess->resume_attempted && NULL != sess->mctx) {
        pn_tls_mbedtls_cache_invalidate(sess->mctx, sess->host);
        sess->resume_attempted = 0;
    }
#endif

    {
        char errbuf[64];
        mbedtls_strerror(rc, errbuf, sizeof(errbuf));
        PUBNUB_LOG(sess->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "TLS handshake error: rc=%d (%s)",
                   rc,
                   errbuf);
    }
    sess->last_error = rc;
    return -1;
}

/**
 * @brief Send data over TLS (non-blocking).
 *
 * @param session struct pn_mbedtls_session from session_create.
 * @param buf     Buffer to send.
 * @param len     Bytes to send.
 * @return >0 bytes sent (may be less than len), 0 if send would block, -1 if
 *         peer closed cleanly, -2 on error.
 */
static int pn_tls_mbedtls_send(void* session, const void* buf, size_t len)
{
    if (NULL == session || (NULL == buf && 0 != len)) {
        return -2;
    }

    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)session;
    int rc = mbedtls_ssl_write(&sess->ssl, (const unsigned char*)buf, len);
    if (0 < rc) {
        return rc;
    }

    if (MBEDTLS_ERR_SSL_WANT_WRITE == rc || MBEDTLS_ERR_SSL_WANT_READ == rc) {
        return 0;
    }
    if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == rc) {
        return -1;
    }

    sess->last_error = rc;
    {
        char errbuf[64];
        mbedtls_strerror(rc, errbuf, sizeof(errbuf));
        PUBNUB_LOG(sess->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "TLS send error: rc=%d (%s)",
                   rc,
                   errbuf);
    }
    return -2;
}

/**
 * @brief Receive data over TLS (non-blocking).
 *
 * @param session struct pn_mbedtls_session from session_create.
 * @param buf     Output buffer.
 * @param len     Capacity of buf.
 * @return >0 bytes received, 0 if receive would block, -1 if peer closed
 *         cleanly, -2 on error.
 */
static int pn_tls_mbedtls_recv(void* session, void* buf, size_t len)
{
    if (NULL == session || NULL == buf || 0 == len) {
        return -2;
    }

    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)session;
    int rc = mbedtls_ssl_read(&sess->ssl, (unsigned char*)buf, len);
    if (0 < rc) {
        return rc;
    }

    if (MBEDTLS_ERR_SSL_WANT_READ == rc || MBEDTLS_ERR_SSL_WANT_WRITE == rc) {
        return 0;
    }
    if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == rc || 0 == rc) {
        return -1;
    }

    sess->last_error = rc;
    {
        char errbuf[64];
        mbedtls_strerror(rc, errbuf, sizeof(errbuf));
        PUBNUB_LOG(sess->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "TLS recv error: rc=%d (%s)",
                   rc,
                   errbuf);
    }
    return -2;
}

/**
 * @brief Destroy an mbedTLS TLS session.
 *
 * Performs best-effort shutdown. Does NOT close the underlying socket (caller
 * manages socket lifetime).
 *
 * @param session struct pn_mbedtls_session from session_create, or NULL.
 */
static void pn_tls_mbedtls_session_destroy(void* session)
{
    if (NULL == session) {
        return;
    }

    struct pn_mbedtls_session* sess = (struct pn_mbedtls_session*)session;
    PUBNUB_LOG(sess->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "TLS session destroy: last_error=%d",
               sess->last_error);
    /* Non-blocking best-effort: returns immediately if socket is not writable. */
    mbedtls_ssl_close_notify(&sess->ssl);
    mbedtls_ssl_free(&sess->ssl);
    PN_FREE(sess->allocator, sess);
}

static int pn_tls_mbedtls_get_session_error(void* session)
{
    if (NULL == session) {
        return 0;
    }
    return ((struct pn_mbedtls_session*)session)->last_error;
}

static const char* pn_tls_mbedtls_session_error_str(int code)
{
    switch (code) {
    case -0x7780: return "SSL_ALLOC_FAILED";
    case -0x7700: return "SSL_BAD_INPUT_DATA";
    case -0x6800: return "SSL_INVALID_RECORD";
    case -0x6480: return "SSL_CONN_EOF";
    case -0x6200: return "SSL_NO_CLIENT_CERTIFICATE";
    case -0x7F00: return "SSL_FATAL_ALERT_MESSAGE";
    case -0x2700: return "X509_CERT_VERIFY_FAILED";
    case -0x2780: return "X509_CERT_NOT_YET_VALID";
    case -0x2800: return "X509_CERT_EXPIRED";
    case -0x2900: return "X509_CERT_UNKNOWN";
    case -0x3000: return "X509_BAD_INPUT_DATA";
    case -0x0050: return "SSL_PEER_CLOSE_NOTIFY";
    default: return NULL;
    }
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_tls_backend_t pn_tls_mbedtls_backend = {
    .ctx_create        = pn_tls_mbedtls_ctx_create,
    .ctx_destroy       = pn_tls_mbedtls_ctx_destroy,
    .session_create    = pn_tls_mbedtls_session_create,
    .session_destroy   = pn_tls_mbedtls_session_destroy,
    .handshake         = pn_tls_mbedtls_handshake,
    .send              = pn_tls_mbedtls_send,
    .recv              = pn_tls_mbedtls_recv,
    .get_session_error = pn_tls_mbedtls_get_session_error,
    .session_error_str = pn_tls_mbedtls_session_error_str,
};

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/providers/provider_deps.h"
#include "pubnub/pubnub_compat.h"
#include "core_internal.h"
#include "config_internal.h"
#include "pn_lock.h"
#include "pn_logger_manager.h"
#include "provider_internal.h"
#include "pn_feature_registry.h"
#include "pn_string.h"
#include "runtime/pending_queue_internal.h"
#include "runtime/pipeline_internal.h"
#include "runtime/request_pool_internal.h"
#include "runtime/timer_internal.h"

#include "pn_format.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/** Magic sentinel - reduces false positives when pubnub_init() is
 *  called on uninitialized caller-provided memory. */
#define PN_INIT_MAGIC 0x504E4F4BU /* ASCII 'PNOK' */

/* Forward declaration (defined after pn_process_tick). */
void pn_context_wake_bg_thread(pubnub_context_t* ctx);

struct pubnub_context {
    pubnub_config_t config;

    /* Resolved provider pointers (populated during init from config
     * values or compiled-in defaults). Internal code accesses these
     * fields, never config.allocator / config.transport / etc.
     * Non-const: the self-pointer pattern requires mutable access. */
    pubnub_allocator_provider_t*     allocator;
    pubnub_transport_provider_t*     transport;
    pubnub_serialization_provider_t* serialization;
    pubnub_platform_provider_t*      platform;
    pubnub_crypto_module_t*          crypto_module;
    pubnub_logger_provider_t*        logger;

    /** Per-context logger manager (embedded, no heap allocation). */
    pn_logger_manager_t logger_manager;

    /* Shared dependency bag passed to per-context provider `init()`.
     * Embedded here so that the pointers remain valid for the lifetime
     * of the context (providers may store references to deps members). */
    pubnub_provider_deps_t deps;

    /* Runtime-mutable shadow fields (setters update these, not config). */
    const char*  auth_token;
    const char*  user_id;
    const char*  dns_primary;
    const char*  dns_secondary;
    unsigned int log_level;

    /** Fixed buffer for the origin hostname. config.origin always
     *  points here after init — no dynamic allocation needed. */
    char origin_buf[PUBNUB_CFG_MAX_HOSTNAME_LEN];

    /** Set by `pubnub_create()`; owns deep-copied config strings. */
    uint8_t owns_config;

    /**
     * Middleware + transport chain. Built by
     * `pn_context_build_pipeline()` after providers are resolved
     * and after string ownership is finalized (so inner layers
     * capture the pointers that live for the context's lifetime).
     * Dispatched by features via `pn_context_pipeline()`.
     */
    pn_pipeline_t pipeline;

    /**
     * Fixed-capacity pool of request slots. Initialized in
     * `pn_context_init_common()` with capacity equal to
     * `PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS`. Feature API calls
     * acquire slots here to produce `pubnub_future_t` handles.
     */
    pn_request_pool_t pool;

    /** Per-context feature registry (cleanup + state). */
    pn_feature_registry_t features;

    /**
     * FIFO queue for requests that arrive when all pool slots are
     * in use. Entries are promoted to real slots as slots are released
     * during the process tick. Capacity is PUBNUB_CFG_MAX_PENDING_REQUESTS.
     */
    pn_pending_queue_t pending_queue;

    /**
     * Mapping from pending-queue logical indices to promoted real slot IDs.
     *
     * When a feature enqueues into the pending queue (because the pool
     * is full), it gets a future with slot_id = pool.capacity + pending_idx.
     * This array maps pending_idx -> real_slot_id after promotion. Before
     * promotion the entry is PUBNUB_SLOT_ID_INVALID (not yet promoted).
     *
     * Sized to PUBNUB_CFG_MAX_PENDING_REQUESTS; allocated alongside the queue.
     */
    uint16_t* pending_slot_map;

    /**
     * Per-context lock (owned, may be NULL).
     *
     * Allocated via allocator->alloc() at init time when
     * PUBNUB_CFG_THREAD_SAFETY is 1 AND the platform provider
     * supplies lock primitives. Initialized in-place by
     * platform->lock_init(). Destroyed and freed during deinit.
     * NULL on cooperative-only targets or when thread safety is
     * disabled at compile time.
     */
    pubnub_lock_t* lock;

    /**
     * Background processing thread handle (opaque, platform-owned).
     * Non-NULL when a background thread is running for this context.
     * Started lazily on first pubnub_async() call when the platform
     * provides thread_create. Joined during deinit.
     * NULL on cooperative-only targets or when thread safety is
     * disabled at compile time.
     */
    void* bg_thread_handle;

    /**
     * Flag controlling the background thread loop. Set to 1 when the
     * thread is started; cleared to 0 by pubnub_deinit before joining.
     *
     * volatile is sufficient for a single-byte stop flag on all
     * SDK-supported architectures (ARM, x86, RISC-V). _Atomic is
     * formally more correct under C11 but adds header dependencies
     * and is unavailable on C99 targets. The bg thread blocks in
     * transport->poll() which provides the scheduling boundary;
     * the thread_join after clearing the flag ensures visibility.
     */
    volatile uint8_t bg_running;

    /** Set when the context owns the transport allocation (defaulted). */
    uint8_t transport_owned;

    /**
     * Guards against concurrent transport->poll() calls. Set to 1
     * under the context lock before entering poll(), cleared to 0
     * after poll() returns. When a second pn_process_tick() sees
     * this flag set, it returns PUBNUB_IN_PROGRESS immediately.
     * Only meaningful when PUBNUB_CFG_THREAD_SAFETY is 1; the
     * check compiles out otherwise via runtime-constant guard.
     */
    uint8_t poll_active;

    /**
     * Prep-pool: pre-allocated pn_pending_entry_t entries that feature
     * functions build HTTP requests into before dispatch. Eliminates
     * ~33 KB stack frames by moving the scratch buffer to the heap.
     *
     * Capacity equals PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS so that the
     * maximum number of concurrent feature-prepare -> dispatch
     * sequences can proceed without contention.
     */
    pn_pending_entry_t* prep_entries;

    /** Bitmap: 1 = slot in use, 0 = free. Indexed by prep slot index.
     *  Acquire scans under pool lock; release is lock-free (single
     *  byte write, ownership guarantee). */
    uint8_t prep_used[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];

    uint32_t initialized;
};

#if defined(PUBNUB_CONTEXT_SIZE)
PUBNUB_STATIC_ASSERT(
    sizeof(struct pubnub_context) <= PUBNUB_CONTEXT_SIZE,
    "PUBNUB_CONTEXT_SIZE is too small; update CMakeLists.txt formula");
#endif

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_HOSTNAME_LEN >= 16
                         && PUBNUB_CFG_MAX_HOSTNAME_LEN <= 512,
                     "PUBNUB_CFG_MAX_HOSTNAME_LEN must be 16..512");

static void pn_context_retry_resolve_defaults(pubnub_config_t* cfg)
{
#if PUBNUB_ENABLE_RETRY
    if (PUBNUB_RETRY_NONE == cfg->retry_configuration.policy) {
        return;
    }

    if (0 == cfg->retry_configuration.delay_ms) {
        cfg->retry_configuration.delay_ms = PUBNUB_CFG_RETRY_DELAY_MS;
    }
    if (0 == cfg->retry_configuration.maximum_retry) {
        cfg->retry_configuration.maximum_retry =
            (PUBNUB_RETRY_LINEAR == cfg->retry_configuration.policy)
                ? PUBNUB_CFG_LINEAR_MAX_RETRIES
                : PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES;
    }
    if (PUBNUB_RETRY_EXPONENTIAL == cfg->retry_configuration.policy
        && 0 == cfg->retry_configuration.maximum_delay_ms) {
        cfg->retry_configuration.maximum_delay_ms = PUBNUB_CFG_RETRY_MAX_DELAY_MS;
    }
    if (0 == cfg->retry_configuration.maximum_retry_after_ms) {
        cfg->retry_configuration.maximum_retry_after_ms =
            PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS;
    }
#else
    (void)cfg;
#endif
}

/** @brief Check that all resolved providers have their mandatory vtable
 * entries. */
static int pn_providers_vtable_valid(const pubnub_context_t* ctx)
{
    if (!ctx->allocator || !ctx->transport || !ctx->serialization || !ctx->platform) {
        return 0;
    }
    if (!ctx->allocator->alloc || !ctx->allocator->free
        || !ctx->allocator->buf_acquire || !ctx->allocator->buf_release) {
        return 0;
    }
    if (!ctx->transport->send || !ctx->transport->poll || !ctx->transport->cancel) {
        return 0;
    }
    if (!ctx->serialization->parse || !ctx->serialization->serialize
        || !ctx->serialization->value_destroy) {
        return 0;
    }
    if (!ctx->platform->monotonic_ms || !ctx->platform->sleep_ms
        || !ctx->platform->random_bytes || !ctx->platform->wall_clock_ms) {
        return 0;
    }
    return 1;
}

/**
 * @brief Resolve `NULL` provider pointers to compiled-in defaults and
 *        call `init()` on per-context providers.
 *
 * @return `PUBNUB_OK` on success.
 */
static pubnub_res_t pn_context_providers_resolve_and_init(pubnub_context_t* ctx)
{
    int transport_defaulted = 0;
    int allocator_inited    = 0;

    ctx->allocator = ctx->config.allocator;
    if (!ctx->allocator) {
        ctx->allocator = pn_allocator_default();
    }
    if (NULL == ctx->allocator) {
        return PUBNUB_ERR_PROVIDER_MISSING;
    }

    /* Initialize the logger manager and register providers. */
    pn_logger_manager_init(&ctx->logger_manager);

    /* Built-in default logger (slot 0) — may be NULL in stub builds. */
    {
        pubnub_logger_provider_t* default_logger = pn_logger_default();
        if (NULL != default_logger) {
            (void)pn_logger_manager_add(&ctx->logger_manager, default_logger);
        }
    }

    /* User-provided logger from config (adds alongside, not replaces). */
    if (NULL != ctx->config.logger) {
        (void)pn_logger_manager_add(&ctx->logger_manager, ctx->config.logger);
    }

    /* ctx->logger always points to the embedded manager. */
    ctx->logger = &ctx->logger_manager.base;

    ctx->platform = ctx->config.platform;
    if (!ctx->platform) {
        ctx->platform = pn_platform_default();
    }
    if (NULL == ctx->platform) {
        return PUBNUB_ERR_PROVIDER_MISSING;
    }

    if (NULL != ctx->allocator->init) {
        const int arc = ctx->allocator->init(ctx->allocator, ctx->platform);
        if (0 != arc) {
            return PUBNUB_ERR_INTERNAL;
        }
        allocator_inited = 1;
    }

    ctx->transport = ctx->config.transport;
    if (!ctx->transport) {
        ctx->transport      = pn_transport_default(ctx->allocator);
        transport_defaulted = 1;
    }

    ctx->serialization = ctx->config.serialization;
    if (!ctx->serialization) {
        ctx->serialization = pn_serialization_default();
    }

    ctx->crypto_module = ctx->config.crypto_module;

    if (!pn_providers_vtable_valid(ctx)) {
        goto cleanup_pre_init;
    }

    /* Wire platform into the logger manager now that it is validated
     * non-NULL with mandatory vtable entries present. Earlier logging
     * (during allocator->init) operates without timestamps; wiring
     * here closes the NULL-dereference window on targets without MMU. */
    pn_logger_manager_wire(&ctx->logger_manager, ctx->platform);

    ctx->deps.allocator = ctx->allocator;
    ctx->deps.logger    = ctx->logger;
    ctx->deps.platform  = ctx->platform;
    ctx->deps.proxy =
        (PUBNUB_PROXY_NONE != ctx->config.proxy.type) ? &ctx->config.proxy : NULL;
    ctx->deps.tcp_keepalive =
        ctx->config.tcp_keepalive.enabled ? &ctx->config.tcp_keepalive : NULL;
    ctx->deps.dns_primary   = ctx->dns_primary;
    ctx->deps.dns_secondary = ctx->dns_secondary;

    if (ctx->transport->init
        && 0 != ctx->transport->init(ctx->transport, &ctx->deps)) {
        if (transport_defaulted) {
            PN_FREE(ctx->allocator, ctx->transport);
            ctx->transport = NULL;
        }
        if (allocator_inited && NULL != ctx->allocator->deinit) {
            ctx->allocator->deinit(ctx->allocator, ctx->platform);
        }
        return PUBNUB_ERR_INTERNAL;
    }
    ctx->transport_owned = (uint8_t)transport_defaulted;

    if (ctx->serialization->init
        && 0 != ctx->serialization->init(ctx->serialization, &ctx->deps)) {
        goto cleanup_transport;
    }

#if PUBNUB_ENABLE_CRYPTO
    if (NULL != ctx->crypto_module
        && 0 != pn_crypto_module_providers_init(ctx->crypto_module, &ctx->deps)) {
        goto cleanup_serialization;
    }
#endif

    return PUBNUB_OK;

cleanup_pre_init:
    if (transport_defaulted && NULL != ctx->transport && NULL != ctx->allocator
        && NULL != ctx->allocator->free) {
        PN_FREE(ctx->allocator, ctx->transport);
        ctx->transport = NULL;
    }
    if (allocator_inited && NULL != ctx->allocator->deinit) {
        ctx->allocator->deinit(ctx->allocator, ctx->platform);
    }
    return PUBNUB_ERR_PROVIDER_MISSING;

#if PUBNUB_ENABLE_CRYPTO
cleanup_serialization:
    if (ctx->serialization && ctx->serialization->deinit) {
        ctx->serialization->deinit(ctx->serialization);
    }
#endif

cleanup_transport:
    if (ctx->transport->deinit) {
        ctx->transport->deinit(ctx->transport);
    }
    if (ctx->transport_owned) {
        PN_FREE(ctx->allocator, ctx->transport);
    }
    ctx->transport = NULL;
    if (allocator_inited && NULL != ctx->allocator->deinit) {
        ctx->allocator->deinit(ctx->allocator, ctx->platform);
    }

    return PUBNUB_ERR_INTERNAL;
}

/** @brief Deinit per-context providers in reverse init order. */
static void pn_context_providers_deinit(pubnub_context_t* ctx)
{
#if PUBNUB_ENABLE_CRYPTO
    pn_crypto_module_providers_deinit(ctx->crypto_module);
#endif
    if (ctx->serialization && ctx->serialization->deinit) {
        ctx->serialization->deinit(ctx->serialization);
    }
    if (ctx->transport && ctx->transport->deinit) {
        ctx->transport->deinit(ctx->transport);
    }
    if (ctx->transport_owned) {
        PN_FREE(ctx->allocator, ctx->transport);
    }
    ctx->transport       = NULL;
    ctx->transport_owned = 0;

    if (ctx->allocator && ctx->allocator->deinit) {
        ctx->allocator->deinit(ctx->allocator, ctx->platform);
    }
}

/** Build the SDK's canonical middleware chain for this context. */
static pubnub_res_t pn_context_build_pipeline(pubnub_context_t* ctx)
{
    if (NULL == ctx->user_id || '\0' == ctx->user_id[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    const pn_pipeline_prepare_opts_t opts = {
        .user_id        = (const char* const*)&ctx->user_id,
        .auth_token     = (const char* const*)&ctx->auth_token,
        .pnsdk_suffix   = ctx->config.pnsdk_suffix,
        .pnsdk_override = ctx->config.pnsdk_override,
        .publish_key    = ctx->config.publish_key,
        .secret_key     = (const char* const*)&ctx->config.secret_key,
        .crypto         = pn_crypto_default(),
        .allocator      = ctx->allocator,
        .platform       = ctx->platform,
        .transport      = ctx->transport,
        .retry_config   = &ctx->config.retry_configuration,
        .logger         = pn_context_logger(ctx),
    };
    return pn_pipeline_prepare_pubnub_middlewares(&ctx->pipeline, &opts);
}

static void pn_context_register_features(pubnub_context_t* ctx)
{
#if PUBNUB_ENABLE_PUBLISH
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_PUBLISH, NULL, NULL);
#endif
#if PUBNUB_ENABLE_SUBSCRIBE
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_SUBSCRIBE, NULL, NULL);
#endif
#if PUBNUB_ENABLE_PRESENCE
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_PRESENCE, NULL, NULL);
#endif
#if PUBNUB_ENABLE_HISTORY
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_HISTORY, NULL, NULL);
#endif
#if PUBNUB_ENABLE_MESSAGE_ACTIONS
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_MESSAGE_ACTIONS, NULL, NULL);
#endif
#if PUBNUB_ENABLE_SIGNAL
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_SIGNAL, NULL, NULL);
#endif
#if PUBNUB_ENABLE_PAM
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_PAM, NULL, NULL);
#endif
#if PUBNUB_ENABLE_APP_CONTEXT
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_APP_CONTEXT, NULL, NULL);
#endif
#if PUBNUB_ENABLE_FILES
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_FILES, NULL, NULL);
#endif
#if PUBNUB_ENABLE_CHANNEL_GROUPS
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_CHANNEL_GROUPS, NULL, NULL);
#endif
#if PUBNUB_ENABLE_CRYPTO
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_CRYPTO, NULL, NULL);
#endif
#if PUBNUB_ENABLE_PUSH_NOTIFICATIONS
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_PUSH_NOTIFICATIONS, NULL, NULL);
#endif
#if PUBNUB_ENABLE_TIME
    pn_feature_register(&ctx->features, PUBNUB_FEATURE_TIME, NULL, NULL);
#endif
}

/* NOLINTNEXTLINE(readability-function-size) */
static pubnub_res_t pn_context_init_common(pubnub_context_t*      ctx,
                                           const pubnub_config_t* config)
{
    if (PN_INIT_MAGIC == ctx->initialized) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_res_t rc = pn_config_validate(config);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->config = *config;

    /* Apply defaults for zero-valued tunables. */
    if (0 == ctx->config.transaction_timeout_ms) {
        ctx->config.transaction_timeout_ms = PUBNUB_CFG_TRANSACTION_TIMEOUT_MS;
    }
    if (0 == ctx->config.non_transaction_timeout_ms) {
        ctx->config.non_transaction_timeout_ms =
            PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS;
    }

    if (NULL == ctx->config.origin || '\0' == ctx->config.origin[0]) {
        ctx->config.origin = PUBNUB_CFG_ORIGIN;
    }

    if (strlen(ctx->config.origin) >= sizeof(ctx->origin_buf)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (pn_str_has_header_unsafe_byte(ctx->config.origin)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    pn_strlcpy(ctx->origin_buf, ctx->config.origin, sizeof(ctx->origin_buf));
    ctx->config.origin = ctx->origin_buf;

    pn_context_retry_resolve_defaults(&ctx->config);

    ctx->auth_token           = ctx->config.auth_token;
    ctx->user_id              = ctx->config.user_id;
    ctx->dns_primary          = ctx->config.dns_primary;
    ctx->dns_secondary        = ctx->config.dns_secondary;
    ctx->log_level            = PUBNUB_LOG_LEVEL_INFO;
    ctx->config.user_id       = NULL;
    ctx->config.auth_token    = NULL;
    ctx->config.dns_primary   = NULL;
    ctx->config.dns_secondary = NULL;

    /* Resolve providers and call per-context init. */
    rc = pn_context_providers_resolve_and_init(ctx);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Propagate initial log level to the embedded logger manager. */
    if (NULL != ctx->logger && NULL != ctx->logger->set_level) {
        ctx->logger->set_level(ctx->logger, ctx->log_level);
    }

    /* Allocate and initialize the per-context lock when thread safety
     * is enabled and the platform supplies lock primitives. Lock init
     * failure is fatal — running thread-safe code without a working
     * mutex is undefined behavior. */
    ctx->lock = NULL;
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != ctx->platform
        && NULL != ctx->platform->lock_size && NULL != ctx->platform->lock_init) {
        const size_t msz = ctx->platform->lock_size(ctx->platform);
        if (msz > 0) {
            pubnub_lock_t* lk =
                (pubnub_lock_t*)PN_ALLOC(ctx->allocator, msz, sizeof(void*));
            if (NULL == lk) {
                pn_context_providers_deinit(ctx);
                return PUBNUB_ERR_NOT_INITIALIZED;
            }
            int mrc = ctx->platform->lock_init(ctx->platform, lk);
            if (0 != mrc) {
                PN_FREE(ctx->allocator, lk);
                pn_context_providers_deinit(ctx);
                return PUBNUB_ERR_NOT_INITIALIZED;
            }
            ctx->lock = lk;
            pn_logger_manager_wire_lock(&ctx->logger_manager, ctx->lock);
        }
    }

    /* Allocate the request slot pool through the resolved allocator. */
    rc = pn_request_pool_init(&ctx->pool,
                              (uint16_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS,
                              ctx->allocator,
                              ctx->platform,
                              ctx->lock,
                              ctx->logger);
    if (PUBNUB_OK != rc) {
        goto cleanup_lock;
    }

    /* Initialize the pending queue for overflow requests. */
    rc = pn_pending_queue_init(&ctx->pending_queue,
                               (uint16_t)PUBNUB_CFG_MAX_PENDING_REQUESTS,
                               ctx->allocator);
    if (PUBNUB_OK != rc) {
        goto cleanup_pool;
    }

    /* Allocate the pending-slot map: one uint16 per pending entry. */
    ctx->pending_slot_map = (uint16_t*)PN_ALLOC(
        ctx->allocator,
        (size_t)PUBNUB_CFG_MAX_PENDING_REQUESTS * sizeof(uint16_t),
        sizeof(uint16_t));
    if (NULL == ctx->pending_slot_map) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup_queue;
    }
    {
        uint16_t i;
        for (i = 0; i < (uint16_t)PUBNUB_CFG_MAX_PENDING_REQUESTS; i++) {
            ctx->pending_slot_map[i] = PUBNUB_SLOT_ID_INVALID;
        }
    }

    /* Prep pool: heap staging for feature request builds (see prep_entries). */
    ctx->prep_entries = (pn_pending_entry_t*)PN_ALLOC(
        ctx->allocator,
        (size_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS * sizeof(pn_pending_entry_t),
        sizeof(void*));
    if (NULL == ctx->prep_entries) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup_slot_map;
    }
    memset(ctx->prep_entries,
           0,
           (size_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS * sizeof(pn_pending_entry_t));
    memset(ctx->prep_used, 0, sizeof(ctx->prep_used));

    pn_feature_registry_init(&ctx->features);
    pn_context_register_features(ctx);

    ctx->initialized = PN_INIT_MAGIC;

    pubnub_set_log_level(ctx, (unsigned int)config->log_level);

    PUBNUB_LOG_TEXT(ctx->logger, PUBNUB_LOG_LEVEL_INFO, "PubNub context initialized");
    {
        const pubnub_config_t* cfg = &ctx->config;
        /* Security: omit secret_key — never log credentials. */
        /* Security: omit cipher_key — never log credentials. */
        /* Security: omit auth_key — never log credentials. */
        pubnub_log_value_t uid_val =
            (pubnub_log_value_t)PUBNUB_LOG_VALUE_STR_INIT(ctx->user_id);
        pubnub_log_value_t uid_entry =
            (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY("user_id", &uid_val, NULL);

        pubnub_log_value_t pub_val =
            (pubnub_log_value_t)PUBNUB_LOG_VALUE_STR_INIT(cfg->publish_key);
        pubnub_log_value_t pub_entry = (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY(
            "publish_key", &pub_val, &uid_entry);

        pubnub_log_value_t sub_val =
            (pubnub_log_value_t)PUBNUB_LOG_VALUE_STR_INIT(cfg->subscribe_key);
        pubnub_log_value_t sub_entry = (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY(
            "subscribe_key", &sub_val, &pub_entry);

        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "config", &sub_entry);
    }

    return PUBNUB_OK;

    /* Cleanup labels in reverse initialization order. Each label falls
     * through to the next, forming a rollback cascade. */
cleanup_slot_map:
    if (NULL != ctx->pending_slot_map) {
        PN_FREE(ctx->allocator, ctx->pending_slot_map);
        ctx->pending_slot_map = NULL;
    }
cleanup_queue:
    pn_pending_queue_deinit(&ctx->pending_queue);
cleanup_pool:
    pn_request_pool_deinit(&ctx->pool);
cleanup_lock:
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != ctx->lock) {
        ctx->platform->lock_destroy(ctx->platform, ctx->lock);
    }
    if (NULL != ctx->lock) {
        PN_FREE(ctx->allocator, ctx->lock);
        ctx->lock = NULL;
    }
    pn_context_providers_deinit(ctx);
    return rc;
}

pubnub_config_t pubnub_config_defaults(void)
{
    pubnub_config_t cfg            = {0};
    cfg.transaction_timeout_ms     = PUBNUB_CFG_TRANSACTION_TIMEOUT_MS;
    cfg.non_transaction_timeout_ms = PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS;

    cfg.tcp_keepalive =
        (pubnub_tcp_keepalive_config_t)PUBNUB_TCP_KEEPALIVE_CONFIG_INIT;
    cfg.retry_configuration.policy = PUBNUB_RETRY_EXPONENTIAL;
    cfg.retry_configuration.excluded_endpoints =
        (unsigned int)PUBNUB_ENDPOINT_MESSAGE_SEND
        | (unsigned int)PUBNUB_ENDPOINT_PRESENCE
        | (unsigned int)PUBNUB_ENDPOINT_MESSAGE_STORAGE
        | (unsigned int)PUBNUB_ENDPOINT_CHANNEL_GROUPS
        | (unsigned int)PUBNUB_ENDPOINT_APP_CONTEXT
        | (unsigned int)PUBNUB_ENDPOINT_MESSAGE_REACTIONS
        | (unsigned int)PUBNUB_ENDPOINT_PAM | (unsigned int)PUBNUB_ENDPOINT_FILES;
    cfg.log_level = PUBNUB_LOG_LEVEL_INFO;
    return cfg;
}

/**
 * @brief Stop and join the background processing thread, if running.
 *
 * Clears the run flag, wakes the thread out of its poll, and joins it.
 * When the calling thread IS the background thread (e.g. a completion
 * callback that tears down its own context), the join is skipped: a
 * self-join returns @c EDEADLK on POSIX (silently doing nothing) and
 * deadlocks on Windows/Zephyr. The run flag is still cleared so the
 * loop exits after the current tick.
 *
 * @param ctx Context whose background thread should be joined.
 */
static void pn_context_join_bg_thread(pubnub_context_t* ctx)
{
    if (!PUBNUB_CFG_THREAD_SAFETY || NULL == ctx->bg_thread_handle) {
        return;
    }

    ctx->bg_running = 0;
    pn_context_wake_bg_thread(ctx);

    if (NULL != ctx->platform->thread_is_current
        && 0 != ctx->platform->thread_is_current(ctx->platform, ctx->bg_thread_handle)) {
        /* Called from the background thread itself: joining would
         * deadlock (or silently no-op via EDEADLK). Leave the handle in
         * place - the loop exits once it observes bg_running == 0. */
        PUBNUB_LOG_TEXT(ctx->logger,
                        PUBNUB_LOG_LEVEL_WARNING,
                        "pubnub teardown invoked from its own background "
                        "thread; skipping self-join");
        return;
    }

    ctx->platform->thread_join(ctx->platform, ctx->allocator, ctx->bg_thread_handle);
    ctx->bg_thread_handle = NULL;
}

#if !PUBNUB_CFG_NO_HEAP
pubnub_context_t* pubnub_create(const pubnub_config_t* config)
{
    if (!config || PUBNUB_OK != pn_config_validate(config)) {
        return NULL;
    }

    /* Resolve allocator before context exists (bootstrap). */
    pubnub_allocator_provider_t* alloc = config->allocator;
    if (!alloc) {
        alloc = pn_allocator_default();
    }
    if (!alloc || !alloc->alloc) {
        return NULL;
    }

    pubnub_context_t* ctx = (pubnub_context_t*)PN_ALLOC(
        alloc, sizeof(pubnub_context_t), sizeof(void*));
    if (!ctx) {
        return NULL;
    }
    memset(ctx, 0, sizeof(*ctx));

    pubnub_config_t init_config = *config;
    init_config.allocator       = alloc;

    const pubnub_res_t rc = pn_context_init_common(ctx, &init_config);
    if (PUBNUB_OK != rc) {
        PN_FREE(alloc, ctx);
        return NULL;
    }

    /* Deep-copy config strings so caller can free originals. */
    {
        pubnub_allocator_provider_t* a = ctx->allocator;

        char* sub        = pn_strdup(config->subscribe_key, a);
        char* pub        = pn_strdup(config->publish_key, a);
        char* sec        = pn_strdup(config->secret_key, a);
        char* uid        = pn_strdup(config->user_id, a);
        char* auth       = pn_strdup(config->auth_token, a);
        char* suffix     = pn_strdup(config->pnsdk_suffix, a);
        char* override   = pn_strdup(config->pnsdk_override, a);
        char* proxy_host = pn_strdup(config->proxy.host, a);
        char* proxy_user = pn_strdup(config->proxy.username, a);
        char* proxy_pass = pn_strdup(config->proxy.password, a);
        char* dns_p      = pn_strdup(config->dns_primary, a);
        char* dns_s      = pn_strdup(config->dns_secondary, a);
        char* filter     = pn_strdup(config->filter_expression, a);

        if (!sub || !uid || (config->publish_key && !pub)
            || (config->secret_key && !sec) || (config->auth_token && !auth)
            || (config->pnsdk_suffix && !suffix)
            || (config->pnsdk_override && !override)
            || (config->proxy.host && !proxy_host)
            || (config->proxy.username && !proxy_user)
            || (config->proxy.password && !proxy_pass)
            || (config->dns_primary && !dns_p) || (config->dns_secondary && !dns_s)
            || (config->filter_expression && !filter)) {
            pn_strfree(sub, a);
            pn_strfree(pub, a);
            pn_strfree_secure(sec, a);
            pn_strfree(uid, a);
            pn_strfree_secure(auth, a);
            pn_strfree(suffix, a);
            pn_strfree(override, a);
            pn_strfree(proxy_host, a);
            pn_strfree_secure(proxy_user, a);
            pn_strfree_secure(proxy_pass, a);
            pn_strfree(dns_p, a);
            pn_strfree(dns_s, a);
            pn_strfree(filter, a);
            pubnub_deinit(ctx);
            PN_FREE(a, ctx);
            return NULL;
        }

        ctx->config.subscribe_key     = sub;
        ctx->config.publish_key       = pub;
        ctx->config.secret_key        = sec;
        ctx->config.pnsdk_suffix      = suffix;
        ctx->config.pnsdk_override    = override;
        ctx->config.proxy.host        = proxy_host;
        ctx->config.proxy.username    = proxy_user;
        ctx->config.proxy.password    = proxy_pass;
        ctx->config.filter_expression = filter;
        ctx->user_id                  = uid;
        ctx->auth_token               = auth;
        ctx->dns_primary              = dns_p;
        ctx->dns_secondary            = dns_s;
        ctx->owns_config              = 1;
    }

    /* Sync deps and transport to deep-copied DNS strings.
     * transport->init received borrowed pointers (from the pre-copy
     * shadow); curl transport stores that raw pointer for use on every
     * subsequent send(). Refreshing here lets the caller safely free
     * the original strings immediately after pubnub_create returns. */
    ctx->deps.dns_primary   = ctx->dns_primary;
    ctx->deps.dns_secondary = ctx->dns_secondary;
    if (NULL != ctx->transport && NULL != ctx->transport->set_dns_servers
        && (NULL != ctx->dns_primary || NULL != ctx->dns_secondary)) {
        ctx->transport->set_dns_servers(
            ctx->transport, ctx->dns_primary, ctx->dns_secondary);
    }

    const pubnub_res_t pipe_rc = pn_context_build_pipeline(ctx);
    if (PUBNUB_OK != pipe_rc) {
        pubnub_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void pubnub_destroy(pubnub_context_t* ctx)
{
    pubnub_allocator_provider_t* alloc;
    int                          owned;
    const char*                  user_id       = NULL;
    const char*                  auth_token    = NULL;
    const char*                  dns_primary   = NULL;
    const char*                  dns_secondary = NULL;

    if (!ctx) {
        return;
    }
    alloc = ctx->allocator;
    owned = ctx->owns_config;

    /* Join the bg thread first: it must stop before teardown fires
     * completion callbacks, otherwise a concurrent poll could race the
     * single-threaded teardown below. pubnub_deinit drains queued EE
     * events (e.g. a presence leave enqueued after the last tick). */
    pn_context_join_bg_thread(ctx);

    if (owned) {
        /* pubnub_deinit NULLs (but does not free) these fields at the
         * end of its teardown, so capture them before the deinit call
         * to free them afterwards. The config.* strings are left intact
         * by deinit and are freed directly below. */
        user_id       = ctx->user_id;
        auth_token    = ctx->auth_token;
        dns_primary   = ctx->dns_primary;
        dns_secondary = ctx->dns_secondary;

        /* Clear the ownership flag so pubnub_deinit runs its teardown
         * (it refuses owned contexts). Config strings stay live so the
         * completion callbacks deinit fires can still read them. */
        ctx->owns_config = 0;
    }

    /* Deinit fires completion callbacks that read config strings, so it
     * must run before those strings are freed. The allocator remains
     * usable after deinit (the same guarantee that lets PN_FREE(alloc,
     * ctx) run below). */
    pubnub_deinit(ctx);

    if (owned) {
        pn_strfree(ctx->config.subscribe_key, alloc);
        pn_strfree(ctx->config.publish_key, alloc);
        pn_strfree_secure(ctx->config.secret_key, alloc);
        pn_strfree(ctx->config.pnsdk_suffix, alloc);
        pn_strfree(ctx->config.pnsdk_override, alloc);
        pn_strfree(ctx->config.proxy.host, alloc);
        pn_strfree_secure(ctx->config.proxy.username, alloc);
        pn_strfree_secure(ctx->config.proxy.password, alloc);
        pn_strfree(ctx->config.filter_expression, alloc);
        pn_strfree(user_id, alloc);
        pn_strfree_secure(auth_token, alloc);
        pn_strfree(dns_primary, alloc);
        pn_strfree(dns_secondary, alloc);
    }

    PN_FREE(alloc, ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

pubnub_res_t pubnub_init(pubnub_context_t* ctx, const pubnub_config_t* config)
{
    if (!ctx || !config) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_res_t rc = pn_context_init_common(ctx, config);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_context_build_pipeline(ctx);
    if (PUBNUB_OK != rc) {
        /* Pipeline build failed after pn_context_init_common()
         * succeeded. The initialized sentinel was set, so
         * pubnub_deinit() performs the complete reverse-order teardown:
         * pending queue, slot map, pool, providers, lock, and allocator
         * internal state. */
        pubnub_deinit(ctx);
        return rc;
    }

    return PUBNUB_OK;
}

void pn_request_abort(pubnub_context_t* ctx,
                      uint16_t          slot_id,
                      uint16_t          expected_generation,
                      pubnub_res_t      reason,
                      int               suppress_callback)
{
    pn_request_t*              slot;
    pubnub_transport_handle_t* handle = NULL;
    pn_request_cb_t            cb     = NULL;
    void*                      ud     = NULL;

    if (NULL == ctx || slot_id >= ctx->pool.capacity) {
        return;
    }

    /* Phase 1: snapshot and clear under lock. */
    pn_ctx_lock(ctx->platform, ctx->lock);
    slot = &ctx->pool.slots[slot_id];
    if (PN_REQUEST_PENDING != slot->state && PN_REQUEST_IN_FLIGHT != slot->state) {
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return;
    }

    /* ABA guard: a caller that captured this slot ID earlier may find
     * that a concurrent thread already cancelled, released, and
     * re-dispatched the physical slot. Aborting on a generation
     * mismatch would hit an unrelated request with a stale reason. */
    if (PN_GENERATION_ANY != expected_generation
        && slot->generation != expected_generation) {
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return;
    }

    handle                 = slot->transport_handle;
    slot->transport_handle = NULL;

    if (!suppress_callback) {
        cb = slot->on_complete;
        ud = slot->user_data;
    }
    slot->on_complete = NULL;
    slot->user_data   = NULL;

    /* Mark HTTP response so result accessors see the error. */
    slot->http_response.completion      = PUBNUB_HTTP_ERROR;
    slot->http_response.transport_error = reason;

    /* Transition to COMPLETING (not straight to a terminal state) so a
     * concurrent pubnub_future_release defers the release instead of
     * recycling the slot. This keeps slot->http_request scratch stable
     * for the post-unlock reads below (log emit + callback). */
    slot->result = reason;
    slot->state  = PN_REQUEST_COMPLETING;

    /* Release-store the publication gate LAST (still under lock): the
     * lock-free reader in pn_request_is_ready acquire-loads it before
     * reading result / http_response error fields, so this abort/cancel
     * result is safely visible on SMP targets. */
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    /* Observability: cancellation is routine (deinit cancels every
     * slot) and logs at DEBUG; timeout/transport aborts are genuine
     * failures and log at ERROR so they stay visible in ERROR-only
     * builds. Emit outside the lock - logging is a provider call. */
#if PUBNUB_LOG_ENABLED(DEBUG)
    if (PUBNUB_ERR_CANCELLED == reason) {
        pn_request_log_net_terminal(
            slot, ctx->logger, 1, 0, reason, PUBNUB_LOG_LEVEL_DEBUG, __FILE__, __LINE__);
    }
#endif
#if PUBNUB_LOG_ENABLED(ERROR)
    if (PUBNUB_ERR_CANCELLED != reason) {
        pn_request_log_net_terminal(
            slot, ctx->logger, 0, 1, reason, PUBNUB_LOG_LEVEL_ERROR, __FILE__, __LINE__);
    }
#endif

    /* Phase 2: cancel transport handle outside lock (may block on TLS
     * teardown, socket close, or allocator buf_release). */
    if (NULL != handle && NULL != ctx->pipeline.chain_head
        && NULL != ctx->pipeline.chain_head->cancel) {
        ctx->pipeline.chain_head->cancel(ctx->pipeline.chain_head, handle);
    }

    /* Phase 3: fire snapshotted callback outside lock. */
    if (NULL != cb) {
        cb(slot, reason, ud);
    }

    /* Phase 4: finalize COMPLETING -> CANCELLED under lock and honor a
     * release that a concurrent thread deferred while the slot was held
     * in COMPLETING. Mirrors the deferred-release finalize in
     * pn_process_tick. Only finalize when still COMPLETING - a callback
     * for a multi-step operation may have re-purposed the slot
     * (reset to PENDING and re-dispatched), in which case leave it be. */
    pn_ctx_lock(ctx->platform, ctx->lock);
    if (PN_REQUEST_COMPLETING == slot->state) {
        slot->state = PN_REQUEST_CANCELLED;
        if (slot->release_deferred) {
            slot->release_deferred = 0;
            pn_request_pool_release(&ctx->pool, slot_id);
        }
    }
    pn_ctx_unlock(ctx->platform, ctx->lock);
}

void pubnub_deinit(pubnub_context_t* ctx)
{
    uint16_t i;
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return;
    }
    assert(!ctx->owns_config && "use pubnub_destroy() for owned contexts");
    if (ctx->owns_config) {
        return;
    }

    PUBNUB_LOG_TEXT(ctx->logger, PUBNUB_LOG_LEVEL_INFO, "PubNub context releasing");

    pn_context_join_bg_thread(ctx);

    /* Drain queued EE events (e.g. presence leave) so they dispatch
     * before feature cleanup frees the managers. Covers both the
     * bg-thread path (events queued after the last tick) and the
     * cooperative path (events queued without a subsequent pump). */
    (void)pn_process_tick(ctx, 0);

    /* Cancel all active slots and fire their callbacks before feature
     * registry cleanup - user async callbacks or internal on_complete
     * handlers may access context-level feature state (e.g., subscribe
     * session) that registry cleanup would free. The bg thread is
     * already joined, so no concurrent poll is running. */
    for (i = 0; i < ctx->pool.capacity; i++) {
        pn_request_abort(ctx, i, PN_GENERATION_ANY, PUBNUB_ERR_CANCELLED, 0);
    }

    /* A successfully-completed future that was never released still holds a
     * live transport handle (kept alive so response->body stayed valid).
     * pn_request_abort above skips terminal slots, so cancel those handles
     * here - while the pipeline chain head is still alive - to free the
     * transport rx buffers. The bg thread is joined, so this runs
     * single-threaded and needs no lock. */
    for (i = 0; i < ctx->pool.capacity; i++) {
        pn_request_t* slot = pn_request_pool_get(&ctx->pool, i);
        if (NULL != slot && NULL != slot->transport_handle) {
            pubnub_transport_handle_t* handle = slot->transport_handle;
            slot->transport_handle            = NULL;
            if (NULL != ctx->pipeline.chain_head
                && NULL != ctx->pipeline.chain_head->cancel) {
                ctx->pipeline.chain_head->cancel(ctx->pipeline.chain_head, handle);
            }
        }
    }

    pn_feature_registry_cleanup_all(&ctx->features, ctx->allocator);

    pn_pipeline_deinit(&ctx->pipeline);

    /* Drain the pending queue, honoring the "async_cb fires exactly
     * once" contract even during teardown. Callbacks receive
     * PUBNUB_ERR_CANCELLED so user code can release resources. */
    while (pn_pending_queue_count(&ctx->pending_queue) > 0) {
        pn_pending_entry_t* head_entry =
            &ctx->pending_queue.entries[ctx->pending_queue.head];
        if (!head_entry->occupied) {
            /* Entry was already cancelled (e.g. pubnub_future_release
             * on a pending-range future). cancel_at zeroed the entry
             * and already decremented count. Advance head only. */
            ctx->pending_queue.head = (uint16_t)((ctx->pending_queue.head + 1)
                                                 % ctx->pending_queue.capacity);
            continue;
        }
        pn_pending_cancel_data_t cancel_data = {0};
        uint16_t                 map_idx     = head_entry->map_index;
        cancel_data.async_cb_future.ctx      = ctx;
        cancel_data.async_cb_future.slot_id =
            (uint16_t)(ctx->pool.capacity + map_idx);
        cancel_data.async_cb_future.status = PUBNUB_IN_PROGRESS;
        (void)pn_pending_queue_cancel_at(&ctx->pending_queue, 0, &cancel_data);
        /* cancel_at zeroed the entry and decremented count but did
         * NOT advance head (by design — mid-queue cancel must not
         * perturb head). Advance head for sequential drain. */
        ctx->pending_queue.head = (uint16_t)((ctx->pending_queue.head + 1)
                                             % ctx->pending_queue.capacity);
        pn_pending_cancel_data_run(&cancel_data);
    }
    pn_pending_queue_deinit(&ctx->pending_queue);

    /* Free the prep pool entries. */
    if (NULL != ctx->prep_entries) {
        PN_FREE(ctx->allocator, ctx->prep_entries);
        ctx->prep_entries = NULL;
    }
    memset(ctx->prep_used, 0, sizeof(ctx->prep_used));

    /* Free the pending-slot map. */
    if (NULL != ctx->pending_slot_map) {
        PN_FREE(ctx->allocator, ctx->pending_slot_map);
        ctx->pending_slot_map = NULL;
    }
    pn_request_pool_deinit(&ctx->pool);

    /* Destroy and free the per-context lock before provider deinit —
     * lock_destroy and allocator->free must precede allocator->deinit. */
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != ctx->lock) {
        ctx->platform->lock_destroy(ctx->platform, ctx->lock);
        PN_FREE(ctx->allocator, ctx->lock);
        ctx->lock = NULL;
    }

    pn_context_providers_deinit(ctx);

    ctx->user_id       = NULL;
    ctx->auth_token    = NULL;
    ctx->dns_primary   = NULL;
    ctx->dns_secondary = NULL;
    ctx->initialized   = 0;
}

size_t pubnub_context_size(void)
{
    return sizeof(pubnub_context_t);
}

int pubnub_has_feature(const pubnub_context_t* ctx, pubnub_feature_t feature)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return 0;
    }
    return pn_feature_registry_has(&ctx->features, feature);
}

const pubnub_config_t* pn_context_config(const pubnub_context_t* ctx)
{
    return NULL != ctx ? &ctx->config : NULL;
}

pn_pipeline_t* pn_context_pipeline(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return &ctx->pipeline;
}

pubnub_transport_provider_t* pn_context_pipeline_chain_head(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->pipeline.chain_head;
}

pn_request_pool_t* pn_context_request_pool(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return &ctx->pool;
}

pn_request_t* pn_ready_slot_for_future(pubnub_future_t future)
{
    if (NULL == future.ctx) {
        return NULL;
    }

    /* Resolve pending-range futures via the map. */
    const uint16_t capacity = pn_context_pool_capacity(future.ctx);
    uint16_t       real_slot_id;

    if (0 != capacity && future.slot_id >= capacity) {
        const uint16_t  pending_idx = (uint16_t)(future.slot_id - capacity);
        const uint16_t* map         = pn_context_pending_slot_map(future.ctx);
        if (NULL == map) {
            return NULL;
        }
        real_slot_id = map[pending_idx];
        if (PUBNUB_SLOT_ID_INVALID == real_slot_id) {
            return NULL;
        }
    } else {
        real_slot_id = future.slot_id;
    }

    pn_request_pool_t* pool = pn_context_request_pool(future.ctx);
    if (NULL == pool) {
        return NULL;
    }
    pn_request_t* slot = pn_request_pool_get(pool, real_slot_id);
    if (NULL == slot) {
        return NULL;
    }
    /* Stale-future guard for direct-slot futures only.
     * Pending-range futures always carry generation=0 and use
     * map-entry invalidation (PUBNUB_SLOT_ID_INVALID) for ABA
     * protection instead of the generation counter. */
    if (0 == capacity || future.slot_id < capacity) {
        if (future.generation != slot->generation) {
            return NULL;
        }
    }
    if (!pn_request_is_ready(slot)) {
        return NULL;
    }
    return slot;
}

void* pn_context_feature_state(const pubnub_context_t* ctx, pubnub_feature_t feature)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return pn_feature_registry_state(&ctx->features, feature);
}

void pn_context_set_feature_state(pubnub_context_t*       ctx,
                                  pubnub_feature_t        feature,
                                  void*                   state,
                                  pn_feature_cleanup_fn_t cleanup)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return;
    }
    /* Re-register overwrites state and cleanup on an existing slot. */
    pn_feature_register(&ctx->features, feature, state, cleanup);
}

void pn_context_set_feature_tick(pubnub_context_t*    ctx,
                                 pubnub_feature_t     feature,
                                 pn_feature_tick_fn_t tick)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return;
    }
    pn_feature_registry_set_tick(&ctx->features, feature, tick);
}

pubnub_lock_t* pn_context_mutex_mem(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->lock;
}

pubnub_allocator_provider_t* pn_context_allocator(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->allocator;
}

pubnub_platform_provider_t* pn_context_platform(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->platform;
}

pubnub_res_t pubnub_logger_add(pubnub_context_t* ctx, pubnub_logger_provider_t* logger)
{
    pubnub_res_t rc;

    if (NULL == ctx || NULL == logger || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);
    rc = pn_logger_manager_add(&ctx->logger_manager, logger);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    return rc;
}

pubnub_res_t pubnub_logger_remove(pubnub_context_t*         ctx,
                                  pubnub_logger_provider_t* logger)
{
    pubnub_res_t rc;

    if (NULL == ctx || NULL == logger || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);
    rc = pn_logger_manager_remove(&ctx->logger_manager, logger);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    return rc;
}

void pubnub_logger_remove_all(pubnub_context_t* ctx)
{
    int i;

    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);
    for (i = 0; i < PUBNUB_CFG_MAX_LOGGERS; i++) {
        ctx->logger_manager.children[i] = NULL;
    }
    /* Release-store the count so the lock-free fan-out reader observes the
     * cleared children before the zeroed count. */
    PUBNUB_ATOMIC_STORE_U8(&ctx->logger_manager.count, 0);
    pn_ctx_unlock(ctx->platform, ctx->lock);
}

pubnub_log_level_t pubnub_logger_log_level(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_LOG_LEVEL_NONE;
    }
    return (pubnub_log_level_t)ctx->log_level;
}

void pubnub_log_text(pubnub_context_t* ctx, pubnub_log_level_t level, const char* message)
{
    if (!PUBNUB_CFG_LOG_LEVEL_COMPILED) {
        return;
    }
    if (NULL == message) {
        return;
    }
    PUBNUB_LOG_TEXT(pn_context_logger(ctx), level, message);
}

void pubnub_log_object(pubnub_context_t*         ctx,
                       pubnub_log_level_t        level,
                       const char*               label,
                       const pubnub_log_value_t* value)
{
    if (!PUBNUB_CFG_LOG_LEVEL_COMPILED) {
        return;
    }
    PUBNUB_LOG_OBJECT(pn_context_logger(ctx), level, label, value);
}

void pubnub_log_error(pubnub_context_t*         ctx,
                      int                       error_code,
                      const char*               message,
                      const pubnub_log_value_t* details)
{
    if (!PUBNUB_CFG_LOG_LEVEL_COMPILED) {
        return;
    }
    PUBNUB_LOG_ERR(
        pn_context_logger(ctx), PUBNUB_LOG_LEVEL_ERROR, error_code, message, details);
}

#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
void pubnub_log_text_formatted(pubnub_context_t*  ctx,
                               pubnub_log_level_t level,
                               const char*        fmt,
                               ...)
{
    char    buf[PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE];
    va_list args;

    if (!PUBNUB_CFG_LOG_LEVEL_COMPILED || NULL == pn_context_logger(ctx)
        || NULL == fmt) {
        return;
    }
    va_start(args, fmt);
    pn_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    buf[sizeof(buf) - 1] = '\0';
    PUBNUB_LOG_TEXT(pn_context_logger(ctx), level, buf);
}
#endif /* PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0 */

pubnub_serialization_provider_t* pn_context_serialization(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->serialization;
}

pubnub_crypto_module_t* pn_context_crypto_module(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->crypto_module;
}

pubnub_transport_provider_t* pn_context_transport(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->transport;
}

pubnub_logger_provider_t* pn_context_logger(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->logger;
}

pubnub_log_level_t pn_context_log_level(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_LOG_LEVEL_NONE;
    }
    return (pubnub_log_level_t)ctx->log_level;
}

pubnub_serialization_provider_t* pubnub_serialization(pubnub_context_t* ctx)
{
    return pn_context_serialization(ctx);
}

pn_pending_queue_t* pn_context_pending_queue(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return &ctx->pending_queue;
}

uint16_t* pn_context_pending_slot_map(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->pending_slot_map;
}

uint16_t pn_context_pool_capacity(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return 0;
    }
    return ctx->pool.capacity;
}

pn_pending_entry_t* pn_prep_acquire(pubnub_context_t* ctx)
{
    uint16_t i;

    if (NULL == ctx || NULL == ctx->prep_entries) {
        return NULL;
    }

    pn_request_pool_lock(&ctx->pool);
    for (i = 0; i < (uint16_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        if (!ctx->prep_used[i]) {
            ctx->prep_used[i] = 1;
            pn_request_pool_unlock(&ctx->pool);
            memset(&ctx->prep_entries[i], 0, sizeof(pn_pending_entry_t));
            return &ctx->prep_entries[i];
        }
    }
    pn_request_pool_unlock(&ctx->pool);
    return NULL;
}

void pn_prep_release(pubnub_context_t* ctx, pn_pending_entry_t* entry)
{
    ptrdiff_t offset;

    if (NULL == ctx || NULL == entry || NULL == ctx->prep_entries) {
        return;
    }

    offset = entry - ctx->prep_entries;
    if (offset < 0 || offset >= (ptrdiff_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS) {
        return;
    }
    /* Lock-free release: byte write is naturally atomic on all
     * supported architectures. The pool lock's barrier in
     * pn_prep_acquire ensures this store is visible to the next
     * locked scan. Worst case: scanner sees stale 'in use' and
     * skips the slot until the next acquire cycle. */
    ctx->prep_used[(uint16_t)offset] = 0;
}

void pn_feature_prep_release(pubnub_context_t* ctx, pn_feature_prep_t* prep)
{
    if (NULL == prep) {
        return;
    }

    if (NULL != prep->entry && NULL != prep->entry->feature_state_cleanup
        && NULL != prep->entry->feature_state) {
        pubnub_allocator_provider_t* alloc =
            (NULL != ctx) ? pn_context_allocator(ctx) : NULL;
        prep->entry->feature_state_cleanup(prep->entry->feature_state, alloc);
        prep->entry->feature_state = NULL;
    }

    if (NULL != ctx) {
        pn_prep_release(ctx, prep->entry);
    }
    prep->entry = NULL;
    prep->state = NULL;
}

pubnub_res_t pn_feature_prepare(pubnub_context_t* ctx,
                                uint8_t           feature_id,
                                size_t            state_size,
                                void (*cleanup)(void*, pubnub_allocator_provider_t*),
                                pubnub_res_t (*validator)(const uint8_t*, size_t, int),
                                pubnub_http_method_t method,
                                uint32_t             timeout_ms,
                                pn_feature_prep_t*   prep)
{
    pubnub_res_t rc;

    *prep = (pn_feature_prep_t){0};
    rc    = pn_validate_ctx(ctx, &prep->cfg);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    prep->allocator = pn_context_allocator(ctx);
    if (NULL == prep->allocator) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    /* Acquire a prep-pool entry so the feature builds the HTTP
     * request on the heap instead of the stack (~33 KB saved). */
    prep->entry = pn_prep_acquire(ctx);
    if (NULL == prep->entry) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    prep->state = PN_ALLOC(prep->allocator, state_size, 0);
    if (NULL == prep->state) {
        pn_prep_release(ctx, prep->entry);
        prep->entry = NULL;
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memset(prep->state, 0, state_size);

    rc = pn_pending_entry_init(
        prep->entry, feature_id, prep->state, cleanup, validator, method, prep->cfg, timeout_ms);
    if (PUBNUB_OK != rc) {
        cleanup(prep->state, prep->allocator);
        pn_prep_release(ctx, prep->entry);
        prep->entry = NULL;
        prep->state = NULL;
        return rc;
    }

    return PUBNUB_OK;
}

/**
 * @brief Populate a slot from a pending entry. Caller holds pool lock.
 *
 * Does NOT copy async_cb/async_cb_user_data - for direct dispatch,
 * these are set later via pubnub_async() on the returned future.
 * The promote path (pn_process_promote_pending) copies them because
 * pubnub_async() may run on pending-range futures before promotion.
 */
static void pn_slot_populate(pn_request_t* slot, const pn_pending_entry_t* entry)
{
    slot->http_request = entry->http_request;
    pn_http_request_relocate_scratch_ptrs(&slot->http_request, &entry->http_request);
    slot->feature_id            = entry->feature_id;
    slot->feature_state         = entry->feature_state;
    slot->feature_state_cleanup = entry->feature_state_cleanup;
    slot->response_validator    = entry->response_validator;
    slot->response_capture      = entry->response_capture;
    slot->on_complete           = entry->on_complete;
    slot->user_data             = entry->user_data;

    /* Opt every feature except subscribe into eager body parsing at
     * completion. Subscribe re-parses each long-poll response through its
     * own slab in the EE on_complete path; a second parse here would be
     * wasted CPU/allocation work every cycle. */
    slot->preparse_on_complete =
        ((uint8_t)PUBNUB_FEATURE_SUBSCRIBE != entry->feature_id);
}

/** @brief Log each occupied slot at DEBUG level. Caller holds pool lock. */
static void pn_log_slot_occupancy_locked(pubnub_logger_provider_t* logger,
                                         pn_request_pool_t*        pool)
{
    uint16_t si;

    /* Compiled-out logging turns every PUBNUB_LOG below into ((void)0),
     * leaving the sink unreferenced. */
    (void)logger;

    /* The label building below is O(slots x segments) snprintf work under the
     * pool lock. Bail out before any of it when DEBUG is stripped, so the
     * critical section stays O(1) and no large stack frame is entered. */
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_DEBUG)) {
        (void)pool;
        return;
    }

    for (si = 0; si < pool->capacity; ++si) {
        pn_request_t* s;
        char          label[128] = {0};
        size_t        pos        = 0;
        const char*   method;
        unsigned int  seg;
        int           n;

        s = pn_request_pool_get(pool, si);
        if (NULL == s || pn_request_is_idle(s)) {
            continue;
        }

        switch (s->http_request.method) {
        case PUBNUB_HTTP_GET: method = "GET"; break;
        case PUBNUB_HTTP_POST: method = "POST"; break;
        case PUBNUB_HTTP_PATCH: method = "PATCH"; break;
        case PUBNUB_HTTP_DELETE: method = "DELETE"; break;
        default: method = "?"; break;
        }
        (void)method; /* Used in PUBNUB_LOG below */

        /* Build "scheme://host/seg0/seg1/seg2" (up to 3 path segments). */
        if (NULL != s->http_request.host) {
            n = pn_snprintf(label,
                            sizeof(label),
                            "%s://%s",
                            s->http_request.secure ? "https" : "http",
                            s->http_request.host);
            if (n > 0) {
                pos = (size_t)n;
            }
        }
        for (seg = 0; seg < s->http_request.path_segment_count && seg < 3; ++seg) {
            if (pos >= sizeof(label) - 1) {
                break;
            }
            if (NULL == s->http_request.path_segments[seg].ptr) {
                break;
            }
            n = pn_snprintf(label + pos,
                            sizeof(label) - pos,
                            "/%.*s",
                            (int)s->http_request.path_segments[seg].len,
                            s->http_request.path_segments[seg].ptr);
            if (n > 0) {
                pos += (size_t)n;
            }
        }
        if (s->http_request.path_segment_count > 3 && pos < sizeof(label) - 4) {
            label[pos]     = '/';
            label[pos + 1] = '.';
            label[pos + 2] = '.';
            label[pos + 3] = '.';
        }

        PUBNUB_LOG(logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "  slot %u: feat=%u %s %s",
                   (unsigned)si,
                   (unsigned)s->feature_id,
                   method,
                   label);
    }
}

/** @brief Enqueue entry into the pending queue. Caller holds pool lock. */
static pubnub_future_t pn_enqueue_pending(pubnub_context_t*   ctx,
                                          pn_request_pool_t*  pool,
                                          pn_pending_queue_t* queue,
                                          pn_pending_entry_t* entry)
{
    const uint16_t pending_idx = queue->tail;
    pubnub_res_t   rc;

    PUBNUB_LOG_TEXT(ctx->logger,
                    PUBNUB_LOG_LEVEL_WARNING,
                    "dispatch: no idle in-flight slot — queuing in pending");
    pn_log_slot_occupancy_locked(ctx->logger, pool);

    /* Set map_index directly on the entry — the pending queue's
     * enqueue copies by value (with scratch relocation). */
    entry->map_index = pending_idx;

    rc = pn_pending_queue_enqueue(queue, entry);
    if (PUBNUB_OK != rc) {
        PUBNUB_LOG_TEXT(ctx->logger,
                        PUBNUB_LOG_LEVEL_WARNING,
                        "request dropped: all slots full");
        pn_log_slot_occupancy_locked(ctx->logger, pool);
        pn_request_pool_unlock(pool);

        /* Release owned resources that would have transferred to the
         * queue entry on success. Mirrors pn_pending_cancel_data_run
         * teardown order: feature state first, then async callback.
         * Both fire outside the lock per lock discipline.
         * Must read entry fields BEFORE releasing the prep slot. */
        if (NULL != entry->feature_state_cleanup && NULL != entry->feature_state) {
            entry->feature_state_cleanup(entry->feature_state, pool->allocator);
            entry->feature_state = NULL;
        }
        if (NULL != entry->async_cb) {
            entry->async_cb((pubnub_future_t){.ctx     = NULL,
                                              .slot_id = PUBNUB_SLOT_ID_INVALID,
                                              .status  = rc},
                            rc,
                            entry->async_cb_user_data);
        }

        pn_prep_release(ctx, entry);

        return (pubnub_future_t){
            .ctx = NULL, .slot_id = PUBNUB_SLOT_ID_INVALID, .status = rc};
    }

    /* Queue owns a copy now; release the prep-pool entry. */
    pn_prep_release(ctx, entry);

    PUBNUB_LOG(ctx->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "request queued in pending (%u/%u slots)",
               (unsigned)pn_pending_queue_count(queue),
               (unsigned)queue->capacity);

    ctx->pending_slot_map[pending_idx] = PUBNUB_SLOT_ID_INVALID;

    {
        pubnub_future_t fut;
        fut.ctx        = ctx;
        fut.slot_id    = (uint16_t)(pool->capacity + pending_idx);
        fut.generation = 0;
        fut.status     = PUBNUB_IN_PROGRESS;

        pn_request_pool_unlock(pool);
        pn_context_wake_bg_thread(ctx);
        return fut;
    }
}

/** @brief Dispatch directly via an acquired pool slot. Caller holds lock. */
static pubnub_future_t pn_dispatch_direct(pubnub_context_t*   ctx,
                                          pn_request_pool_t*  pool,
                                          pn_pipeline_t*      pipeline,
                                          pn_pending_entry_t* entry,
                                          pubnub_future_t     fut)
{
    pn_request_t* slot = pn_request_pool_get(pool, fut.slot_id);

    PUBNUB_LOG(ctx->logger,
               PUBNUB_LOG_LEVEL_TRACE,
               "slot %u IDLE->PENDING",
               (unsigned)fut.slot_id);

    pn_slot_populate(slot, entry);

    /* Slot has its own copy now; release the prep-pool entry. */
    pn_prep_release(ctx, entry);

    if (PUBNUB_CFG_THREAD_SAFETY && NULL != ctx->bg_thread_handle) {
        pn_request_pool_unlock(pool);
        pn_context_wake_bg_thread(ctx);
        return fut;
    }

    pubnub_res_t rc =
        pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    if (PUBNUB_OK == rc) {
        PUBNUB_LOG(ctx->logger,
                   PUBNUB_LOG_LEVEL_TRACE,
                   "slot %u PENDING->IN_FLIGHT",
                   (unsigned)fut.slot_id);
    }

    pn_request_pool_unlock(pool);

    if (PUBNUB_OK != rc) {
        PUBNUB_LOG_TEXT(
            ctx->logger,
            PUBNUB_LOG_LEVEL_WARNING,
            "dispatch: transport rejected request — slot marked FAILED");
        (void)rc;
    }

    pn_context_wake_bg_thread(ctx);
    return fut;
}

pubnub_future_t pn_dispatch_or_enqueue(pubnub_context_t*   ctx,
                                       pn_pending_entry_t* entry)
{
    if (NULL == ctx || NULL == entry) {
        return (pubnub_future_t){.ctx     = NULL,
                                 .slot_id = PUBNUB_SLOT_ID_INVALID,
                                 .status  = PUBNUB_ERR_INVALID_ARGUMENT};
    }

    pn_request_pool_t*  pool     = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue    = pn_context_pending_queue(ctx);
    pn_pipeline_t*      pipeline = pn_context_pipeline(ctx);

    if (NULL == pool || NULL == queue || NULL == pipeline) {
        return (pubnub_future_t){.ctx     = NULL,
                                 .slot_id = PUBNUB_SLOT_ID_INVALID,
                                 .status  = PUBNUB_ERR_NOT_INITIALIZED};
    }

    pn_request_pool_lock(pool);

    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);

    if (PUBNUB_OK != rc) {
        return pn_enqueue_pending(ctx, pool, queue, entry);
    }

    return pn_dispatch_direct(ctx, pool, pipeline, entry, fut);
}

/**
 * @brief Promote entries from the pending queue into freed pool slots.
 *
 * @param pool   Request pool (caller holds lock).
 * @param queue  Pending queue (caller holds lock).
 * @param ctx    Context for future binding.
 */
static void pn_process_promote_pending(pn_request_pool_t*  pool,
                                       pn_pending_queue_t* queue,
                                       pubnub_context_t*   ctx)
{
    uint16_t* map = ctx->pending_slot_map;

    while (pn_pending_queue_count(queue) > 0 && pool->in_use_count < pool->capacity) {
        pn_pending_entry_t* pe;
        pubnub_future_t     promoted_fut;
        pubnub_res_t        arc;
        pn_request_t*       slot;

        /* Skip cancelled (non-occupied) entries at the head. */
        while (queue->count > 0 && !queue->entries[queue->head].occupied) {
            queue->head = (uint16_t)((queue->head + 1) % queue->capacity);
            queue->count--;
        }
        if (0 == queue->count) {
            break;
        }

        pe = &queue->entries[queue->head];

        /* Acquire the known-free slot — guaranteed by loop guard. */
        arc = pn_request_pool_acquire(pool, ctx, &promoted_fut);
        if (PUBNUB_OK != arc) {
            PUBNUB_LOG_TEXT(ctx->logger,
                            PUBNUB_LOG_LEVEL_ERROR,
                            "pool acquire failed in promote path: "
                            "internal invariant broken");
            break;
        }

        PUBNUB_LOG(ctx->logger,
                   PUBNUB_LOG_LEVEL_TRACE,
                   "slot %u IDLE->PENDING",
                   (unsigned)promoted_fut.slot_id);

        /* Populate the newly-acquired slot directly from the queue
         * entry — no 33 KB stack local needed. */
        slot               = pn_request_pool_get(pool, promoted_fut.slot_id);
        slot->http_request = pe->http_request;
        pn_http_request_relocate_scratch_ptrs(&slot->http_request,
                                              &pe->http_request);
        slot->feature_id            = pe->feature_id;
        slot->feature_state         = pe->feature_state;
        slot->feature_state_cleanup = pe->feature_state_cleanup;
        slot->response_validator    = pe->response_validator;
        slot->response_capture      = pe->response_capture;
        slot->on_complete           = pe->on_complete;
        slot->user_data             = pe->user_data;
        slot->async_cb              = pe->async_cb;
        slot->async_cb_user_data    = pe->async_cb_user_data;

        /* Promoted requests need the same eager-parse opt-in as directly
         * dispatched ones (see pn_slot_populate): every feature except
         * subscribe parses the body at completion so a later accessor never
         * reads a transport buffer reclaimed on slot reuse. */
        slot->preparse_on_complete =
            ((uint8_t)PUBNUB_FEATURE_SUBSCRIBE != pe->feature_id);

        PUBNUB_LOG(ctx->logger,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "request promoted pending->in-flight slot %u",
                   (unsigned)promoted_fut.slot_id);

        /* Update the pending-slot map so futures that reference the
         * pending-range slot_id can resolve to the real slot. */
        if (NULL != map
            && pe->map_index < (uint16_t)PUBNUB_CFG_MAX_PENDING_REQUESTS) {
            map[pe->map_index] = promoted_fut.slot_id;
        }

        /* Consume the head entry: clear and advance. */
        memset(pe, 0, sizeof(*pe));
        queue->head = (uint16_t)((queue->head + 1) % queue->capacity);
        queue->count--;
    }
}

/** @brief Dispatch every PENDING slot through the middleware chain. */
static void pn_process_dispatch_pending(pn_request_pool_t*          pool,
                                        pn_pipeline_t*              pipeline,
                                        pubnub_platform_provider_t* platform,
                                        pubnub_logger_provider_t*   logger)
{
    uint16_t i;
    (void)logger;
    for (i = 0; i < pool->capacity; i++) {
        pn_request_t* req = &pool->slots[i];
        if (PN_REQUEST_PENDING != req->state) {
            continue;
        }
        const pubnub_res_t rc = pn_request_dispatch(pipeline, req, platform);
        if (PUBNUB_OK == rc) {
            PUBNUB_LOG(logger,
                       PUBNUB_LOG_LEVEL_TRACE,
                       "slot %u PENDING->IN_FLIGHT",
                       (unsigned)i);
        }
    }
}

/** @brief Give the transport a slice of CPU with configurable timeout. */
static void pn_process_poll_transport(pn_pipeline_t* pipeline, unsigned int timeout_ms)
{
    if (NULL != pipeline->chain_head && NULL != pipeline->chain_head->poll) {
        (void)pipeline->chain_head->poll(pipeline->chain_head, timeout_ms);
    }
}

/**
 * @brief Collect slot IDs whose SDK-level deadline has expired.
 *
 * Does not modify slot state - pn_request_abort handles the full
 * cancel-and-transition sequence outside the lock.
 *
 * @param pool     Request pool (caller must hold context lock).
 * @param platform Platform provider for monotonic_ms (borrowed).
 * @param[out] out_ids   Slot IDs to abort (caller array).
 * @param[out] out_gens  Per-slot generation captured with each ID, so
 *                       the later out-of-lock abort can detect ABA reuse.
 * @param[out] out_count Number of IDs written.
 */
static void pn_process_check_deadlines(pn_request_pool_t*          pool,
                                       pubnub_platform_provider_t* platform,
                                       uint16_t*                   out_ids,
                                       uint16_t*                   out_gens,
                                       uint16_t*                   out_count)
{
    uint16_t count = 0;
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        pn_request_t* slot = &pool->slots[i];
        if (PN_REQUEST_IN_FLIGHT != slot->state) {
            continue;
        }
        /* If poll() already completed this slot on the same tick,
         * honor that completion - do not overwrite with a timeout. */
        if (PUBNUB_HTTP_PENDING != slot->http_response.completion) {
            continue;
        }
        if (slot->http_request.deadline_suspended) {
            continue;
        }
        if (!pn_timer_is_active(slot->deadline)) {
            continue;
        }
        if (!pn_timer_is_expired(slot->deadline, platform)) {
            continue;
        }
        out_ids[count]  = i;
        out_gens[count] = slot->generation;
        count++;
    }
    *out_count = count;
}

/**
 * @brief Collect live slots flagged for a cross-thread cancel.
 *
 * Runs on the poll-owning thread after poll(): clears each flag so a
 * request aborts once, captures the generation for ABA detection, and
 * skips slots already terminal or completed on this poll (completion
 * wins over a same-tick cancel).
 *
 * @param pool           Pool to scan (caller holds ctx lock).
 * @param[out] out_ids   Slot IDs to abort.
 * @param[out] out_gens  Generation captured per ID.
 * @param[out] out_count Entries written.
 */
static void pn_process_collect_cancel_requested(pn_request_pool_t* pool,
                                                uint16_t*          out_ids,
                                                uint16_t*          out_gens,
                                                uint16_t*          out_count)
{
    uint16_t count = 0;
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        pn_request_t* slot = &pool->slots[i];
        if (0 == slot->cancel_requested) {
            continue;
        }
        slot->cancel_requested = 0;
        if (PN_REQUEST_PENDING != slot->state
            && PN_REQUEST_IN_FLIGHT != slot->state) {
            continue;
        }
        /* Response arrived on this poll: route_completions finishes it, so
         * completion wins the same-tick cancel. Only IN_FLIGHT can complete. */
        if (PN_REQUEST_IN_FLIGHT == slot->state
            && PUBNUB_HTTP_PENDING != slot->http_response.completion) {
            continue;
        }
        out_ids[count]  = i;
        out_gens[count] = slot->generation;
        count++;
    }
    *out_count = count;
}

/**
 * @brief Collect slot IDs with transport-initiated failures.
 *
 * When the transport FSM drives a request to failure (e.g. TLS
 * handshake timeout, TCP reset), it sets completion to
 * PUBNUB_HTTP_ERROR but leaves transport_handle non-NULL.
 * pn_request_abort handles the full cancel-and-transition outside
 * the lock. The per-slot transport error is captured so abort
 * receives the accurate failure reason.
 *
 * @param pool        Request pool to scan (caller holds ctx lock).
 * @param[out] out_ids     Slot IDs to abort.
 * @param[out] out_gens    Per-slot generation captured with each ID, so
 *                         the later out-of-lock abort can detect ABA reuse.
 * @param[out] out_reasons Per-slot transport error code.
 * @param[out] out_count   Number of entries written.
 */
static void pn_process_collect_transport_failures(pn_request_pool_t* pool,
                                                  uint16_t*          out_ids,
                                                  uint16_t*          out_gens,
                                                  pubnub_res_t* out_reasons,
                                                  uint16_t*     out_count)
{
    uint16_t count = 0;
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        pn_request_t* slot = &pool->slots[i];
        if (PN_REQUEST_IN_FLIGHT != slot->state) {
            continue;
        }
        if (PUBNUB_HTTP_ERROR != slot->http_response.completion) {
            continue;
        }
        if (NULL == slot->transport_handle) {
            continue;
        }
        out_ids[count]     = i;
        out_gens[count]    = slot->generation;
        out_reasons[count] = slot->http_response.transport_error;
        if (PUBNUB_OK == out_reasons[count]) {
            out_reasons[count] = PUBNUB_ERR_TRANSPORT;
        }
        count++;
    }
    *out_count = count;
}

/**
 * @brief Eagerly parse completed response bodies before completions are routed.
 *
 * Runs on the poll-owning thread OUTSIDE the context lock, after transport
 * poll() and before pn_process_route_completions transitions slots to
 * COMPLETING. Parsing here (rather than lazily on the first accessor call)
 * closes a use-after-free for the socket transport's Connection: close path:
 * the response body aliases the connection rx buffer, which the second
 * dispatch pass in this same tick can reclaim before the caller reads any
 * result. The parsed tree copies the body, so it survives buffer reuse.
 * Both success (2xx) and error (4xx/5xx) bodies are parsed — the failure-path
 * service-error classifier reads the parsed tree too.
 *
 * Placing this before the COMPLETING transition (the readiness gate polled
 * lock-free by pubnub_await) guarantees the parse cache is fully populated
 * before any awaiting thread can observe the future as ready — so a
 * concurrent accessor never races this parse (nor the lazy-parse write in
 * pn_request_get_parsed_body). Kept outside the lock so the unbounded
 * parse+allocation never runs inside a critical section.
 *
 * pn_request_get_parsed_body is idempotent (parsed_body_attempted), so the
 * later lazy accessor call becomes a fast-path cache hit.
 *
 * @param pool   Request pool (caller must NOT hold the lock).
 * @param serial Serialization provider used to parse; when NULL the bodies
 *               are marked attempted (yielding a NULL tree) and only
 *               response_capture runs.
 */
static void pn_process_preparse_completions(pn_request_pool_t* pool,
                                            pubnub_serialization_provider_t* serial)
{
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        pn_request_t* slot = &pool->slots[i];
        if (PN_REQUEST_IN_FLIGHT != slot->state || !slot->preparse_on_complete) {
            continue;
        }
        if (PUBNUB_HTTP_COMPLETE != slot->http_response.completion) {
            continue;
        }
        /* Copy raw response bytes directly into fixed feature-owned state
         * (e.g. the time feature's char[21] timetoken buffer) before the
         * rx buffer can be reclaimed. Runs before on_complete to survive
         * pubnub_async, which overwrites on_complete. Not meaningful for
         * error responses, whose data is exposed via the parsed tree below. */
        if (400 > slot->http_response.status_code && NULL != slot->response_capture) {
            slot->response_capture(slot);
        }
        /* Eager parse: tree is stable before the readiness gate fires,
         * so concurrent result accessors never race the lazy-parse write. */
        (void)pn_request_get_parsed_body(slot, serial);
    }
}

/**
 * @brief Route transport completions into slot state transitions.
 *
 * Routing for PUBNUB_HTTP_COMPLETE:
 * 1. Feature validator (if present) runs first — catches
 *    body-level failures (e.g. publish [0,...]) and returns a
 *    feature-specific error code.
 * 2. HTTP status check: status_code >= 400 routes to
 *    PUBNUB_ERR_SERVER. Finer granularity (429, specific 4xx/5xx)
 *    is available via @c pubnub_response_status_code().
 * 3. Otherwise: PUBNUB_OK (successful completion).
 *
 * Transport errors use @c http_response.transport_error when set
 * (e.g. PUBNUB_ERR_TIMEOUT), falling back to PUBNUB_ERR_TRANSPORT.
 */
static void pn_process_route_completions(pn_request_pool_t* pool)
{
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        pn_request_t* slot = &pool->slots[i];
        if (PN_REQUEST_IN_FLIGHT != slot->state) {
            continue;
        }
        switch (slot->http_response.completion) {
        case PUBNUB_HTTP_COMPLETE:
            /* Run the feature-owned validator probe when present.
             * Allows features to reject logically-failed responses
             * (e.g. publish [0,...]) that arrive with HTTP 2xx. */
            if (NULL != slot->response_validator) {
                const pubnub_res_t vrc =
                    slot->response_validator(slot->http_response.body,
                                             slot->http_response.body_len,
                                             slot->http_response.status_code);
                if (PUBNUB_OK != vrc) {
                    PN_REQUEST_ON_FAILURE(slot, vrc);
                    break;
                }
            }
            /* HTTP 4xx/5xx that the validator did not catch.
             * status_code 0 (no HTTP response) routes to success
             * as a fail-open; the transport contract guarantees a
             * valid code when completion == COMPLETE. */
            if (400 <= slot->http_response.status_code) {
                PN_REQUEST_ON_FAILURE(slot, PUBNUB_ERR_SERVER);
                break;
            }
            pn_request_on_success(slot, PUBNUB_OK);
            break;
        case PUBNUB_HTTP_ERROR: {
            pubnub_res_t err = slot->http_response.transport_error;
            if (PUBNUB_OK == err) {
                err = PUBNUB_ERR_TRANSPORT;
            }
            PN_REQUEST_ON_FAILURE(slot, err);
            break;
        }
        case PUBNUB_HTTP_PENDING:
        default:
            /* Still waiting on the transport. */
            break;
        }
    }
}

/** @brief Collect all COMPLETING slot indices into a stack array. */
static uint16_t pn_process_collect_completing(const pn_request_pool_t* pool,
                                              uint16_t*                out_ids)
{
    uint16_t count = 0;
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        if (PN_REQUEST_COMPLETING == pool->slots[i].state) {
            out_ids[count] = i;
            count++;
        }
    }
    return count;
}

/** @brief Report whether any slot is still non-terminal. */
static int pn_process_pool_has_active_slots(const pn_request_pool_t* pool)
{
    uint16_t i;
    for (i = 0; i < pool->capacity; i++) {
        const pn_request_t* slot = &pool->slots[i];
        if (PN_REQUEST_PENDING == slot->state
            || PN_REQUEST_IN_FLIGHT == slot->state) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Deliver completion notifications for the collected COMPLETING slots.
 *
 * Runs outside the context lock: each notification invokes the user callback.
 *
 * @param ctx              Initialized context (non-NULL).
 * @param completing       Indices of slots in the COMPLETING state.
 * @param completing_count Number of valid entries in @p completing.
 */
static void pn_process_tick_deliver_notifications(pubnub_context_t* ctx,
                                                  const uint16_t*   completing,
                                                  uint16_t completing_count)
{
    uint16_t i;
    for (i = 0; i < completing_count; i++) {
        pn_request_t* slot = pn_request_pool_get(&ctx->pool, completing[i]);
        if (NULL != slot) {
            pn_request_deliver_notification(slot);
        }
    }
}

/**
 * @brief Collect slots whose future release was deferred into the tick.
 *
 * Handles both COMPLETING slots (release requested from inside the callback)
 * and terminal slots that bypassed COMPLETING (on_complete == NULL path).
 * For each drained slot the live transport handle is snapshotted and cleared
 * so the caller can cancel it OUTSIDE the lock (the transport cancel frees
 * the rx buffer that response->body aliased and may call the allocator or
 * fire callbacks). The slot is NOT released here — the caller releases it
 * after cancelling the snapshotted handle.
 *
 * @param ctx              Initialized context (non-NULL).
 * @param completing       Indices of slots in the COMPLETING state.
 * @param completing_count Number of valid entries in @p completing.
 * @param out_ids          Caller array (>= pool capacity) receiving the slot
 *                         ids to release.
 * @param out_handles      Caller array (>= pool capacity) receiving the
 *                         snapshotted transport handle for each id (may be
 *                         NULL per entry when the slot held no handle).
 * @return Number of drained slots written to @p out_ids / @p out_handles.
 * @note caller must hold ctx lock
 */
static uint16_t pn_process_tick_collect_deferred(pubnub_context_t* ctx,
                                                 const uint16_t*   completing,
                                                 uint16_t  completing_count,
                                                 uint16_t* out_ids,
                                                 pubnub_transport_handle_t** out_handles)
{
    uint16_t count = 0;
    uint16_t i;
    for (i = 0; i < completing_count; i++) {
        pn_request_t* slot = pn_request_pool_get(&ctx->pool, completing[i]);
        if (NULL != slot && slot->release_deferred) {
            PUBNUB_LOG(ctx->logger,
                       PUBNUB_LOG_LEVEL_TRACE,
                       "slot %u deferred-release fired",
                       (unsigned)completing[i]);
            slot->release_deferred = 0;
            out_ids[count]         = completing[i];
            out_handles[count]     = slot->transport_handle;
            slot->transport_handle = NULL;
            count++;
        }
    }

    /* Also collect any COMPLETE/FAILED slots whose release was deferred
     * but that bypassed COMPLETING (on_complete==NULL path). */
    for (i = 0; i < ctx->pool.capacity; i++) {
        pn_request_t* slot = pn_request_pool_get(&ctx->pool, i);
        if (NULL != slot && pn_request_is_terminal(slot) && slot->release_deferred) {
            PUBNUB_LOG_TEXT(ctx->logger,
                            PUBNUB_LOG_LEVEL_TRACE,
                            "deferred release (terminal, no callback)");
            slot->release_deferred = 0;
            out_ids[count]         = i;
            out_handles[count]     = slot->transport_handle;
            slot->transport_handle = NULL;
            count++;
        }
    }
    return count;
}

/**
 * @brief Internal process tick: run one iteration of the event loop.
 *
 * Performs promotion, dispatch, poll, deadline enforcement, completion
 * routing, callback delivery, deferred release, re-promotion, and a
 * second dispatch pass to drain the newly-freed slots in the same tick.
 *
 * @param ctx            Initialized context (non-NULL, already validated).
 * @param poll_timeout_ms Maximum time to block in transport->poll().
 *                         0 = non-blocking (cooperative mode).
 * @return PUBNUB_IN_PROGRESS if active work remains, PUBNUB_OK otherwise.
 */
pubnub_res_t pn_process_tick(pubnub_context_t* ctx, unsigned int poll_timeout_ms)
{
    PUBNUB_STATIC_ASSERT(
        PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS <= 16,
        "Stack array for completing slots assumes <= 16 in-flight");

    uint16_t     completing[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     completing_count = 0;
    uint16_t     expired_ids[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     expired_gens[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     expired_count = 0;
    uint16_t     failed_ids[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     failed_gens[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_res_t failed_reasons[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     failed_count = 0;
    uint16_t     cancel_ids[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     cancel_gens[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t     cancel_count = 0;
    uint16_t     release_ids[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_transport_handle_t* release_handles[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    uint16_t release_count = 0;
    uint16_t i;
    int      active;
    int      pending_active;
    int      features_active;

    pn_ctx_lock(ctx->platform, ctx->lock);

    /* Bail if another thread is already inside transport->poll(). */
    if (PUBNUB_CFG_THREAD_SAFETY && ctx->poll_active) {
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return PUBNUB_IN_PROGRESS;
    }

    /* Promote queued entries into freed slots before dispatching.
     * Dispatch under lock is safe: send() only enqueues the request
     * (no blocking I/O); actual network I/O happens in poll() which
     * runs outside the lock below. */
    pn_process_promote_pending(&ctx->pool, &ctx->pending_queue, ctx);
    pn_process_dispatch_pending(
        &ctx->pool, &ctx->pipeline, ctx->platform, ctx->logger);

    if (PUBNUB_CFG_THREAD_SAFETY) {
        ctx->poll_active = 1;
    }
    pn_ctx_unlock(ctx->platform, ctx->lock);

    pn_process_poll_transport(&ctx->pipeline, poll_timeout_ms);

    pn_ctx_lock(ctx->platform, ctx->lock);
    if (PUBNUB_CFG_THREAD_SAFETY) {
        ctx->poll_active = 0;
    }
    pn_process_check_deadlines(
        &ctx->pool, ctx->platform, expired_ids, expired_gens, &expired_count);
    pn_process_collect_cancel_requested(
        &ctx->pool, cancel_ids, cancel_gens, &cancel_count);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    /* Abort expired slots outside the lock. pn_request_abort handles
     * transport cancel, state transition, and callback delivery. The
     * captured generation guards against a slot being recycled between
     * collection and abort on threaded targets. */
    for (i = 0; i < expired_count; i++) {
        pn_request_abort(ctx, expired_ids[i], expired_gens[i], PUBNUB_ERR_TIMEOUT, 0);
    }

    /* Service cancels on the poll-owning thread, after poll(), so the
     * transport teardown never races the non-thread-safe poll. A slot also
     * hit by the timeout loop above no-ops in pn_request_abort. */
    for (i = 0; i < cancel_count; i++) {
        pn_request_abort(ctx, cancel_ids[i], cancel_gens[i], PUBNUB_ERR_CANCELLED, 0);
    }

    /* Transport-initiated failures: abort slots that the transport
     * FSM drove to PUBNUB_HTTP_ERROR (e.g. TLS handshake timeout,
     * TCP reset) but the deadline step did not already cancel. */
    pn_ctx_lock(ctx->platform, ctx->lock);
    pn_process_collect_transport_failures(
        &ctx->pool, failed_ids, failed_gens, failed_reasons, &failed_count);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    for (i = 0; i < failed_count; i++) {
        pn_request_abort(ctx, failed_ids[i], failed_gens[i], failed_reasons[i], 0);
    }

    /* Eager-parse completed bodies OUTSIDE the lock, before the routing
     * step below publishes the COMPLETING readiness gate. This keeps the
     * unbounded parse out of the critical section and out of the race with
     * a lock-free pubnub_await reader, and copies the body out of the
     * transport rx buffer before the second dispatch pass can reclaim it. */
    pn_process_preparse_completions(&ctx->pool, pn_context_serialization(ctx));

    pn_ctx_lock(ctx->platform, ctx->lock);
    pn_process_route_completions(&ctx->pool);
    completing_count = pn_process_collect_completing(&ctx->pool, completing);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    pn_process_tick_deliver_notifications(ctx, completing, completing_count);

    /* Deferred releases happen for slots where the user called
     * pubnub_future_release() from inside the callback (or terminal slots
     * with no callback). Snapshot + clear their live transport handles under
     * the lock without releasing the slots yet. */
    pn_ctx_lock(ctx->platform, ctx->lock);
    release_count = pn_process_tick_collect_deferred(
        ctx, completing, completing_count, release_ids, release_handles);
    pn_ctx_unlock(ctx->platform, ctx->lock);

    /* Cancel the snapshotted handles OUTSIDE the lock. A successfully
     * completed request keeps its handle live so response->body (which
     * aliases the transport rx buffer) stays valid until release; cancel
     * frees that buffer and may call the allocator or fire callbacks, so it
     * must not run under the lock. */
    for (i = 0; i < release_count; i++) {
        if (NULL != release_handles[i] && NULL != ctx->pipeline.chain_head
            && NULL != ctx->pipeline.chain_head->cancel) {
            ctx->pipeline.chain_head->cancel(ctx->pipeline.chain_head,
                                             release_handles[i]);
        }
    }

    pn_ctx_lock(ctx->platform, ctx->lock);
    for (i = 0; i < release_count; i++) {
        pn_request_pool_release(&ctx->pool, release_ids[i]);
    }

    /* Promote pending queue entries into freed slots. Must happen
     * after deferred releases to maximize available slots. */
    pn_process_promote_pending(&ctx->pool, &ctx->pending_queue, ctx);
    /* Dispatch promoted slots immediately so they enter IN_FLIGHT on
     * this tick rather than waiting for the next. Mirrors the first
     * promote/dispatch pair above. */
    pn_process_dispatch_pending(
        &ctx->pool, &ctx->pipeline, ctx->platform, ctx->logger);

    active         = pn_process_pool_has_active_slots(&ctx->pool);
    pending_active = pn_pending_queue_count(&ctx->pending_queue) > 0;
    pn_ctx_unlock(ctx->platform, ctx->lock);

    /* Feature tick callbacks: give each registered feature a CPU
     * slice outside the lock. Subscribe and presence hook in here to
     * drain event queues, fire timers, and dispatch effects without
     * core knowing feature internals. */
    features_active = pn_feature_registry_tick_all(&ctx->features);

    return (active || pending_active || features_active) ? PUBNUB_IN_PROGRESS
                                                         : PUBNUB_OK;
}

/** @brief Background thread entry point. */
static void pn_bg_thread_fn(void* arg)
{
    pubnub_context_t*           ctx      = (pubnub_context_t*)arg;
    pubnub_platform_provider_t* platform = ctx->platform;

    while (ctx->bg_running) {
        pubnub_res_t rc = pn_process_tick(ctx, PUBNUB_CFG_MAX_POLL_MS);
        if (PUBNUB_IN_PROGRESS == rc && NULL != platform
            && NULL != platform->sleep_ms) {
            platform->sleep_ms(platform, 5);
        }
    }
}

/**
 * @brief Lazily start the background processing thread.
 *
 * @param ctx Initialized context.
 * @return PUBNUB_OK on success (or already running), error code on failure.
 */
static pubnub_res_t pn_bg_thread_start(pubnub_context_t* ctx)
{
    if (!PUBNUB_CFG_THREAD_SAFETY) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }

    if (NULL == ctx->platform || NULL == ctx->platform->thread_create
        || NULL == ctx->platform->thread_join) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);

    if (NULL != ctx->bg_thread_handle) {
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return PUBNUB_OK;
    }

    ctx->bg_running = 1;
    void* handle    = ctx->platform->thread_create(
        ctx->platform, ctx->allocator, pn_bg_thread_fn, ctx);
    if (NULL == handle) {
        ctx->bg_running = 0;
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return PUBNUB_ERR_INTERNAL;
    }

    ctx->bg_thread_handle = handle;
    pn_ctx_unlock(ctx->platform, ctx->lock);
    return PUBNUB_OK;
}

void pn_context_wake_bg_thread(pubnub_context_t* ctx)
{
    if (NULL == ctx) {
        return;
    }
    if (!PUBNUB_CFG_THREAD_SAFETY || NULL == ctx->bg_thread_handle) {
        return;
    }

    if (NULL != ctx->transport && NULL != ctx->transport->wake) {
        ctx->transport->wake(ctx->transport);
    }
    /* No wake() on transport: bg thread discovers new work at next
       PUBNUB_CFG_MAX_POLL_MS timeout boundary. */
}

void pn_context_wake(pubnub_context_t* ctx)
{
    if (NULL == ctx || !PUBNUB_CFG_THREAD_SAFETY) {
        return;
    }
    /* transport->wake() is thread-safe; fine to call during a concurrent poll. */
    if (NULL != ctx->transport && NULL != ctx->transport->wake) {
        ctx->transport->wake(ctx->transport);
    }
}

pubnub_res_t pubnub_process(pubnub_context_t* ctx)
{
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    /* When a background thread is active, it drives processing.
     * The public pubnub_process() becomes a no-op to prevent double
     * processing and lock contention. */
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != ctx->bg_thread_handle) {
        return PUBNUB_OK;
    }

    return pn_process_tick(ctx, 0);
}

pubnub_res_t pn_context_start_bg_thread(pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    return pn_bg_thread_start(ctx);
}

int pn_context_has_bg_thread(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return 0;
    }
    return PUBNUB_CFG_THREAD_SAFETY && NULL != ctx->bg_thread_handle;
}

pubnub_res_t pubnub_set_auth_token(pubnub_context_t* ctx, const char* token)
{
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);

    if (ctx->owns_config) {
        char* dup = pn_strdup(token, ctx->allocator);
        if (token && !dup) {
            pn_ctx_unlock(ctx->platform, ctx->lock);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        pn_strfree_secure(ctx->auth_token, ctx->allocator);
        ctx->auth_token = dup;
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return PUBNUB_OK;
    }

    ctx->auth_token = token;
    pn_ctx_unlock(ctx->platform, ctx->lock);
    return PUBNUB_OK;
}

pubnub_res_t pubnub_set_user_id(pubnub_context_t* ctx, const char* user_id)
{
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (!user_id || '\0' == user_id[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);

    if (ctx->owns_config) {
        char* dup = pn_strdup(user_id, ctx->allocator);
        if (!dup) {
            pn_ctx_unlock(ctx->platform, ctx->lock);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        pn_strfree(ctx->user_id, ctx->allocator);
        ctx->user_id = dup;
        pn_ctx_unlock(ctx->platform, ctx->lock);
        return PUBNUB_OK;
    }

    ctx->user_id = user_id;
    pn_ctx_unlock(ctx->platform, ctx->lock);
    return PUBNUB_OK;
}

pubnub_res_t pubnub_set_origin(pubnub_context_t* ctx, const char* origin)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (NULL == origin || '\0' == origin[0]) {
        origin = PUBNUB_CFG_ORIGIN;
    }
    if (strlen(origin) >= sizeof(ctx->origin_buf)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (pn_str_has_header_unsafe_byte(origin)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    pn_ctx_lock(ctx->platform, ctx->lock);
    pn_strlcpy(ctx->origin_buf, origin, sizeof(ctx->origin_buf));
    pn_ctx_unlock(ctx->platform, ctx->lock);
    return PUBNUB_OK;
}

const char* pubnub_get_origin(const pubnub_context_t* ctx)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->config.origin;
}

pubnub_res_t pubnub_set_dns_servers(pubnub_context_t* ctx,
                                    const char*       primary,
                                    const char*       secondary)
{
    const char* cur_p;
    const char* cur_s;

    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);

    if (ctx->owns_config) {
        char* dup_p = pn_strdup(primary, ctx->allocator);
        char* dup_s = pn_strdup(secondary, ctx->allocator);
        if ((NULL != primary && NULL == dup_p)
            || (NULL != secondary && NULL == dup_s)) {
            pn_strfree(dup_p, ctx->allocator);
            pn_strfree(dup_s, ctx->allocator);
            pn_ctx_unlock(ctx->platform, ctx->lock);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        pn_strfree(ctx->dns_primary, ctx->allocator);
        pn_strfree(ctx->dns_secondary, ctx->allocator);
        ctx->dns_primary   = dup_p;
        ctx->dns_secondary = dup_s;
    } else {
        ctx->dns_primary   = primary;
        ctx->dns_secondary = secondary;
    }

    cur_p = ctx->dns_primary;
    cur_s = ctx->dns_secondary;
    pn_ctx_unlock(ctx->platform, ctx->lock);

    /* Delegate to transport outside the lock. */
    if (NULL != ctx->transport && NULL != ctx->transport->set_dns_servers) {
        return ctx->transport->set_dns_servers(ctx->transport, cur_p, cur_s);
    }

    return PUBNUB_OK;
}

pubnub_res_t pubnub_set_tls_ca_bundle(pubnub_context_t* ctx, const char* ca_pem)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (NULL == ctx->transport || NULL == ctx->transport->set_tls_ca_bundle) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    ctx->transport->set_tls_ca_bundle(ctx->transport, ca_pem);
    return PUBNUB_OK;
}

pubnub_res_t pubnub_set_tls_skip_verify(pubnub_context_t* ctx, uint8_t skip_verify)
{
    if (NULL == ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (NULL == ctx->transport || NULL == ctx->transport->set_tls_verify) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }
    if (0 != skip_verify) {
        PUBNUB_LOG_TEXT(ctx->logger,
                        PUBNUB_LOG_LEVEL_WARNING,
                        "TLS certificate verification disabled - do not "
                        "use in production");
    }
    ctx->transport->set_tls_verify(ctx->transport, skip_verify);
    return PUBNUB_OK;
}

const char* pn_context_user_id(const pubnub_context_t* ctx)
{
    return (NULL != ctx) ? ctx->user_id : NULL;
}

const char* pn_context_origin(const pubnub_context_t* ctx)
{
    return (NULL != ctx) ? ctx->config.origin : NULL;
}

const char* pubnub_get_user_id(const pubnub_context_t* ctx)
{
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->user_id;
}

const char* pubnub_get_auth_token(const pubnub_context_t* ctx)
{
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return NULL;
    }
    return ctx->auth_token;
}

void* pn_resolve_cached_parse(pn_request_t*          slot,
                              pubnub_future_t        future,
                              void**                 cache_slot,
                              size_t                 parsed_size,
                              int                    zero_init,
                              pn_parse_response_fn_t parse_fn,
                              pubnub_json_value_t**  out_tree)
{
    pubnub_serialization_provider_t* serial;
    pubnub_json_value_t*             tree;
    pubnub_allocator_provider_t*     allocator;
    void*                            cached;
    pubnub_res_t                     rc;

    if (NULL == cache_slot) {
        return NULL;
    }
    if (NULL != *cache_slot) {
        return *cache_slot;
    }

    serial = pn_context_serialization(future.ctx);
    tree   = pn_request_get_parsed_body(slot, serial);
    if (NULL == tree) {
        return NULL;
    }

    allocator = pn_context_allocator(future.ctx);
    if (NULL == allocator) {
        return NULL;
    }

    cached = PN_ALLOC(allocator, parsed_size, 0);
    if (NULL == cached) {
        return NULL;
    }

    if (zero_init) {
        memset(cached, 0, parsed_size);
    }

    rc = parse_fn(serial, tree, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    if (NULL != out_tree) {
        *out_tree = tree;
    }
    *cache_slot = cached;
    return cached;
}

pubnub_res_t pubnub_set_log_level(pubnub_context_t* ctx, unsigned int level)
{
    if (!ctx || PN_INIT_MAGIC != ctx->initialized) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    pn_ctx_lock(ctx->platform, ctx->lock);
    ctx->log_level = level;
    if (ctx->logger && ctx->logger->set_level) {
        ctx->logger->set_level(ctx->logger, level);
    }
    pn_ctx_unlock(ctx->platform, ctx->lock);
    return PUBNUB_OK;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CORE_INTERNAL_H
#define PN_CORE_INTERNAL_H

#include "pn_crypto_module.h"
#include "pn_feature_registry.h"
#include "pubnub/capabilities.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/providers/serialization.h"
#include "runtime/middleware/middleware_internal.h"
#include "runtime/pending_queue_internal.h"
#include "runtime/pipeline_internal.h"
#include "runtime/request_pool_internal.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Validate required fields in a configuration struct.
 *
 * @param config Configuration to validate (borrowed, may be NULL).
 * @return `PUBNUB_OK` when all required fields are present and valid;
 *         argument-class error when a required field is missing or invalid.
 */
pubnub_res_t pn_config_validate(const pubnub_config_t* config);

/**
 * @brief Return the context's read-only configuration snapshot.
 *
 * @param ctx Context to query (borrowed).
 * @return Configuration pointer (borrowed), or NULL if ctx is NULL.
 */
const pubnub_config_t* pn_context_config(const pubnub_context_t* ctx);

/**
 * @brief Return the context's current user ID.
 *
 * Features MUST use this instead of reading cfg->user_id directly —
 * the config field is NULLed after init (user_id is runtime-mutable
 * via pubnub_set_user_id and stored separately).
 *
 * @param ctx Context to query (borrowed).
 * @return User ID string (borrowed), or NULL if ctx is NULL.
 */
const char* pn_context_user_id(const pubnub_context_t* ctx);

/**
 * @brief Return the current origin hostname.
 *
 * @param ctx Context to query (borrowed).
 * @return Current origin string (points to context-internal buffer),
 *         or NULL if ctx is NULL.
 */
const char* pn_context_origin(const pubnub_context_t* ctx);

/**
 * @brief Return the context's middleware pipeline.
 *
 * @param ctx Context to query (borrowed).
 * @return Pipeline pointer (borrowed), or NULL if ctx is NULL.
 */
pn_pipeline_t* pn_context_pipeline(pubnub_context_t* ctx);

/**
 * @brief Return the pipeline's outermost transport chain head.
 *
 * The chain head is the entry point for send/poll/cancel on a request's
 * transport handle. Exposed separately from pn_context_pipeline so callers
 * that only need to cancel a handle (e.g. pubnub_future_release) do not
 * reach into the pipeline struct layout.
 *
 * @param ctx Context to query (borrowed).
 * @return Chain-head transport provider (borrowed), or NULL if ctx is NULL,
 *         uninitialized, or the pipeline has no chain head.
 */
pubnub_transport_provider_t* pn_context_pipeline_chain_head(pubnub_context_t* ctx);

/**
 * @brief Return the context's request slot pool.
 *
 * @param ctx Context to query (borrowed).
 * @return Request pool pointer (borrowed), or NULL if ctx is NULL.
 */
pn_request_pool_t* pn_context_request_pool(pubnub_context_t* ctx);

/**
 * @brief Retrieve per-feature opaque state for a registered feature.
 *
 * @param ctx     Context to query (borrowed).
 * @param feature Feature identifier to look up.
 * @return Feature state pointer (borrowed), or NULL if unregistered.
 */
void* pn_context_feature_state(const pubnub_context_t* ctx,
                               pubnub_feature_t        feature);

/**
 * @brief Set per-feature state on a registered feature slot.
 *
 * Called by features that lazily allocate their state on first use
 * rather than at context init time. The feature must already be
 * registered (via pn_feature_register at init) — this overwrites
 * the state and cleanup fields.
 *
 * @param ctx     Context (non-NULL, initialized).
 * @param feature Feature identifier (must be registered).
 * @param state   Per-context state (may be NULL to clear).
 * @param cleanup Release callback (may be NULL).
 */
void pn_context_set_feature_state(pubnub_context_t*       ctx,
                                  pubnub_feature_t        feature,
                                  void*                   state,
                                  pn_feature_cleanup_fn_t cleanup);

/**
 * @brief Register a per-process-tick callback for a feature.
 *
 * Called by features that need periodic processing (e.g., subscribe's
 * event engine). The tick callback is invoked from pubnub_process()
 * OUTSIDE the context lock and should return non-zero when the
 * feature has active work remaining.
 *
 * @param ctx     Context (non-NULL, initialized).
 * @param feature Feature identifier (must be registered).
 * @param tick    Tick callback, or NULL to clear.
 */
void pn_context_set_feature_tick(pubnub_context_t*    ctx,
                                 pubnub_feature_t     feature,
                                 pn_feature_tick_fn_t tick);

/**
 * @brief Return the context's per-context lock, or NULL.
 *
 * Returns the opaque lock that was allocated during context init
 * when PUBNUB_CFG_THREAD_SAFETY is enabled and the platform
 * provider supplies lock support. Returns NULL otherwise.
 *
 * @param ctx Context to query (borrowed).
 * @return Lock pointer (borrowed), or NULL.
 */
pubnub_lock_t* pn_context_mutex_mem(const pubnub_context_t* ctx);

/**
 * @brief Return the context's resolved platform provider, or NULL.
 *
 * @param ctx Context to query (borrowed).
 * @return Platform provider pointer (borrowed), or NULL.
 */
pubnub_platform_provider_t* pn_context_platform(const pubnub_context_t* ctx);

/**
 * @brief Retrieve the logger provider for a context.
 *
 * @param ctx Context to query. May be NULL.
 * @return Logger provider, or NULL when ctx is NULL or no logger is set.
 */
pubnub_logger_provider_t* pn_context_logger(const pubnub_context_t* ctx);

/**
 * @brief Return the context's current runtime log level threshold.
 *
 * @param ctx Context to query (borrowed, may be NULL).
 * @return Current threshold, or PUBNUB_LOG_LEVEL_NONE when ctx is NULL
 *         or not initialized.
 */
pubnub_log_level_t pn_context_log_level(const pubnub_context_t* ctx);

/**
 * @brief Check whether an entry at @p level would pass the runtime
 *        threshold and reach the logger provider.
 *
 * Use as a guard before building log map structures to avoid wasted
 * stack work when the runtime level would filter the entry.
 *
 * @param ctx   Initialized context (borrowed, may be NULL).
 * @param level Log level of the entry being considered.
 * @return Non-zero if the entry would be emitted, 0 if it would be
 *         dropped.
 */
static inline int pn_log_would_emit(const pubnub_context_t* ctx,
                                    pubnub_log_level_t      level)
{
    pubnub_log_level_t min;
    if (NULL == ctx || NULL == pn_context_logger(ctx)) {
        return 0;
    }
    min = pn_context_log_level(ctx);
    if (PUBNUB_LOG_LEVEL_NONE == min) {
        return 0;
    }
    if (PUBNUB_LOG_LEVEL_ALL == min) {
        return 1;
    }
    return (unsigned int)level >= (unsigned int)min;
}

/** @brief Printf-style log at TRACE level using a context pointer. */
#define PN_LOG_TRACE(ctx, ...) \
    PUBNUB_LOG(pn_context_logger(ctx), PUBNUB_LOG_LEVEL_TRACE, __VA_ARGS__)

/** @brief Printf-style log at DEBUG level using a context pointer. */
#define PN_LOG_DEBUG(ctx, ...) \
    PUBNUB_LOG(pn_context_logger(ctx), PUBNUB_LOG_LEVEL_DEBUG, __VA_ARGS__)

/** @brief Printf-style log at INFO level using a context pointer. */
#define PN_LOG_INFO(ctx, ...) \
    PUBNUB_LOG(pn_context_logger(ctx), PUBNUB_LOG_LEVEL_INFO, __VA_ARGS__)

/** @brief Printf-style log at WARNING level using a context pointer. */
#define PN_LOG_WARN(ctx, ...) \
    PUBNUB_LOG(pn_context_logger(ctx), PUBNUB_LOG_LEVEL_WARNING, __VA_ARGS__)

/** @brief Printf-style log at ERROR level using a context pointer. */
#define PN_LOG_ERR(ctx, ...) \
    PUBNUB_LOG(pn_context_logger(ctx), PUBNUB_LOG_LEVEL_ERROR, __VA_ARGS__)

/** @brief Structured object log entry using a context pointer. */
#define PN_LOG_OBJECT(ctx, lvl, lbl, vdata) \
    PUBNUB_LOG_OBJECT(pn_context_logger(ctx), lvl, lbl, vdata)

/** @brief Error entry log using a context pointer. */
#define PN_LOG_ERROR_ENTRY(ctx, code, msg, details) \
    PUBNUB_LOG_ERR(pn_context_logger(ctx), PUBNUB_LOG_LEVEL_ERROR, code, msg, details)

/**
 * @brief Return the context's resolved allocator provider, or NULL.
 *
 * @param ctx Context to query (@b borrowed).
 * @return Allocator provider (@b borrowed), or NULL if ctx is NULL or
 *         not initialized.
 */
pubnub_allocator_provider_t* pn_context_allocator(const pubnub_context_t* ctx);

/**
 * @brief Return the context's resolved serialization provider, or NULL.
 *
 * @param ctx Context to query (borrowed).
 * @return Serialization provider (borrowed), or NULL.
 */
pubnub_serialization_provider_t* pn_context_serialization(const pubnub_context_t* ctx);

/**
 * @brief Return the context's crypto module, or NULL.
 *
 * Returns the user-configured crypto module for payload
 * encryption/decryption. NULL when no module is set.
 *
 * @param ctx Context to query (borrowed).
 * @return Crypto module pointer (borrowed), or NULL.
 */
pubnub_crypto_module_t* pn_context_crypto_module(const pubnub_context_t* ctx);

/**
 * @brief Return the raw transport provider (no middleware wrapping).
 *
 * Use for direct-to-transport dispatch that must bypass the middleware
 * pipeline (e.g., S3 file upload where PubNub auth headers are invalid).
 *
 * @param ctx Context to query (borrowed).
 * @return Transport provider (borrowed), or NULL if ctx is NULL.
 */
pubnub_transport_provider_t* pn_context_transport(const pubnub_context_t* ctx);

/**
 * @brief Return the context's pending queue, or NULL.
 *
 * @param ctx Context to query (borrowed).
 * @return Pending queue pointer (borrowed), or NULL if ctx is NULL.
 */
pn_pending_queue_t* pn_context_pending_queue(pubnub_context_t* ctx);

/**
 * @brief Return the context's pending-slot map, or NULL.
 *
 * The map has PUBNUB_CFG_MAX_PENDING_REQUESTS entries. Each entry
 * holds either PUBNUB_SLOT_ID_INVALID (not yet promoted) or the
 * real slot_id that the pending entry was promoted into.
 *
 * @param ctx Context to query (borrowed).
 * @return Map array pointer (borrowed), or NULL if ctx is NULL.
 */
uint16_t* pn_context_pending_slot_map(pubnub_context_t* ctx);

/**
 * @brief Return the pool capacity for pending-range checks.
 *
 * Pending-range futures have slot_id >= pool capacity. This accessor
 * provides the threshold for the is_ready / status / release paths.
 * Pool capacity is PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS.
 *
 * @param ctx Context to query (borrowed).
 * @return Pool capacity, or 0 if ctx is NULL.
 */
uint16_t pn_context_pool_capacity(const pubnub_context_t* ctx);

/**
 * @brief Result struct for pn_feature_prepare().
 *
 * Bundles the validated configuration, resolved allocator, allocated
 * feature state, and a pointer to a pre-acquired prep-pool entry
 * produced by the common public-API preamble. Callers cast @c state
 * to the concrete feature state type and use @c entry / @c allocator
 * / @c cfg for the remainder of the request-building sequence.
 *
 * The entry pointer references a context-owned prep-pool slot whose
 * buffers (scratch, path_segments, query_params, headers) belong
 * exclusively to this request until dispatch or release. Each active
 * request has its own independent buffers; concurrent requests never
 * share memory.
 */
typedef struct pn_feature_prep {
    /** Context configuration snapshot (borrowed). */
    const pubnub_config_t* cfg;

    /** Resolved allocator provider (borrowed). */
    pubnub_allocator_provider_t* allocator;

    /** Allocated and zero-initialized feature state (owned). */
    void* state;

    /** Pointer to a pre-acquired prep-pool entry (context-owned).
     *  Features build path/query/headers into entry->http_request.
     *  Released automatically by pn_dispatch_or_enqueue() on success,
     *  or manually via pn_feature_prep_release() on error paths. */
    pn_pending_entry_t* entry;
} pn_feature_prep_t;

/* pn_feature_prep_t is now pointer-sized (4 pointers). The 33 KB
 * scratch buffer lives in the prep-pool entry (heap), not on the
 * stack. No embedded-stack-budget guard needed. */
PUBNUB_STATIC_ASSERT(sizeof(pn_feature_prep_t) <= 64U,
                     "pn_feature_prep_t grew beyond 4 pointers");

/**
 * @brief Common preamble for public feature API entry points.
 *
 * Validates the context, resolves the allocator, acquires a prep-pool
 * entry (pre-allocated per-request buffers), allocates and
 * zero-initializes feature state of @p state_size bytes, and
 * initializes the pending entry. On failure the error is logged
 * internally and all acquired resources are released.
 *
 * @param ctx        Client context (may be NULL - validates internally).
 * @param feature_id Feature capability identifier.
 * @param state_size Byte count to allocate for feature state.
 * @param cleanup    Cleanup callback for the allocated state.
 * @param validator  Response body validator (may be NULL).
 * @param method     HTTP method for this request.
 * @param timeout_ms Per-request timeout override; 0 = context default.
 * @param[out] prep  Populated on success. prep->entry points to the
 *                   acquired prep-pool entry.
 * @return PUBNUB_OK on success. On failure the caller should return
 *         pn_failed_future(rc).
 */
pubnub_res_t pn_feature_prepare(pubnub_context_t* ctx,
                                uint8_t           feature_id,
                                size_t            state_size,
                                void (*cleanup)(void*, pubnub_allocator_provider_t*),
                                pubnub_res_t (*validator)(const uint8_t*, size_t, int),
                                pubnub_http_method_t method,
                                uint32_t             timeout_ms,
                                pn_feature_prep_t*   prep);

/**
 * @brief Release a prep-pool entry and clean up feature state on error.
 *
 * Call this when a feature function fails BETWEEN pn_feature_prepare()
 * (which acquires the prep entry) and pn_dispatch_or_enqueue() (which
 * consumes it). Releases the prep-pool slot back to the context and
 * invokes the feature-state cleanup callback.
 *
 * Safe to call when prep->entry is NULL (no-op).
 *
 * @param ctx  Context that owns the prep pool (non-NULL).
 * @param prep Prep struct to release. entry is set to NULL on return.
 */
void pn_feature_prep_release(pubnub_context_t* ctx, pn_feature_prep_t* prep);

/**
 * @brief Acquire a prep-pool entry for building an HTTP request.
 *
 * Returns a pointer to a pre-allocated pn_pending_entry_t from the
 * context's prep pool. The entry is zero-initialized and its buffers
 * (scratch, path_segments, etc.) belong exclusively to the caller
 * until released via pn_prep_release().
 *
 * Used by features that bypass pn_feature_prepare() and build entries
 * directly (subscribe, presence heartbeat, file upload stages).
 *
 * @param ctx Context (non-NULL, initialized).
 * @return Entry pointer, or NULL when all prep slots are in use.
 */
pn_pending_entry_t* pn_prep_acquire(pubnub_context_t* ctx);

/**
 * @brief Release a prep-pool entry back to the context.
 *
 * Marks the slot as free so it can be reused by subsequent requests.
 * The entry data is NOT zeroed on release (zeroed on next acquire).
 * Safe to call with a pointer that is NOT from the prep pool (no-op).
 *
 * @param ctx   Context that owns the prep pool (non-NULL).
 * @param entry Entry to release (may be NULL or non-prep; both no-op).
 */
void pn_prep_release(pubnub_context_t* ctx, pn_pending_entry_t* entry);

/**
 * @brief Signature for feature-specific response parsers used by
 *        pn_resolve_cached_parse.
 *
 * @param serial  Serialization provider (for tree queries).
 * @param tree    Parsed JSON tree from the response body.
 * @param out     Pointer to the feature-specific parsed struct
 *                (caller-allocated, may or may not be zero-filled
 *                depending on the feature).
 * @return PUBNUB_OK on success, or an error code on parse failure.
 */
typedef pubnub_res_t (*pn_parse_response_fn_t)(pubnub_serialization_provider_t* serial,
                                               pubnub_json_value_t* tree,
                                               void*                out);

/**
 * @brief Lazy-parse a response body and cache the result.
 *
 * On first call, resolves serialization and allocator providers from
 * the future's context, parses the response tree via @p parse_fn,
 * and stores the result at @p *cache_slot.  Subsequent calls return
 * the cached pointer directly.
 *
 * @param slot        Request slot with the raw HTTP response.
 * @param future      Future handle for provider resolution.
 * @param cache_slot  Pointer to the feature-state's cached-parse
 *                    field (void** - the caller casts from their
 *                    typed field).
 * @param parsed_size sizeof(feature_parsed_t) to allocate.
 * @param zero_init   Non-zero to memset the allocated struct before
 *                    calling parse_fn.
 * @param parse_fn    Feature-specific parse function.
 * @param[out] out_tree  If non-NULL, receives the parsed JSON tree
 *                       pointer (for features that need to store
 *                       the tree on the cached struct).
 * @return Pointer to cached parsed struct, or NULL on failure.
 */
void* pn_resolve_cached_parse(pn_request_t*          slot,
                              pubnub_future_t        future,
                              void**                 cache_slot,
                              size_t                 parsed_size,
                              int                    zero_init,
                              pn_parse_response_fn_t parse_fn,
                              pubnub_json_value_t**  out_tree);

/**
 * @brief Fetch a JSON array element by index using a cached forward
 *        cursor.
 *
 * Amortizes indexed array access on backends whose @c array_get is a
 * linked-list walk (e.g. cJSON), where a consumer loop
 * `for (i = 0; i < count; ++i) accessor(fut, i)` degrades to O(n^2).
 * The cursor caches an iterator and the index it is positioned at, so
 * sequential forward access is O(1) per element.
 *
 * The cursor lives in caller-owned storage (three fields, all
 * zero-initialized on first use). Requesting an index behind the
 * cursor restarts the walk. Falls back to @c array_get when the
 * backend does not expose iteration.
 *
 * @param serial     Serialization provider (borrowed). Required.
 * @param arr        Array node to index into (borrowed). Required.
 * @param index      Zero-based element index.
 * @param iter_cache Caller-owned iterator storage; zero on first use.
 * @param iter_pos   Index the cursor's next step will return; zero on
 *                   first use.
 * @param iter_valid Non-zero when @p iter_cache is usable; zero on
 *                   first use / to force a restart.
 * @return Borrowed element pointer, or @c NULL when the index is out
 *         of range or an input is invalid.
 */
pubnub_json_value_t* pn_json_array_cursor_get(pubnub_serialization_provider_t* serial,
                                              const pubnub_json_value_t* arr,
                                              size_t                     index,
                                              pubnub_json_array_iter_t* iter_cache,
                                              size_t*  iter_pos,
                                              uint8_t* iter_valid);

/**
 * @brief Initialize a pending entry with standard HTTP dispatch fields.
 *
 * Zero-initializes @p entry via compound-literal assignment, then
 * populates all fields required for a feature dispatch: feature
 * identity, state ownership, HTTP method, host (scratch-copied), TLS
 * flag, and resolved timeout.
 *
 * @param entry       Entry to initialize (non-NULL, written from scratch).
 * @param feature_id  Feature capability identifier.
 * @param state       Per-request feature state (ownership transferred).
 * @param cleanup     Cleanup callback for @p state (may be NULL).
 * @param validator   Response body validator (may be NULL).
 * @param method      HTTP method for this request.
 * @param cfg         Context configuration (non-NULL).
 * @param timeout_ms  Per-request timeout override; 0 uses
 *                    cfg->transaction_timeout_ms.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_BUFFER_TOO_SMALL when
 *         the host string does not fit in the scratch buffer.
 */
static inline pubnub_res_t
pn_pending_entry_init(pn_pending_entry_t* entry,
                      uint8_t             feature_id,
                      void*               state,
                      void (*cleanup)(void*, pubnub_allocator_provider_t*),
                      pubnub_res_t (*validator)(const uint8_t*, size_t, int),
                      pubnub_http_method_t   method,
                      const pubnub_config_t* cfg,
                      uint32_t               timeout_ms)
{
    *entry                       = (pn_pending_entry_t){0};
    entry->feature_id            = feature_id;
    entry->feature_state         = state;
    entry->feature_state_cleanup = cleanup;
    entry->response_validator    = validator;
    entry->http_request.method   = method;
    entry->http_request.secure   = PUBNUB_ENABLE_SECURE_TRANSPORT;
    entry->http_request.timeout_ms =
        (0 != timeout_ms) ? timeout_ms : cfg->transaction_timeout_ms;
    return pn_request_set_host(&entry->http_request, cfg->origin);
}

/**
 * @brief Try to acquire a slot and dispatch; enqueue if the pool is full.
 *
 * Features call this instead of manually pool_acquire + dispatch.
 * On success, the request is either dispatched (slot in IN_FLIGHT)
 * or enqueued in the pending queue (future in pending range). The
 * returned future is valid in both cases.
 *
 * The entry data is copied into a pool slot (direct dispatch) or
 * pending queue entry (overflow). After the copy, the entry is
 * released back to the prep pool if it belongs to one.
 *
 * @param ctx   Context (non-NULL, initialized).
 * @param entry Populated pending entry (consumed on success). May be
 *              from the context's prep pool (auto-released) or from
 *              any other storage (caller manages lifetime).
 * @return Future handle (check status for errors).
 */
pubnub_future_t pn_dispatch_or_enqueue(pubnub_context_t*   ctx,
                                       pn_pending_entry_t* entry);

/**
 * @brief Cancel an active request and release its transport resources.
 *
 * Centralizes the lock-safe cancel pattern used at 8 call sites across
 * client.c, future.c, subscribe, and presence. Under the context lock,
 * snapshots and clears the transport handle, then cancels the handle
 * outside the lock (transport cancel may block on TLS teardown).
 * Finally transitions the slot to CANCELLED and fires the on_complete
 * callback (unless suppressed).
 *
 * Safe to call on any slot state. PENDING and IN_FLIGHT are aborted;
 * all other states (IDLE, COMPLETING, terminal) are no-ops.
 *
 * When @p expected_generation is not #PN_GENERATION_ANY, the slot's
 * current generation must match it or the abort is a no-op. This closes
 * the threaded ABA window where a caller captures a slot ID, and a
 * concurrent thread cancels + releases + re-dispatches that physical
 * slot before the abort runs - the generation check prevents aborting
 * the unrelated freshly-dispatched request. Mirrors the generation
 * re-validation done by pubnub_future_cancel().
 *
 * @param ctx                 Context (non-NULL, initialized).
 * @param slot_id             Pool slot index to abort.
 * @param expected_generation Generation the slot must still carry, or
 *                            #PN_GENERATION_ANY to skip the check
 *                            (callers that already validated generation,
 *                            or teardown/manager cleanup that abort
 *                            unconditionally).
 * @param reason              Result code for the cancellation (e.g.
 *                            PUBNUB_ERR_CANCELLED, PUBNUB_ERR_TIMEOUT).
 * @param suppress_callback   Non-zero to discard on_complete before
 *                            firing (used by subscribe/presence managers
 *                            during cleanup to prevent re-entry).
 */
void pn_request_abort(pubnub_context_t* ctx,
                      uint16_t          slot_id,
                      uint16_t          expected_generation,
                      pubnub_res_t      reason,
                      int               suppress_callback);

/**
 * @brief Lazily start the context's background processing thread.
 *
 * No-op when the thread is already running or the platform does not
 * provide thread_create/thread_join. Called by pubnub_async() to
 * enable fire-and-forget async callbacks without user-driven
 * pubnub_process() loops.
 *
 * When PUBNUB_CFG_THREAD_SAFETY is 0, returns PUBNUB_ERR_NOT_SUPPORTED
 * unconditionally (no bg thread fields exist).
 *
 * @param ctx Context (non-NULL, initialized).
 * @return PUBNUB_OK on success or already running;
 *         PUBNUB_ERR_NOT_SUPPORTED when threads unavailable;
 *         PUBNUB_ERR_INTERNAL on thread creation failure.
 */
pubnub_res_t pn_context_start_bg_thread(pubnub_context_t* ctx);

/**
 * @brief Query whether a background thread is currently active.
 *
 * Returns non-zero if a prior pubnub_async() call started the
 * background thread and it has not yet been torn down. Used by
 * pubnub_await to decide between polling and cooperative processing
 * without side effects (no thread start).
 *
 * Always returns 0 when PUBNUB_CFG_THREAD_SAFETY is disabled.
 *
 * @param ctx Context (borrowed, may be NULL).
 * @return Non-zero if a bg thread is running, 0 otherwise.
 */
int pn_context_has_bg_thread(const pubnub_context_t* ctx);

/**
 * @brief Signal the background thread to wake up.
 *
 * Calls transport->wake() when a bg thread is active. No-op when
 * PUBNUB_CFG_THREAD_SAFETY is 0 or no bg thread is running.
 *
 * @param ctx Context (borrowed, may be NULL).
 */
void pn_context_wake_bg_thread(pubnub_context_t* ctx);

/**
 * @brief Wake the transport poll loop from any thread.
 *
 * Lets a non-poll thread (e.g. a concurrent pubnub_future_cancel) break
 * the owning thread out of a blocking poll. No-op when
 * PUBNUB_CFG_THREAD_SAFETY is 0 or the transport exposes no wake().
 *
 * @param ctx Context (borrowed, may be NULL).
 */
void pn_context_wake(pubnub_context_t* ctx);

/**
 * @brief Run one processing tick: poll transport, drain completions,
 *        promote pending entries, and fire feature ticks.
 *
 * The @p poll_timeout_ms parameter controls blocking behavior:
 * - 0 for non-blocking (cooperative pubnub_process style),
 * - PUBNUB_CFG_MAX_POLL_MS for background-thread blocking poll.
 *
 * @param ctx             Context (non-NULL, initialized).
 * @param poll_timeout_ms Maximum milliseconds to block in transport poll.
 * @return PUBNUB_IN_PROGRESS if active work remains, PUBNUB_OK otherwise.
 */
pubnub_res_t pn_process_tick(pubnub_context_t* ctx, unsigned int poll_timeout_ms);

/**
 * @brief Construct an immediate-failure future carrying @p err.
 *
 * @param err Error code to embed in the future.
 * @return Future with NULL context, invalid slot, and the given status.
 */
static inline pubnub_future_t pn_failed_future(const pubnub_res_t err)
{
    pubnub_future_t f = {0};
    f.ctx             = NULL;
    f.slot_id         = PUBNUB_SLOT_ID_INVALID;
    f.status          = err;
    return f;
}

/**
 * @brief Validate the minimum config required for any REST feature call.
 *
 * Checks that @p ctx is non-NULL, subscribe_key is set, and the
 * context user_id is set. All three are required for every PubNub REST
 * endpoint. On success @p out_cfg receives the config pointer.
 *
 * Features that additionally require publish_key or secret_key must
 * check those fields after this call returns PUBNUB_OK.
 *
 * @param ctx     Client context (may be NULL).
 * @param out_cfg Receives the config pointer on PUBNUB_OK (non-NULL).
 * @return PUBNUB_OK on success; PUBNUB_ERR_INVALID_ARGUMENT otherwise.
 */
static inline pubnub_res_t pn_validate_ctx(pubnub_context_t*       ctx,
                                           const pubnub_config_t** out_cfg)
{
    if (NULL == ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    const pubnub_config_t* cfg = pn_context_config(ctx);
    if (NULL == cfg || NULL == cfg->subscribe_key) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == pn_context_user_id(ctx)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out_cfg = cfg;
    return PUBNUB_OK;
}

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_CORE_INTERNAL_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file request_internal.h
 * @brief Internal request descriptor and state machine.
 *
 * Lifecycle:
 *   IDLE -> PENDING -> IN_FLIGHT -> COMPLETING -> COMPLETE / FAILED
 *                                -> CANCELLED
 *
 * COMPLETING exists so callbacks fire outside the context lock.
 * The descriptor is context-agnostic; the context owns an array and
 * drives transitions. Timeout/cancellation are the caller's
 * responsibility - the module performs no I/O and registers no timers.
 */

#ifndef PN_REQUEST_INTERNAL_H
#define PN_REQUEST_INTERNAL_H

#include "pubnub/capabilities.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"
#include "timer_internal.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Lifecycle states for a request slot.
 *
 * Valid transitions:
 * - @c IDLE       -> @c PENDING     (acquired and populated)
 * - @c PENDING    -> @c IN_FLIGHT   (dispatched to transport via send())
 * - @c PENDING    -> @c CANCELLED   (cancelled before dispatch)
 * - @c IN_FLIGHT  -> @c COMPLETING  (result stored, callback pending delivery)
 * - @c IN_FLIGHT  -> @c COMPLETE    (no callback, success)
 * - @c IN_FLIGHT  -> @c FAILED      (no callback, error/timeout)
 * - @c IN_FLIGHT  -> @c CANCELLED   (explicitly cancelled)
 * - @c COMPLETING -> @c COMPLETE    (callback delivered, success)
 * - @c COMPLETING -> @c FAILED      (callback delivered, error)
 * - @c COMPLETE   -> @c IDLE        (slot released)
 * - @c FAILED     -> @c IDLE        (slot released)
 * - @c CANCELLED  -> @c IDLE        (slot released)
 *
 *   @attention All in-progress states MUST precede COMPLETE - terminal-state
 *              detection uses >= @c PN_REQUEST_COMPLETE.
 */
typedef enum pn_request_state {
    /** Slot is unused and available for acquisition. */
    PN_REQUEST_IDLE = 0,

    /** Request is populated and queued, waiting for dispatch. */
    PN_REQUEST_PENDING,

    /** Request has been sent to transport, awaiting response. */
    PN_REQUEST_IN_FLIGHT,

    /** Result is stored and stable; callback has not yet fired. */
    PN_REQUEST_COMPLETING,

    /** Transport reported successful completion. */
    PN_REQUEST_COMPLETE,

    /** Transport error, timeout, or server error. */
    PN_REQUEST_FAILED,

    /** Request was explicitly cancelled. */
    PN_REQUEST_CANCELLED
} pn_request_state_t;

/** Forward declaration - full struct below. */
typedef struct pn_request pn_request_t;

/**
 * @brief Generation sentinel meaning "match any generation".
 *
 * Passed as the expected-generation argument by callers that abort a
 * slot unconditionally (teardown, manager cleanup) or that already
 * validated the generation under lock. pn_request_reset() skips this
 * value when incrementing, so a live slot never carries the sentinel.
 */
#define PN_GENERATION_ANY ((uint16_t)UINT16_MAX)

/**
 * @brief Completion callback invoked when a request reaches a
 *        terminal state (COMPLETE, FAILED, or CANCELLED).
 *
 * @param request   The request that completed (borrowed).
 * @param status    Final SDK-level result code.
 * @param user_data Opaque pointer set when the request was created.
 */
typedef void (*pn_request_cb_t)(pn_request_t* request,
                                pubnub_res_t  status,
                                void*         user_data);

/**
 * @brief Feature-owned hook that captures volatile response data at
 *        completion, while the response body is still valid.
 *
 * Invoked on the poll-owning thread OUTSIDE the context lock, after
 * transport completion and BEFORE the second dispatch pass can reclaim
 * the transport rx buffer. Its job is to copy any response data that
 * aliases that buffer (e.g. a raw numeric substring the parsed JSON tree
 * cannot represent losslessly) into feature-owned storage so later result
 * accessors read a stable copy.
 *
 * Unlike @ref pn_request_cb_t, this hook is never overwritten by
 * @c pubnub_async, so the capture always runs on the async path too.
 *
 * @param slot The completed request slot (borrowed); reads
 *             @c http_response and resolves feature state via
 *             @ref pn_request_feature_state_for.
 */
typedef void (*pn_response_capture_fn_t)(pn_request_t* slot);

/**
 * @brief Internal request descriptor.
 *
 * Holds everything needed to drive a single HTTP round-trip from
 * the SDK core's perspective. Owned by the context's slot pool.
 */
struct pn_request {
    /** Current lifecycle state. */
    pn_request_state_t state;

    /** HTTP request descriptor; populated by features before enqueue. */
    pubnub_http_request_t http_request;

    /** HTTP response descriptor; populated by transport on completion. */
    pubnub_http_response_t http_response;

    /** Transport handle; valid only in IN_FLIGHT state, NULL otherwise. */
    pubnub_transport_handle_t* transport_handle;

    /** SDK-level deadline timer; started on dispatch, checked each tick.
     *  Zero-initialized (inactive) until pn_timer_start() is called. */
    pn_timer_t deadline;

    /** SDK-level result code. Set on terminal state transition. */
    pubnub_res_t result;

    /** Completion callback (may be NULL for fire-and-forget). */
    pn_request_cb_t on_complete;

    /** Opaque user data forwarded to on_complete. */
    void* user_data;

    /** Logger for network diagnostics (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;

    /** Feature-owned parsed result cache (lazy); freed via cleanup. */
    void* feature_state;

    /** Cleanup function for @ref feature_state (called on slot release). */
    void (*feature_state_cleanup)(void*, pubnub_allocator_provider_t*);

    /**
     * Optional response validator probe (NULL = HTTP status only).
     * Called after transport completion to detect logical failure
     * despite HTTP 2xx.
     */
    pubnub_res_t (*response_validator)(const uint8_t* body,
                                       size_t         body_len,
                                       int            http_status);

    /**
     * Optional feature-owned capture hook (NULL = none). Runs at
     * completion on the poll thread, before the rx buffer can be
     * reclaimed, to copy volatile response data into feature-owned
     * storage. Not clobbered by @c pubnub_async (unlike @ref on_complete).
     */
    pn_response_capture_fn_t response_capture;

    /** Slot index within the context's request pool (set once). */
    uint16_t slot_id;

    /** Incremented each time the slot is reset (reused); compared against
     *  @c pubnub_future_t.generation to detect stale handles. The ABA window
     *  is 65536 reuse cycles per slot — negligible at typical request rates. */
    uint16_t generation;

    /** Feature that owns this slot; PUBNUB_FEATURE_COUNT when unassigned. */
    uint8_t feature_id;

    /** Cross-thread cancel flag (0 = none). Set under the context lock by
     *  pubnub_future_cancel; the poll-owning thread consumes it in
     *  pn_process_tick and runs the transport cancel there. */
    uint8_t cancel_requested;

    /** Lazily-parsed JSON tree of the response body, or NULL. */
    pubnub_json_value_t* parsed_body_tree;

    /** Provider that produced @ref parsed_body_tree (for cleanup). */
    pubnub_serialization_provider_t* parsed_body_owner;

    /** 1 once parse has been attempted (even if result is NULL). */
    uint8_t parsed_body_attempted;

    /** 1 to eagerly parse the response body at completion time (on the
     *  poll thread, before the readiness gate is published) instead of
     *  lazily on the first accessor call. Set for user-facing feature
     *  requests whose result body aliases a transport buffer that may be
     *  reclaimed before the accessor runs (socket Connection: close).
     *  Left 0 for subscribe long-polls, which parse via their own slab. */
    uint8_t preparse_on_complete;

    /** Cached service-error classification (cast to pn_service_error_kind_t).
     */
    uint8_t svc_error_kind;

    /** 1 once service-error classification has been performed.
     *  Write with release semantics; read with acquire semantics via
     *  PUBNUB_ATOMIC_STORE_U8 / PUBNUB_ATOMIC_LOAD_U8. */
    PUBNUB_ATOMIC_UINT8 svc_error_classified;

    /** Publication gate for state/result/parsed_body_tree. Set to 1
     *  (release) as the LAST write once all result data is stable; read
     *  (acquire) first in pn_request_is_ready before any gated field.
     *  One-way latch: 0 -> 1, reset to 0 only by pn_request_reset. */
    PUBNUB_ATOMIC_UINT8 ready;

    /** 1 when release was requested from inside the on_complete callback. */
    uint8_t release_deferred;

    /** Public async callback registered via pubnub_async(). Fires
     *  after the internal on_complete (if any) and after the slot
     *  transitions to a ready state. NULL when not registered. */
    pubnub_async_cb_t async_cb;

    /** User data forwarded to async_cb. */
    void* async_cb_user_data;
};

/* Fixed per-slot overhead (everything but the two profile-scaled HTTP
 * buffers) must not grow; cancel_requested is expected to fit existing
 * padding. Adding a field that does not fit the remaining padding trips
 * this. */
PUBNUB_STATIC_ASSERT(sizeof(struct pn_request) - sizeof(pubnub_http_request_t)
                             - sizeof(pubnub_http_response_t)
                         <= 144,
                     "pn_request fixed bookkeeping overhead pinned");

/**
 * @brief Return feature_state if the slot belongs to @p expected, else NULL.
 *
 * @param slot     Request slot (may be NULL).
 * @param expected Feature ID the accessor expects.
 * @return feature_state pointer, or NULL on mismatch.
 */
static inline void* pn_request_feature_state_for(pn_request_t*    slot,
                                                 pubnub_feature_t expected)
{
    if (NULL == slot || NULL == slot->feature_state) {
        return NULL;
    }
    if (slot->feature_id >= (uint8_t)PUBNUB_FEATURE_COUNT) {
        return NULL;
    }
    if (slot->feature_id != (uint8_t)expected) {
        return NULL;
    }
    return slot->feature_state;
}

/**
 * @brief Check if a request slot is available for use.
 *
 * @param req Request to check (borrowed).
 * @return Non-zero if state == IDLE, 0 otherwise.
 */
int pn_request_is_idle(const pn_request_t* req);

/**
 * @brief Check if result data is stable and readable (state >= COMPLETING).
 *
 * @param req Request to check (borrowed).
 * @return Non-zero if ready, 0 otherwise.
 */
int pn_request_is_ready(const pn_request_t* req);

/**
 * @brief Check if a request is in a terminal state (COMPLETE/FAILED/CANCELLED).
 *
 * @param req Request to check (borrowed).
 * @return Non-zero if terminal, 0 otherwise.
 */
int pn_request_is_terminal(const pn_request_t* req);

/**
 * @brief Initialize a request slot (one-time setup during pool init).
 *
 * @param req     Request to initialize (owned by caller).
 * @param slot_id Index within the context pool (immutable after init).
 */
void pn_request_init(pn_request_t* req, uint16_t slot_id);

/**
 * @brief Reset a request slot to IDLE for reuse (any state -> IDLE).
 *
 * @param req Request to reset (owned by caller).
 */
void pn_request_reset(pn_request_t* req);

/**
 * @brief Transition IDLE -> PENDING.
 *
 * @param req Request to transition (must be IDLE).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_enqueue(pn_request_t* req);

/**
 * @brief Transition PENDING -> IN_FLIGHT.
 *
 * @param req              Request to transition (must be PENDING).
 * @param transport_handle Handle returned by transport->send().
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_accept_handle(pn_request_t* req,
                                      pubnub_transport_handle_t* transport_handle);

/**
 * @brief Transition IN_FLIGHT -> COMPLETING (if callback set) or COMPLETE.
 *
 * Does NOT invoke the callback; use @ref pn_request_deliver_notification.
 *
 * @param req    Request to transition (must be IN_FLIGHT).
 * @param status SDK result code (typically PUBNUB_OK).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_on_success(pn_request_t* req, pubnub_res_t status);

/**
 * @brief Transition IN_FLIGHT -> COMPLETING (if callback set) or FAILED.
 *
 * Does NOT invoke the callback; use @ref pn_request_deliver_notification.
 * Caller must cancel the transport handle and timeout timer.
 *
 * @param req         Request to transition (must be IN_FLIGHT).
 * @param status      SDK error code (e.g. PUBNUB_ERR_TIMEOUT).
 * @param caller_file Source file of the call site (injected by macro).
 * @param caller_line Source line of the call site (injected by macro).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_on_failure_impl(pn_request_t* req,
                                        pubnub_res_t  status,
                                        const char*   caller_file,
                                        int           caller_line);

/** Inject call-site __FILE__/__LINE__ into failure logging. */
#define PN_REQUEST_ON_FAILURE(req, status) \
    pn_request_on_failure_impl((req), (status), __FILE__, __LINE__)

/**
 * @brief Emit a network-request log entry for a terminated request.
 *
 * Builds and dispatches a @c PUBNUB_LOG_ENTRY_NET_REQ entry recording a
 * request that reached a cancelled or failed terminal state. Shared by
 * the cancel, failure, and abort paths so the diagnostic field set stays
 * identical across all of them. The method and URL are derived from
 * @p req->http_request; the request-header map is included when present.
 *
 * Compiles to a no-op when none of the DEBUG, WARNING, or ERROR levels
 * are compiled in. Must be called WITHOUT the context lock held, since it
 * invokes the logger provider.
 *
 * @param req         Request whose method/URL/slot are logged (borrowed;
 *                    a NULL @p req is tolerated and produces no entry).
 * @param logger      Logger to emit through (borrowed; a NULL logger or a
 *                    NULL @c log callback produces no entry).
 * @param canceled    Non-zero when the request was cancelled.
 * @param failed      Non-zero when the request failed (timeout/transport).
 * @param result      SDK result code recorded on the entry.
 * @param level       Severity level for the entry.
 * @param caller_file Source file of the call site (typically @c __FILE__).
 * @param caller_line Source line of the call site (typically @c __LINE__).
 */
void pn_request_log_net_terminal(const pn_request_t*       req,
                                 pubnub_logger_provider_t* logger,
                                 int                       canceled,
                                 int                       failed,
                                 pubnub_res_t              result,
                                 pubnub_log_level_t        level,
                                 const char*               caller_file,
                                 int                       caller_line);

/**
 * @brief Fire on_complete and transition COMPLETING -> terminal state.
 *
 * Must be called WITHOUT the context lock held. No-op if @p req is
 * NULL or not in COMPLETING state.
 *
 * @param req Request to deliver notification for.
 */
void pn_request_deliver_notification(pn_request_t* req);

/**
 * @brief Parse the slot's response body (idempotent, cached).
 *
 * Must NOT be called while holding the pool lock.
 *
 * @param req    Slot whose body should be parsed (borrowed).
 * @param serial Serialization provider (borrowed).
 * @return Cached parse tree, or NULL when not available.
 */
pubnub_json_value_t* pn_request_get_parsed_body(pn_request_t* req,
                                                pubnub_serialization_provider_t* serial);

/**
 * @brief Resolve the slot behind @p future when result data is stable.
 *
 * Returns NULL in all of the following cases, so callers do not need
 * individual guards:
 * - @p future.ctx is NULL (invalid sentinel).
 * - The slot has not yet reached a terminal state (not ready).
 * - @p future.generation does not match the slot's current generation
 *   (future was released, or the slot was recycled for a new request).
 *
 * This is the single choke point for all result accessors. The generation
 * check here makes every accessor safe to call on a released future —
 * it returns a zero-initialised result rather than accessing freed data.
 *
 * @param future Future handle to resolve (by value).
 * @return Slot pointer (borrowed, valid until @c pubnub_future_release),
 *         or NULL when the future is invalid, not yet ready, or stale.
 */
pn_request_t* pn_ready_slot_for_future(pubnub_future_t future);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_REQUEST_INTERNAL_H */

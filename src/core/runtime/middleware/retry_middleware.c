/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file retry_middleware.c
 * @brief Retry engine transport decorator.
 *
 * Intercepts transport completions, classifies retriable failures,
 * schedules non-blocking backoff via per-slot timers, and
 * re-dispatches through the inner chain (signature middleware gets
 * a fresh HMAC on each retry attempt).
 */

#include "middleware_internal.h"
#include "retry_middleware_internal.h"

#include "core/pn_format.h"
#include "core/runtime/request_internal.h"

#include "pubnub/config.h"
#include "pubnub/providers/logger_types.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <string.h>

/**
 * @brief Generate a sub-second jitter value in [0, 999] ms.
 *
 * Returns 0 when random source is unavailable — deterministic
 * delay without spreading is better than unpredictable jitter.
 */
static uint32_t pn_retry_jitter_ms(pubnub_platform_provider_t* platform)
{
    uint32_t raw = 0;
    int      rc;

    if (NULL == platform || NULL == platform->random_bytes) {
        return 0;
    }

    rc = platform->random_bytes(platform, (uint8_t*)&raw, sizeof(raw));
    if (0 != rc) {
        return 0;
    }

    return raw % 1000;
}

pubnub_milliseconds_t pn_retry_delay_exponential(unsigned int base_delay_ms,
                                                 unsigned int max_delay_ms,
                                                 unsigned int attempt)
{
    uint32_t delay;
    uint32_t i;

    if (0 == base_delay_ms) {
        return 0;
    }

    delay = (uint32_t)base_delay_ms;
    for (i = 0U; i < (uint32_t)attempt && delay < (uint32_t)max_delay_ms; ++i) {
        delay = (delay > (uint32_t)max_delay_ms / 2U) ? (uint32_t)max_delay_ms
                                                      : delay * 2U;
    }

    return (pubnub_milliseconds_t)delay;
}

pubnub_milliseconds_t pn_retry_parse_retry_after(const pubnub_http_response_t* response)
{
    unsigned int i;

    if (NULL == response) {
        return 0;
    }

    for (i = 0; i < response->header_count; i++) {
        const char         expected[] = "retry-after";
        int                match      = 1;
        size_t             c;
        unsigned int       seconds = 0;
        size_t             j;
        const pubnub_kv_t* hdr = &response->headers[i];
        if (NULL == hdr->key.ptr || 11 != hdr->key.len) {
            continue;
        }

        /* Case-insensitive comparison for "retry-after". ASCII only,
         * so manual lower-case check avoids locale dependency. */
        for (c = 0; c < 11; c++) {
            char ch = hdr->key.ptr[c];
            /* ASCII lower-case conversion. */
            if (ch >= 'A' && ch <= 'Z') {
                ch = (char)(ch + ('a' - 'A'));
            }
            if (ch != expected[c]) {
                match = 0;
                break;
            }
        }
        if (0 == match) {
            continue;
        }

        /* Parse integer seconds from value. */
        if (NULL == hdr->value.ptr || 0 == hdr->value.len) {
            return 0;
        }

        for (j = 0; j < hdr->value.len; j++) {
            unsigned int prev;
            char         digit = hdr->value.ptr[j];
            if (digit < '0' || digit > '9') {
                /* Non-digit: not an integer Retry-After (could be a
                 * date format). Ignore. */
                return 0;
            }
            prev    = seconds;
            seconds = seconds * 10 + (unsigned int)(digit - '0');
            if (seconds < prev) {
                /* Overflow. Cap at a large value. */
                return (pubnub_milliseconds_t)3600000;
            }
        }

        return (pubnub_milliseconds_t)seconds * 1000;
    }

    return 0;
}

/**
 * @brief Recover the parent struct from a pointer to an embedded member.
 *
 * @pre @p ptr MUST point to the @p member field of a live @p type instance.
 *      pn_request_dispatch() is the sole production entry point into the
 *      middleware chain and always passes `&req->http_request`, guaranteeing
 *      every `pubnub_http_request_t*` here is embedded inside a
 *      `pn_request_t`.
 *
 * The `1 ? (ptr) : &((type*)0)->member` ternary is a compile-time type guard:
 * the runtime branch always selects @p ptr, but C composite-type rules require
 * both branches to be pointer-compatible, so passing a wrong statically-typed
 * pointer is rejected at compile time. This guards static type only — it does
 * NOT prove @p ptr actually points to an embedded @p member at runtime; a
 * correctly-typed pointer to a foreign object still requires a caller-side
 * identity check (see find_slot_by_request()).
 *
 * @param ptr    Pointer to the embedded member.
 * @param type   Enclosing struct type (e.g. pn_request_t).
 * @param member Name of the field within @p type that @p ptr points to.
 */
#define PN_CONTAINER_OF(ptr, type, member) \
    ((type*)((char*)(1 ? (ptr) : &((type*)0)->member) - offsetof(type, member)))

PUBNUB_STATIC_ASSERT(offsetof(pn_request_t, http_request) < sizeof(pn_request_t),
                     "http_request must be embedded inside pn_request_t");

PUBNUB_STATIC_ASSERT(sizeof(pubnub_retry_configuration_t) <= 32,
                     "pubnub_retry_configuration_t exceeds 32-byte budget");

/**
 * @brief Map feature_id to the endpoint-group bitmask for exclusion.
 *
 * @param feature_id Feature enum value (pubnub_feature_t cast to uint8_t).
 * @return Endpoint group bitmask, or 0 when the feature has no assigned
 *         group (never excluded from retry).
 */
static unsigned int endpoint_group_from_feature(uint8_t feature_id)
{
    switch ((pubnub_feature_t)feature_id) {
    case PUBNUB_FEATURE_PUBLISH:
    case PUBNUB_FEATURE_SIGNAL:
        return (unsigned int)PUBNUB_ENDPOINT_MESSAGE_SEND;
    case PUBNUB_FEATURE_SUBSCRIBE:
        return (unsigned int)PUBNUB_ENDPOINT_SUBSCRIBE;
    case PUBNUB_FEATURE_PRESENCE: return (unsigned int)PUBNUB_ENDPOINT_PRESENCE;
    case PUBNUB_FEATURE_HISTORY:
        return (unsigned int)PUBNUB_ENDPOINT_MESSAGE_STORAGE;
    case PUBNUB_FEATURE_CHANNEL_GROUPS:
        return (unsigned int)PUBNUB_ENDPOINT_CHANNEL_GROUPS;
    case PUBNUB_FEATURE_APP_CONTEXT:
        return (unsigned int)PUBNUB_ENDPOINT_APP_CONTEXT;
    case PUBNUB_FEATURE_MESSAGE_ACTIONS:
        return (unsigned int)PUBNUB_ENDPOINT_MESSAGE_REACTIONS;
    case PUBNUB_FEATURE_PAM: return (unsigned int)PUBNUB_ENDPOINT_PAM;
    case PUBNUB_FEATURE_FILES: return (unsigned int)PUBNUB_ENDPOINT_FILES;
    default: return 0;
    }
}

/**
 * @brief Check if a request's endpoint is excluded from retry.
 *
 * Recovers the owning pn_request_t via container_of to read the feature_id
 * without coupling the pipeline to the retry middleware's internals.
 *
 * @param mw      Retry middleware instance; must be non-NULL.
 * @param request HTTP request embedded in a pn_request_t; must be non-NULL.
 * @return 1 if the request's endpoint group is in the exclusion mask, 0
 *         otherwise.
 */
static int is_excluded(const pn_middleware_retry_t* mw, pubnub_http_request_t* request)
{
    const pn_request_t* req;
    unsigned int        group;

    if (0 == mw->config.excluded_endpoints) {
        return 0;
    }
    req   = PN_CONTAINER_OF(request, pn_request_t, http_request);
    group = endpoint_group_from_feature(req->feature_id);
    if (0 == group) {
        return 0;
    }
    return (mw->config.excluded_endpoints & group) != 0;
}

/**
 * @brief Check if a completed response represents a retriable failure.
 *
 * Retriable: HTTP 429, 5xx, transport error (status_code==0), timeout.
 * Non-retriable: 2xx, 4xx (except 429), cancelled.
 *
 * @param response Completed HTTP response; NULL is treated as non-retriable.
 * @return 1 if the response should be retried, 0 otherwise.
 */
static int is_retriable(const pubnub_http_response_t* response)
{
    if (NULL == response) {
        return 0;
    }

    if (PUBNUB_HTTP_ERROR == response->completion) {
        /* Transport-level failure or timeout — retriable. */
        if (PUBNUB_ERR_CANCELLED == response->transport_error) {
            return 0;
        }
        if (PUBNUB_ERR_BUFFER_TOO_SMALL == response->transport_error
            || PUBNUB_ERR_OUT_OF_MEMORY == response->transport_error) {
            return 0;
        }
        return 1;
    }

    if (PUBNUB_HTTP_COMPLETE != response->completion) {
        return 0;
    }

    /* HTTP 429 (rate limit) is retriable. */
    if (429 == response->status_code) {
        return 1;
    }

    /* HTTP 5xx (server error) is retriable. */
    if (response->status_code >= 500 && response->status_code < 600) {
        return 1;
    }

    return 0;
}

/**
 * @brief Find a free retry slot, or NULL if all are busy.
 *
 * @param mw Retry middleware instance; must be non-NULL.
 * @return Pointer to an IDLE slot, or NULL when all slots are in use.
 */
static pn_retry_slot_t* acquire_slot(pn_middleware_retry_t* mw)
{
    unsigned int i;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        if (PN_RETRY_SLOT_IDLE == mw->slots[i].state) {
            memset(&mw->slots[i], 0, sizeof(mw->slots[i]));
            return &mw->slots[i];
        }
    }
    return NULL;
}

/**
 * @brief Find the slot tracking a given request, or NULL.
 *
 * @param mw      Retry middleware instance; must be non-NULL.
 * @param request HTTP request pointer; must be non-NULL.
 * @return Pointer to the slot tracking this request, or NULL if not found or
 *         if the request is not under retry tracking.
 */
static pn_retry_slot_t* find_slot_by_request(pn_middleware_retry_t* mw,
                                             const pubnub_http_request_t* request)
{
    unsigned int i;
    uint16_t     generation;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        if (PN_RETRY_SLOT_IDLE == mw->slots[i].state
            || mw->slots[i].request != request) {
            continue;
        }
        /* Only after the pointer matches a tracked slot is `request` known
         * to be embedded in a pn_request_t. Passthrough handles (inner
         * transport handles) are foreign pointers, so container_of on them
         * would be undefined behaviour — the pointer compare filters them
         * out first. */
        generation =
            PN_CONTAINER_OF(request, pn_request_t, http_request)->generation;
        if (mw->slots[i].request_generation == generation) {
            return &mw->slots[i];
        }
    }
    return NULL;
}

/**
 * @brief Copy terminal response from internal buffer to caller's response.
 *
 * Transitions to DONE (not IDLE) because the inner transport handle is
 * still live — caller_response->body aliases the inner RX buffer. The
 * poll sweep reclaims success/HTTP-status terminals; transport-error
 * terminals stay DONE until the core aborts the request through cancel().
 *
 * @param slot Retry slot; must be non-NULL. Sets slot->state to DONE
 *             after copying the response.
 */
static void finalize_slot(pn_retry_slot_t* slot)
{
    if (NULL != slot->caller_response) {
        memcpy(slot->caller_response,
               &slot->internal_response,
               sizeof(pubnub_http_response_t));
    }
    slot->state = PN_RETRY_SLOT_DONE;
}

/**
 * @brief Roll back query params and scratch to pre-send state, then
 *        re-dispatch through the inner chain.
 *
 * Cancels the prior attempt's inner handle first to release transport
 * resources. On success, transitions the slot to IN_FLIGHT. On immediate
 * inner-chain rejection, finalizes the slot (transitions to DONE) and
 * copies the error to caller_response.
 *
 * @param mw   Retry middleware instance; must be non-NULL and have a
 *             non-NULL next pointer.
 * @param slot Retry slot in WAITING state; must be non-NULL. On return,
 *             state is either IN_FLIGHT (if send succeeded) or DONE (if
 *             send failed immediately).
 */
static void redispatch_slot(pn_middleware_retry_t* mw, pn_retry_slot_t* slot)
{
    pubnub_transport_handle_t* handle;

    if (NULL != mw->logger && NULL != mw->logger->log) {
        pubnub_log_entry_text_t log_e = {0};
        char                    buf[48];
        log_e.base.type  = PUBNUB_LOG_ENTRY_TEXT;
        log_e.base.level = PUBNUB_LOG_LEVEL_DEBUG;
        log_e.base.file  = __FILE__;
        log_e.base.line  = __LINE__;
        pn_snprintf(buf, sizeof(buf), "Retry fired: attempt=%u", slot->attempt);
        log_e.message = buf;
        mw->logger->log(mw->logger, (const pubnub_log_entry_t*)&log_e);
    }

    /* Release the prior attempt's transport resources. The completion
     * data has already been consumed by handle_completion(). */
    if (NULL != slot->inner_handle) {
        mw->next->cancel(mw->next, slot->inner_handle);
        slot->inner_handle = NULL;
    }

    /* Rollback: remove signature/timestamp params from prior attempt. */
    slot->request->query_param_count = slot->saved_query_param_count;
    slot->request->scratch_used      = slot->saved_scratch_used;

    /* Clear internal response for the new attempt. */
    memset(&slot->internal_response, 0, sizeof(slot->internal_response));

    /* Resume the core deadline before redispatch. */
    slot->request->deadline_suspended = 0;

    handle = mw->next->send(mw->next, slot->request, &slot->internal_response);

    if (NULL == handle) {
        /* Inner chain rejected immediately — report transport error
         * so the core routes this to FAILED instead of hanging on
         * PENDING indefinitely. */
        slot->internal_response.completion      = PUBNUB_HTTP_ERROR;
        slot->internal_response.transport_error = PUBNUB_ERR_TRANSPORT;
        finalize_slot(slot);
        return;
    }

    slot->inner_handle = handle;
    slot->state        = PN_RETRY_SLOT_IN_FLIGHT;
}

/**
 * @brief Compute the delay for this slot and start the backoff timer.
 *
 * Increments the attempt count, starts a pn_timer for the computed delay
 * (respecting Retry-After header if present), and transitions the slot to
 * WAITING state.
 *
 * @param mw   Retry middleware instance; must be non-NULL and have a
 *             non-NULL platform pointer.
 * @param slot Retry slot in IN_FLIGHT state with a completed response;
 *             must be non-NULL.
 */
static void schedule_retry(pn_middleware_retry_t* mw, pn_retry_slot_t* slot)
{
    pubnub_milliseconds_t delay = 0;
    pubnub_milliseconds_t retry_after;

    if (PUBNUB_RETRY_LINEAR == mw->config.policy) {
        delay = (pubnub_milliseconds_t)mw->base_delay_ms;
    } else {
        delay = pn_retry_delay_exponential(
            mw->base_delay_ms, mw->max_delay_ms, slot->attempt);
    }

    /* Respect Retry-After header (take the maximum), but clamp it to the
     * configured upper bound so a hostile or misconfigured server cannot
     * stall the request for an unbounded time. */
    retry_after = pn_retry_parse_retry_after(&slot->internal_response);
    if (retry_after > (pubnub_milliseconds_t)mw->max_retry_after_ms) {
        retry_after = (pubnub_milliseconds_t)mw->max_retry_after_ms;
    }
    if (retry_after > delay) {
        delay = retry_after;
    }

    /* Additive jitter applied to the final delay (including
     * Retry-After) to spread retries across clients. */
    delay += (pubnub_milliseconds_t)pn_retry_jitter_ms(mw->platform);

    slot->attempt++;
    slot->state   = PN_RETRY_SLOT_WAITING;
    slot->backoff = pn_timer_start(delay, mw->platform);

    /* Suspend the core deadline while in backoff — transport re-arms
     * its own per-attempt timeout on redispatch. */
    slot->request->deadline_suspended = 1;

    if (NULL != mw->logger && NULL != mw->logger->log) {
        pubnub_log_entry_text_t log_e = {0};
        char                    buf[64];
        log_e.base.type  = PUBNUB_LOG_ENTRY_TEXT;
        log_e.base.level = PUBNUB_LOG_LEVEL_DEBUG;
        log_e.base.file  = __FILE__;
        log_e.base.line  = __LINE__;
        pn_snprintf(buf,
                    sizeof(buf),
                    "Retry scheduled: attempt=%u delay_ms=%llu",
                    slot->attempt,
                    (unsigned long long)delay);
        log_e.message = buf;
        mw->logger->log(mw->logger, (const pubnub_log_entry_t*)&log_e);
    }
}

/**
 * @brief Process a completed inner request for a slot: decide whether
 *        to retry or finalize.
 *
 * Checks if the response is retriable and if the attempt limit is
 * reached. Endpoint exclusion is already handled at slot-acquisition
 * time in retry_send(). Transitions to WAITING (if retry is warranted)
 * or DONE (if finalization).
 *
 * @param mw   Retry middleware instance; must be non-NULL.
 * @param slot Retry slot in IN_FLIGHT state with a completed response in
 *             slot->internal_response; must be non-NULL.
 */
static void handle_completion(pn_middleware_retry_t* mw, pn_retry_slot_t* slot)
{
    if (!is_retriable(&slot->internal_response)) {
        finalize_slot(slot);
        return;
    }

    if (slot->attempt >= mw->max_retries) {
        finalize_slot(slot);
        return;
    }

    schedule_retry(mw, slot);
}

/**
 * @brief Transport vtable send() method for the retry middleware.
 *
 * Either passes through to the inner chain without tracking (when retry is
 * disabled or the endpoint is excluded), or acquires a slot and tracks the
 * request for potential retry.
 *
 * @param self     Retry middleware instance cast from self pointer.
 * @param request  HTTP request; must be non-NULL.
 * @param response Caller-owned response buffer where completion will be
 *                 copied; must be non-NULL.
 * @return Opaque transport handle (request pointer for tracked requests, or
 *         inner handle for passthrough). Returns NULL if the inner chain
 *         rejects immediately or if parameters are invalid.
 */
static pubnub_transport_handle_t* retry_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    pn_middleware_retry_t*     mw;
    pn_retry_slot_t*           slot;
    pubnub_transport_handle_t* handle;

    if (NULL == self || NULL == response) {
        return NULL;
    }
    mw = (pn_middleware_retry_t*)self;
    if (NULL == mw->next) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Skip for external requests (e.g., S3 uploads). */
    if (request->external) {
        return mw->next->send(mw->next, request, response);
    }

    /* Passthrough when retry is disabled or the request's endpoint group
     * is excluded from retry. */
    if (PUBNUB_RETRY_NONE == mw->config.policy || is_excluded(mw, request)) {
        return mw->next->send(mw->next, request, response);
    }

    slot = acquire_slot(mw);
    if (NULL == slot) {
        /* All retry slots busy — passthrough without retry tracking. */
        return mw->next->send(mw->next, request, response);
    }

    slot->request = request;
    slot->request_generation =
        PN_CONTAINER_OF(request, pn_request_t, http_request)->generation;
    slot->caller_response = response;

    /* Snapshot query state before inner chain mutates it. */
    slot->saved_query_param_count = request->query_param_count;
    slot->saved_scratch_used      = request->scratch_used;

    handle = mw->next->send(mw->next, request, &slot->internal_response);

    if (NULL == handle) {
        /* Immediate failure — no inner handle to keep alive, go
         * straight to IDLE so the slot is immediately reusable. */
        slot->state          = PN_RETRY_SLOT_IDLE;
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    slot->inner_handle = handle;
    slot->state        = PN_RETRY_SLOT_IN_FLIGHT;

    /* Return the request pointer as our opaque handle. The caller
     * identifies this request by the handle for cancel(). */
    return (pubnub_transport_handle_t*)request;
}

/**
 * @brief Transport vtable poll() method for the retry middleware.
 *
 * Drives the inner transport, checks in-flight slots for completed requests
 * (decide retry or finalize), expires waiting timers, and returns the count
 * of newly-terminal slots visible to the caller.
 *
 * @param self       Retry middleware instance cast from self pointer.
 * @param timeout_ms Maximum milliseconds to poll the inner transport.
 * @return Number of tracked slots that reached terminal state and are now
 *         visible to the caller. Returns -1 if self is NULL or next is NULL.
 */
static int retry_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    pn_middleware_retry_t* mw;
    int                    completed;
    int                    visible_completed = 0;
    unsigned int           i;

    if (NULL == self) {
        return -1;
    }
    mw = (pn_middleware_retry_t*)self;
    if (NULL == mw->next) {
        return -1;
    }

    /* Drive inner transport I/O. */
    completed = mw->next->poll(mw->next, timeout_ms);

    /* Check in-flight slots for completed inner requests. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_retry_slot_t* slot = &mw->slots[i];
        if (PN_RETRY_SLOT_IN_FLIGHT != slot->state) {
            continue;
        }
        if (PUBNUB_HTTP_PENDING == slot->internal_response.completion) {
            continue;
        }
        /* Inner request completed — decide retry or finalize. */
        handle_completion(mw, slot);
    }

    /* Check waiting slots for expired backoff timers. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_retry_slot_t* slot = &mw->slots[i];
        if (PN_RETRY_SLOT_WAITING != slot->state) {
            continue;
        }
        if (!pn_timer_is_expired(slot->backoff, mw->platform)) {
            continue;
        }
        /* Timer expired — re-dispatch through the inner chain. */
        redispatch_slot(mw, slot);
    }

    /* Terminal slots (COMPLETE and ERROR alike) stay DONE with their
     * request + inner_handle preserved: the core issues cancel() on every
     * terminal slot when pubnub_future_release runs, and that cancel arrives
     * with our request-as-handle. The slot must still be findable so the
     * cancel forwards the inner_handle down the chain (freeing the transport
     * rx buffer that response->body aliases) instead of forwarding the raw
     * request pointer to the inner layer. Reaping COMPLETE slots here would
     * both strand the inner handle (leak) and, once the core cancels, feed a
     * request pointer to the transport as if it were a transport handle. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_retry_slot_t* slot = &mw->slots[i];
        if (PN_RETRY_SLOT_DONE != slot->state) {
            continue;
        }
        /* Count each terminal slot as visible at most once. A NULL
         * caller_response marks a slot already counted (terminal slots
         * persist across poll cycles until cancel() reclaims them). Drop
         * only the caller_response reference so re-sweeps do not recount. */
        if (NULL != slot->caller_response
            && PUBNUB_HTTP_PENDING != slot->caller_response->completion) {
            visible_completed++;
        }
        slot->caller_response = NULL;
    }

    /* If inner transport reported completions that were absorbed by
     * retry (scheduled for re-dispatch), they are not visible to the
     * caller. Report only truly-terminal completions. */
    (void)completed;
    return visible_completed;
}

/**
 * @brief Transport vtable cancel() method for the retry middleware.
 *
 * For tracked requests, cancels the in-flight or done inner handle and
 * marks the caller's response as cancelled. For passthrough requests,
 * delegates to the inner cancel. DONE slots release their inner handle
 * (freeing the transport's RX buffer) on cancel.
 *
 * @param self              Retry middleware instance cast from self pointer.
 * @param transport_handle  Opaque handle returned by retry_send (request
 *                          pointer for tracked, inner handle for passthrough).
 */
static void retry_cancel(pubnub_transport_provider_t* self,
                         pubnub_transport_handle_t*   transport_handle)
{
    pn_middleware_retry_t*       mw;
    const pubnub_http_request_t* request;
    pn_retry_slot_t*             slot;

    if (NULL == self || NULL == transport_handle) {
        return;
    }
    mw = (pn_middleware_retry_t*)self;
    if (NULL == mw->next) {
        return;
    }

    /* For tracked requests, we returned the request pointer as handle.
     * For passthrough requests (excluded/NONE), we returned the inner
     * handle directly. Distinguish by searching our slots. */
    request = (const pubnub_http_request_t*)transport_handle;
    slot    = find_slot_by_request(mw, request);
    if (NULL == slot) {
        /* Passthrough: the handle IS the inner handle (excluded/NONE
         * requests were never tracked in a slot), so forward it directly.
         * Tracked terminal slots keep their request pointer until this
         * cancel reaps them, so they are always found above. */
        mw->next->cancel(mw->next, transport_handle);
        return;
    }

    if (PN_RETRY_SLOT_IDLE != slot->state && NULL != slot->inner_handle) {
        mw->next->cancel(mw->next, slot->inner_handle);
    }

    /* Mark caller's response as cancelled, but only if no terminal
     * status has already been written (e.g., TIMEOUT from the core). */
    if (NULL != slot->caller_response
        && PUBNUB_HTTP_PENDING == slot->caller_response->completion) {
        slot->caller_response->completion      = PUBNUB_HTTP_ERROR;
        slot->caller_response->transport_error = PUBNUB_ERR_CANCELLED;
    }

    /* Resume the core deadline if the slot was in backoff. */
    if (NULL != slot->request) {
        slot->request->deadline_suspended = 0;
    }

    slot->state           = PN_RETRY_SLOT_IDLE;
    slot->inner_handle    = NULL;
    slot->caller_response = NULL;
    slot->request         = NULL;
}

/**
 * @brief Initialize a retry middleware instance (caller-allocated).
 *
 * Configures the retry policy, delay parameters, and maximum retry count
 * from the provided configuration (filling in defaults for unspecified
 * values). Early return (no-op) if any required parameter is NULL.
 *
 * @param mw       Caller-provided retry middleware struct; must be
 *                 non-NULL. Will be zero-initialized and populated.
 * @param config   Retry configuration; must be non-NULL. On NULL, function
 *                 returns early without modification.
 * @param platform Platform provider for timer/random; must be non-NULL.
 *                 On NULL, function returns early.
 * @param next     Inner transport provider; must be non-NULL. On NULL,
 *                 function returns early.
 */
void pn_middleware_retry_init(pn_middleware_retry_t*              mw,
                              const pubnub_retry_configuration_t* config,
                              pubnub_platform_provider_t*         platform,
                              pubnub_transport_provider_t*        next)
{
    if (NULL == mw || NULL == config || NULL == platform || NULL == next) {
        return;
    }

    memset(mw, 0, sizeof(*mw));

    mw->base.send   = retry_send;
    mw->base.poll   = retry_poll;
    mw->base.cancel = retry_cancel;
    mw->base.init   = NULL;
    mw->base.deinit = NULL;
    mw->next        = next;
    mw->platform    = platform;
    mw->config      = *config;

    /* Resolve defaults. */
    mw->base_delay_ms = config->delay_ms;
    if (0 == mw->base_delay_ms) {
        mw->base_delay_ms = PUBNUB_CFG_RETRY_DELAY_MS;
    }

    mw->max_delay_ms = config->maximum_delay_ms;
    if (0 == mw->max_delay_ms) {
        mw->max_delay_ms = PUBNUB_CFG_RETRY_MAX_DELAY_MS;
    }

    mw->max_retries = config->maximum_retry;
    if (0 == mw->max_retries) {
        if (PUBNUB_RETRY_LINEAR == config->policy) {
            mw->max_retries = PUBNUB_CFG_LINEAR_MAX_RETRIES;
        } else {
            mw->max_retries = PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES;
        }
    }

    mw->max_retry_after_ms = config->maximum_retry_after_ms;
    if (0 == mw->max_retry_after_ms) {
        mw->max_retry_after_ms = PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS;
    }
}

/**
 * @brief Create a retry middleware instance (allocator-managed).
 *
 * Allocates a new retry middleware struct and initializes it via
 * pn_middleware_retry_init(). Returns NULL if the retry policy is NONE
 * (no retry enabled), if allocation fails, or if any required parameter
 * is invalid.
 *
 * @param config    Retry configuration; must be non-NULL.
 * @param platform  Platform provider for timer/random; must be non-NULL.
 * @param next      Inner transport provider; must be non-NULL.
 * @param allocator Allocator provider; must be non-NULL with a valid
 *                  alloc function. Used to allocate the middleware struct.
 * @return Pointer to a newly-allocated retry middleware (cast as
 *         pubnub_transport_provider_t*), or NULL if policy is NONE, if
 *         allocation fails, or if required parameters are invalid. Caller
 *         must pass the returned pointer to pn_middleware_retry_destroy()
 *         when done.
 */
pubnub_transport_provider_t*
pn_middleware_retry_create(const pubnub_retry_configuration_t* config,
                           pubnub_platform_provider_t*         platform,
                           pubnub_transport_provider_t*        next,
                           pubnub_allocator_provider_t*        allocator,
                           pubnub_logger_provider_t*           logger)
{
    pn_middleware_retry_t* mw;

    if (NULL == allocator || NULL == allocator->alloc || NULL == next
        || NULL == config || NULL == platform) {
        return NULL;
    }

    if (PUBNUB_RETRY_NONE == config->policy) {
        return NULL;
    }

    mw = (pn_middleware_retry_t*)PN_ALLOC(allocator, sizeof(*mw), 0);
    if (NULL == mw) {
        return NULL;
    }

    pn_middleware_retry_init(mw, config, platform, next);
    mw->logger = logger;

    return (pubnub_transport_provider_t*)mw;
}

/**
 * @brief Destroy a retry middleware instance and release its resources.
 *
 * Cancels all in-flight slots via the inner chain to prevent dangling
 * transport handles, then frees the middleware struct via allocator.
 * Early return (no-op) if mw is NULL or allocator is NULL/invalid.
 *
 * @param mw        Retry middleware instance (output of pn_middleware_retry_create);
 *                  may be NULL (safe no-op). On NULL, function returns early.
 * @param allocator Allocator provider with valid free function; may be NULL
 *                  (safe no-op, but middleware is not freed). On NULL or
 *                  invalid, function returns early without deallocating mw.
 */
void pn_middleware_retry_destroy(pubnub_transport_provider_t* mw,
                                 pubnub_allocator_provider_t* allocator)
{
    pn_middleware_retry_t* retry;
    unsigned int           i;

    if (NULL == mw) {
        return;
    }

    retry = (pn_middleware_retry_t*)mw;

    /* Cancel any in-flight or done slots to prevent dangling handles. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_retry_slot_t* slot = &retry->slots[i];
        if (PN_RETRY_SLOT_IDLE != slot->state && NULL != slot->inner_handle
            && NULL != retry->next) {
            retry->next->cancel(retry->next, slot->inner_handle);
        }
        slot->state        = PN_RETRY_SLOT_IDLE;
        slot->inner_handle = NULL;
    }

    if (NULL == allocator || NULL == allocator->free) {
        return;
    }
    PN_FREE(allocator, mw);
}

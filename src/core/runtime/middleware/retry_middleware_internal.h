/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file retry_middleware_internal.h
 * @brief Internal types for the retry transport decorator.
 *
 * The retry middleware intercepts transport failures, schedules
 * non-blocking backoff delays via per-slot timers, and re-dispatches
 * requests through the inner chain (which includes signature, so each
 * retry gets a fresh HMAC).
 */

#ifndef PN_RETRY_MIDDLEWARE_INTERNAL_H
#define PN_RETRY_MIDDLEWARE_INTERNAL_H

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"

#include "core/runtime/timer_internal.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Per-request retry tracking state.
 *
 * One slot per possible in-flight request. Tracks attempt count,
 * backoff timer, and the state needed to re-dispatch.
 */
typedef enum pn_retry_slot_state {
    /** Slot is not tracking any request. */
    PN_RETRY_SLOT_IDLE = 0,
    /** Request is in-flight through the inner transport. */
    PN_RETRY_SLOT_IN_FLIGHT,
    /** Waiting for backoff timer to expire before re-dispatch. */
    PN_RETRY_SLOT_WAITING,
    /**
     * Response delivered to caller; inner handle still live. Body data in
     * the inner transport's RX buffer remains valid in this state.
     *
     * Success and HTTP-status terminals are reclaimed by the poll sweep
     * on the same tick they complete. Transport-error terminals stay DONE
     * (request and inner handle preserved) until the core aborts the
     * request through cancel(), which releases the inner handle and
     * reclaims the slot. Slots in DONE are not reusable by acquire_slot().
     */
    PN_RETRY_SLOT_DONE
} pn_retry_slot_state_t;

/**
 * @brief Retry slot — tracks a single request across retry attempts.
 */
typedef struct pn_retry_slot {
    /** Current slot state. */
    pn_retry_slot_state_t state;

    /** Number of retry attempts made so far (0 = original send). */
    unsigned int attempt;

    /** Backoff timer (active only in WAITING state). */
    pn_timer_t backoff;

    /**
     * Snapshot of query_param_count before delegating to next->send().
     * Used to roll back signature/timestamp params on retry.
     */
    unsigned int saved_query_param_count;

    /**
     * Snapshot of scratch_used before delegating to next->send().
     * Used to roll back scratch consumed by signature middleware.
     */
    unsigned int saved_scratch_used;

    /** Transport handle from the inner chain (valid in IN_FLIGHT). */
    pubnub_transport_handle_t* inner_handle;

    /** Request descriptor (borrowed from caller, stable for slot life). */
    pubnub_http_request_t* request;

    /** Generation of the pn_request_t that owns @ref request, captured at
     *  send time. Stale-handle detection: a recycled pool slot reuses the
     *  same request address but increments generation. */
    uint16_t request_generation;

    /** Caller's response descriptor (final result written here). */
    pubnub_http_response_t* caller_response;

    /** Internal response buffer used while retrying. */
    pubnub_http_response_t internal_response;
} pn_retry_slot_t;

/**
 * @brief Retry middleware (full transport decorator).
 *
 * Embeds pubnub_transport_provider_t as first member for safe
 * cast to/from the transport interface.
 */
typedef struct pn_middleware_retry {
    /** Transport vtable (must be first member). */
    pubnub_transport_provider_t base;

    /** Next transport in the chain (signature middleware). */
    pubnub_transport_provider_t* next;

    /** Retry policy configuration (copied at creation time). */
    pubnub_retry_configuration_t config;

    /** Resolved base delay (never 0 after creation). */
    unsigned int base_delay_ms;

    /** Resolved max delay for exponential (never 0 after creation). */
    unsigned int max_delay_ms;

    /** Resolved maximum retry count (never 0 after creation). */
    unsigned int max_retries;

    /** Resolved Retry-After upper bound in ms (never 0 after creation). */
    unsigned int max_retry_after_ms;

    /** Platform provider for timers and random_bytes (borrowed). */
    pubnub_platform_provider_t* platform;

    /** Logger for retry diagnostics (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;

    /** Retry tracking slots (one per possible in-flight request). */
    pn_retry_slot_t slots[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
} pn_middleware_retry_t;

PUBNUB_STATIC_ASSERT(sizeof(pn_retry_slot_t) <= 512,
                     "retry slot exceeds 512-byte per-slot embedded budget");

/**
 * @brief Compute the deterministic exponential backoff delay.
 *
 * Uses the formula: min(max_delay_ms, base_delay_ms * 2^attempt).
 * Jitter is applied separately by the caller (schedule_retry).
 *
 * @param base_delay_ms Base delay in milliseconds.
 * @param max_delay_ms  Maximum delay cap in milliseconds.
 * @param attempt       Current attempt number (0-based).
 * @return Delay in milliseconds, capped at max_delay_ms.
 */
pubnub_milliseconds_t pn_retry_delay_exponential(unsigned int base_delay_ms,
                                                 unsigned int max_delay_ms,
                                                 unsigned int attempt);

/**
 * @brief Parse a Retry-After header value (integer seconds).
 *
 * Scans the response headers for a "Retry-After" header and parses
 * it as an integer number of seconds. Non-integer values (dates)
 * are ignored and treated as absent.
 *
 * @param response Response whose headers to scan (borrowed).
 * @return Parsed value in milliseconds, or 0 if header is absent or
 *         unparseable.
 */
pubnub_milliseconds_t pn_retry_parse_retry_after(const pubnub_http_response_t* response);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_RETRY_MIDDLEWARE_INTERNAL_H */

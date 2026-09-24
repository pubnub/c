/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file timer_internal.h
 * @brief Deadline timer built on top of platform monotonic_ms().
 *
 * pn_timer_t is a small value type (stack-allocatable) that records a
 * start timestamp and a duration. All operations require a pointer to
 * the platform provider so that the timer never stores its own clock
 * reference - the caller is responsible for passing the same provider
 * that was used to start the timer.
 */

#ifndef PN_TIMER_INTERNAL_H
#define PN_TIMER_INTERNAL_H

#include "pubnub/providers/platform.h"
#include "pubnub/types.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief A deadline timer.
 *
 * Value type - safe to copy, assign, and store on the stack.
 * A zero-initialized timer (start_ms == 0 && duration_ms == 0) is
 * considered inactive; pn_timer_is_active() returns 0 for it.
 *
 * Both fields use pubnub_milliseconds_t (uint64_t) so that
 * arithmetic between start and duration never requires mixed-width
 * casts.
 */
typedef struct pn_timer {
    pubnub_milliseconds_t start_ms; /**< Monotonic timestamp when the timer was started. */
    pubnub_milliseconds_t duration_ms; /**< Timeout duration in milliseconds. */
} pn_timer_t;

/**
 * @brief Start (or restart) a timer with the given duration.
 *
 * Captures the current monotonic time as the start point.
 *
 * @param duration_ms Timeout duration in milliseconds.
 *                    0 creates an already-expired timer.
 * @param platform    Provider supplying monotonic_ms (borrowed).
 * @return An active timer.
 */
pn_timer_t pn_timer_start(pubnub_milliseconds_t       duration_ms,
                          pubnub_platform_provider_t* platform);

/**
 * @brief Check whether a timer has expired.
 *
 * @param timer    Timer to check.
 * @param platform Provider supplying monotonic_ms (borrowed).
 * @return Non-zero if elapsed >= duration, 0 otherwise.
 *         An inactive timer (zero-initialized) is treated as expired.
 */
int pn_timer_is_expired(pn_timer_t timer, pubnub_platform_provider_t* platform);

/**
 * @brief Return milliseconds remaining before expiry.
 *
 * @param timer    Timer to query.
 * @param platform Provider supplying monotonic_ms (borrowed).
 * @return Remaining ms.  0 if already expired or inactive.
 */
pubnub_milliseconds_t pn_timer_remaining_ms(pn_timer_t timer,
                                            pubnub_platform_provider_t* platform);

/**
 * @brief Return milliseconds elapsed since the timer was started.
 *
 * @param timer    Timer to query.
 * @param platform Provider supplying monotonic_ms (borrowed).
 * @return Elapsed ms since start.  0 if inactive.
 */
pubnub_milliseconds_t pn_timer_elapsed_ms(pn_timer_t                  timer,
                                          pubnub_platform_provider_t* platform);

/**
 * @brief Reset a timer to start counting again with the same duration.
 *
 * Equivalent to pn_timer_start(timer->duration_ms, platform).
 *
 * @note Valid only on an already-active timer (duration_ms > 0).
 *       Calling on a stopped or zero-initialized timer is a no-op.
 *
 * @param timer    Pointer to the timer to reset (modified in place).
 * @param platform Provider supplying monotonic_ms (borrowed).
 */
void pn_timer_reset(pn_timer_t* timer, pubnub_platform_provider_t* platform);

/**
 * @brief Stop a timer, returning it to the inactive state.
 *
 * After stop, pn_timer_is_active() returns 0 and
 * pn_timer_is_expired() treats it as expired.
 *
 * @param timer Pointer to the timer to stop (modified in place).
 */
void pn_timer_stop(pn_timer_t* timer);

/**
 * @brief Check whether a timer is active (has been started).
 *
 * A zero-initialized pn_timer_t is considered inactive.
 *
 * @param timer Timer to check.
 * @return Non-zero if the timer has been started, 0 if inactive.
 */
int pn_timer_is_active(pn_timer_t timer);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_TIMER_INTERNAL_H */

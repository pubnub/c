/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file timer.c
 * @brief Internal deadline timer implementation.
 *
 * monotonic_ms() is treated as infallible: the platform provider
 * contract requires it to always return a valid, non-decreasing
 * timestamp. There is no error return path to check.
 */

#include "timer_internal.h"

pn_timer_t pn_timer_start(pubnub_milliseconds_t       duration_ms,
                          pubnub_platform_provider_t* platform)
{
    pn_timer_t t;
    t.start_ms    = platform->monotonic_ms(platform);
    t.duration_ms = duration_ms;
    return t;
}

int pn_timer_is_expired(pn_timer_t timer, pubnub_platform_provider_t* platform)
{
    if (!pn_timer_is_active(timer)) {
        return 1;
    }
    pubnub_milliseconds_t now     = platform->monotonic_ms(platform);
    pubnub_milliseconds_t elapsed = now - timer.start_ms;
    return elapsed >= timer.duration_ms;
}

pubnub_milliseconds_t pn_timer_remaining_ms(pn_timer_t timer,
                                            pubnub_platform_provider_t* platform)
{
    if (!pn_timer_is_active(timer)) {
        return 0;
    }
    pubnub_milliseconds_t now     = platform->monotonic_ms(platform);
    pubnub_milliseconds_t elapsed = now - timer.start_ms;
    if (elapsed >= timer.duration_ms) {
        return 0;
    }
    return timer.duration_ms - elapsed;
}

pubnub_milliseconds_t pn_timer_elapsed_ms(pn_timer_t                  timer,
                                          pubnub_platform_provider_t* platform)
{
    if (!pn_timer_is_active(timer)) {
        return 0;
    }
    pubnub_milliseconds_t now = platform->monotonic_ms(platform);
    return now - timer.start_ms;
}

void pn_timer_reset(pn_timer_t* timer, pubnub_platform_provider_t* platform)
{
    if (NULL == timer || 0U == timer->duration_ms) {
        return;
    }
    timer->start_ms = platform->monotonic_ms(platform);
}

void pn_timer_stop(pn_timer_t* timer)
{
    if (NULL == timer) {
        return;
    }
    timer->start_ms    = 0;
    timer->duration_ms = 0;
}

int pn_timer_is_active(pn_timer_t timer)
{
    return 0 != timer.start_ms || 0 != timer.duration_ms;
}

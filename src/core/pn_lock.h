/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_lock.h
 * @brief Per-context lock helpers for PUBNUB_CFG_THREAD_SAFETY.
 *
 * These static-inline helpers use the runtime-constant-guard pattern:
 * when PUBNUB_CFG_THREAD_SAFETY is 0, the compiler dead-code-
 * eliminates the entire body at -O1 and above. No #if guards at
 * call sites.
 */

#ifndef PN_LOCK_H
#define PN_LOCK_H

#include "pubnub/config.h"
#include "pubnub/providers/platform.h"

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Acquire the per-context lock if thread safety is enabled.
 *
 * No-op when PUBNUB_CFG_THREAD_SAFETY is 0 or when the platform
 * does not supply lock primitives (cooperative-only targets).
 *
 * @param platform Platform provider (borrowed, may be NULL).
 * @param lock     Lock instance (may be NULL).
 */
static inline void pn_ctx_lock(pubnub_platform_provider_t* platform,
                               pubnub_lock_t*              lock)
{
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != lock && NULL != platform
        && NULL != platform->lock_acquire) {
        platform->lock_acquire(platform, lock);
    }
}

/**
 * @brief Release the per-context lock if thread safety is enabled.
 *
 * @param platform Platform provider (borrowed, may be NULL).
 * @param lock     Lock instance (may be NULL).
 */
static inline void pn_ctx_unlock(pubnub_platform_provider_t* platform,
                                 pubnub_lock_t*              lock)
{
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != lock && NULL != platform
        && NULL != platform->lock_release) {
        platform->lock_release(platform, lock);
    }
}

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_LOCK_H */

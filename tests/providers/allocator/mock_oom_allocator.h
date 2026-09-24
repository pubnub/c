/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file providers/allocator/mock_oom_allocator.h
 * @brief Failure-injecting allocator provider for OOM unit tests.
 *
 * Thin wrapper around the C standard library allocator. Every vtable
 * method delegates to @c malloc / @c realloc / @c free unless failure
 * injection is armed for that tier. Two independent tiers can be armed:
 *
 *   - the general tier (@c alloc), and
 *   - the purpose-tagged buffer tier (@c buf_acquire).
 *
 * Each tier has its own call counter and a "fail after N calls"
 * threshold. When a tier's call count reaches its threshold, that tier
 * starts returning failure (@c NULL for @c alloc, a zero-capacity
 * descriptor for @c buf_acquire) instead of delegating to the standard
 * library. @c realloc, @c free, @c buf_release, and @c buf_grow always
 * delegate and are never failure-injected.
 *
 * The provider carries its state inline: embed a
 * @c pn_mock_oom_allocator_t, call @c pn_mock_oom_init to wire the
 * vtable, and pass @c &instance.base as @c pubnub_config_t::allocator.
 *
 * Typical use is to create a context with the mock disarmed (so context
 * construction succeeds), then arm a tier before dispatching the
 * operation under test.
 */

#ifndef PN_MOCK_OOM_ALLOCATOR_H
#define PN_MOCK_OOM_ALLOCATOR_H

#include "pubnub/providers/allocator.h"

#include <stddef.h>

/** Threshold value meaning "never inject failure for this tier". */
#define PN_MOCK_OOM_NEVER (-1)

/**
 * @brief Failure-injecting allocator instance.
 *
 * The @c base vtable must remain the first member so that a
 * @c pubnub_allocator_provider_t* can be recovered by pointer cast.
 */
typedef struct pn_mock_oom_allocator {
    /** Provider vtable (must be first member). */
    pubnub_allocator_provider_t base;
    /** Number of @c alloc calls observed since the last reset. */
    long alloc_calls;
    /** Number of @c buf_acquire calls observed since the last reset. */
    long buf_acquire_calls;
    /**
     * @brief Fail @c alloc once this many calls have been made.
     *
     * @c PN_MOCK_OOM_NEVER disables injection. A value of @c 0 fails the
     * very first @c alloc call.
     */
    long alloc_fail_after;
    /**
     * @brief Fail @c buf_acquire once this many calls have been made.
     *
     * @c PN_MOCK_OOM_NEVER disables injection. A value of @c 0 fails the
     * very first @c buf_acquire call.
     */
    long buf_acquire_fail_after;
} pn_mock_oom_allocator_t;

/**
 * @brief Wire the vtable and reset all counters and thresholds.
 *
 * Leaves both tiers disarmed (@c PN_MOCK_OOM_NEVER). Call once before
 * using the instance as a config allocator.
 *
 * @param mock Instance to initialize (@b required, non-NULL).
 */
void pn_mock_oom_init(pn_mock_oom_allocator_t* mock);

/**
 * @brief Reset call counters to zero and disarm both tiers.
 *
 * Does not touch the vtable, so the instance stays usable. Use between
 * operations in a single test to return to transparent passthrough.
 *
 * @param mock Instance to reset (@b required, non-NULL).
 */
void pn_mock_oom_reset(pn_mock_oom_allocator_t* mock);

/**
 * @brief Arm the general (@c alloc) tier to fail after @p n calls.
 *
 * @param mock Instance to arm (@b required, non-NULL).
 * @param n    Calls to allow before failing; @c 0 fails immediately.
 */
void pn_mock_oom_fail_alloc_after(pn_mock_oom_allocator_t* mock, long n);

/**
 * @brief Arm the buffer (@c buf_acquire) tier to fail after @p n calls.
 *
 * @param mock Instance to arm (@b required, non-NULL).
 * @param n    Calls to allow before failing; @c 0 fails immediately.
 */
void pn_mock_oom_fail_buf_acquire_after(pn_mock_oom_allocator_t* mock, long n);

#endif /* PN_MOCK_OOM_ALLOCATOR_H */

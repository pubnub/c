/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file request_pool_internal.h
 * @brief Context-owned fixed-capacity pool of pn_request_t slots.
 *
 * Backs the @ref pubnub_future_t handle system. Capacity is bounded
 * by @c PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; returns
 * @c PUBNUB_ERR_QUEUE_FULL when exhausted.
 *
 * Thread safety: when a mutex is configured, acquire/release serialize
 * via the context mutex (borrowed, not owned by the pool).
 */

#ifndef PN_REQUEST_POOL_INTERNAL_H
#define PN_REQUEST_POOL_INTERNAL_H

#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"
#include "request_internal.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Fixed-capacity pool of request slots.
 */
typedef struct pn_request_pool {
    /** Array of @c capacity request descriptors (owned). */
    pn_request_t* slots;

    /** Number of entries in @c slots. */
    uint16_t capacity;

    /** Slots whose state is != IDLE. Bounded by @c capacity. */
    uint16_t in_use_count;

    /** Allocator used for @c slots (borrowed; must outlive the pool). */
    pubnub_allocator_provider_t* allocator;

    /** Platform provider for mutex ops (borrowed; NULL on cooperative targets). */
    pubnub_platform_provider_t* platform;

    /** Context-owned lock (borrowed; NULL when thread safety disabled). */
    pubnub_lock_t* lock;

    /** Logger for slot-level diagnostics (borrowed; may be NULL). */
    pubnub_logger_provider_t* logger;
} pn_request_pool_t;

/**
 * @brief Initialize @p pool with @p capacity pre-allocated IDLE slots.
 *
 * @param pool      Pool to initialize (caller-owned).
 * @param capacity  Number of slots to allocate (must be > 0).
 * @param allocator Allocator provider (borrowed, non-NULL).
 * @param platform  Platform provider for mutex ops (borrowed, may be NULL).
 * @param lock      Context-owned lock (borrowed, may be NULL).
 * @param logger    Logger for slot-level diagnostics (borrowed, may be NULL).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_pool_init(pn_request_pool_t*           pool,
                                  uint16_t                     capacity,
                                  pubnub_allocator_provider_t* allocator,
                                  pubnub_platform_provider_t*  platform,
                                  pubnub_lock_t*               lock,
                                  pubnub_logger_provider_t*    logger);

/**
 * @brief Tear down the pool, freeing the slots array.
 *
 * Safe to call on a zero-initialized pool (no-op). Does NOT cancel
 * active requests - caller must drive them to terminal first
 * (pubnub_deinit handles this via transport->cancel before calling
 * pool_deinit).
 */
void pn_request_pool_deinit(pn_request_pool_t* pool);

/**
 * @brief Claim an IDLE slot and bind a future to it.
 *
 * Does NOT lock internally - caller must hold the context mutex.
 *
 * @param pool            Initialized pool.
 * @param ctx_for_future  Context to embed in the future (borrowed, may be NULL).
 * @param out_future      Populated on success.
 * @return PUBNUB_OK or PUBNUB_ERR_QUEUE_FULL.
 */
pubnub_res_t pn_request_pool_acquire(pn_request_pool_t* pool,
                                     pubnub_context_t*  ctx_for_future,
                                     pubnub_future_t*   out_future);

/**
 * @brief Release a slot back to the pool (any state -> IDLE).
 *
 * Does NOT lock internally - caller must hold the context mutex.
 *
 * @param pool    Pool owning the slot.
 * @param slot_id Index returned by a previous acquire call.
 */
void pn_request_pool_release(pn_request_pool_t* pool, uint16_t slot_id);

/**
 * @brief Look up the request descriptor for @p slot_id.
 *
 * @param pool    Pool to query.
 * @param slot_id Slot index (must be < pool->capacity).
 * @return Slot pointer, or NULL if out of bounds.
 */
pn_request_t* pn_request_pool_get(pn_request_pool_t* pool, uint16_t slot_id);

/**
 * @brief Acquire the pool mutex (no-op on cooperative targets).
 *
 * @param pool Pool whose mutex to acquire.
 */
void pn_request_pool_lock(pn_request_pool_t* pool);

/**
 * @brief Release the pool mutex if one exists.
 *
 * @param pool Pool whose mutex to release.
 */
void pn_request_pool_unlock(pn_request_pool_t* pool);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_REQUEST_POOL_INTERNAL_H */

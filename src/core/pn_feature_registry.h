/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_FEATURE_REGISTRY_H
#define PN_FEATURE_REGISTRY_H

#include "pubnub/capabilities.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/pubnub_compat.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Called during teardown to release per-feature state. */
typedef void (*pn_feature_cleanup_fn_t)(void*                        state,
                                        pubnub_allocator_provider_t* alloc);

/**
 * @brief Called once per process tick when the feature has active work.
 *
 * Registered features that supply a tick callback will be invoked from
 * pn_process_tick() OUTSIDE the context lock. The callback must not
 * assume any lock is held and must not call back into lock-protected
 * context accessors that would deadlock.
 *
 * @param state  Per-context feature state (same pointer as slot.state).
 * @return Non-zero if the feature has active work remaining (contributes
 *         to the PUBNUB_IN_PROGRESS return from pubnub_process), 0 if idle.
 */
typedef int (*pn_feature_tick_fn_t)(void* state);

/** @brief Per-feature state slot in the registry. */
typedef struct pn_feature_slot {
    void*                   state;   /**< Opaque per-context state, or NULL. */
    pn_feature_cleanup_fn_t cleanup; /**< Release @c state via allocator. */
    pn_feature_tick_fn_t    tick;    /**< Process-tick hook, or NULL. */
} pn_feature_slot_t;

/**
 * @brief Fixed-size per-context feature registry.
 *
 * Embedded in pubnub_context. Array indexed by pubnub_feature_t;
 * bitmap provides O(1) has-feature queries.
 */
typedef struct pn_feature_registry {
    /** Per-feature slots indexed by `pubnub_feature_t`. */
    pn_feature_slot_t slots[PUBNUB_FEATURE_COUNT];
    /** Bit N set = feature N registered. */
    uint32_t active_mask;
} pn_feature_registry_t;

PUBNUB_STATIC_ASSERT(PUBNUB_FEATURE_COUNT <= 32,
                     "pubnub_feature_t count must fit in active_mask bitmap");

/** @brief Zero-initialize the registry. */
void pn_feature_registry_init(pn_feature_registry_t* reg);

/**
 * @brief Mark a feature as active with optional state and cleanup.
 *
 * @param reg     Non-NULL registry.
 * @param feature Feature to register (must be < PUBNUB_FEATURE_COUNT).
 * @param state   Per-context state (may be NULL for stateless features).
 * @param cleanup Called during teardown (may be NULL if no cleanup needed).
 */
void pn_feature_register(pn_feature_registry_t*  reg,
                         pubnub_feature_t        feature,
                         void*                   state,
                         pn_feature_cleanup_fn_t cleanup);

/**
 * @brief Query whether a feature is registered.
 *
 * @param reg     Registry (may be NULL — returns 0).
 * @param feature Feature to query.
 * @return Non-zero if registered, 0 otherwise.
 */
int pn_feature_registry_has(const pn_feature_registry_t* reg,
                            pubnub_feature_t             feature);

/**
 * @brief Retrieve per-context state for a registered feature.
 *
 * @param reg     Non-NULL registry.
 * @param feature Feature whose state to retrieve.
 * @return State pointer, or NULL if not registered.
 */
void* pn_feature_registry_state(const pn_feature_registry_t* reg,
                                pubnub_feature_t             feature);

/**
 * @brief Set the tick callback for a registered feature.
 *
 * Must be called after pn_feature_register(). No-op when the feature
 * is not registered.
 *
 * @param reg     Non-NULL registry.
 * @param feature Feature whose tick to set.
 * @param tick    Tick callback, or NULL to clear.
 */
void pn_feature_registry_set_tick(pn_feature_registry_t* reg,
                                  pubnub_feature_t       feature,
                                  pn_feature_tick_fn_t   tick);

/**
 * @brief Invoke tick callbacks on all registered features.
 *
 * Iterates features in registration order. Returns non-zero if ANY
 * feature's tick reports active work remaining.
 *
 * @param reg Non-NULL registry.
 * @return Non-zero if at least one feature is active, 0 if all idle.
 */
int pn_feature_registry_tick_all(pn_feature_registry_t* reg);

/**
 * @brief Cleanup all registered features in reverse order and reset.
 *
 * @param reg   Non-NULL registry.
 * @param alloc Passed to each cleanup callback for deallocation.
 */
void pn_feature_registry_cleanup_all(pn_feature_registry_t*       reg,
                                     pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_FEATURE_REGISTRY_H */

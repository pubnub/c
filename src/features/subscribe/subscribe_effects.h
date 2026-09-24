/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_SUBSCRIBE_EFFECTS_H
#define PN_SUBSCRIBE_EFFECTS_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_effects.h requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "subscribe_internal.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** Forward declaration — full definition in subscribe_manager_internal.h */
typedef struct pn_subscribe_manager pn_subscribe_manager_t;

/**
 * @brief Execute a single effect produced by the event engine.
 *
 * Dispatches to the appropriate handler based on @p effect. Each
 * handler is self-contained and interacts with the manager's context
 * providers (pipeline, pool, platform) as needed.
 *
 * Must be called WITHOUT the context lock held — handlers may invoke
 * transport send/cancel and listener callbacks which must not nest
 * inside a locked section.
 *
 * @param mgr    Subscribe manager (non-NULL).
 * @param effect Effect descriptor from the transition result.
 */
void pn_subscribe_execute_effect(pn_subscribe_manager_t*         mgr,
                                 const pn_subscribe_ee_effect_t* effect);

/**
 * @brief Execute the full effect list from a transition result.
 *
 * Iterates @p result->effects[0..effect_count-1] and calls
 * @ref pn_subscribe_execute_effect for each. Cancel effects are
 * executed before action effects (HANDSHAKE/RECEIVE) to ensure
 * the previous request is cancelled before a new one starts.
 *
 * @param mgr    Subscribe manager (non-NULL).
 * @param result Transition result from the state machine.
 */
void pn_subscribe_execute_effects(pn_subscribe_manager_t* mgr,
                                  const pn_subscribe_ee_transition_result_t* result);

/**
 * @brief Process one tick of the subscribe event engine.
 *
 * Drains the event queue, feeds each event through the state machine,
 * executes resulting effects, and fires expired timers. Called from
 * pubnub_process() when the subscribe feature is active.
 *
 * @param mgr Subscribe manager (non-NULL).
 */
void pn_subscribe_tick(pn_subscribe_manager_t* mgr);

/**
 * @brief Feature-registry tick adaptor for subscribe.
 *
 * Conforms to pn_feature_tick_fn_t. Casts state to the subscribe
 * manager, runs the tick if the EE is not unsubscribed, and returns
 * whether the feature has active work.
 *
 * @param state Subscribe manager (cast from void*).
 * @return Non-zero if the subscribe EE is active, 0 if idle.
 */
int pn_subscribe_feature_tick(void* state);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_SUBSCRIBE_EFFECTS_H */

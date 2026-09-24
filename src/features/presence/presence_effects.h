/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_EFFECTS_H
#define PN_PRESENCE_EFFECTS_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_effects.h requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "presence_manager.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Notify presence that channels were joined.
 *
 * Called from the presence API layer when the active channel set
 * changes (subscription activated). Copies the full current
 * channel/group strings into the manager and drives the EE with a
 * JOINED event.
 *
 * @param mgr      Presence manager (non-NULL).
 * @param channels Comma-separated channel names (full current set).
 * @param groups   Comma-separated groups (full current set, or NULL).
 */
void pn_presence_joined(pn_presence_manager_t* mgr,
                        const char*            channels,
                        const char*            groups);

/**
 * @brief Notify presence that channels were removed (partial leave).
 *
 * Fires a LEFT event into the presence EE. Stores the removed channels
 * in leave_channels for the leave request, and updates the current
 * channel set to the remaining channels for future heartbeats.
 *
 * @param mgr                Presence manager (non-NULL).
 * @param remaining_channels Comma-separated channels still active.
 * @param remaining_groups   Comma-separated groups still active (or NULL).
 * @param removed_channels   Comma-separated channels being left.
 * @param removed_groups     Comma-separated groups being left (or NULL).
 * @param subscriptions_empty     1 if the subscription set is now empty.
 */
void pn_presence_left(pn_presence_manager_t* mgr,
                      const char*            remaining_channels,
                      const char*            remaining_groups,
                      const char*            removed_channels,
                      const char*            removed_groups,
                      uint8_t                subscriptions_empty);

/**
 * @brief Notify presence that all channels were removed at once.
 *
 * Fires LEFT_ALL into the presence EE.
 *
 * @param mgr Presence manager (non-NULL).
 */
void pn_presence_left_all(pn_presence_manager_t* mgr);

/**
 * @brief Notify presence of an explicit disconnect.
 *
 * @param mgr Presence manager (non-NULL).
 */
void pn_presence_disconnect(pn_presence_manager_t* mgr);

/**
 * @brief Notify presence of a reconnect from stopped/failed state.
 *
 * @param mgr Presence manager (non-NULL).
 */
void pn_presence_reconnect(pn_presence_manager_t* mgr);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PRESENCE_EFFECTS_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_API_H
#define PN_PRESENCE_API_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_api.h requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "presence_manager.h"
#include "pubnub/types_fwd.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Notify presence that channels were joined.
 *
 * Lazy-allocates the presence manager on first call. Builds the EE
 * JOINED event with the full current channel/group set.
 *
 * @param ctx      Context (may be NULL — no-op).
 * @param channels Comma-separated channel names (full current set).
 * @param groups   Comma-separated groups (full current set, or NULL).
 */
void pn_presence_api_joined(pubnub_context_t* ctx,
                            const char*       channels,
                            const char*       groups);

/**
 * @brief Notify presence that channels were removed (partial leave).
 *
 * Delegates to pn_presence_left or pn_presence_left_all depending
 * on @p subscriptions_empty. No-op when the presence manager has not
 * been created yet.
 *
 * @param ctx                Context (may be NULL — no-op).
 * @param remaining_channels Comma-separated channels still active.
 * @param remaining_groups   Comma-separated groups still active (or NULL).
 * @param removed_channels   Comma-separated channels being left.
 * @param removed_groups     Comma-separated groups being left (or NULL).
 * @param subscriptions_empty     1 if the subscription set is now empty.
 */
void pn_presence_api_left(pubnub_context_t* ctx,
                          const char*       remaining_channels,
                          const char*       remaining_groups,
                          const char*       removed_channels,
                          const char*       removed_groups,
                          uint8_t           subscriptions_empty);

/**
 * @brief Notify presence that all channels were removed at once.
 *
 * No-op when the presence manager has not been created yet.
 *
 * @param ctx Context (may be NULL — no-op).
 */
void pn_presence_api_left_all(pubnub_context_t* ctx);

/**
 * @brief Notify presence of an explicit disconnect.
 *
 * No-op when the presence manager has not been created yet.
 *
 * @param ctx Context (may be NULL — no-op).
 */
void pn_presence_api_disconnect(pubnub_context_t* ctx);

/**
 * @brief Notify presence of a reconnect from stopped/failed state.
 *
 * No-op when the presence manager has not been created yet.
 *
 * @param ctx Context (may be NULL — no-op).
 */
void pn_presence_api_reconnect(pubnub_context_t* ctx);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PRESENCE_API_H */

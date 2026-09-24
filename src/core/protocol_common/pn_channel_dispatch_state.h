/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CHANNEL_DISPATCH_STATE_H
#define PN_CHANNEL_DISPATCH_STATE_H

#include "pubnub/providers/allocator.h"

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Heap-owned encoded channel/group strings for a dispatch request.
 *
 * Both strings are URL-encoded with PN_ENCODE_KEEP_COMMAS and
 * heap-allocated via the stored allocator. Release with
 * pn_channel_dispatch_state_cleanup().
 */
typedef struct pn_channel_dispatch_state {
    /** URL-encoded comma-separated channel list (heap-owned). */
    char* encoded_channels;
    /** URL-encoded comma-separated channel-group list
     *  (heap-owned, may be NULL). */
    char* encoded_channel_groups;
    /** Allocator used for both strings (borrowed). */
    pubnub_allocator_provider_t* allocator;
} pn_channel_dispatch_state_t;

/**
 * @brief Release the heap-owned strings and free the struct itself.
 *
 * Frees both encoded strings via the stored allocator, then frees the
 * struct via @p alloc. Safe to call when @p state is NULL.
 *
 * Conforms to the feature_state_cleanup signature expected by the
 * pending queue (void* state, allocator*).
 *
 * @param state Dispatch state pointer (cast from void*, may be NULL).
 * @param alloc Allocator used to free the struct itself.
 */
void pn_channel_dispatch_state_cleanup(void*                        state,
                                       pubnub_allocator_provider_t* alloc);

/**
 * @brief Allocate and populate a dispatch state from pre-encoded strings.
 *
 * Takes ownership of @p encoded_channels and @p encoded_groups (both
 * must have been allocated via @p allocator). On failure, frees both
 * strings and returns NULL.
 *
 * @param encoded_channels Pre-encoded channel string (required, ownership
 *                         transfers on success).
 * @param encoded_groups   Pre-encoded group string (may be NULL, ownership
 *                         transfers on success).
 * @param allocator        Allocator for the struct and string ownership.
 * @return Pointer to populated state, or NULL on allocation failure
 *         (both input strings freed on failure).
 */
pn_channel_dispatch_state_t*
pn_channel_dispatch_state_create(char*                        encoded_channels,
                                 char*                        encoded_groups,
                                 pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_CHANNEL_DISPATCH_STATE_H */

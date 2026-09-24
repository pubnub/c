/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CHANNEL_GROUPS_INTERNAL_H
#define PN_CHANNEL_GROUPS_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_CHANNEL_GROUPS

#include "pubnub/error.h"
#include "pubnub/features/channel_groups.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Parsed decomposition of a list-channels response body.
 *
 * Caches the parsed JSON tree and extracted channel views for
 * indexed access.
 */
typedef struct pn_channel_groups_parsed {
    /** Number of channels found in the response. */
    uint32_t count;
    /** Parsed JSON tree (borrowed from request slot; not owned). */
    pubnub_json_value_t* tree;
    /** JSON array node containing channel strings (borrowed from tree). */
    const pubnub_json_value_t* channels_array;
    /** Cached forward cursor for O(1) sequential indexed accessors. */
    pubnub_json_array_iter_t iter_cache;
    /** Index the cached cursor's next step will return. */
    size_t iter_pos;
    /** Non-zero when @ref iter_cache is usable (zero = restart). */
    uint8_t iter_valid;
} pn_channel_groups_parsed_t;

/**
 * @brief Per-request state for channel group operations.
 *
 * Released via @ref pn_channel_groups_feature_state_cleanup.
 */
typedef struct pn_channel_groups_state {
    /** Lazy parsed result; NULL until first getter access. */
    pn_channel_groups_parsed_t* parsed;
    /** Allocator-owned encoded channel query value (nullable). */
    char* encoded_channels;
} pn_channel_groups_state_t;

/**
 * @brief Build the REST path for channel group operations.
 *
 * Encodes the group name into the request scratch buffer via
 * pn_request_scratch_encode (PN_ENCODE_FULL).
 *
 * Path: /v1/channel-registration/sub-key/{sub}/channel-group/{group}
 * With remove_group: .../channel-group/{group}/remove
 *
 * @param request       Populated with path segments on success.
 * @param subscribe_key Subscribe key (@b borrowed, NUL-terminated).
 * @param channel_group Channel group name (@b borrowed, NUL-terminated).
 * @param remove_group  Non-zero appends "remove" segment (delete group).
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_channel_groups_build_path(pubnub_http_request_t* request,
                                          const char*            subscribe_key,
                                          const char*            channel_group,
                                          int                    remove_group);

/**
 * @brief Lightweight response validator for channel group responses.
 *
 * Byte-scans for `"error"` key followed by `:` and `true` within a
 * bounded window (~150 bytes). No allocation.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return @c PUBNUB_OK on logical success; server-class error on failure.
 */
pubnub_res_t pn_channel_groups_response_validator(const uint8_t* body,
                                                  size_t         body_len,
                                                  int            http_status);

/**
 * @brief Parse the list-channels response to extract channel names.
 *
 * Expected shape:
 * @code
 * { "payload": { "channels": ["ch1", "ch2"] }, "status": 200 }
 * @endcode
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed body tree (borrowed; caller retains ownership).
 * @param out    Receives parsed result on success.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_SERIALIZATION.
 */
pubnub_res_t
pn_channel_groups_parse_list_response(pubnub_serialization_provider_t* serial,
                                      pubnub_json_value_t*             tree,
                                      pn_channel_groups_parsed_t*      out);

/**
 * @brief Cleanup for the channel groups slot's feature_state.
 *
 * @param state     The @ref pn_channel_groups_state_t pointer.
 * @param allocator Allocator for deallocation.
 */
void pn_channel_groups_feature_state_cleanup(void* state,
                                             pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_CHANNEL_GROUPS */

#endif /* PN_CHANNEL_GROUPS_INTERNAL_H */

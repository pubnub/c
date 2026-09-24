/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_API_INTERNAL_H
#define PN_PRESENCE_API_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_PRESENCE

#include "pubnub/error.h"
#include "pubnub/features/presence.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/types.h"

#include <stddef.h>
#include <stdint.h>

#include "pubnub/pubnub_compat.h"

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 9,
                     "Presence feature requires at least 9 path segments "
                     "(set-state uses 9)");

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Borrowed wire-level inputs for the here-now path builder.
 *
 * All pointer fields are borrowed and must remain valid until
 * dispatch completes.
 */
typedef struct pn_presence_here_now_wire_inputs {
    /** Subscribe key (NUL-terminated, required). */
    const char* subscribe_key;
    /** Pre-joined channel names, or NULL for global here-now. */
    const char* channels;
    /** Pre-joined channel-group names, or NULL. */
    const char* channel_groups;
    /** Non-zero to include UUIDs in the response. */
    uint8_t include_uuids;
    /** Non-zero to include per-user state objects. */
    uint8_t include_state;
    /** Maximum occupants to return per channel (0 = server default). */
    uint32_t limit;
    /** Zero-based index of the first occupant to return (0 = start). */
    uint32_t offset;
    /** Per-request timeout override (0 = use context default). */
    uint32_t timeout_ms;
} pn_presence_here_now_wire_inputs_t;

/**
 * @brief Borrowed wire-level inputs for the where-now path builder.
 */
typedef struct pn_presence_where_now_wire_inputs {
    /** Subscribe key (NUL-terminated, required). */
    const char* subscribe_key;
    /** UUID to look up (NUL-terminated, required). */
    const char* uuid;
    /** Per-request timeout override (0 = use context default). */
    uint32_t timeout_ms;
} pn_presence_where_now_wire_inputs_t;

/**
 * @brief Borrowed wire-level inputs for the set-state path builder.
 */
typedef struct pn_presence_set_state_wire_inputs {
    /** Subscribe key (NUL-terminated, required). */
    const char* subscribe_key;
    /** Pre-joined channel names (NUL-terminated, required). */
    const char* channels;
    /** Pre-joined channel-group names, or NULL. */
    const char* channel_groups;
    /** UUID to set state for (NUL-terminated, required). */
    const char* uuid;
    /** JSON state string (NUL-terminated, required). */
    const char* state;
    /** Length of @c state in bytes. */
    size_t state_len;
    /** Per-request timeout override (0 = use context default). */
    uint32_t timeout_ms;
} pn_presence_set_state_wire_inputs_t;

/**
 * @brief Borrowed wire-level inputs for the get-state path builder.
 */
typedef struct pn_presence_get_state_wire_inputs {
    /** Subscribe key (NUL-terminated, required). */
    const char* subscribe_key;
    /** Pre-joined channel names (NUL-terminated, required). */
    const char* channels;
    /** Pre-joined channel-group names, or NULL. */
    const char* channel_groups;
    /** UUID to query state for (NUL-terminated, required). */
    const char* uuid;
    /** Per-request timeout override (0 = use context default). */
    uint32_t timeout_ms;
} pn_presence_get_state_wire_inputs_t;

/**
 * @brief A single occupant entry within a here-now channel result.
 */
typedef struct pn_presence_here_now_occupant {
    /** UUID view into the parsed tree. */
    pubnub_string_view_t uuid;
    /** Raw JSON state view, or {NULL, 0} when absent. */
    pubnub_string_view_t state;
} pn_presence_here_now_occupant_t;

/**
 * @brief Per-channel occupancy detail in a here-now response.
 */
typedef struct pn_presence_here_now_channel {
    /** Channel name view into the parsed tree. */
    pubnub_string_view_t name;
    /** Occupancy count reported by the server. */
    uint32_t occupancy;
    /** Allocator-owned array of occupants (NULL when empty). */
    pn_presence_here_now_occupant_t* occupants;
    /** Number of entries in @c occupants. */
    size_t occupant_count;
} pn_presence_here_now_channel_t;

/**
 * @brief Fully parsed here-now response body.
 *
 * Allocator-owned; freed via @ref pn_presence_api_state_cleanup.
 */
typedef struct pn_presence_here_now_parsed {
    /** Server-reported total occupancy across all channels. */
    uint32_t total_occupancy;
    /** Server-reported total channel count. */
    uint32_t total_channels;
    /** Allocator-owned array of per-channel results. */
    pn_presence_here_now_channel_t* channels;
    /** Number of entries in @c channels. */
    size_t channel_count;
} pn_presence_here_now_parsed_t;

/**
 * @brief Fully parsed where-now response body.
 *
 * Allocator-owned; freed via @ref pn_presence_api_state_cleanup.
 */
typedef struct pn_presence_where_now_parsed {
    /** Allocator-owned array of channel name views. */
    pubnub_string_view_t* channels;
    /** Number of entries in @c channels. */
    size_t channel_count;
} pn_presence_where_now_parsed_t;

/**
 * @brief A single channel+state entry in a get-state response.
 */
typedef struct pn_presence_state_entry {
    /** Channel name view into the parsed tree. */
    pubnub_string_view_t channel;
    /** Borrowed pointer to the state node in the parsed tree. NULL when
     *  no state is set. Valid for the tree lifetime. */
    const pubnub_json_value_t* state;
} pn_presence_state_entry_t;

/**
 * @brief Fully parsed get-state (or set-state) response body.
 *
 * Allocator-owned; freed via @ref pn_presence_api_state_cleanup.
 */
typedef struct pn_presence_state_parsed {
    /** Allocator-owned array of channel+state entries. */
    pn_presence_state_entry_t* entries;
    /** Number of entries in @c entries. */
    size_t entry_count;
} pn_presence_state_parsed_t;

/**
 * @brief Discriminator for presence public-API request types.
 */
typedef enum pn_presence_op {
    /** Here-now request. */
    PN_PRESENCE_OP_HERE_NOW = 0,
    /** Where-now request. */
    PN_PRESENCE_OP_WHERE_NOW,
    /** Set-state request. */
    PN_PRESENCE_OP_SET_STATE,
    /** Get-state request. */
    PN_PRESENCE_OP_GET_STATE
} pn_presence_op_t;

/**
 * @brief Per-request feature state for presence public-API operations.
 *
 * Stored in @c pn_request_t::feature_state and cleaned up via
 * @ref pn_presence_api_state_cleanup.
 */
typedef struct pn_presence_api_state {
    /** Which presence operation this slot is serving. */
    pn_presence_op_t op;
    /** Non-zero when get-state targeted a single channel (affects
     *  response envelope shape). */
    uint8_t single_channel;

    /** Allocator-owned channel name for single-channel set/get-state
     *  (used to inject the channel into the parsed result entry).
     *  NULL when not applicable. */
    const char* channel_name;
    /** Length of @c channel_name in bytes. */
    size_t channel_name_len;

    /** Allocator-owned percent-encoded state string for set-state.
     *  Freed during cleanup. NULL when not applicable. */
    char* encoded_state;

    /** Lazy-parsed result; NULL until first accessor call. */
    union {
        pn_presence_here_now_parsed_t*  here_now;
        pn_presence_where_now_parsed_t* where_now;
        pn_presence_state_parsed_t*     state;
    } parsed;
} pn_presence_api_state_t;

/**
 * @brief Build the here-now HTTP request path and query parameters.
 *
 * @param request  Request descriptor to populate.
 * @param inputs   Wire-level inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_presence_build_here_now(pubnub_http_request_t* request,
                                        const pn_presence_here_now_wire_inputs_t* inputs);

/**
 * @brief Build the where-now HTTP request path and query parameters.
 *
 * @param request  Request descriptor to populate.
 * @param inputs   Wire-level inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_presence_build_where_now(pubnub_http_request_t*                     request,
                            const pn_presence_where_now_wire_inputs_t* inputs);

/**
 * @brief Build the set-state HTTP request path and query parameters.
 *
 * @param request  Request descriptor to populate.
 * @param inputs   Wire-level inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_presence_build_set_state(pubnub_http_request_t*                     request,
                            const pn_presence_set_state_wire_inputs_t* inputs);

/**
 * @brief Build the get-state HTTP request path and query parameters.
 *
 * @param request  Request descriptor to populate.
 * @param inputs   Wire-level inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_presence_build_get_state(pubnub_http_request_t*                     request,
                            const pn_presence_get_state_wire_inputs_t* inputs);

/**
 * @brief Parse a here-now JSON response into structured results.
 *
 * @param serial  Serialization provider (borrowed).
 * @param tree    Parsed response tree (borrowed, valid for tree
 *               lifetime).
 * @param alloc   Allocator for result arrays.
 * @param out     Receives parsed results on success.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_presence_parse_here_now(pubnub_serialization_provider_t* serial,
                                        const pubnub_json_value_t*       tree,
                                        pubnub_allocator_provider_t*     alloc,
                                        pn_presence_here_now_parsed_t*   out);

/**
 * @brief Parse a where-now JSON response into structured results.
 *
 * @param serial  Serialization provider (borrowed).
 * @param tree    Parsed response tree (borrowed).
 * @param alloc   Allocator for result arrays.
 * @param out     Receives parsed results on success.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_presence_parse_where_now(pubnub_serialization_provider_t* serial,
                                         const pubnub_json_value_t*      tree,
                                         pubnub_allocator_provider_t*    alloc,
                                         pn_presence_where_now_parsed_t* out);

/**
 * @brief Parse a get-state (or set-state) JSON response.
 *
 * @param serial          Serialization provider (borrowed).
 * @param tree            Parsed response tree (borrowed).
 * @param alloc           Allocator for result arrays.
 * @param out             Receives parsed results on success.
 * @param single_channel  Non-zero when the request targeted exactly
 *                        one channel (affects envelope shape).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_presence_parse_state(pubnub_serialization_provider_t* serial,
                                     const pubnub_json_value_t*       tree,
                                     pubnub_allocator_provider_t*     alloc,
                                     pn_presence_state_parsed_t*      out,
                                     uint8_t single_channel);

/**
 * @brief Minimal response validator probe for presence operations.
 *
 * Checks HTTP status and probes for a recognizable success envelope.
 * No allocation.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on logical success; server-class error otherwise.
 */
pubnub_res_t pn_presence_response_validator(const uint8_t* body,
                                            size_t         body_len,
                                            int            http_status);

/**
 * @brief Cleanup callback for @ref pn_presence_api_state_t.
 *
 * Frees all allocator-owned arrays within the parsed union based on
 * the @c op discriminator. Safe to call with NULL @p state.
 *
 * @param state  The @ref pn_presence_api_state_t pointer (or NULL).
 * @param alloc  Allocator for deallocation.
 */
void pn_presence_api_state_cleanup(void* state, pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_PRESENCE */

#endif /* PN_PRESENCE_API_INTERNAL_H */

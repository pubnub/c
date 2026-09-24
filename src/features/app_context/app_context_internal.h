/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_APP_CONTEXT_INTERNAL_H
#define PN_APP_CONTEXT_INTERNAL_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_internal.h requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "pubnub/error.h"
#include "pubnub/features/app_context.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

#include <stddef.h>
#include <stdint.h>

/** Forward declarations. */
struct pn_request;
typedef struct pn_request pn_request_t;
struct pn_pending_entry;
typedef struct pn_pending_entry pn_pending_entry_t;
struct pubnub_config;
typedef struct pubnub_config pubnub_config_t;

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Parsed response tree cached for lazy accessor access.
 *
 * The JSON tree is borrowed from the request slot (freed by
 * pn_request_pool_release, not by feature state cleanup). This
 * struct exists only to cache the tree pointer for repeated
 * accessor calls.
 */
typedef struct pn_app_context_parsed {
    /** Root of the parsed JSON tree (borrowed from slot). */
    pubnub_json_value_t* tree;
    /** Serialization provider (borrowed, for vtable access in parsers). */
    pubnub_serialization_provider_t* serial;
    /** Cached forward cursor for O(1) sequential indexed accessors. */
    pubnub_json_array_iter_t iter_cache;
    /** Index the cached cursor's next step will return. */
    size_t iter_pos;
    /** Non-zero when @ref iter_cache is usable (zero = restart). */
    uint8_t iter_valid;
} pn_app_context_parsed_t;

/**
 * @brief Per-request feature state for App Context operations.
 *
 * Attached to the request slot's feature_state field. Released via
 * @ref pn_app_context_feature_state_cleanup.
 */
typedef struct pn_app_context_state {
    /** Lazy-allocated parsed response cache (NULL until first access). */
    pn_app_context_parsed_t* parsed;
    /** Buffer for PATCH/POST request bodies (owned by allocator). */
    pubnub_buffer_t owned_body_buf;
    /** Allocator-owned URL-encoded path segment (uuid or channel ID). */
    char* encoded_path_segment;
} pn_app_context_state_t;

/**
 * @brief Cleanup callback for App Context per-request feature state.
 *
 * @param state     The @ref pn_app_context_state_t pointer.
 * @param allocator Allocator for deallocation.
 */
void pn_app_context_feature_state_cleanup(void* state,
                                          pubnub_allocator_provider_t* allocator);

/**
 * @brief Allocate and zero-initialize per-request feature state.
 *
 * @param allocator Allocator for the allocation (borrowed).
 * @return Zeroed state struct, or NULL on allocation failure.
 */
pn_app_context_state_t* pn_app_context_state_alloc(pubnub_allocator_provider_t* allocator);

/**
 * @brief Extract a string view from a named JSON object field.
 *
 * Looks up @p key in @p parent and, if found with string type,
 * assigns the result to @p out_view. No-op if absent or wrong type.
 *
 * @param serial   Serialization provider (borrowed).
 * @param parent   Parent object node (borrowed).
 * @param key      Field name (NUL-terminated).
 * @param key_len  Length of key (excluding NUL).
 * @param out_view Receives string view on success (caller-owned).
 */
static inline void pn_extract_obj_string(pubnub_serialization_provider_t* serial,
                                         pubnub_json_value_t*  parent,
                                         const char*           key,
                                         size_t                key_len,
                                         pubnub_string_view_t* out_view)
{
    pubnub_json_value_t* node = serial->object_get(parent, key, key_len);
    if (NULL != node) {
        size_t      len  = 0;
        const char* sptr = serial->value_as_string(node, &len);
        if (NULL != sptr) {
            out_view->ptr = sptr;
            out_view->len = len;
        }
    }
}

/**
 * @brief Lazy-parse the slot's response body and cache the result.
 *
 * @param slot   Request slot (borrowed).
 * @param future Future for context access.
 * @param state  Per-request feature state.
 * @return Cached parse, or NULL on failure.
 */
const pn_app_context_parsed_t*
pn_app_context_get_cached_parse(pn_request_t*           slot,
                                pubnub_future_t         future,
                                pn_app_context_state_t* state);

/**
 * @brief Add all common list query parameters.
 *
 * @param request Request to modify (borrowed).
 * @param include Include bitmask.
 * @param limit   Page size (0 = omit).
 * @param start   Next-page cursor (NULL = omit).
 * @param end     Prev-page cursor (NULL = omit).
 * @param filter  Filter expression (NULL = omit).
 * @param sort    Sort expression (NULL = omit).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_add_list_params(pubnub_http_request_t* request,
                                            uint32_t               include,
                                            uint32_t               limit,
                                            const char*            start,
                                            const char*            end,
                                            const char*            filter,
                                            const char*            sort);

/**
 * @brief Resolve the parsed feature state from a ready future slot.
 *
 * @param slot Request slot (borrowed).
 * @return Feature state, or NULL if not present.
 */
pn_app_context_state_t* pn_app_context_state_for_future(pn_request_t* slot);

/**
 * @brief Resolve slot and parsed cache for a result accessor.
 *
 * Combines the three-step prologue (ready-slot lookup, feature-state
 * extraction, cached-parse acquisition) into a single call. Returns
 * NULL when any step fails.
 *
 * @param future   Completed future to inspect.
 * @param out_slot Receives the resolved request slot (borrowed).
 * @return Cached parse, or NULL on failure.
 */
const pn_app_context_parsed_t*
pn_app_context_resolve_parsed(pubnub_future_t future, pn_request_t** out_slot);

/**
 * @brief Add the `include` query parameter based on a bitmask.
 *
 * Converts the bitmask to a comma-separated token string and appends
 * it as the `include` query parameter. Skips
 * PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT (handled separately by count param).
 *
 * @param request      Request to modify (borrowed).
 * @param include_mask Bitwise OR of PUBNUB_APP_CONTEXT_INCLUDE_* flags.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_add_include_param(pubnub_http_request_t* request,
                                              uint32_t include_mask);

/**
 * @brief Add an `If-Match` header for optimistic concurrency control.
 *
 * When @p if_match is non-NULL, its value is validated to contain no
 * CR or LF (guarding against header injection) and copied into the
 * request scratch buffer. Copying makes the request self-contained: the
 * header value survives a pending-queue round-trip even though the
 * caller's @p if_match pointer is only borrowed for the call.
 *
 * @param request  Request to modify (borrowed).
 * @param if_match ETag value (NUL-terminated, borrowed, NULL to skip).
 * @return PUBNUB_OK on success (including when @p if_match is NULL),
 *         PUBNUB_ERR_INVALID_ARGUMENT when @p request is NULL or the
 *         value contains CR/LF, or an allocation/capacity error code.
 */
pubnub_res_t pn_app_context_add_if_match(pubnub_http_request_t* request,
                                         const char*            if_match);

/**
 * @brief Add pagination query parameters when non-default.
 *
 * @param request Request to modify (borrowed).
 * @param limit   Page size (0 = omit).
 * @param start   Next-page cursor (NULL = omit, NUL-terminated).
 * @param end     Prev-page cursor (NULL = omit, NUL-terminated).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_add_pagination_params(pubnub_http_request_t* request,
                                                  uint32_t    limit,
                                                  const char* start,
                                                  const char* end);

/**
 * @brief Add the `filter` query parameter when non-NULL.
 *
 * @param request Request to modify (borrowed).
 * @param filter  Filter expression (NUL-terminated, borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_add_filter_param(pubnub_http_request_t* request,
                                             const char*            filter);

/**
 * @brief Add the `sort` query parameter when non-NULL.
 *
 * @param request Request to modify (borrowed).
 * @param sort    Sort expression (NUL-terminated, borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_add_sort_param(pubnub_http_request_t* request,
                                           const char*            sort);

/**
 * @brief Add `count=true` query parameter when TOTAL_COUNT is set.
 *
 * @param request      Request to modify (borrowed).
 * @param include_mask Bitwise OR of PUBNUB_APP_CONTEXT_INCLUDE_* flags.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_add_count_param(pubnub_http_request_t* request,
                                            uint32_t include_mask);

/**
 * @brief Attach a "custom" JSON field to an object node.
 *
 * Handles both the pre-built value-tree path and the raw-string path.
 * On failure, destroys @p custom_value (if non-NULL) before returning.
 * No-op (returns PUBNUB_OK) when both custom inputs are NULL.
 *
 * @param serial        Serialization provider (borrowed).
 * @param obj           Target JSON object to attach "custom" to.
 * @param custom_value  Pre-built JSON tree (ownership transfers on
 *                      success; destroyed on failure). NULL to skip.
 * @param custom_raw    Raw JSON string (NULL to skip).
 * @param custom_raw_len Length of custom_raw (0 = use strlen).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_app_context_set_custom_field(pubnub_serialization_provider_t* serial,
                                             pubnub_json_value_t* obj,
                                             pubnub_json_value_t* custom_value,
                                             const char*          custom_raw,
                                             size_t custom_raw_len);

/**
 * @brief Response validator probe for App Context endpoints.
 *
 * Checks HTTP 2xx and that body starts with '{'. No allocation.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on logical success, PUBNUB_ERR_SERVER otherwise.
 */
pubnub_res_t pn_app_context_response_validator(const uint8_t* body,
                                               size_t         body_len,
                                               int            http_status);

/**
 * @brief Extract pagination metadata from a parsed response tree.
 *
 * Reads `totalCount`, `next`, `prev` from the root object and counts
 * the `data` array size.
 *
 * @param serial   Serialization provider (borrowed).
 * @param tree     Parsed response root (borrowed, must be object).
 * @param out_page Receives pagination metadata (caller-owned).
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERIALIZATION if the
 *         envelope is malformed.
 */
pubnub_res_t pn_app_context_parse_page(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       tree,
                                       pubnub_app_context_page_t* out_page);

/**
 * @brief Get the "data" array from the response envelope.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed response root (borrowed).
 * @return Borrowed pointer to the data array node, or NULL if absent.
 */
pubnub_json_value_t*
pn_app_context_get_data_array(pubnub_serialization_provider_t* serial,
                              const pubnub_json_value_t*       tree);

/**
 * @brief Get the "data" object from the response envelope.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed response root (borrowed).
 * @return Borrowed pointer to the data object node, or NULL if absent.
 */
pubnub_json_value_t*
pn_app_context_get_data_object(pubnub_serialization_provider_t* serial,
                               const pubnub_json_value_t*       tree);

/**
 * @brief Build path segments for GET all UUID metadata.
 *
 * Populates: ["v2", "objects", "{sub_key}", "uuids"]
 *
 * @param request       Request to modify (borrowed).
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_uuid_metadata_build_path_get_all(pubnub_http_request_t* request,
                                                 const char* subscribe_key);

/**
 * @brief Build path segments for single UUID metadata operations.
 *
 * Populates: ["v2", "objects", "{sub_key}", "uuids", "{uuid}"]
 * The UUID segment is URL-encoded via heap allocation.
 *
 * @param request       Request to modify (borrowed).
 * @param allocator     Allocator for the encoded segment (borrowed).
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @param uuid          UUID to encode (NUL-terminated, borrowed).
 * @param out_encoded   Receives allocator-owned encoded string for
 *                      cleanup by the caller.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_uuid_metadata_build_path_single(pubnub_http_request_t* request,
                                                pubnub_allocator_provider_t* allocator,
                                                const char* subscribe_key,
                                                const char* uuid,
                                                char**      out_encoded);

/**
 * @brief Serialize a UUID metadata PATCH body from options.
 *
 * Builds a JSON object containing only non-NULL fields from opts and
 * serializes it into body_buf, growing the buffer via @p alloc when
 * the initial capacity is insufficient.
 *
 * @param serial   Serialization provider (borrowed).
 * @param alloc    Allocator for buffer growth (borrowed, may be NULL).
 * @param opts     Set UUID metadata options (borrowed).
 * @param body_buf Buffer to receive serialized body. Must have
 *                 non-NULL data and non-zero cap on entry;
 *                 len is set on success.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_uuid_metadata_build_body(pubnub_serialization_provider_t* serial,
                                         pubnub_allocator_provider_t* alloc,
                                         const pubnub_set_uuid_metadata_opts_t* opts,
                                         pubnub_buffer_t* body_buf);

/**
 * @brief Parse a UUID metadata object from a JSON "data" node.
 *
 * Extracts all known fields into out. String views alias the parsed
 * tree and are valid until the tree is destroyed.
 *
 * @param serial    Serialization provider (borrowed).
 * @param data_node Parsed "data" object node (borrowed).
 * @param out       Receives parsed metadata (caller-owned).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_uuid_metadata_parse(pubnub_serialization_provider_t* serial,
                                    const pubnub_json_value_t*       data_node,
                                    pubnub_uuid_metadata_t*          out);

/**
 * @brief Build path segments for GET all channel metadata.
 *
 * Populates: ["v2", "objects", "{sub_key}", "channels"]
 *
 * @param request       Request to modify (borrowed).
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_channel_metadata_build_path_get_all(pubnub_http_request_t* request,
                                                    const char* subscribe_key);

/**
 * @brief Build path segments for single channel metadata operations.
 *
 * Populates: ["v2", "objects", "{sub_key}", "channels", "{channel}"]
 * The channel segment is URL-encoded via heap allocation.
 *
 * @param request       Request to modify (borrowed).
 * @param allocator     Allocator for the encoded segment (borrowed).
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @param channel       Channel to encode (NUL-terminated, borrowed).
 * @param out_encoded   Receives allocator-owned encoded string for
 *                      cleanup by the caller.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_channel_metadata_build_path_single(pubnub_http_request_t* request,
                                                   pubnub_allocator_provider_t* allocator,
                                                   const char* subscribe_key,
                                                   const char* channel,
                                                   char**      out_encoded);

/**
 * @brief Serialize a channel metadata PATCH body from options.
 *
 * Builds a JSON object containing only non-NULL fields from opts and
 * serializes it into body_buf, growing the buffer via @p alloc when
 * the initial capacity is insufficient.
 *
 * @param serial   Serialization provider (borrowed).
 * @param alloc    Allocator for buffer growth (borrowed, may be NULL).
 * @param opts     Set channel metadata options (borrowed).
 * @param body_buf Buffer to receive serialized body. Must have
 *                 non-NULL data and non-zero cap on entry;
 *                 len is set on success.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_channel_metadata_build_body(pubnub_serialization_provider_t*          serial,
                               pubnub_allocator_provider_t*              alloc,
                               const pubnub_set_channel_metadata_opts_t* opts,
                               pubnub_buffer_t* body_buf);

/**
 * @brief Parse a channel metadata object from a JSON "data" node.
 *
 * Extracts all known fields into out. String views alias the parsed
 * tree and are valid until the tree is destroyed.
 *
 * @param serial    Serialization provider (borrowed).
 * @param data_node Parsed "data" object node (borrowed).
 * @param out       Receives parsed metadata (caller-owned).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_channel_metadata_parse(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t* data_node,
                                       pubnub_channel_metadata_t* out);

/**
 * @brief Build path segments for membership operations (UUID→channels).
 *
 * Populates: ["v2", "objects", "{sub_key}", "uuids", "{uuid}", "channels"]
 * The UUID segment is URL-encoded via heap allocation.
 *
 * @param request       Request to modify (borrowed).
 * @param allocator     Allocator for the encoded segment (borrowed).
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @param uuid          UUID to encode (NUL-terminated, borrowed).
 * @param out_encoded   Receives allocator-owned encoded string for
 *                      cleanup by the caller.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_memberships_build_path(pubnub_http_request_t*       request,
                                       pubnub_allocator_provider_t* allocator,
                                       const char* subscribe_key,
                                       const char* uuid,
                                       char**      out_encoded);

/**
 * @brief Build path segments for member operations (channel→UUIDs).
 *
 * Populates: ["v2", "objects", "{sub_key}", "channels", "{channel}", "uuids"]
 * The channel segment is URL-encoded via heap allocation.
 *
 * @param request       Request to modify (borrowed).
 * @param allocator     Allocator for the encoded segment (borrowed).
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @param channel       Channel to encode (NUL-terminated, borrowed).
 * @param out_encoded   Receives allocator-owned encoded string for
 *                      cleanup by the caller.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_members_build_path(pubnub_http_request_t*       request,
                                   pubnub_allocator_provider_t* allocator,
                                   const char*                  subscribe_key,
                                   const char*                  channel,
                                   char**                       out_encoded);

/**
 * @brief Build PATCH body for membership set/remove operations.
 *
 * Constructs a JSON object with "set" and/or "delete" arrays. Set
 * items include the channel identifier and optional status/type/custom.
 * Remove items include only the channel identifier. The buffer is
 * grown via @p alloc when the initial capacity is insufficient.
 *
 * @param serial       Serialization provider (borrowed).
 * @param alloc        Allocator for buffer growth (borrowed, may be NULL).
 * @param set_items    Array of items to set (NULL if set_count is 0).
 * @param set_count    Number of set items.
 * @param remove_items Array of items to remove (NULL if remove_count is 0).
 * @param remove_count Number of remove items.
 * @param body_buf     Buffer to receive serialized body. Must have
 *                     non-NULL data and non-zero cap on entry;
 *                     len is set on success.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_memberships_build_body(pubnub_serialization_provider_t* serial,
                                       pubnub_allocator_provider_t*     alloc,
                                       const pubnub_membership_input_t* set_items,
                                       size_t set_count,
                                       const pubnub_membership_input_t* remove_items,
                                       size_t           remove_count,
                                       pubnub_buffer_t* body_buf);

/**
 * @brief Build PATCH body for member set/remove operations.
 *
 * Constructs a JSON object with "set" and/or "delete" arrays. Set
 * items include the UUID identifier and optional status/type/custom.
 * Remove items include only the UUID identifier. The buffer is grown
 * via @p alloc when the initial capacity is insufficient.
 *
 * @param serial       Serialization provider (borrowed).
 * @param alloc        Allocator for buffer growth (borrowed, may be NULL).
 * @param set_items    Array of items to set (NULL if set_count is 0).
 * @param set_count    Number of set items.
 * @param remove_items Array of items to remove (NULL if remove_count is 0).
 * @param remove_count Number of remove items.
 * @param body_buf     Buffer to receive serialized body. Must have
 *                     non-NULL data and non-zero cap on entry;
 *                     len is set on success.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_members_build_body(pubnub_serialization_provider_t* serial,
                                   pubnub_allocator_provider_t*     alloc,
                                   const pubnub_member_input_t*     set_items,
                                   size_t                           set_count,
                                   const pubnub_member_input_t* remove_items,
                                   size_t                       remove_count,
                                   pubnub_buffer_t*             body_buf);

/**
 * @brief Parse a membership object from a JSON "data" node.
 *
 * Extracts the "channel" sub-object via @ref pn_channel_metadata_parse
 * and the relationship-level fields (status, type, custom, updated,
 * eTag). String views alias the parsed tree lifetime.
 *
 * @param serial    Serialization provider (borrowed).
 * @param data_node Parsed "data" object node (borrowed).
 * @param out       Receives parsed membership (caller-owned).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_membership_parse(pubnub_serialization_provider_t* serial,
                                 const pubnub_json_value_t*       data_node,
                                 pubnub_membership_t*             out);

/**
 * @brief Parse a member object from a JSON "data" node.
 *
 * Extracts the "uuid" sub-object via @ref pn_uuid_metadata_parse and
 * the relationship-level fields (status, type, custom, updated, eTag).
 * String views alias the parsed tree lifetime.
 *
 * @param serial    Serialization provider (borrowed).
 * @param data_node Parsed "data" object node (borrowed).
 * @param out       Receives parsed member (caller-owned).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_member_parse(pubnub_serialization_provider_t* serial,
                             const pubnub_json_value_t*       data_node,
                             pubnub_member_t*                 out);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_APP_CONTEXT_INTERNAL_H */

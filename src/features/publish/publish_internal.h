/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file publish_internal.h
 * @brief Internal declarations shared between publish_api.c and
 *        publish_wire.c.
 */

#ifndef PN_PUBLISH_INTERNAL_H
#define PN_PUBLISH_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_PUBLISH

#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Parsed decomposition of a publish response body.
 */
typedef struct pn_publish_parsed {
    /** Timetoken view (aliases parsed tree; valid until future release). */
    pubnub_timetoken_t timetoken;
} pn_publish_parsed_t;

/**
 * @brief Per-request state for @ref pubnub_publish.
 *
 * Covers both string and value-tree paths. Released via
 * @ref pn_publish_feature_state_cleanup.
 */
typedef struct pn_publish_state {
    /** Lazy parsed result; NULL until first getter access. */
    pn_publish_parsed_t* parsed;
    /** Allocator-owned percent-encoded channel, or NULL. */
    char* encoded_channel;
    /** Allocator-owned percent-encoded message, or NULL (POST-style). */
    char* encoded_message;
    /** Buffer whose lifetime extends until slot cleanup (POST body). */
    pubnub_buffer_t owned_body_buf;
    /** Allocator-owned encrypted+quoted payload, or NULL when crypto
     *  is inactive. Freed on state cleanup. */
    char* encrypted_payload;
    /** 1 once the response parse has been cached in @c parsed.
     *  Uses acquire/release semantics for concurrent readers. */
    PUBNUB_ATOMIC_UINT8 parsed_cached;
} pn_publish_state_t;

/**
 * @brief Inputs to the publish path builder.
 */
typedef struct pn_publish_path_inputs {
    /** Publisher key (@b borrowed, NUL-terminated). */
    const char* publish_key;
    /** Subscriber key (@b borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (@b borrowed, NUL-terminated). */
    const char* channel;
    /** Pre-serialized message bytes (@b borrowed; NULL only when
     *  include_message is 0). */
    const uint8_t* serialized;
    /** Length of @c serialized in bytes. */
    size_t serialized_len;
    /** Non-zero = GET-style (message in path); 0 = POST-style. */
    int include_message;
} pn_publish_path_inputs_t;

/**
 * @brief Allocator-owned URL-percent-encoded path strings.
 */
typedef struct pn_publish_url_encoded {
    /** URL-percent-encoded channel (allocator-owned). */
    char* channel;
    /** URL-percent-encoded message, or NULL for POST-style. */
    char* message;
} pn_publish_url_encoded_t;

/**
 * @brief Serialize a JSON value tree into a caller-provided buffer.
 *
 * @param serialization Serialization provider (borrowed, non-NULL).
 * @param value         Value tree to serialize (borrowed, non-NULL).
 * @param buf           Output buffer (non-NULL).
 * @param buf_cap       Capacity of @p buf in bytes.
 * @param out_len       Receives bytes written on success.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_publish_serialize_json_value(pubnub_serialization_provider_t* serialization,
                                             const pubnub_json_value_t* value,
                                             uint8_t*                   buf,
                                             size_t                     buf_cap,
                                             size_t* out_len);

/**
 * @brief Build the REST publish path into @p request's path_segments.
 *
 * @param request   Populated with path segments on success.
 * @param allocator For URL-encode allocations (@b borrowed).
 * @param in        Path inputs (@b borrowed).
 * @param out       Receives allocator-owned encoded buffers on success.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_publish_build_path(pubnub_http_request_t*          request,
                                   pubnub_allocator_provider_t*    allocator,
                                   const pn_publish_path_inputs_t* in,
                                   pn_publish_url_encoded_t*       out);

/**
 * @brief Append publish-specific query parameters to @p request.
 *
 * @param request             Request to populate.
 * @param opts_meta           Non-zero to emit a meta query param.
 * @param meta_text           Pre-serialized meta JSON (@b borrowed,
 *                            NUL-terminated; NULL to skip).
 * @param meta_len            Length of meta_text (ignored when NULL).
 * @param store               Storage override.
 * @param ttl                 Per-message TTL in hours; 0 omits.
 * @param custom_message_type Optional label; NULL omits.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_publish_add_query_params(pubnub_http_request_t* request,
                                         int                    opts_meta,
                                         const char*            meta_text,
                                         size_t                 meta_len,
                                         pubnub_publish_store_t store,
                                         unsigned int           ttl,
                                         const char* custom_message_type);

/**
 * @brief Minimal response validator probe for publish.
 *
 * Checks array[0] digit for success (1) vs failure (0). Scans
 * at most ~20 bytes. No allocation.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return @c PUBNUB_OK on logical success; server-class error on logical
 *         failure.
 */
pubnub_res_t pn_publish_response_validator(const uint8_t* body,
                                           size_t         body_len,
                                           int            http_status);

/**
 * @brief Extract the publish timetoken from a parsed response tree.
 *
 * Expected shape: `[<status>,"<message>","<timetoken>"]`.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed body tree (borrowed).
 * @param out    Receives timetoken; zero-initialized on failure.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_SERIALIZATION.
 */
pubnub_res_t pn_publish_parse_response(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       tree,
                                       pn_publish_parsed_t*             out);

/**
 * @brief Cleanup for the publish slot's feature_state.
 *
 * @param state     The @ref pn_publish_state_t pointer.
 * @param allocator Allocator for deallocation.
 */
void pn_publish_feature_state_cleanup(void*                        state,
                                      pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_PUBLISH */

#endif /* PN_PUBLISH_INTERNAL_H */

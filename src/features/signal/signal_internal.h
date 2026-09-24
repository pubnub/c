/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_SIGNAL_INTERNAL_H
#define PN_SIGNAL_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_SIGNAL

#include "pubnub/error.h"
#include "pubnub/features/signal.h"
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
 * @brief Parsed decomposition of a signal response body.
 */
typedef struct pn_signal_parsed {
    /** Timetoken view (aliases parsed tree; valid until future release). */
    pubnub_timetoken_t timetoken;
} pn_signal_parsed_t;

/**
 * @brief Per-request state for @ref pubnub_signal.
 *
 * Released via @ref pn_signal_feature_state_cleanup.
 */
typedef struct pn_signal_state {
    /** Lazy parsed result; NULL until first getter access. */
    pn_signal_parsed_t* parsed;
    /** Allocator-owned percent-encoded channel, or NULL. */
    char* encoded_channel;
    /** Allocator-owned percent-encoded message, or NULL. */
    char* encoded_message;
} pn_signal_state_t;

/**
 * @brief Inputs to the signal path builder.
 */
typedef struct pn_signal_path_inputs {
    /** Publisher key (@b borrowed, NUL-terminated). */
    const char* publish_key;
    /** Subscriber key (@b borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (@b borrowed, NUL-terminated). */
    const char* channel;
    /** Pre-serialized message bytes (@b borrowed). */
    const uint8_t* serialized;
    /** Length of @c serialized in bytes. */
    size_t serialized_len;
} pn_signal_path_inputs_t;

/**
 * @brief Allocator-owned URL-percent-encoded path strings.
 */
typedef struct pn_signal_url_encoded {
    /** URL-percent-encoded channel (allocator-owned). */
    char* channel;
    /** URL-percent-encoded message (allocator-owned). */
    char* message;
} pn_signal_url_encoded_t;

/**
 * @brief Build the REST signal path into @p request's path_segments.
 *
 * Path layout: `/signal/{pub}/{sub}/0/{channel}/0/{payload}`
 *
 * @param request   Populated with path segments on success.
 * @param allocator For URL-encode allocations (@b borrowed).
 * @param in        Path inputs (@b borrowed).
 * @param out       Receives allocator-owned encoded buffers on success.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_signal_build_path(pubnub_http_request_t*         request,
                                  pubnub_allocator_provider_t*   allocator,
                                  const pn_signal_path_inputs_t* in,
                                  pn_signal_url_encoded_t*       out);

/**
 * @brief Append signal-specific query parameters to @p request.
 *
 * @param request             Request to populate.
 * @param custom_message_type Optional label; NULL omits.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_signal_add_query_params(pubnub_http_request_t* request,
                                        const char* custom_message_type);

/**
 * @brief Minimal response validator probe for signal.
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
pubnub_res_t pn_signal_response_validator(const uint8_t* body,
                                          size_t         body_len,
                                          int            http_status);

/**
 * @brief Extract the signal timetoken from a parsed response tree.
 *
 * Expected shape: `[<status>,"<message>","<timetoken>"]`.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed body tree (borrowed).
 * @param out    Receives timetoken; zero-initialized on failure.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_SERIALIZATION.
 */
pubnub_res_t pn_signal_parse_response(pubnub_serialization_provider_t* serial,
                                      const pubnub_json_value_t*       tree,
                                      pn_signal_parsed_t*              out);

/**
 * @brief Cleanup for the signal slot's feature_state.
 *
 * @param state     The @ref pn_signal_state_t pointer.
 * @param allocator Allocator for deallocation.
 */
void pn_signal_feature_state_cleanup(void*                        state,
                                     pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_SIGNAL */

#endif /* PN_SIGNAL_INTERNAL_H */

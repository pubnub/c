/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_ACCESS_INTERNAL_H
#define PN_ACCESS_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_PAM

#include "pubnub/error.h"
#include "pubnub/features/access.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

#include "pn_cbor.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Parsed decomposition of a grant_token response body.
 */
typedef struct pn_access_grant_parsed {
    /** Token string view (aliases the parsed body tree). */
    pubnub_string_view_t token;
} pn_access_grant_parsed_t;

/**
 * @brief Per-request feature state for grant/revoke operations.
 *
 * Attached to the request slot via feature_state. Released via
 * @ref pn_access_feature_state_cleanup.
 */
typedef struct pn_access_state {
    /** Lazy-parsed grant result; NULL until first accessor call. */
    pn_access_grant_parsed_t* parsed;
    /** URL-encoded token for revoke path (allocator-owned). */
    char* encoded_token;
    /** POST body buffer for grant (buf_acquire-owned). */
    pubnub_buffer_t owned_body_buf;
} pn_access_state_t;

/**
 * @brief Per-context state for parse_token result caching.
 *
 * Stored in the feature registry. Replaced on each call to
 * @ref pubnub_parse_token. Released via
 * @ref pn_access_token_state_cleanup.
 */
typedef struct pn_access_token_state {
    /** Decoded CBOR tree (allocator-owned). */
    pn_cbor_value_t* parsed_tree;
    /** Raw decoded bytes; CBOR string nodes alias this buffer. */
    uint8_t* decoded_buf;
    /** Cached parsed result populated from the CBOR tree. */
    pubnub_parsed_token_t result;
} pn_access_token_state_t;

/**
 * @brief Build the grant_token REST path into request path_segments.
 *
 * Populates: `/v3/pam/{subscribe_key}/grant`.
 *
 * @param request       Request to populate (borrowed).
 * @param subscribe_key Subscriber key (borrowed, NUL-terminated).
 * @return @c PUBNUB_OK on success, or an error code on overflow.
 */
pubnub_res_t pn_access_grant_build_path(pubnub_http_request_t* request,
                                        const char*            subscribe_key);

/**
 * @brief Serialize the grant_token JSON request body.
 *
 * Builds the JSON envelope containing TTL, permissions, and
 * optional metadata, then serializes into the provided buffer.
 *
 * @param serial  Serialization provider (borrowed).
 * @param opts    Grant-token options (borrowed).
 * @param buf     Output buffer for serialized body.
 * @param cap     Capacity of @p buf in bytes.
 * @param out_len Receives bytes written on success.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_access_grant_build_body(pubnub_serialization_provider_t* serial,
                                        const pubnub_grant_token_opts_t* opts,
                                        uint8_t*                         buf,
                                        size_t                           cap,
                                        size_t* out_len);

/**
 * @brief Build the revoke_token REST path into request path_segments.
 *
 * Populates: `/v3/pam/{subscribe_key}/grant/{encoded_token}`.
 * The token is URL-encoded via the allocator and returned via
 * @p out_encoded_token for later cleanup.
 *
 * @param request           Request to populate (borrowed).
 * @param alloc             Allocator for encoding (borrowed).
 * @param subscribe_key     Subscriber key (borrowed, NUL-terminated).
 * @param token             Raw token string (borrowed, NUL-terminated).
 * @param out_encoded_token Receives allocator-owned encoded token on
 *                          success; caller must free via @p alloc.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_access_revoke_build_path(pubnub_http_request_t*       request,
                                         pubnub_allocator_provider_t* alloc,
                                         const char* subscribe_key,
                                         const char* token,
                                         char**      out_encoded_token);

/**
 * @brief Minimal response validator probe for grant_token.
 *
 * Checks HTTP status and body for logical success indicators.
 * No allocation.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return @c PUBNUB_OK on logical success, or an error code.
 */
pubnub_res_t pn_access_grant_response_validator(const uint8_t* body,
                                                size_t         body_len,
                                                int            http_status);

/**
 * @brief Extract the token from a parsed grant_token response tree.
 *
 * Expected shape: `{"data":{"token":"..."}}`.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed response body tree (borrowed).
 * @param out    Receives token view; zero-initialized on failure.
 * @return @c PUBNUB_OK on success, or
 *         @c PUBNUB_ERR_SERIALIZATION on malformed response.
 */
pubnub_res_t pn_access_grant_parse_response(pubnub_serialization_provider_t* serial,
                                            const pubnub_json_value_t* tree,
                                            pn_access_grant_parsed_t*  out);

/**
 * @brief Decode a base64url-encoded access token into parsed form.
 *
 * Performs base64url decode, CBOR parse, and field extraction.
 * Populates the output state with the decoded CBOR tree and
 * the extracted result fields.
 *
 * @param token Raw base64url token string (borrowed, NUL-terminated).
 * @param alloc Allocator for CBOR tree nodes (borrowed).
 * @param out   Output state; populated on success. On failure,
 *              partially-allocated memory is cleaned up internally.
 * @return @c PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_access_parse_token_impl(const char*                  token,
                                        pubnub_allocator_provider_t* alloc,
                                        pn_access_token_state_t*     out);

/**
 * @brief Cleanup callback for per-request PAM feature state.
 *
 * Frees encoded_token, releases owned_body_buf, and frees the
 * parsed struct if present.
 *
 * @param state The @ref pn_access_state_t pointer (or NULL).
 * @param alloc Allocator for deallocation (or NULL).
 */
void pn_access_feature_state_cleanup(void*                        state,
                                     pubnub_allocator_provider_t* alloc);

/**
 * @brief Cleanup callback for per-context token parse state.
 *
 * Frees the CBOR tree and any associated memory.
 *
 * @param state The @ref pn_access_token_state_t pointer (or NULL).
 * @param alloc Allocator for deallocation (or NULL).
 */
void pn_access_token_state_cleanup(void* state, pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_PAM */

#endif /* PN_ACCESS_INTERNAL_H */

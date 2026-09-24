/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PUSH_INTERNAL_H
#define PN_PUSH_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_PUSH_NOTIFICATIONS

#include "pubnub/error.h"
#include "pubnub/features/push.h"
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

/** @brief Parsed decomposition of a list-channels response. */
typedef struct pn_push_list_parsed {
    /** Number of channels in the parsed array. */
    uint32_t channel_count;
    /** Parsed JSON tree (ownership: kept alive by slot response). */
    const pubnub_json_value_t* tree;
    /** Cached forward cursor for O(1) sequential indexed accessors. */
    pubnub_json_array_iter_t iter_cache;
    /** Index the cached cursor's next step will return. */
    size_t iter_pos;
    /** Non-zero when @ref iter_cache is usable (zero = restart). */
    uint8_t iter_valid;
} pn_push_list_parsed_t;

/** @brief Per-request state for push operations. */
typedef struct pn_push_state {
    /** Lazy-parsed result for list; NULL for mutations. */
    pn_push_list_parsed_t* parsed;
    /** Heap-allocated encoded channel list, or NULL. */
    char* encoded_channels;
} pn_push_state_t;

/** @brief Inputs to the push path builder. */
typedef struct pn_push_path_inputs {
    /** Subscriber key (borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Device token (borrowed, NUL-terminated). */
    const char* device;
    /** Gateway type. */
    pubnub_push_gateway_t gateway;
    /** Non-zero to append "/remove" suffix. */
    int append_remove;
} pn_push_path_inputs_t;

/**
 * @brief Build the REST path for a push operation.
 *
 * @param request HTTP request (path_segments populated).
 * @param in Path inputs (sub key, device, gateway, remove flag).
 * @return PUBNUB_OK on success, or an error code on validation/scratch failure.
 */
pubnub_res_t pn_push_build_path(pubnub_http_request_t*       request,
                                const pn_push_path_inputs_t* in);

/**
 * @brief Append gateway-type query parameters (type, environment, topic).
 *
 * @param request HTTP request (query_params populated).
 * @param gateway Gateway type.
 * @param environment APNS environment (ignored for non-APNS).
 * @param topic FCM topic (ignored for non-FCM).
 * @return PUBNUB_OK on success, or an error code on scratch failure.
 */
pubnub_res_t pn_push_add_gateway_params(pubnub_http_request_t*    request,
                                        pubnub_push_gateway_t     gateway,
                                        pubnub_push_environment_t environment,
                                        const char*               topic);

/**
 * @brief Append the `add` query parameter with heap-encoded channels.
 *
 * @param request HTTP request (query_params populated).
 * @param encoded_channels Heap-allocated URL-encoded comma-separated channel
 *                         list (borrowed).
 * @return PUBNUB_OK on success, or an error code on scratch failure.
 */
pubnub_res_t pn_push_add_channels_param(pubnub_http_request_t* request,
                                        const char* encoded_channels);

/**
 * @brief Append the `remove` query parameter with heap-encoded channels.
 *
 * @param request HTTP request (query_params populated).
 * @param encoded_channels Heap-allocated URL-encoded comma-separated channel
 *                         list (borrowed).
 * @return PUBNUB_OK on success, or an error code on scratch failure.
 */
pubnub_res_t pn_push_remove_channels_param(pubnub_http_request_t* request,
                                           const char* encoded_channels);

/**
 * @brief Append pagination params (start, count) for list operation.
 *
 * @param request HTTP request (query_params populated).
 * @param start Pagination start token (may be NULL).
 * @param count Maximum channels to return (0 = server default).
 * @return PUBNUB_OK on success, or an error code on scratch failure.
 */
pubnub_res_t pn_push_add_list_params(pubnub_http_request_t* request,
                                     const char*            start,
                                     uint16_t               count);

/**
 * @brief Response validator for mutation operations (add/remove/remove_device).
 *
 * @param body HTTP response body.
 * @param body_len Length of body in bytes.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK if validation succeeds, or an error code for malformed
 *         responses.
 */
pubnub_res_t pn_push_mutation_response_validator(const uint8_t* body,
                                                 size_t         body_len,
                                                 int            http_status);

/**
 * @brief Response validator for list-channels operation.
 *
 * @param body HTTP response body.
 * @param body_len Length of body in bytes.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK if validation succeeds, or an error code for malformed
 *         responses.
 */
pubnub_res_t pn_push_list_response_validator(const uint8_t* body,
                                             size_t         body_len,
                                             int            http_status);

/**
 * @brief Parse a list-channels response array.
 *
 * @param serial Serialization provider.
 * @param tree Parsed JSON response tree (contains top-level array).
 * @param out Output parsed decomposition (channel_count, tree pointer).
 * @return PUBNUB_OK on success, or an error code on parse failure.
 */
pubnub_res_t pn_push_list_parse_response(pubnub_serialization_provider_t* serial,
                                         const pubnub_json_value_t* tree,
                                         pn_push_list_parsed_t*     out);

/**
 * @brief Cleanup for the push slot's feature_state.
 *
 * @param state Opaque pn_push_state_t pointer.
 * @param allocator Allocator provider for freeing heap memory.
 */
void pn_push_feature_state_cleanup(void*                        state,
                                   pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_PUSH_NOTIFICATIONS */

#endif /* PN_PUSH_INTERNAL_H */

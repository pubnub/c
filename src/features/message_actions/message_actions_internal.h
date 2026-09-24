/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_MESSAGE_ACTIONS_INTERNAL_H
#define PN_MESSAGE_ACTIONS_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_MESSAGE_ACTIONS

#include "pubnub/error.h"
#include "pubnub/features/message_actions.h"
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

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 9,
                     "Remove Message Action requires at least 9 path segments");

/** @brief Operation discriminator for per-request feature state. */
typedef enum pn_message_actions_op {
    PN_MESSAGE_ACTIONS_OP_ADD = 0,
    PN_MESSAGE_ACTIONS_OP_GET,
    PN_MESSAGE_ACTIONS_OP_REMOVE
} pn_message_actions_op_t;

/** @brief Parsed single action (shared between add result and get array). */
typedef struct pn_message_actions_action_parsed {
    pubnub_string_view_t type;
    pubnub_string_view_t value;
    pubnub_string_view_t uuid;
    pubnub_string_view_t action_timetoken;
    pubnub_string_view_t message_timetoken;
} pn_message_actions_action_parsed_t;

/** @brief Parsed result for the get-message-actions operation. */
typedef struct pn_message_actions_get_parsed {
    /** Allocator-owned array of parsed actions. */
    pn_message_actions_action_parsed_t* actions;
    size_t                              count;
    uint8_t                             has_more;
    pubnub_string_view_t                more_start;
    pubnub_string_view_t                more_end;
    uint32_t                            more_limit;
} pn_message_actions_get_parsed_t;

/** @brief Per-request feature state for message actions. */
typedef struct pn_message_actions_state {
    pn_message_actions_op_t op;

    /** Body buffer acquired for POST serialization (add op). */
    pubnub_buffer_t owned_body_buf;

    union {
        /** Single action result (add). Allocator-owned. */
        pn_message_actions_action_parsed_t* add;
        /** Array + pagination (get). Allocator-owned. */
        pn_message_actions_get_parsed_t* get;
    } parsed;
} pn_message_actions_state_t;

/** @brief Wire inputs for the add operation. */
typedef struct pn_message_actions_add_wire_inputs {
    const char* subscribe_key;
    const char* channel;
    const char* message_timetoken;
    const char* type;
    const char* value;
    uint32_t    timeout_ms;
} pn_message_actions_add_wire_inputs_t;

/** @brief Wire inputs for the get operation. */
typedef struct pn_message_actions_get_wire_inputs {
    const char* subscribe_key;
    const char* channel;
    const char* start;
    const char* end;
    uint32_t    limit;
    uint32_t    timeout_ms;
} pn_message_actions_get_wire_inputs_t;

/** @brief Wire inputs for the remove operation. */
typedef struct pn_message_actions_remove_wire_inputs {
    const char* subscribe_key;
    const char* channel;
    const char* message_timetoken;
    const char* action_timetoken;
    uint32_t    timeout_ms;
} pn_message_actions_remove_wire_inputs_t;

/**
 * @brief Extract action fields from a JSON object node into @p out.
 *
 * Reads type, value, uuid, actionTimetoken, and messageTimetoken string
 * fields from @p node. Missing or non-string fields are left as empty
 * views ({NULL, 0}) — this is not an error.
 *
 * @param serial Serialization provider (non-NULL).
 * @param node   JSON object node for a single action (non-NULL).
 * @param out    Destination struct (non-NULL, caller-zeroed).
 */
void pn_message_actions_extract_action(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       node,
                                       pn_message_actions_action_parsed_t* out);

/**
 * @brief Build the HTTP request for add-message-action (POST).
 *
 * @param request Populated with path segments on success.
 * @param inputs  Wire inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_message_actions_build_add(pubnub_http_request_t* request,
                             const pn_message_actions_add_wire_inputs_t* inputs);

/**
 * @brief Build the HTTP request for get-message-actions (GET).
 *
 * @param request Populated with path segments and query params.
 * @param inputs  Wire inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_message_actions_build_get(pubnub_http_request_t* request,
                             const pn_message_actions_get_wire_inputs_t* inputs);

/**
 * @brief Build the HTTP request for remove-message-action (DELETE).
 *
 * @param request Populated with path segments on success.
 * @param inputs  Wire inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_message_actions_build_remove(
    pubnub_http_request_t*                         request,
    const pn_message_actions_remove_wire_inputs_t* inputs);

/**
 * @brief Parse a single action from an add-message-action response.
 *
 * Expects the parsed tree to be `{"status":200,"data":{...}}`.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed response body (borrowed).
 * @param alloc  Allocator for result storage (borrowed).
 * @param out    Receives parsed action fields on success.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_SERIALIZATION.
 */
pubnub_res_t pn_message_actions_parse_add(pubnub_serialization_provider_t* serial,
                                          const pubnub_json_value_t*   tree,
                                          pubnub_allocator_provider_t* alloc,
                                          pn_message_actions_action_parsed_t* out);

/**
 * @brief Parse the get-message-actions response array and pagination.
 *
 * Expects `{"status":200,"data":[...],"more":{...}}`.
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed response body (borrowed).
 * @param alloc  Allocator for result storage (borrowed).
 * @param out    Receives parsed action array and pagination metadata.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_message_actions_parse_get(pubnub_serialization_provider_t* serial,
                                          const pubnub_json_value_t*   tree,
                                          pubnub_allocator_provider_t* alloc,
                                          pn_message_actions_get_parsed_t* out);

/**
 * @brief Lightweight response validator probe for message actions.
 *
 * Accepts HTTP 200 and 207 as success. Returns PUBNUB_ERR_SERVER for
 * 4xx/5xx. Scans at most 64 bytes for an "error" flag.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_SERVER.
 */
pubnub_res_t pn_message_actions_response_validator(const uint8_t* body,
                                                   size_t         body_len,
                                                   int            http_status);

/**
 * @brief Cleanup callback for message actions feature state.
 *
 * Frees the per-request parsed result and the state struct itself.
 *
 * @param state     The pn_message_actions_state_t pointer.
 * @param allocator Allocator for deallocation.
 */
void pn_message_actions_state_cleanup(void*                        state,
                                      pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_MESSAGE_ACTIONS */

#endif /* PN_MESSAGE_ACTIONS_INTERNAL_H */

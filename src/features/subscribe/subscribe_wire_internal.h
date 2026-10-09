/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_wire_internal.h
 * @brief Wire-level types and function declarations for the subscribe V2
 *        request builder and response parser.
 */

#ifndef PN_SUBSCRIBE_WIRE_INTERNAL_H
#define PN_SUBSCRIBE_WIRE_INTERNAL_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_wire_internal.h requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "core/protocol_common/pn_channel_dispatch_state.h"

#include "pubnub/error.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/types.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief The `-pnpres` presence suffix literal. */
#define PN_PNPRES_SUFFIX "-pnpres"
/** @brief Byte length of the `-pnpres` suffix (excludes NUL). */
#define PN_PNPRES_SUFFIX_LEN ((size_t)7)

/**
 * @brief Test whether a name ends with `-pnpres` over a non-empty base.
 *
 * @param ptr Name bytes, not necessarily NUL-terminated; may be NULL.
 * @param len Byte count of @p ptr.
 * @retval 1 Name is `<base>-pnpres` with a non-empty base.
 * @retval 0 Otherwise.
 */
static inline int pn_pnpres_has_suffix(const char* ptr, size_t len)
{
    if (NULL == ptr || len <= PN_PNPRES_SUFFIX_LEN) {
        return 0;
    }
    return 0
        == memcmp(ptr + len - PN_PNPRES_SUFFIX_LEN,
                  PN_PNPRES_SUFFIX,
                  PN_PNPRES_SUFFIX_LEN);
}

/**
 * @brief Return the base-name length with any `-pnpres` suffix removed.
 *
 * @param ptr Name bytes; may be NULL.
 * @param len Number of bytes in @p ptr.
 * @return @p len minus the suffix when present, otherwise @p len.
 */
static inline size_t pn_pnpres_base_len(const char* ptr, size_t len)
{
    return pn_pnpres_has_suffix(ptr, len) ? len - PN_PNPRES_SUFFIX_LEN : len;
}

/**
 * @brief Subscribe cursor holding the timetoken and region from the
 *        server's envelope.
 *
 * Stored as a NUL-terminated decimal string to avoid 64-bit division
 * on constrained targets. The server emits 17-digit decimal strings;
 * the buffer is sized to 19 + NUL for headroom.
 */
typedef struct pn_subscribe_cursor {
    /** Decimal timetoken string (NUL-terminated). */
    char timetoken[20];
    /** Number of valid characters in @c timetoken (excluding NUL). */
    uint8_t timetoken_len;
    /** Server-assigned region for cursor affinity. */
    uint32_t region;
} pn_subscribe_cursor_t;

/**
 * @brief Inputs required to build a subscribe HTTP request.
 *
 * All pointers are borrowed and must remain valid until the request
 * is dispatched to the transport.
 */
typedef struct pn_subscribe_wire_inputs {
    /** Subscriber key (NUL-terminated, required). */
    const char* subscribe_key;
    /** Comma-separated channel names. */
    const char* channels;
    /** Comma-separated channel group names, or NULL. */
    const char* channel_groups;
    /** Filter expression, or NULL. */
    const char* filter_expr;
    /** Presence heartbeat in seconds; 0 = omit. */
    uint32_t heartbeat_sec;
    /** Per-request timeout override in milliseconds. */
    uint32_t timeout_ms;
} pn_subscribe_wire_inputs_t;

/**
 * @brief Parsed subscribe V2 response envelope.
 *
 * Callers MUST destroy the tree after processing by calling
 * `serial->value_destroy(serial, out->_tree)` — the string views
 * in @c messages alias memory owned by the tree.
 */
typedef struct pn_subscribe_parsed_response {
    /** Updated cursor (timetoken + region) for the next request. */
    pn_subscribe_cursor_t cursor;
    /** Parsed message batch. String views in each event alias memory
     *  owned by @c _tree and become invalid once the tree is destroyed. */
    pubnub_subscribe_event_t messages[PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE];
    /** Number of valid entries in @c messages. */
    uint16_t message_count;
    /** 1 if the response contained more messages than the batch cap. */
    uint8_t truncated;
    /** 1 if an inspected message lacked a usable channel; the whole batch
     *  is dropped (@c message_count = 0) and only the cursor survives. */
    uint8_t malformed;
    /**
     * Parsed JSON tree (caller-owned). Must be destroyed via
     * `serial->value_destroy(serial, _tree)` after processing.
     * NULL if parsing failed.
     */
    pubnub_json_value_t* _tree;
} pn_subscribe_parsed_response_t;

/**
 * @brief Per-request dispatch state for subscribe.
 *
 * Holds allocator-owned encoded channel strings that back the
 * string_view pointers in pn_subscribe_wire_inputs_t. Attached to
 * the pending entry as feature_state so the strings remain valid
 * through dispatch and are freed on slot release.
 */
typedef pn_channel_dispatch_state_t pn_subscribe_dispatch_state_t;

/**
 * @brief Build a subscribe handshake request (tt="0").
 *
 * Populates @p request with the path segments, query parameters,
 * method, and timeout for an initial subscribe handshake.
 *
 * @param request HTTP request descriptor to populate (caller-owned,
 *                should be zero-initialized before call).
 * @param inputs  Wire inputs describing channels and configuration.
 * @return PUBNUB_OK on success, PUBNUB_ERR_INVALID_ARGUMENT if
 *         required inputs are NULL, PUBNUB_ERR_BUFFER_TOO_SMALL if
 *         query params exceed the request's capacity.
 */
pubnub_res_t pn_subscribe_build_handshake(pubnub_http_request_t* request,
                                          const pn_subscribe_wire_inputs_t* inputs);

/**
 * @brief Build a subscribe receive request (with an existing cursor).
 *
 * Populates @p request identically to the handshake but uses the
 * cursor's timetoken and region for continuation.
 *
 * @param request HTTP request descriptor to populate.
 * @param inputs  Wire inputs describing channels and configuration.
 * @param cursor  Current subscribe cursor (timetoken + region).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_subscribe_build_receive(pubnub_http_request_t* request,
                                        const pn_subscribe_wire_inputs_t* inputs,
                                        const pn_subscribe_cursor_t* cursor);

/**
 * @brief Parse a subscribe V2 response envelope.
 *
 * Extracts the cursor and message batch from the JSON body. The
 * parsed tree is stored in @p out->_tree and must be destroyed by
 * the caller after processing messages (all string views in the
 * message batch alias tree-owned memory).
 *
 * @param serial   Serialization provider for JSON parsing.
 * @param log      Logger provider for debug diagnostics; may be NULL, in
 *                 which case nothing is logged.
 * @param body     Raw response body bytes.
 * @param body_len Length of @p body in bytes.
 * @param out      Parsed response (caller-owned, zero-initialized on
 *                 entry). On success, caller must destroy @c _tree.
 * @return PUBNUB_OK when the envelope parsed and the cursor was extracted
 *         (even if the batch is unusable — see @c malformed);
 *         PUBNUB_ERR_SERIALIZATION when the body is not a parseable JSON
 *         object or the cursor is missing or invalid.
 * @note A bad message array sets @c malformed (with @c message_count 0), not
 *       the return code — advance the cursor and deliver nothing. Elements
 *       with a non-integer or out-of-range @c e are skipped (not counted in
 *       @c message_count) and logged at debug level, even if the batch is
 *       later dropped as malformed.
 */
pubnub_res_t pn_subscribe_parse_response(pubnub_serialization_provider_t* serial,
                                         pubnub_logger_provider_t* log,
                                         const uint8_t*            body,
                                         size_t                    body_len,
                                         pn_subscribe_parsed_response_t* out);

/**
 * @brief Fast response validator probe for subscribe responses.
 *
 * Performs a bounded bytewise check to determine whether the
 * response is a valid subscribe envelope. Runs on every response
 * before the full JSON parse.
 *
 * @param body        Response body bytes.
 * @param body_len    Body length in bytes.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK if the response appears valid, or an error code
 *         indicating the response should be treated as a failure.
 */
pubnub_res_t pn_subscribe_response_validator(const uint8_t* body,
                                             size_t         body_len,
                                             int            http_status);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_SUBSCRIBE_WIRE_INTERNAL_H */

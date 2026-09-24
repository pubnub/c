/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_HISTORY_INTERNAL_H
#define PN_HISTORY_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_HISTORY

#include "pubnub/error.h"
#include "pubnub/features/history.h"
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

/** @brief Discriminator for the history operation type. */
typedef enum pn_history_op {
    /** Fetch messages (v3 batch history). */
    PN_HISTORY_OP_FETCH = 0,
    /** Delete messages from a channel. */
    PN_HISTORY_OP_DELETE = 1,
    /** Message counts per channel. */
    PN_HISTORY_OP_COUNTS = 2
} pn_history_op_t;

/**
 * @brief Pre-walked channel entry for fetch_messages lazy parse.
 *
 * Each entry caches a channel name and a borrowed pointer into the
 * parsed JSON tree's messages array.
 */
typedef struct pn_history_fetch_channel_entry {
    /** Channel name (aliases parsed tree). */
    pubnub_string_view_t name;
    /** Borrowed pointer to the messages array node. */
    const pubnub_json_value_t* messages_array;
    /** Number of messages in the array. */
    uint32_t message_count;
    /** Cached forward cursor for O(1) sequential indexed accessors. */
    pubnub_json_array_iter_t iter_cache;
    /** Index the cached cursor's next step will return. */
    size_t iter_pos;
    /** Non-zero when @ref iter_cache is usable (zero = restart). */
    uint8_t iter_valid;
} pn_history_fetch_channel_entry_t;

/**
 * @brief Lazy-parsed cache for fetch_messages.
 */
typedef struct pn_history_fetch_parsed {
    /** Channel entries (allocator-owned array). */
    pn_history_fetch_channel_entry_t* channel_entries;
    /** Number of channels in the response. */
    uint32_t channel_count;

    /**
     * @brief Next-page cursor extracted from the @c "more" object.
     *
     * Aliases the parsed response tree (valid until the slot is
     * released). Zero-length when no @c "more" object is present.
     */
    pubnub_timetoken_t next_cursor;

    /** Cached decrypted message tree (parse of decrypted bytes). */
    pubnub_json_value_t* decrypted_msg_tree;
    /** Channel index of the cached decrypted message. */
    size_t cached_channel_idx;
    /** Message index of the cached decrypted message. */
    size_t cached_message_idx;
    /** Allocator used for decrypt buffer allocation. */
    pubnub_allocator_provider_t* allocator;
    /** Serialization provider (for destroying decrypted trees). */
    pubnub_serialization_provider_t* serial;
    /** Cached parsed tree from decrypted file message (or NULL). */
    pubnub_json_value_t* decrypted_file_tree;
} pn_history_fetch_parsed_t;

/**
 * @brief Pre-walked channel entry for message_counts lazy parse.
 */
typedef struct pn_history_counts_channel_entry {
    /** Channel name (aliases parsed tree). */
    pubnub_string_view_t name;
    /** Number of messages since the given timetoken. */
    uint32_t count;
} pn_history_counts_channel_entry_t;

/**
 * @brief Lazy-parsed cache for message_counts.
 */
typedef struct pn_history_counts_parsed {
    /** Channel entries (allocator-owned array). */
    pn_history_counts_channel_entry_t* channel_entries;
    /** Number of channels in the response. */
    uint32_t channel_count;
} pn_history_counts_parsed_t;

/**
 * @brief Per-request state for all history operations.
 *
 * Released via @ref pn_history_feature_state_cleanup.
 */
typedef struct pn_history_state {
    /** Lazy-parsed result (type depends on @c operation). */
    void* parsed;
    /** Allocator-owned percent-encoded channel string, or NULL. */
    char* encoded_channels;
    /** Which operation this slot belongs to. */
    uint8_t operation;
} pn_history_state_t;

/**
 * @brief Build the path segments for fetch_messages into @p request.
 *
 * Populates path as:
 *   `/v3/history/sub-key/{sub}/channel/{encoded_channels}`
 * or `/v3/history-with-actions/sub-key/{sub}/channel/{encoded_channel}`
 *
 * @param request       Request to populate.
 * @param subscribe_key Subscribe key (NUL-terminated, borrowed).
 * @param encoded_channels Pre-encoded channel string (borrowed view).
 * @param with_actions  Non-zero to use history-with-actions path.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_build_fetch_path(pubnub_http_request_t* request,
                                         const char*            subscribe_key,
                                         pubnub_string_view_t encoded_channels,
                                         int                  with_actions);

/**
 * @brief Build the path segments for delete_messages into @p request.
 *
 * Path: `/v3/history/sub-key/{sub}/channel/{encoded_channel}`
 *
 * @param request         Request to populate.
 * @param subscribe_key   Subscribe key (NUL-terminated, borrowed).
 * @param encoded_channel Pre-encoded single channel (borrowed view).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_build_delete_path(pubnub_http_request_t* request,
                                          const char*            subscribe_key,
                                          pubnub_string_view_t encoded_channel);

/**
 * @brief Build the path segments for message_counts into @p request.
 *
 * Path: `/v3/history/sub-key/{sub}/message-counts/{encoded_channels}`
 *
 * @param request          Request to populate.
 * @param subscribe_key    Subscribe key (NUL-terminated, borrowed).
 * @param encoded_channels Pre-encoded channel string (borrowed view).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_build_counts_path(pubnub_http_request_t* request,
                                          const char*            subscribe_key,
                                          pubnub_string_view_t encoded_channels);

/**
 * @brief Append query params for fetch_messages.
 *
 * @param request Request to populate.
 * @param opts    Fetch options (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_add_fetch_query_params(pubnub_http_request_t* request,
                                               const pubnub_fetch_messages_opts_t* opts);

/**
 * @brief Append query params for delete_messages.
 *
 * @param request Request to populate.
 * @param opts    Delete options (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_history_add_delete_query_params(pubnub_http_request_t*               request,
                                   const pubnub_delete_messages_opts_t* opts);

/**
 * @brief Append query params for message_counts.
 *
 * @param request Request to populate.
 * @param opts    Counts options (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_add_counts_query_params(pubnub_http_request_t* request,
                                                const pubnub_message_counts_opts_t* opts);

/**
 * @brief Response validator for fetch_messages and message_counts.
 *
 * Scans for `"status":` in the first ~50 bytes; returns ERR_SERVER
 * when the status value is >= 400.
 *
 * @param body        Response body (borrowed).
 * @param body_len    Body length.
 * @param http_status HTTP status code from transport.
 * @return PUBNUB_OK on logical success, or PUBNUB_ERR_SERVER.
 */
pubnub_res_t pn_history_response_validator(const uint8_t* body,
                                           size_t         body_len,
                                           int            http_status);

/**
 * @brief Response validator for delete_messages.
 *
 * Delete success is determined solely by HTTP status < 400.
 *
 * @param body        Response body (borrowed, ignored).
 * @param body_len    Body length (ignored).
 * @param http_status HTTP status code.
 * @return PUBNUB_OK when < 400, PUBNUB_ERR_SERVER otherwise.
 */
pubnub_res_t pn_history_delete_response_validator(const uint8_t* body,
                                                  size_t         body_len,
                                                  int            http_status);

/**
 * @brief Parse the fetch_messages response into a cached structure.
 *
 * Walks the `"channels"` object in the parsed tree and populates
 * @p out with allocator-owned channel_entries.
 *
 * @param serial    Serialization provider (borrowed).
 * @param tree      Parsed response body (borrowed).
 * @param allocator Allocator for channel_entries array.
 * @param out       Output (zero-initialized on entry).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_parse_fetch(pubnub_serialization_provider_t* serial,
                                    const pubnub_json_value_t*       tree,
                                    pubnub_allocator_provider_t*     allocator,
                                    pn_history_fetch_parsed_t*       out);

/**
 * @brief Parse the message_counts response into a cached structure.
 *
 * Walks the `"channels"` object and extracts integer counts.
 *
 * @param serial    Serialization provider (borrowed).
 * @param tree      Parsed response body (borrowed).
 * @param allocator Allocator for channel_entries array.
 * @param out       Output (zero-initialized on entry).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_history_parse_counts(pubnub_serialization_provider_t* serial,
                                     const pubnub_json_value_t*       tree,
                                     pubnub_allocator_provider_t*     allocator,
                                     pn_history_counts_parsed_t*      out);

/**
 * @brief Cleanup for the history slot's feature_state.
 *
 * Frees parsed cache, encoded_channels, and the state struct itself.
 *
 * @param state     The @ref pn_history_state_t pointer.
 * @param allocator Allocator for deallocation.
 */
void pn_history_feature_state_cleanup(void*                        state,
                                      pubnub_allocator_provider_t* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_HISTORY */

#endif /* PN_HISTORY_INTERNAL_H */

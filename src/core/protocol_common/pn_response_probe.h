/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_RESPONSE_PROBE_H
#define PN_RESPONSE_PROBE_H

#include "pubnub/error.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Probe whether a PubNub array response carries a success status.
 *
 * Scans the first @p probe_limit bytes of @p body for the pattern
 * `[` followed by the digit `1`. Returns PUBNUB_OK when found,
 * PUBNUB_ERR_SERVER otherwise. Also returns PUBNUB_ERR_SERVER when
 * @p http_status >= 400.
 *
 * @param body        Response body (may be NULL when body_len is 0).
 * @param body_len    Number of bytes in @p body.
 * @param http_status HTTP status code from the completed response.
 * @param probe_limit Maximum bytes to scan (typically 20).
 * @return PUBNUB_OK on success; PUBNUB_ERR_SERVER on failure.
 */
pubnub_res_t pn_probe_array_status(const uint8_t* body,
                                   size_t         body_len,
                                   int            http_status,
                                   size_t         probe_limit);

/**
 * @brief Probe whether a PubNub JSON object response carries an error flag.
 *
 * Scans the first @p probe_limit bytes of @p body for the pattern
 * `"error"` followed (after optional whitespace and `:`) by `true`.
 * Returns PUBNUB_ERR_SERVER when the error flag is present,
 * PUBNUB_OK otherwise. Also returns PUBNUB_ERR_SERVER when
 * @p http_status >= 400.
 *
 * @param body        Response body (may be NULL when body_len is 0).
 * @param body_len    Number of bytes in @p body.
 * @param http_status HTTP status code from the completed response.
 * @param probe_limit Maximum bytes to scan (typically 64 or 150).
 * @return PUBNUB_OK when no error flag detected; PUBNUB_ERR_SERVER when
 *         error flag present or HTTP status >= 400.
 */
pubnub_res_t pn_probe_object_error_flag(const uint8_t* body,
                                        size_t         body_len,
                                        int            http_status,
                                        size_t         probe_limit);

/**
 * @brief Parse a PubNub `[status, message, timetoken]` array response.
 *
 * Extracts the timetoken string from position 2 of the top-level JSON array.
 * Used by features whose REST responses follow the publish/signal envelope.
 *
 * @param serial     Serialization provider (non-NULL).
 * @param tree       Parsed JSON tree of the response body (non-NULL).
 * @param out_token  Receives the timetoken string view on success.
 * @return PUBNUB_OK on success; PUBNUB_ERR_SERIALIZATION when the tree
 *         does not match the expected array shape.
 */
pubnub_res_t pn_parse_publish_array_response(pubnub_serialization_provider_t* serial,
                                             const pubnub_json_value_t* tree,
                                             pubnub_timetoken_t* out_token);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_RESPONSE_PROBE_H */

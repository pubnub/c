/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "push_internal.h"

#if !PUBNUB_ENABLE_PUSH_NOTIFICATIONS
#error "push_list_channels_wire.c requires PUBNUB_ENABLE_PUSH_NOTIFICATIONS=ON"
#endif

#include "core/pn_format.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

/**
 * @brief Add pagination parameters for list-channels operation.
 *
 * @param request HTTP request to populate.
 * @param start Pagination cursor (optional).
 * @param count Max results (clamped to 1000, 0 = server default).
 * @return PUBNUB_OK on success, or error code.
 */
pubnub_res_t pn_push_add_list_params(pubnub_http_request_t* request,
                                     const char*            start,
                                     uint16_t               count)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL != start && '\0' != start[0]) {
        const pubnub_res_t rc =
            pn_request_add_query_param(request, "start", start, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (count > 0) {
        const uint16_t clamped = (count > 1000) ? 1000 : count;
        char           count_buf[8];
        (void)pn_snprintf(count_buf, sizeof(count_buf), "%u", (unsigned int)clamped);
        const pubnub_res_t rc =
            pn_request_add_query_param(request, "count", count_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

#define PN_PUSH_LIST_PROBE_LIMIT 20

/**
 * @brief Validate list-channels response format.
 *
 * Expects array starting with [ followed by " (string) or ] (empty).
 *
 * @param body Response body.
 * @param body_len Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERVER on failure.
 */
pubnub_res_t pn_push_list_response_validator(const uint8_t* body,
                                             size_t         body_len,
                                             int            http_status)
{
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    size_t i = 0;
    while (i < body_len && i < PN_PUSH_LIST_PROBE_LIMIT) {
        const uint8_t c = body[i];
        if (' ' == c || '\t' == c || '\r' == c || '\n' == c) {
            i++;
            continue;
        }
        break;
    }

    if (i >= body_len || '[' != body[i]) {
        return PUBNUB_ERR_SERVER;
    }
    i++;

    while (i < body_len && i < PN_PUSH_LIST_PROBE_LIMIT) {
        const uint8_t c = body[i];
        if (' ' == c || '\t' == c || '\r' == c || '\n' == c) {
            i++;
            continue;
        }
        break;
    }

    if (i >= body_len) {
        return PUBNUB_OK;
    }

    if ('"' == body[i] || ']' == body[i]) {
        return PUBNUB_OK;
    }

    if ('0' == body[i]) {
        return PUBNUB_ERR_SERVER;
    }

    return PUBNUB_OK;
}

/**
 * @brief Parse list-channels response.
 *
 * Extracts channel array from JSON tree.
 *
 * @param serial Serialization provider.
 * @param tree Parsed JSON root.
 * @param out Parsed output (channel count and borrowed tree reference).
 * @return PUBNUB_OK on success, or error code.
 */
pubnub_res_t pn_push_list_parse_response(pubnub_serialization_provider_t* serial,
                                         const pubnub_json_value_t* tree,
                                         pn_push_list_parsed_t*     out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->channel_count = 0;
    out->tree          = NULL;

    if (NULL == serial || NULL == tree || NULL == serial->value_type
        || NULL == serial->array_size) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_ARRAY != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const size_t n     = serial->array_size(tree);
    out->channel_count = (uint32_t)n;
    out->tree          = tree;
    return PUBNUB_OK;
}

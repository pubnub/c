/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "message_actions_internal.h"

#if !PUBNUB_ENABLE_MESSAGE_ACTIONS
#error "message_actions_wire_get.c requires PUBNUB_ENABLE_MESSAGE_ACTIONS=ON"
#endif

#include "core/pn_format.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

/**
 * @brief Validate that a timetoken is 1-19 decimal digits.
 *
 * The @c start / @c end pagination cursors are copied verbatim into the
 * request query string, so a value carrying anything other than decimal
 * digits would inject unexpected characters into the URL. A valid
 * PubNub timetoken is a decimal integer that fits in 64 bits (at most 19
 * digits).
 *
 * @param tt NUL-terminated candidate timetoken.
 * @return PUBNUB_OK when valid, PUBNUB_ERR_INVALID_ARGUMENT otherwise.
 */
static pubnub_res_t pn_validate_timetoken(const char* tt)
{
    size_t len;

    if (NULL == tt || '\0' == tt[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    for (len = 0; '\0' != tt[len]; ++len) {
        if (len >= 19 || tt[len] < '0' || tt[len] > '9') {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t
pn_message_actions_build_get(pubnub_http_request_t* request,
                             const pn_message_actions_get_wire_inputs_t* inputs)
{
    unsigned int         n = 0;
    pubnub_string_view_t sub_key_view;
    pubnub_string_view_t encoded_channel;
    pubnub_res_t         rc;

    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channel) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if ('\0' == inputs->channel[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Scratch-copy subscribe_key so the request is self-contained. */
    rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* /v1/message-actions/{sub_key}/channel/{channel} */
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"message-actions", 15};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};

    /* Percent-encode the channel. */
    rc = pn_request_scratch_encode(
        request, inputs->channel, &encoded_channel, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = encoded_channel;

    request->path_segment_count = n;

    /* Optional query params: start, end, limit. */
    if (NULL != inputs->start) {
        if (PUBNUB_OK != pn_validate_timetoken(inputs->start)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(
            request, "start", inputs->start, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != inputs->end) {
        if (PUBNUB_OK != pn_validate_timetoken(inputs->end)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(request, "end", inputs->end, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (0 != inputs->limit) {
        char limit_buf[12];
        pn_snprintf(limit_buf, sizeof(limit_buf), "%u", (unsigned int)inputs->limit);
        rc = pn_request_add_query_param(request, "limit", limit_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

void pn_message_actions_extract_action(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       node,
                                       pn_message_actions_action_parsed_t* out)
{
    const pubnub_json_value_t* field;
    const char*                ptr;
    size_t                     len;

    if (NULL == serial->object_get || NULL == serial->value_as_string) {
        return;
    }

    field = serial->object_get(node, "type", 4);
    if (NULL != field) {
        ptr = serial->value_as_string(field, &len);
        if (NULL != ptr) {
            out->type = (pubnub_string_view_t){ptr, len};
        }
    }

    field = serial->object_get(node, "value", 5);
    if (NULL != field) {
        ptr = serial->value_as_string(field, &len);
        if (NULL != ptr) {
            out->value = (pubnub_string_view_t){ptr, len};
        }
    }

    field = serial->object_get(node, "uuid", 4);
    if (NULL != field) {
        ptr = serial->value_as_string(field, &len);
        if (NULL != ptr) {
            out->uuid = (pubnub_string_view_t){ptr, len};
        }
    }

    field = serial->object_get(node, "actionTimetoken", 15);
    if (NULL != field) {
        ptr = serial->value_as_string(field, &len);
        if (NULL != ptr) {
            out->action_timetoken = (pubnub_string_view_t){ptr, len};
        }
    }

    field = serial->object_get(node, "messageTimetoken", 16);
    if (NULL != field) {
        ptr = serial->value_as_string(field, &len);
        if (NULL != ptr) {
            out->message_timetoken = (pubnub_string_view_t){ptr, len};
        }
    }
}

/**
 * @brief Parse the "more" pagination object if present.
 */
static void parse_pagination(pubnub_serialization_provider_t* serial,
                             const pubnub_json_value_t*       tree,
                             pn_message_actions_get_parsed_t* out)
{
    const pubnub_json_value_t* more;
    const pubnub_json_value_t* node;
    const char*                ptr;
    size_t                     len;

    more = serial->object_get(tree, "more", 4);
    if (NULL == more || PUBNUB_JSON_OBJECT != serial->value_type(more)) {
        return;
    }

    out->has_more = 1;

    node = serial->object_get(more, "start", 5);
    if (NULL != node) {
        ptr = serial->value_as_string(node, &len);
        if (NULL != ptr) {
            out->more_start = (pubnub_string_view_t){ptr, len};
        }
    }

    node = serial->object_get(more, "end", 3);
    if (NULL != node) {
        ptr = serial->value_as_string(node, &len);
        if (NULL != ptr) {
            out->more_end = (pubnub_string_view_t){ptr, len};
        }
    }

    /* Server returns "limit" as a string (e.g. "2"). */
    node = serial->object_get(more, "limit", 5);
    if (NULL != node) {
        ptr = serial->value_as_string(node, &len);
        if (NULL != ptr && len > 0) {
            uint32_t limit_val = 0;
            size_t   i;
            for (i = 0; i < len; ++i) {
                if (ptr[i] < '0' || ptr[i] > '9') {
                    break;
                }
                if (limit_val > 429496729U) {
                    break;
                }
                limit_val = limit_val * 10 + (uint32_t)(ptr[i] - '0');
            }
            out->more_limit = limit_val;
        }
    }
}

pubnub_res_t pn_message_actions_parse_get(pubnub_serialization_provider_t* serial,
                                          const pubnub_json_value_t*   tree,
                                          pubnub_allocator_provider_t* alloc,
                                          pn_message_actions_get_parsed_t* out)
{
    const pubnub_json_value_t*          data;
    size_t                              count;
    pn_message_actions_action_parsed_t* actions;
    size_t                              i;
    pubnub_json_array_iter_t            iter;
    pubnub_json_value_t*                element = NULL;

    if (NULL == serial || NULL == tree || NULL == alloc || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->array_size || NULL == serial->array_iter_init
        || NULL == serial->array_iter_next) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Navigate to "data" array. */
    data = serial->object_get(tree, "data", 4);
    if (NULL == data || PUBNUB_JSON_ARRAY != serial->value_type(data)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    count = serial->array_size(data);
    if (0 == count) {
        /* Empty result is valid. */
        parse_pagination(serial, tree, out);
        return PUBNUB_OK;
    }

    actions = (pn_message_actions_action_parsed_t*)PN_ALLOC(
        alloc, count * sizeof(pn_message_actions_action_parsed_t), 0);
    if (NULL == actions) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memset(actions, 0, count * sizeof(pn_message_actions_action_parsed_t));

    i = 0;
    if (serial->array_iter_init(data, &iter)) {
        while (i < count && serial->array_iter_next(&iter, &element)) {
            if (NULL != element
                && PUBNUB_JSON_OBJECT == serial->value_type(element)) {
                pn_message_actions_extract_action(serial, element, &actions[i]);
            }
            i++;
        }
    }

    out->actions = actions;
    out->count   = count;

    /* Parse pagination metadata. */
    parse_pagination(serial, tree, out);

    return PUBNUB_OK;
}

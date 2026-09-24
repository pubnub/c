/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "message_actions_internal.h"

#if !PUBNUB_ENABLE_MESSAGE_ACTIONS
#error "message_actions_wire_add.c requires PUBNUB_ENABLE_MESSAGE_ACTIONS=ON"
#endif

#include "core/runtime/middleware/middleware_internal.h"

/**
 * @brief Validate that a timetoken is 1-19 decimal digits.
 *
 * Timetokens are copied verbatim into the request path, so a value
 * carrying anything other than decimal digits would inject unexpected
 * characters into the URL. A valid PubNub timetoken is a decimal
 * integer that fits in 64 bits (at most 19 digits).
 *
 * @param tt NUL-terminated candidate timetoken.
 * @return PUBNUB_OK when valid, PUBNUB_ERR_INVALID_ARGUMENT otherwise.
 */
static pubnub_res_t pn_validate_timetoken(const char* tt)
{
    size_t len = 0;

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
pn_message_actions_build_add(pubnub_http_request_t* request,
                             const pn_message_actions_add_wire_inputs_t* inputs)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channel || NULL == inputs->message_timetoken) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if ('\0' == inputs->channel[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (PUBNUB_OK != pn_validate_timetoken(inputs->message_timetoken)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    unsigned int         n = 0;
    pubnub_string_view_t sub_key_view;
    pubnub_string_view_t encoded_channel;
    pubnub_string_view_t mtt_view;
    pubnub_res_t         rc;

    /* Scratch-copy subscribe_key so the request is self-contained. */
    rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* /v1/message-actions/{sub_key}/channel/{channel}/message/{mtt} */
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"message-actions", 15};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};

    /* Percent-encode the channel into the scratch buffer. */
    rc = pn_request_scratch_encode(
        request, inputs->channel, &encoded_channel, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = encoded_channel;

    request->path_segments[n++] = (pubnub_string_view_t){"message", 7};

    /* Scratch-copy the (already validated, digit-only) timetoken so the
     * request no longer borrows the caller's pointer once queued. */
    rc = pn_request_scratch_encode(
        request, inputs->message_timetoken, &mtt_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = mtt_view;

    request->path_segment_count = n;

    return PUBNUB_OK;
}

pubnub_res_t pn_message_actions_parse_add(pubnub_serialization_provider_t* serial,
                                          const pubnub_json_value_t*   tree,
                                          pubnub_allocator_provider_t* alloc,
                                          pn_message_actions_action_parsed_t* out)
{
    (void)alloc;

    if (NULL == serial || NULL == tree || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Navigate to "data" object. */
    const pubnub_json_value_t* data = serial->object_get(tree, "data", 4);
    if (NULL == data || PUBNUB_JSON_OBJECT != serial->value_type(data)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    pn_message_actions_extract_action(serial, data, out);
    return PUBNUB_OK;
}

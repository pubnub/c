/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_api_internal.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_wire_user_state.c requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 9,
                     "Set State requires at least 9 path segments");

pubnub_res_t pn_presence_build_set_state(pubnub_http_request_t* request,
                                         const pn_presence_set_state_wire_inputs_t* inputs)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channels || NULL == inputs->uuid
        || NULL == inputs->state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_string_view_t encoded_channels;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, inputs->channels, &encoded_channels, PN_ENCODE_KEEP_COMMAS);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    pubnub_string_view_t encoded_uuid;
    rc = pn_request_scratch_encode(
        request, inputs->uuid, &encoded_uuid, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    pubnub_string_view_t sub_key_view;
    rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"presence", 8};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};
    request->path_segments[n++] = encoded_channels;
    request->path_segments[n++] = (pubnub_string_view_t){"uuid", 4};
    request->path_segments[n++] = encoded_uuid;
    request->path_segments[n++] = (pubnub_string_view_t){"data", 4};
    request->path_segment_count = n;

    /* State arrives pre-encoded from the API layer (heap-allocated via
     * pn_url_encode_alloc_n to handle payloads up to 32KB). */
    pubnub_string_view_t state_view = {inputs->state, inputs->state_len};
    rc = pn_request_add_query_param_view(request, "state", state_view);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* channel-group - omit when NULL or empty. */
    if (NULL != inputs->channel_groups && '\0' != inputs->channel_groups[0]) {
        rc = pn_request_add_query_param(
            request, "channel-group", inputs->channel_groups, PN_ENCODE_KEEP_COMMAS);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_presence_build_get_state(pubnub_http_request_t* request,
                                         const pn_presence_get_state_wire_inputs_t* inputs)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channels || NULL == inputs->uuid) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_string_view_t encoded_channels;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, inputs->channels, &encoded_channels, PN_ENCODE_KEEP_COMMAS);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    pubnub_string_view_t encoded_uuid;
    rc = pn_request_scratch_encode(
        request, inputs->uuid, &encoded_uuid, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    pubnub_string_view_t sub_key_view;
    rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"presence", 8};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};
    request->path_segments[n++] = encoded_channels;
    request->path_segments[n++] = (pubnub_string_view_t){"uuid", 4};
    request->path_segments[n++] = encoded_uuid;
    request->path_segment_count = n;

    /* channel-group - omit when NULL or empty. */
    if (NULL != inputs->channel_groups && '\0' != inputs->channel_groups[0]) {
        rc = pn_request_add_query_param(
            request, "channel-group", inputs->channel_groups, PN_ENCODE_KEEP_COMMAS);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_presence_parse_state(pubnub_serialization_provider_t* serial,
                                     const pubnub_json_value_t*       tree,
                                     pubnub_allocator_provider_t*     alloc,
                                     pn_presence_state_parsed_t*      out,
                                     uint8_t single_channel)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->entries     = NULL;
    out->entry_count = 0;

    if (NULL == serial || NULL == tree || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Navigate to "payload". */
    const pubnub_json_value_t* payload = serial->object_get(tree, "payload", 7);
    if (NULL == payload) {
        return PUBNUB_OK;
    }

    if (single_channel) {
        /* Single-channel: payload IS the state for that channel. */
        pn_presence_state_entry_t* entries = (pn_presence_state_entry_t*)PN_ALLOC(
            alloc, sizeof(pn_presence_state_entry_t), 0);
        if (NULL == entries) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }

        entries[0].channel = (pubnub_string_view_t){NULL, 0};
        entries[0].state   = payload;

        out->entries     = entries;
        out->entry_count = 1;
        return PUBNUB_OK;
    }

    /* Multi-channel: server wraps entries under payload["channels"].
     * Fall back to payload directly when the key is absent. */
    const pubnub_json_value_t* channel_map =
        serial->object_get(payload, "channels", 8);
    if (NULL == channel_map) {
        channel_map = payload;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(channel_map)) {
        return PUBNUB_OK;
    }

    if (NULL == serial->object_size || NULL == serial->object_iter_init
        || NULL == serial->object_iter_next) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const size_t count = serial->object_size(channel_map);
    if (0 == count) {
        return PUBNUB_OK;
    }

    pn_presence_state_entry_t* entries = (pn_presence_state_entry_t*)PN_ALLOC(
        alloc, count * sizeof(pn_presence_state_entry_t), 0);
    if (NULL == entries) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    pubnub_json_iter_t iter;
    int    has_entries = serial->object_iter_init(channel_map, &iter);
    size_t idx         = 0;

    while (has_entries && idx < count) {
        const char*          key     = NULL;
        size_t               key_len = 0;
        pubnub_json_value_t* value   = NULL;

        int step = serial->object_iter_next(&iter, &key, &key_len, &value);
        if (0 == step) {
            break;
        }

        entries[idx].channel = (pubnub_string_view_t){key, key_len};
        entries[idx].state   = value;
        idx++;
    }

    out->entries     = entries;
    out->entry_count = idx;
    return PUBNUB_OK;
}

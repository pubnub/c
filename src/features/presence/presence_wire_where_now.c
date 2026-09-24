/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_api_internal.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_wire_where_now.c requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 6,
                     "Where Now requires at least 6 path segments");

/** @brief Build the where-now HTTP request path. */
pubnub_res_t pn_presence_build_where_now(pubnub_http_request_t* request,
                                         const pn_presence_where_now_wire_inputs_t* inputs)
{
    pubnub_string_view_t encoded_uuid;
    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc;
    unsigned int         n = 0;

    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->uuid) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    rc = pn_request_scratch_encode(
        request, inputs->uuid, &encoded_uuid, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"presence", 8};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"uuid", 4};
    request->path_segments[n++] = encoded_uuid;
    request->path_segment_count = n;

    return PUBNUB_OK;
}

/** @brief Parse the where-now JSON response into structured results. */
pubnub_res_t pn_presence_parse_where_now(pubnub_serialization_provider_t* serial,
                                         const pubnub_json_value_t*      tree,
                                         pubnub_allocator_provider_t*    alloc,
                                         pn_presence_where_now_parsed_t* out)
{
    const pubnub_json_value_t* payload;
    const pubnub_json_value_t* channels_node;
    size_t                     count;
    pubnub_string_view_t*      channels;
    size_t                     i;
    pubnub_json_array_iter_t   iter;
    pubnub_json_value_t*       entry = NULL;

    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channels      = NULL;
    out->channel_count = 0;

    if (NULL == serial || NULL == tree || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->value_as_string) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Navigate: payload.channels */
    payload = serial->object_get(tree, "payload", 7);
    if (NULL == payload || PUBNUB_JSON_OBJECT != serial->value_type(payload)) {
        return PUBNUB_OK;
    }

    channels_node = serial->object_get(payload, "channels", 8);
    if (NULL == channels_node
        || PUBNUB_JSON_ARRAY != serial->value_type(channels_node)) {
        return PUBNUB_OK;
    }

    if (NULL == serial->array_size || NULL == serial->array_iter_init
        || NULL == serial->array_iter_next) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    count = serial->array_size(channels_node);
    if (0 == count) {
        return PUBNUB_OK;
    }

    channels = (pubnub_string_view_t*)PN_ALLOC(
        alloc, count * sizeof(pubnub_string_view_t), 0);
    if (NULL == channels) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    i = 0;
    if (serial->array_iter_init(channels_node, &iter)) {
        while (i < count && serial->array_iter_next(&iter, &entry)) {
            size_t      len = 0;
            const char* ptr;

            channels[i] = (pubnub_string_view_t){NULL, 0};

            if (NULL != entry && PUBNUB_JSON_STRING == serial->value_type(entry)) {
                ptr = serial->value_as_string(entry, &len);
                if (NULL != ptr) {
                    channels[i] = (pubnub_string_view_t){ptr, len};
                }
            }
            i++;
        }
    }

    out->channels      = channels;
    out->channel_count = count;
    return PUBNUB_OK;
}

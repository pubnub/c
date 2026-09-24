/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "channel_groups_internal.h"

#if !PUBNUB_ENABLE_CHANNEL_GROUPS
#error "channel_groups_wire_list.c requires PUBNUB_ENABLE_CHANNEL_GROUPS=ON"
#endif

#include <stdint.h>

pubnub_res_t pn_channel_groups_parse_list_response(pubnub_serialization_provider_t* serial,
                                                   pubnub_json_value_t* tree,
                                                   pn_channel_groups_parsed_t* out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->count          = 0;
    out->tree           = NULL;
    out->channels_array = NULL;

    if (NULL == serial || NULL == tree || NULL == serial->value_type
        || NULL == serial->object_get || NULL == serial->array_size) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Expected shape:
     * { "payload": { "channels": [...] }, "status": 200 } */
    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* payload = serial->object_get(tree, "payload", 7);
    if (NULL == payload || PUBNUB_JSON_OBJECT != serial->value_type(payload)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* channels =
        serial->object_get(payload, "channels", 8);
    if (NULL == channels || PUBNUB_JSON_ARRAY != serial->value_type(channels)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const size_t count = serial->array_size(channels);
    if (count > UINT32_MAX) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    out->count          = (uint32_t)count;
    out->channels_array = channels;
    return PUBNUB_OK;
}

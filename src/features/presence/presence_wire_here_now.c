/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_api_internal.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_wire_here_now.c requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "core/pn_format.h"
#include "core/protocol_common/pn_response_probe.h"
#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 6,
                     "Here Now requires at least 6 path segments");

/**
 * @brief Extract UUID and optional state from an object-shaped
 *        occupant entry.
 */
/** @brief Initial serialize buffer for state JSON. */
#define PN_STATE_SERIALIZE_CAP 128

/** @brief Maximum retry size for state serialization. */
#define PN_STATE_SERIALIZE_MAX 4096

/**
 * @brief Serialize a state node to raw JSON in an allocator-owned buffer.
 *
 * Returns the JSON text (e.g. `{"mood":"happy"}`). The returned
 * view.ptr is allocator-owned and must be freed in cleanup.
 */
static pubnub_string_view_t serialize_state(pubnub_serialization_provider_t* serial,
                                            const pubnub_json_value_t*   node,
                                            pubnub_allocator_provider_t* alloc)
{
    const pubnub_string_view_t empty = {NULL, 0};
    size_t                     cap   = PN_STATE_SERIALIZE_CAP;

    if (NULL == node || NULL == serial || NULL == serial->serialize
        || NULL == alloc || NULL == alloc->alloc) {
        return empty;
    }
    while (cap <= PN_STATE_SERIALIZE_MAX) {
        size_t       out_len = 0;
        pubnub_res_t rc;
        uint8_t*     buf = (uint8_t*)PN_ALLOC(alloc, cap, 0);
        if (NULL == buf) {
            return empty;
        }

        rc = serial->serialize(serial, node, buf, cap, &out_len);
        if (PUBNUB_OK == rc) {
            return (pubnub_string_view_t){(const char*)buf, out_len};
        }

        PN_FREE(alloc, buf);
        if (PUBNUB_ERR_BUFFER_TOO_SMALL != rc) {
            return empty;
        }
        cap *= 2;
    }

    return empty;
}

static void parse_occupant_object(pubnub_serialization_provider_t* serial,
                                  const pubnub_json_value_t*       entry,
                                  pubnub_allocator_provider_t*     alloc,
                                  pn_presence_here_now_occupant_t* occupant)
{
    const pubnub_json_value_t* uuid_node;
    const pubnub_json_value_t* state_node;

    if (NULL == serial->object_get) {
        return;
    }

    uuid_node = serial->object_get(entry, "uuid", 4);
    if (NULL != uuid_node && PUBNUB_JSON_STRING == serial->value_type(uuid_node)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(uuid_node, &len);
        if (NULL != ptr) {
            occupant->uuid = (pubnub_string_view_t){ptr, len};
        }
    }

    state_node = serial->object_get(entry, "state", 5);
    if (NULL == state_node) {
        return;
    }
    occupant->state = serialize_state(serial, state_node, alloc);
}

/**
 * @brief Parse the UUID list for a single channel from a here-now
 *        response.
 *
 * Handles both plain-string UUID entries and object entries with
 * "uuid" + optional "state" fields.
 */
static pubnub_res_t parse_occupants(pubnub_serialization_provider_t* serial,
                                    const pubnub_json_value_t*       uuids_node,
                                    pubnub_allocator_provider_t*     alloc,
                                    pn_presence_here_now_occupant_t** out_occupants,
                                    size_t* out_count)
{
    size_t                           count;
    pn_presence_here_now_occupant_t* occupants;
    size_t                           i;
    pubnub_json_array_iter_t         iter;
    pubnub_json_value_t*             entry = NULL;

    *out_occupants = NULL;
    *out_count     = 0;

    if (NULL == uuids_node) {
        return PUBNUB_OK;
    }

    if (NULL == serial->array_size || NULL == serial->array_iter_init
        || NULL == serial->array_iter_next) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    count = serial->array_size(uuids_node);
    if (0 == count) {
        return PUBNUB_OK;
    }

    occupants = (pn_presence_here_now_occupant_t*)PN_ALLOC(
        alloc, count * sizeof(pn_presence_here_now_occupant_t), 0);
    if (NULL == occupants) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    i = 0;
    if (serial->array_iter_init(uuids_node, &iter)) {
        while (i < count && serial->array_iter_next(&iter, &entry)) {
            pubnub_json_type_t entry_type;

            occupants[i].uuid  = (pubnub_string_view_t){NULL, 0};
            occupants[i].state = (pubnub_string_view_t){NULL, 0};

            if (NULL != entry) {
                entry_type = serial->value_type(entry);

                if (PUBNUB_JSON_STRING == entry_type) {
                    size_t      len   = 0;
                    const char* ptr   = serial->value_as_string(entry, &len);
                    occupants[i].uuid = (NULL != ptr)
                                          ? (pubnub_string_view_t){ptr, len}
                                          : (pubnub_string_view_t){NULL, 0};
                } else if (PUBNUB_JSON_OBJECT == entry_type) {
                    parse_occupant_object(serial, entry, alloc, &occupants[i]);
                }
            }
            i++;
        }
    }

    *out_occupants = occupants;
    *out_count     = count;
    return PUBNUB_OK;
}

/**
 * @brief Parse Shape A (single-channel) here-now response into out.
 *
 * Expected top-level: {"occupancy":N,"uuids":[...], ...}
 */
static pubnub_res_t parse_shape_a(pubnub_serialization_provider_t* serial,
                                  const pubnub_json_value_t*       tree,
                                  pubnub_allocator_provider_t*     alloc,
                                  pn_presence_here_now_parsed_t*   out)
{
    const pubnub_json_value_t*      occ_node;
    pn_presence_here_now_channel_t* channels;
    const pubnub_json_value_t*      uuids_node;

    /* Read occupancy. */
    occ_node = serial->object_get(tree, "occupancy", 9);
    if (NULL != occ_node && NULL != serial->value_as_int) {
        int occ = 0;
        if (PUBNUB_OK == serial->value_as_int(occ_node, &occ) && occ >= 0) {
            out->total_occupancy = (uint32_t)occ;
        }
    }

    out->total_channels = 1;

    /* Allocate a single channel entry. */
    channels = (pn_presence_here_now_channel_t*)PN_ALLOC(
        alloc, sizeof(pn_presence_here_now_channel_t), 0);
    if (NULL == channels) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    channels[0].name           = (pubnub_string_view_t){NULL, 0};
    channels[0].occupancy      = out->total_occupancy;
    channels[0].occupants      = NULL;
    channels[0].occupant_count = 0;

    /* Parse UUID list if present. */
    uuids_node = serial->object_get(tree, "uuids", 5);
    if (NULL != uuids_node && PUBNUB_JSON_ARRAY == serial->value_type(uuids_node)) {
        pubnub_res_t rc = parse_occupants(serial,
                                          uuids_node,
                                          alloc,
                                          &channels[0].occupants,
                                          &channels[0].occupant_count);
        if (PUBNUB_OK != rc) {
            PN_FREE(alloc, channels);
            return rc;
        }
    }

    out->channels      = channels;
    out->channel_count = 1;
    return PUBNUB_OK;
}

/**
 * @brief Parse a single channel entry from the multi-channel "channels"
 *        object.
 *
 * Populates occupancy and occupant list within the pre-zeroed channel
 * slot.
 */
static pubnub_res_t parse_channel_entry(pubnub_serialization_provider_t* serial,
                                        const pubnub_json_value_t*       value,
                                        pubnub_allocator_provider_t*     alloc,
                                        pn_presence_here_now_channel_t* channel)
{
    const pubnub_json_value_t* occ_node;
    const pubnub_json_value_t* uuids_node;

    if (NULL == value || PUBNUB_JSON_OBJECT != serial->value_type(value)) {
        return PUBNUB_OK;
    }
    if (NULL == serial->object_get) {
        return PUBNUB_OK;
    }

    occ_node = serial->object_get(value, "occupancy", 9);
    if (NULL != occ_node && NULL != serial->value_as_int) {
        int occ = 0;
        if (PUBNUB_OK == serial->value_as_int(occ_node, &occ) && occ >= 0) {
            channel->occupancy = (uint32_t)occ;
        }
    }

    uuids_node = serial->object_get(value, "uuids", 5);
    if (NULL == uuids_node || PUBNUB_JSON_ARRAY != serial->value_type(uuids_node)) {
        return PUBNUB_OK;
    }

    return parse_occupants(
        serial, uuids_node, alloc, &channel->occupants, &channel->occupant_count);
}

/**
 * @brief Parse Shape B (multi-channel/global) here-now response.
 *
 * Expected: {"payload":{"channels":{...},"total_channels":N,
 *            "total_occupancy":N}, ...}
 */
static pubnub_res_t parse_shape_b(pubnub_serialization_provider_t* serial,
                                  const pubnub_json_value_t*       payload,
                                  pubnub_allocator_provider_t*     alloc,
                                  pn_presence_here_now_parsed_t*   out)
{
    const pubnub_json_value_t*      total_occ_node;
    const pubnub_json_value_t*      total_ch_node;
    const pubnub_json_value_t*      channels_obj;
    size_t                          ch_count;
    pn_presence_here_now_channel_t* channels;
    pubnub_json_iter_t              iter;
    int                             has_entries;
    size_t                          idx = 0;

    /* Extract totals from payload. */
    total_occ_node = serial->object_get(payload, "total_occupancy", 15);
    if (NULL != total_occ_node && NULL != serial->value_as_int) {
        int val = 0;
        if (PUBNUB_OK == serial->value_as_int(total_occ_node, &val) && val >= 0) {
            out->total_occupancy = (uint32_t)val;
        }
    }

    total_ch_node = serial->object_get(payload, "total_channels", 14);
    if (NULL != total_ch_node && NULL != serial->value_as_int) {
        int val = 0;
        if (PUBNUB_OK == serial->value_as_int(total_ch_node, &val) && val >= 0) {
            out->total_channels = (uint32_t)val;
        }
    }

    /* Get the "channels" sub-object. */
    channels_obj = serial->object_get(payload, "channels", 8);
    if (NULL == channels_obj
        || PUBNUB_JSON_OBJECT != serial->value_type(channels_obj)) {
        return PUBNUB_OK;
    }

    if (NULL == serial->object_size || NULL == serial->object_iter_init
        || NULL == serial->object_iter_next) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    ch_count = serial->object_size(channels_obj);
    if (0 == ch_count) {
        return PUBNUB_OK;
    }

    channels = (pn_presence_here_now_channel_t*)PN_ALLOC(
        alloc, ch_count * sizeof(pn_presence_here_now_channel_t), 0);
    if (NULL == channels) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Walk each channel entry via object iterator. */
    has_entries = serial->object_iter_init(channels_obj, &iter);
    idx         = 0;

    while (has_entries && idx < ch_count) {
        const char*          key     = NULL;
        size_t               key_len = 0;
        pubnub_json_value_t* value   = NULL;
        pubnub_res_t         rc;
        size_t               j;
        int step = serial->object_iter_next(&iter, &key, &key_len, &value);
        if (0 == step) {
            break;
        }

        channels[idx].name           = (pubnub_string_view_t){key, key_len};
        channels[idx].occupancy      = 0;
        channels[idx].occupants      = NULL;
        channels[idx].occupant_count = 0;

        rc = parse_channel_entry(serial, value, alloc, &channels[idx]);
        if (PUBNUB_OK != rc) {
            /* Cleanup already-allocated channel entries. */
            for (j = 0; j < idx; j++) {
                if (NULL != channels[j].occupants) {
                    PN_FREE(alloc, channels[j].occupants);
                }
            }
            PN_FREE(alloc, channels);
            return rc;
        }
        idx++;
    }

    out->channels      = channels;
    out->channel_count = idx;
    return PUBNUB_OK;
}

pubnub_res_t pn_presence_response_validator(const uint8_t* body,
                                            size_t         body_len,
                                            int            http_status)
{
    return pn_probe_object_error_flag(body, body_len, http_status, 64);
}

pubnub_res_t pn_presence_build_here_now(pubnub_http_request_t* request,
                                        const pn_presence_here_now_wire_inputs_t* inputs)
{
    int                  has_channels;
    int                  has_groups;
    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc;
    unsigned int         n = 0;

    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    has_channels = (NULL != inputs->channels && '\0' != inputs->channels[0]);
    has_groups =
        (NULL != inputs->channel_groups && '\0' != inputs->channel_groups[0]);

    /* At least one targeting field is required; global here-now is not
     * supported. */
    if (!has_channels && !has_groups) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
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

    if (has_channels) {
        pubnub_string_view_t encoded_channels;
        rc = pn_request_scratch_encode(
            request, inputs->channels, &encoded_channels, PN_ENCODE_KEEP_COMMAS);
        if (PUBNUB_OK != rc) {
            return rc;
        }
        request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};
        request->path_segments[n++] = encoded_channels;
    }
    request->path_segment_count = n;

    /* disable_uuids=1 when UUIDs are not requested. */
    if (!inputs->include_uuids) {
        rc = pn_request_add_query_param(request, "disable_uuids", "1", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    /* state=1 when per-user state is requested. */
    if (inputs->include_state) {
        rc = pn_request_add_query_param(request, "state", "1", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    /* limit=N when caller requests a bounded occupant list. */
    if (0U < inputs->limit) {
        char buf[12];
        int  rc_fmt;
        rc_fmt = pn_snprintf(buf, sizeof(buf), "%u", (unsigned int)inputs->limit);
        if (0 > rc_fmt || rc_fmt >= (int)sizeof(buf)) {
            return PUBNUB_ERR_SERIALIZATION;
        }
        rc = pn_request_add_query_param(request, "limit", buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    /* offset=N to skip the first N occupants in the server-ordered list. */
    if (0U < inputs->offset) {
        char buf[12];
        int  rc_fmt;
        rc_fmt = pn_snprintf(buf, sizeof(buf), "%u", (unsigned int)inputs->offset);
        if (0 > rc_fmt || rc_fmt >= (int)sizeof(buf)) {
            return PUBNUB_ERR_SERIALIZATION;
        }
        rc = pn_request_add_query_param(request, "offset", buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    /* channel-group query param when groups are targeted. */
    if (has_groups) {
        rc = pn_request_add_query_param(
            request, "channel-group", inputs->channel_groups, PN_ENCODE_KEEP_COMMAS);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_presence_parse_here_now(pubnub_serialization_provider_t* serial,
                                        const pubnub_json_value_t*       tree,
                                        pubnub_allocator_provider_t*     alloc,
                                        pn_presence_here_now_parsed_t*   out)
{
    const pubnub_json_value_t* occ_probe;
    const pubnub_json_value_t* payload;

    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->total_occupancy = 0;
    out->total_channels  = 0;
    out->channels        = NULL;
    out->channel_count   = 0;

    if (NULL == serial || NULL == tree || NULL == alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->value_as_string || NULL == serial->value_as_int) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Discriminate response shape: if top-level has "occupancy" key,
     * it is Shape A (single channel). Otherwise look for "payload"
     * (Shape B, multi-channel/global). */
    occ_probe = serial->object_get(tree, "occupancy", 9);
    if (NULL != occ_probe) {
        return parse_shape_a(serial, tree, alloc, out);
    }

    payload = serial->object_get(tree, "payload", 7);
    if (NULL != payload && PUBNUB_JSON_OBJECT == serial->value_type(payload)) {
        return parse_shape_b(serial, payload, alloc, out);
    }

    /* Neither shape matched - possibly an error envelope already
     * caught by the validator, or unexpected format. */
    return PUBNUB_ERR_SERIALIZATION;
}

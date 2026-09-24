/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "app_context_internal.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_wire_uuid.c requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "core/protocol_common/pn_buf_serialize.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

pubnub_res_t pn_uuid_metadata_build_path_get_all(pubnub_http_request_t* request,
                                                 const char* subscribe_key)
{
    if (NULL == request || NULL == subscribe_key) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"objects", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"uuids", 5};
    request->path_segment_count = n;

    return PUBNUB_OK;
}

pubnub_res_t pn_uuid_metadata_build_path_single(pubnub_http_request_t* request,
                                                pubnub_allocator_provider_t* allocator,
                                                const char* subscribe_key,
                                                const char* uuid,
                                                char**      out_encoded)
{
    if (NULL == request || NULL == allocator || NULL == subscribe_key
        || NULL == uuid || NULL == out_encoded) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_encoded = NULL;

    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    size_t uuid_len     = strlen(uuid);
    char*  encoded_uuid = pn_url_encode_alloc_n(
        (const uint8_t*)uuid, uuid_len, allocator, PN_ENCODE_FULL);
    if (NULL == encoded_uuid) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"objects", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"uuids", 5};
    request->path_segments[n++] =
        (pubnub_string_view_t){encoded_uuid, strlen(encoded_uuid)};
    request->path_segment_count = n;

    *out_encoded = encoded_uuid;
    return PUBNUB_OK;
}

static pubnub_res_t set_string_field(pubnub_serialization_provider_t* serial,
                                     pubnub_json_value_t*             obj,
                                     const char*                      key,
                                     size_t                           key_len,
                                     const char*                      value)
{
    pubnub_json_value_t* val =
        serial->value_create_string(serial, value, strlen(value));
    if (NULL == val) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    pubnub_res_t rc = serial->object_set(serial, obj, key, key_len, val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, val);
    }
    return rc;
}

pubnub_res_t pn_uuid_metadata_build_body(pubnub_serialization_provider_t* serial,
                                         pubnub_allocator_provider_t* alloc,
                                         const pubnub_set_uuid_metadata_opts_t* opts,
                                         pubnub_buffer_t* body_buf)
{
    if (NULL == serial || NULL == opts || NULL == body_buf
        || NULL == body_buf->data || 0 == body_buf->cap) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->value_create_object || NULL == serial->object_set
        || NULL == serial->value_create_string || NULL == serial->serialize
        || NULL == serial->value_destroy) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    pubnub_json_value_t* obj = serial->value_create_object(serial);
    if (NULL == obj) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    pubnub_res_t rc = PUBNUB_OK;

    if (NULL != opts->name) {
        rc = set_string_field(serial, obj, "name", 4, opts->name);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    if (NULL != opts->external_id) {
        rc = set_string_field(serial, obj, "externalId", 10, opts->external_id);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    if (NULL != opts->profile_url) {
        rc = set_string_field(serial, obj, "profileUrl", 10, opts->profile_url);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    if (NULL != opts->email) {
        rc = set_string_field(serial, obj, "email", 5, opts->email);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    if (NULL != opts->type) {
        rc = set_string_field(serial, obj, "type", 4, opts->type);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    if (NULL != opts->status) {
        rc = set_string_field(serial, obj, "status", 6, opts->status);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    rc = pn_app_context_set_custom_field(
        serial, obj, opts->custom_value, opts->custom, opts->custom_len);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_buf_serialize_grow(alloc, serial, obj, body_buf);

cleanup:
    serial->value_destroy(serial, obj);
    return rc;
}

pubnub_res_t pn_uuid_metadata_parse(pubnub_serialization_provider_t* serial,
                                    const pubnub_json_value_t*       data_node,
                                    pubnub_uuid_metadata_t*          out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));

    if (NULL == serial || NULL == data_node) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->object_get || NULL == serial->value_as_string) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    pubnub_json_value_t* parent = (pubnub_json_value_t*)data_node;

    pn_extract_obj_string(serial, parent, "id", 2, &out->id);
    pn_extract_obj_string(serial, parent, "name", 4, &out->name);
    pn_extract_obj_string(serial, parent, "externalId", 10, &out->external_id);
    pn_extract_obj_string(serial, parent, "profileUrl", 10, &out->profile_url);
    pn_extract_obj_string(serial, parent, "email", 5, &out->email);
    pn_extract_obj_string(serial, parent, "type", 4, &out->type);
    pn_extract_obj_string(serial, parent, "status", 6, &out->status);

    out->custom = serial->object_get(parent, "custom", 6);

    pn_extract_obj_string(serial, parent, "updated", 7, &out->updated);
    pn_extract_obj_string(serial, parent, "eTag", 4, &out->etag);

    return PUBNUB_OK;
}

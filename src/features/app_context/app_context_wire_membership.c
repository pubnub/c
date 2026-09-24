/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "app_context_internal.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_wire_membership.c requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "core/protocol_common/pn_buf_serialize.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <string.h>

typedef struct build_set_extras {
    const char*               status;
    const char*               type;
    const char*               custom;
    size_t                    custom_len;
    struct pubnub_json_value* custom_value;
} build_set_extras_t;

/**
 * @brief Build a single membership/member set-item JSON object.
 *
 * Constructs {"channel":{"id":"..."}, "status":"...", ...} for
 * memberships or {"uuid":{"id":"..."}, ...} for members. Optional
 * fields (status, type, custom) are only included when non-NULL.
 *
 * @param serial     Serialization provider.
 * @param id_value   The identifier string (channel_id or uuid_id).
 * @param id_key     The JSON key for the identifier object
 *                   ("channel" or "uuid").
 * @param id_key_len Length of id_key.
 * @param extras     Optional fields (status, type, custom). May be
 *                   NULL to skip all optional fields.
 * @return Owned JSON object node, or NULL on failure.
 */
static pubnub_json_value_t* build_set_item(pubnub_serialization_provider_t* serial,
                                           const char*               id_value,
                                           const char*               id_key,
                                           size_t                    id_key_len,
                                           const build_set_extras_t* extras)
{
    pubnub_json_value_t* item = serial->value_create_object(serial);
    if (NULL == item) {
        return NULL;
    }

    /* Build inner identifier object: {"id": "<id_value>"}. */
    pubnub_json_value_t* id_obj = serial->value_create_object(serial);
    if (NULL == id_obj) {
        goto fail;
    }

    pubnub_json_value_t* id_str =
        serial->value_create_string(serial, id_value, strlen(id_value));
    if (NULL == id_str) {
        serial->value_destroy(serial, id_obj);
        goto fail;
    }

    if (PUBNUB_OK != serial->object_set(serial, id_obj, "id", 2, id_str)) {
        serial->value_destroy(serial, id_str);
        serial->value_destroy(serial, id_obj);
        goto fail;
    }

    /* Attach the identifier object under the direction key. */
    if (PUBNUB_OK != serial->object_set(serial, item, id_key, id_key_len, id_obj)) {
        serial->value_destroy(serial, id_obj);
        goto fail;
    }

    /* Optional fields — skip entirely when extras is NULL. */
    if (NULL != extras) {
        /* Optional: status. */
        if (NULL != extras->status) {
            pubnub_json_value_t* val = serial->value_create_string(
                serial, extras->status, strlen(extras->status));
            if (NULL == val) {
                goto fail;
            }
            if (PUBNUB_OK != serial->object_set(serial, item, "status", 6, val)) {
                serial->value_destroy(serial, val);
                goto fail;
            }
        }

        /* Optional: type. */
        if (NULL != extras->type) {
            pubnub_json_value_t* val = serial->value_create_string(
                serial, extras->type, strlen(extras->type));
            if (NULL == val) {
                goto fail;
            }
            if (PUBNUB_OK != serial->object_set(serial, item, "type", 4, val)) {
                serial->value_destroy(serial, val);
                goto fail;
            }
        }

        /* Optional: custom (JSON value tree or raw string). */
        if (PUBNUB_OK
            != pn_app_context_set_custom_field(
                serial, item, extras->custom_value, extras->custom, extras->custom_len)) {
            goto fail;
        }
    }

    return item;

fail:
    serial->value_destroy(serial, item);
    return NULL;
}

/**
 * @brief Build a remove-item JSON object (id-only).
 *
 * Constructs {"channel":{"id":"..."}} or {"uuid":{"id":"..."}}.
 */
static pubnub_json_value_t* build_remove_item(pubnub_serialization_provider_t* serial,
                                              const char* id_value,
                                              const char* id_key,
                                              size_t      id_key_len)
{
    pubnub_json_value_t* item = serial->value_create_object(serial);
    if (NULL == item) {
        return NULL;
    }

    pubnub_json_value_t* id_obj = serial->value_create_object(serial);
    if (NULL == id_obj) {
        goto fail;
    }

    pubnub_json_value_t* id_str =
        serial->value_create_string(serial, id_value, strlen(id_value));
    if (NULL == id_str) {
        serial->value_destroy(serial, id_obj);
        goto fail;
    }

    if (PUBNUB_OK != serial->object_set(serial, id_obj, "id", 2, id_str)) {
        serial->value_destroy(serial, id_str);
        serial->value_destroy(serial, id_obj);
        goto fail;
    }

    if (PUBNUB_OK != serial->object_set(serial, item, id_key, id_key_len, id_obj)) {
        serial->value_destroy(serial, id_obj);
        goto fail;
    }

    return item;

fail:
    serial->value_destroy(serial, item);
    return NULL;
}

/**
 * @brief Validate serialization vtable for body building.
 */
static pubnub_res_t validate_serial_for_body(pubnub_serialization_provider_t* serial,
                                             pubnub_buffer_t* body_buf)
{
    if (NULL == serial || NULL == body_buf || NULL == body_buf->data
        || 0 == body_buf->cap) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->value_create_object || NULL == serial->object_set
        || NULL == serial->value_create_string
        || NULL == serial->value_create_array || NULL == serial->array_append
        || NULL == serial->serialize || NULL == serial->value_destroy) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    return PUBNUB_OK;
}

pubnub_res_t pn_memberships_build_path(pubnub_http_request_t*       request,
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
    request->path_segments[n++] = (pubnub_string_view_t){"channels", 8};
    request->path_segment_count = n;

    *out_encoded = encoded_uuid;
    return PUBNUB_OK;
}

pubnub_res_t pn_members_build_path(pubnub_http_request_t*       request,
                                   pubnub_allocator_provider_t* allocator,
                                   const char*                  subscribe_key,
                                   const char*                  channel,
                                   char**                       out_encoded)
{
    if (NULL == request || NULL == allocator || NULL == subscribe_key
        || NULL == channel || NULL == out_encoded) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_encoded = NULL;

    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    size_t channel_len     = strlen(channel);
    char*  encoded_channel = pn_url_encode_alloc_n(
        (const uint8_t*)channel, channel_len, allocator, PN_ENCODE_FULL);
    if (NULL == encoded_channel) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"objects", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channels", 8};
    request->path_segments[n++] =
        (pubnub_string_view_t){encoded_channel, strlen(encoded_channel)};
    request->path_segments[n++] = (pubnub_string_view_t){"uuids", 5};
    request->path_segment_count = n;

    *out_encoded = encoded_channel;
    return PUBNUB_OK;
}

/**
 * @brief Common layout shared by pubnub_membership_input_t and
 * pubnub_member_input_t (identical binary layout; only the first
 * field name differs: channel_id vs uuid_id).
 */
typedef struct pn_relation_input_view {
    const char*               id;
    const char*               status;
    const char*               type;
    const char*               custom;
    size_t                    custom_len;
    struct pubnub_json_value* custom_value;
} pn_relation_input_view_t;

PUBNUB_STATIC_ASSERT(sizeof(pn_relation_input_view_t)
                         == sizeof(pubnub_membership_input_t),
                     "membership input layout mismatch");
PUBNUB_STATIC_ASSERT(sizeof(pn_relation_input_view_t)
                         == sizeof(pubnub_member_input_t),
                     "member input layout mismatch");
PUBNUB_STATIC_ASSERT(offsetof(pn_relation_input_view_t, status)
                         == offsetof(pubnub_membership_input_t, status),
                     "status offset mismatch with membership");
PUBNUB_STATIC_ASSERT(offsetof(pn_relation_input_view_t, status)
                         == offsetof(pubnub_member_input_t, status),
                     "status offset mismatch with member");
PUBNUB_STATIC_ASSERT(offsetof(pn_relation_input_view_t, custom_len)
                         == offsetof(pubnub_membership_input_t, custom_len),
                     "custom_len offset mismatch with membership");
PUBNUB_STATIC_ASSERT(offsetof(pn_relation_input_view_t, custom_len)
                         == offsetof(pubnub_member_input_t, custom_len),
                     "custom_len offset mismatch with member");
PUBNUB_STATIC_ASSERT(offsetof(pn_relation_input_view_t, custom_value)
                         == offsetof(pubnub_membership_input_t, custom_value),
                     "custom_value offset mismatch with membership");
PUBNUB_STATIC_ASSERT(offsetof(pn_relation_input_view_t, custom_value)
                         == offsetof(pubnub_member_input_t, custom_value),
                     "custom_value offset mismatch with member");

/**
 * @brief Build the "set" JSON array and attach it to @p root under "set".
 *
 * On success the array is owned by @p root. On failure the partially-built
 * array is destroyed and @p root is left untouched for the caller to free.
 *
 * @param serial      Serialization provider.
 * @param root        Parent object to receive the "set" array.
 * @param set_view    Array of relation inputs to serialize.
 * @param set_count   Number of entries in @p set_view.
 * @param id_key      Identity key name ("uuid" or "channel").
 * @param id_key_len  Length of @p id_key.
 * @return PUBNUB_OK on success, or an error code on validation / allocation
 *         failure.
 */
static pubnub_res_t build_set_array(pubnub_serialization_provider_t* serial,
                                    pubnub_json_value_t*             root,
                                    const pn_relation_input_view_t*  set_view,
                                    size_t                           set_count,
                                    const char*                      id_key,
                                    size_t                           id_key_len)
{
    size_t               i;
    pubnub_res_t         rc  = PUBNUB_OK;
    pubnub_json_value_t* arr = serial->value_create_array(serial);

    if (NULL == arr) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    for (i = 0; i < set_count; ++i) {
        build_set_extras_t   extras = {0};
        pubnub_json_value_t* item   = NULL;

        if (NULL == set_view[i].id) {
            serial->value_destroy(serial, arr);
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        extras.status       = set_view[i].status;
        extras.type         = set_view[i].type;
        extras.custom       = set_view[i].custom;
        extras.custom_len   = set_view[i].custom_len;
        extras.custom_value = set_view[i].custom_value;
        item = build_set_item(serial, set_view[i].id, id_key, id_key_len, &extras);
        if (NULL == item) {
            serial->value_destroy(serial, arr);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        rc = serial->array_append(serial, arr, item);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, item);
            serial->value_destroy(serial, arr);
            return rc;
        }
    }

    rc = serial->object_set(serial, root, "set", 3, arr);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, arr);
    }
    return rc;
}

/**
 * @brief Build the "delete" JSON array and attach it to @p root under "delete".
 *
 * "delete" is the PubNub Objects v2 API key for removals. On success the
 * array is owned by @p root; on failure it is destroyed and @p root is left
 * untouched for the caller to free.
 *
 * @param serial        Serialization provider.
 * @param root          Parent object to receive the "delete" array.
 * @param remove_view   Array of relation inputs to serialize.
 * @param remove_count  Number of entries in @p remove_view.
 * @param id_key        Identity key name ("uuid" or "channel").
 * @param id_key_len    Length of @p id_key.
 * @return PUBNUB_OK on success, or an error code on validation / allocation
 *         failure.
 */
static pubnub_res_t build_delete_array(pubnub_serialization_provider_t* serial,
                                       pubnub_json_value_t*             root,
                                       const pn_relation_input_view_t* remove_view,
                                       size_t      remove_count,
                                       const char* id_key,
                                       size_t      id_key_len)
{
    size_t               i;
    pubnub_res_t         rc  = PUBNUB_OK;
    pubnub_json_value_t* arr = serial->value_create_array(serial);

    if (NULL == arr) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    for (i = 0; i < remove_count; ++i) {
        pubnub_json_value_t* item = NULL;

        if (NULL == remove_view[i].id) {
            serial->value_destroy(serial, arr);
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        item = build_remove_item(serial, remove_view[i].id, id_key, id_key_len);
        if (NULL == item) {
            serial->value_destroy(serial, arr);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        rc = serial->array_append(serial, arr, item);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, item);
            serial->value_destroy(serial, arr);
            return rc;
        }
    }

    rc = serial->object_set(serial, root, "delete", 6, arr);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, arr);
    }
    return rc;
}

/**
 * @brief Build a PATCH body with "set" and "delete" arrays for
 * membership or member operations.
 *
 * Both pubnub_membership_input_t and pubnub_member_input_t share
 * identical binary layout, so we treat items through a common view.
 *
 * @param id_key Identity key name and length ("uuid" or "channel").
 */
static pubnub_res_t build_set_remove_body(pubnub_serialization_provider_t* serial,
                                          pubnub_allocator_provider_t* alloc,
                                          const void*          set_items,
                                          size_t               set_count,
                                          const void*          remove_items,
                                          size_t               remove_count,
                                          pubnub_string_view_t id_key,
                                          pubnub_buffer_t*     body_buf)
{
    pubnub_res_t rc = validate_serial_for_body(serial, body_buf);

    if (PUBNUB_OK != rc) {
        return rc;
    }
    if (0 == set_count && 0 == remove_count) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if ((set_count > 0 && NULL == set_items)
        || (remove_count > 0 && NULL == remove_items)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_json_value_t* root = serial->value_create_object(serial);
    if (NULL == root) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    const pn_relation_input_view_t* set_view =
        (const pn_relation_input_view_t*)set_items;
    const pn_relation_input_view_t* rem_view =
        (const pn_relation_input_view_t*)remove_items;

    if (set_count > 0) {
        rc = build_set_array(
            serial, root, set_view, set_count, id_key.ptr, id_key.len);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    if (remove_count > 0) {
        rc = build_delete_array(
            serial, root, rem_view, remove_count, id_key.ptr, id_key.len);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    rc = pn_buf_serialize_grow(alloc, serial, root, body_buf);

cleanup:
    serial->value_destroy(serial, root);
    return rc;
}

pubnub_res_t pn_memberships_build_body(pubnub_serialization_provider_t* serial,
                                       pubnub_allocator_provider_t*     alloc,
                                       const pubnub_membership_input_t* set_items,
                                       size_t set_count,
                                       const pubnub_membership_input_t* remove_items,
                                       size_t           remove_count,
                                       pubnub_buffer_t* body_buf)
{
    return build_set_remove_body(serial,
                                 alloc,
                                 set_items,
                                 set_count,
                                 remove_items,
                                 remove_count,
                                 (pubnub_string_view_t){"channel", 7},
                                 body_buf);
}

pubnub_res_t pn_members_build_body(pubnub_serialization_provider_t* serial,
                                   pubnub_allocator_provider_t*     alloc,
                                   const pubnub_member_input_t*     set_items,
                                   size_t                           set_count,
                                   const pubnub_member_input_t* remove_items,
                                   size_t                       remove_count,
                                   pubnub_buffer_t*             body_buf)
{
    return build_set_remove_body(serial,
                                 alloc,
                                 set_items,
                                 set_count,
                                 remove_items,
                                 remove_count,
                                 (pubnub_string_view_t){"uuid", 4},
                                 body_buf);
}

/**
 * @brief Parse top-level membership/member fields (status, type,
 * custom, updated, eTag) from a JSON data node.
 */
static void parse_relationship_fields(pubnub_serialization_provider_t* serial,
                                      const pubnub_json_value_t*  data_node,
                                      pubnub_string_view_t*       out_status,
                                      pubnub_string_view_t*       out_type,
                                      const pubnub_json_value_t** out_custom,
                                      pubnub_string_view_t*       out_updated,
                                      pubnub_string_view_t*       out_etag)
{
    pubnub_json_value_t* parent = (pubnub_json_value_t*)data_node;

    pn_extract_obj_string(serial, parent, "status", 6, out_status);
    pn_extract_obj_string(serial, parent, "type", 4, out_type);

    *out_custom = serial->object_get(parent, "custom", 6);

    pn_extract_obj_string(serial, parent, "updated", 7, out_updated);
    pn_extract_obj_string(serial, parent, "eTag", 4, out_etag);
}

pubnub_res_t pn_membership_parse(pubnub_serialization_provider_t* serial,
                                 const pubnub_json_value_t*       data_node,
                                 pubnub_membership_t*             out)
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

    /* Extract the "channel" sub-object and delegate to metadata parse. */
    pubnub_json_value_t* channel_node =
        serial->object_get((pubnub_json_value_t*)data_node, "channel", 7);
    if (NULL != channel_node) {
        pn_channel_metadata_parse(serial, channel_node, &out->channel);
    }

    /* Extract relationship-level fields. */
    parse_relationship_fields(serial,
                              data_node,
                              &out->status,
                              &out->type,
                              &out->custom,
                              &out->updated,
                              &out->etag);

    return PUBNUB_OK;
}

pubnub_res_t pn_member_parse(pubnub_serialization_provider_t* serial,
                             const pubnub_json_value_t*       data_node,
                             pubnub_member_t*                 out)
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

    /* Extract the "uuid" sub-object and delegate to metadata parse. */
    pubnub_json_value_t* uuid_node =
        serial->object_get((pubnub_json_value_t*)data_node, "uuid", 4);
    if (NULL != uuid_node) {
        pn_uuid_metadata_parse(serial, uuid_node, &out->uuid);
    }

    /* Extract relationship-level fields. */
    parse_relationship_fields(serial,
                              data_node,
                              &out->status,
                              &out->type,
                              &out->custom,
                              &out->updated,
                              &out->etag);

    return PUBNUB_OK;
}

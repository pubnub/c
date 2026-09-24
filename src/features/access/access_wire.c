/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "access_internal.h"

#if !PUBNUB_ENABLE_PAM
#error "access_wire.c requires PUBNUB_ENABLE_PAM=ON"
#endif

#include "core/pn_format.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

/**
 * @brief Populate a resource sub-object (channels/groups/uuids) from
 *        a permissions array.
 *
 * Each entry in @p perms becomes a key-value pair where the key is the
 * resource name and the value is the integer permission bitmask.
 *
 * @param serial      Serialization provider (borrowed).
 * @param container   Object node to populate (ownership retained by
 *                    caller).
 * @param perms       Array of resource permissions (borrowed).
 * @param count       Number of entries in @p perms.
 * @return @c PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t
pn_access_populate_resource_obj(pubnub_serialization_provider_t* serial,
                                pubnub_json_value_t*             container,
                                const pubnub_access_resource_permission_t* perms,
                                size_t count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        if (NULL == perms[i].name) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        pubnub_json_value_t* val =
            serial->value_create_int(serial, (int)perms[i].permissions);
        if (NULL == val) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        pubnub_res_t rc = serial->object_set(
            serial, container, perms[i].name, strlen(perms[i].name), val);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, val);
            return rc;
        }
    }
    return PUBNUB_OK;
}

/**
 * @brief Build the "resources" or "patterns" sub-object containing
 *        channels, groups, and uuids keys.
 *
 * Always creates all three child objects (server requires them even
 * when empty).
 *
 * @param serial      Serialization provider (borrowed).
 * @param channels    Channel permissions (or NULL).
 * @param ch_count    Channel permissions count.
 * @param groups      Group permissions (or NULL).
 * @param grp_count   Group permissions count.
 * @param uuids       UUID permissions (or NULL).
 * @param uuid_count  UUID permissions count.
 * @return Owned object node, or NULL on allocation/build failure.
 */
static pubnub_json_value_t*
pn_access_build_scope_obj(pubnub_serialization_provider_t*           serial,
                          const pubnub_access_resource_permission_t* channels,
                          size_t                                     ch_count,
                          const pubnub_access_resource_permission_t* groups,
                          size_t                                     grp_count,
                          const pubnub_access_resource_permission_t* uuids,
                          size_t                                     uuid_count)
{
    pubnub_json_value_t* scope = serial->value_create_object(serial);
    if (NULL == scope) {
        return NULL;
    }

    pubnub_json_value_t* ch_obj = serial->value_create_object(serial);
    if (NULL == ch_obj) {
        serial->value_destroy(serial, scope);
        return NULL;
    }
    if (NULL != channels && ch_count > 0) {
        pubnub_res_t rc =
            pn_access_populate_resource_obj(serial, ch_obj, channels, ch_count);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, ch_obj);
            serial->value_destroy(serial, scope);
            return NULL;
        }
    }
    pubnub_res_t rc = serial->object_set(serial, scope, "channels", 8, ch_obj);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, ch_obj);
        serial->value_destroy(serial, scope);
        return NULL;
    }

    pubnub_json_value_t* grp_obj = serial->value_create_object(serial);
    if (NULL == grp_obj) {
        serial->value_destroy(serial, scope);
        return NULL;
    }
    if (NULL != groups && grp_count > 0) {
        rc = pn_access_populate_resource_obj(serial, grp_obj, groups, grp_count);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, grp_obj);
            serial->value_destroy(serial, scope);
            return NULL;
        }
    }
    rc = serial->object_set(serial, scope, "groups", 6, grp_obj);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, grp_obj);
        serial->value_destroy(serial, scope);
        return NULL;
    }

    pubnub_json_value_t* uuid_obj = serial->value_create_object(serial);
    if (NULL == uuid_obj) {
        serial->value_destroy(serial, scope);
        return NULL;
    }
    if (NULL != uuids && uuid_count > 0) {
        rc = pn_access_populate_resource_obj(serial, uuid_obj, uuids, uuid_count);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, uuid_obj);
            serial->value_destroy(serial, scope);
            return NULL;
        }
    }
    rc = serial->object_set(serial, scope, "uuids", 5, uuid_obj);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, uuid_obj);
        serial->value_destroy(serial, scope);
        return NULL;
    }

    return scope;
}

pubnub_res_t pn_access_grant_build_path(pubnub_http_request_t* request,
                                        const char*            subscribe_key)
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
    request->path_segments[n++] = (pubnub_string_view_t){"v3", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"pam", 3};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"grant", 5};
    request->path_segment_count = n;

    return PUBNUB_OK;
}

pubnub_res_t pn_access_grant_build_body(pubnub_serialization_provider_t* serial,
                                        const pubnub_grant_token_opts_t* opts,
                                        uint8_t*                         buf,
                                        size_t                           cap,
                                        size_t* out_len)
{
    if (NULL == serial || NULL == opts || NULL == buf || 0 == cap
        || NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->value_create_object || NULL == serial->value_create_int
        || NULL == serial->value_create_string || NULL == serial->object_set
        || NULL == serial->serialize || NULL == serial->value_destroy) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Root object. */
    pubnub_json_value_t* root = serial->value_create_object(serial);
    if (NULL == root) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* "ttl" */
    pubnub_json_value_t* ttl_val = serial->value_create_int(serial, (int)opts->ttl);
    if (NULL == ttl_val) {
        serial->value_destroy(serial, root);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    pubnub_res_t rc = serial->object_set(serial, root, "ttl", 3, ttl_val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, ttl_val);
        serial->value_destroy(serial, root);
        return rc;
    }

    /* "permissions" object */
    pubnub_json_value_t* perms = serial->value_create_object(serial);
    if (NULL == perms) {
        serial->value_destroy(serial, root);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* "resources" */
    pubnub_json_value_t* resources = pn_access_build_scope_obj(serial,
                                                               opts->channels,
                                                               opts->channel_count,
                                                               opts->groups,
                                                               opts->group_count,
                                                               opts->uuids,
                                                               opts->uuid_count);
    if (NULL == resources) {
        serial->value_destroy(serial, perms);
        serial->value_destroy(serial, root);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    rc = serial->object_set(serial, perms, "resources", 9, resources);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, resources);
        serial->value_destroy(serial, perms);
        serial->value_destroy(serial, root);
        return rc;
    }

    /* "patterns" */
    pubnub_json_value_t* patterns =
        pn_access_build_scope_obj(serial,
                                  opts->channel_patterns,
                                  opts->channel_pattern_count,
                                  opts->group_patterns,
                                  opts->group_pattern_count,
                                  opts->uuid_patterns,
                                  opts->uuid_pattern_count);
    if (NULL == patterns) {
        serial->value_destroy(serial, perms);
        serial->value_destroy(serial, root);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    rc = serial->object_set(serial, perms, "patterns", 8, patterns);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, patterns);
        serial->value_destroy(serial, perms);
        serial->value_destroy(serial, root);
        return rc;
    }

    /* "meta" — optional raw JSON passthrough. */
    if (NULL != opts->meta) {
        if (NULL == serial->parse) {
            serial->value_destroy(serial, perms);
            serial->value_destroy(serial, root);
            return PUBNUB_ERR_SERIALIZATION;
        }
        pubnub_json_value_t* meta_val =
            serial->parse(serial, (const uint8_t*)opts->meta, strlen(opts->meta));
        if (NULL == meta_val) {
            serial->value_destroy(serial, perms);
            serial->value_destroy(serial, root);
            return PUBNUB_ERR_SERIALIZATION;
        }
        rc = serial->object_set(serial, perms, "meta", 4, meta_val);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, meta_val);
            serial->value_destroy(serial, perms);
            serial->value_destroy(serial, root);
            return rc;
        }
    }

    /* "uuid" — optional authorized UUID. */
    if (NULL != opts->authorized_uuid) {
        pubnub_json_value_t* uuid_val = serial->value_create_string(
            serial, opts->authorized_uuid, strlen(opts->authorized_uuid));
        if (NULL == uuid_val) {
            serial->value_destroy(serial, perms);
            serial->value_destroy(serial, root);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        rc = serial->object_set(serial, perms, "uuid", 4, uuid_val);
        if (PUBNUB_OK != rc) {
            serial->value_destroy(serial, uuid_val);
            serial->value_destroy(serial, perms);
            serial->value_destroy(serial, root);
            return rc;
        }
    }

    /* Attach permissions to root. */
    rc = serial->object_set(serial, root, "permissions", 11, perms);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, perms);
        serial->value_destroy(serial, root);
        return rc;
    }

    /* Serialize the tree into the output buffer. */
    rc = serial->serialize(serial, root, buf, cap, out_len);
    serial->value_destroy(serial, root);
    return rc;
}

pubnub_res_t pn_access_revoke_build_path(pubnub_http_request_t*       request,
                                         pubnub_allocator_provider_t* alloc,
                                         const char* subscribe_key,
                                         const char* token,
                                         char**      out_encoded_token)
{
    if (NULL == request || NULL == alloc || NULL == subscribe_key
        || NULL == token || NULL == out_encoded_token) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_encoded_token = NULL;

    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Tokens can be long (hundreds of bytes); use heap-allocated
     * encoding rather than the fixed scratch buffer. */
    char* encoded = pn_url_encode_alloc_n(
        (const uint8_t*)token, strlen(token), alloc, PN_ENCODE_FULL);
    if (NULL == encoded) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v3", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"pam", 3};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"grant", 5};
    request->path_segments[n++] = (pubnub_string_view_t){encoded, strlen(encoded)};
    request->path_segment_count = n;

    *out_encoded_token = encoded;
    return PUBNUB_OK;
}

pubnub_res_t pn_access_grant_response_validator(const uint8_t* body,
                                                size_t         body_len,
                                                int            http_status)
{
    (void)body;
    (void)body_len;

    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }
    return PUBNUB_OK;
}

pubnub_res_t pn_access_grant_parse_response(pubnub_serialization_provider_t* serial,
                                            const pubnub_json_value_t* tree,
                                            pn_access_grant_parsed_t*  out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->token = (pubnub_string_view_t){NULL, 0};

    if (NULL == serial || NULL == tree || NULL == serial->value_type
        || NULL == serial->object_get || NULL == serial->value_as_string) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Navigate: root["data"]["token"] */
    const pubnub_json_value_t* data_node = serial->object_get(tree, "data", 4);
    if (NULL == data_node || PUBNUB_JSON_OBJECT != serial->value_type(data_node)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* token_node =
        serial->object_get(data_node, "token", 5);
    if (NULL == token_node || PUBNUB_JSON_STRING != serial->value_type(token_node)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    size_t      tok_len = 0;
    const char* tok_ptr = serial->value_as_string(token_node, &tok_len);
    if (NULL == tok_ptr) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    out->token = (pubnub_string_view_t){tok_ptr, tok_len};
    return PUBNUB_OK;
}

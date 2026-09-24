/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/app_context.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

#include "features/app_context/app_context_internal.h"

extern pubnub_serialization_provider_t* pn_serialization_default(void);

static void* stub_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* stub_realloc(pubnub_allocator_provider_t* self,
                          void*                        ptr,
                          size_t                       old_size,
                          size_t                       new_size,
                          size_t                       align)
{
    (void)self;
    (void)old_size;
    (void)align;
    return realloc(ptr, new_size);
}

static void stub_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_alloc = {
    .alloc       = stub_alloc,
    .realloc     = stub_realloc,
    .free        = stub_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

/* ---- Memberships path tests ---- */

static void memberships_path_populates_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_memberships_build_path(
        &req, &s_alloc, "sub-c-key", "user-123", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 6);
    assert_memory_equal(req.path_segments[0].ptr, "v2", 2);
    assert_int_equal(req.path_segments[0].len, 2);
    assert_memory_equal(req.path_segments[1].ptr, "objects", 7);
    assert_int_equal(req.path_segments[1].len, 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-c-key", 9);
    assert_int_equal(req.path_segments[2].len, 9);
    assert_memory_equal(req.path_segments[3].ptr, "uuids", 5);
    assert_int_equal(req.path_segments[3].len, 5);
    assert_non_null(encoded);
    assert_string_equal(encoded, "user-123");
    assert_memory_equal(req.path_segments[4].ptr, "user-123", 8);
    assert_int_equal(req.path_segments[4].len, 8);
    assert_memory_equal(req.path_segments[5].ptr, "channels", 8);
    assert_int_equal(req.path_segments[5].len, 8);

    s_alloc.free(&s_alloc, encoded);
}

static void memberships_path_encodes_special_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_memberships_build_path(
        &req, &s_alloc, "sub-k", "user/test@foo", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(encoded);
    assert_non_null(strstr(encoded, "%2F"));
    assert_non_null(strstr(encoded, "%40"));

    s_alloc.free(&s_alloc, encoded);
}

static void memberships_path_rejects_null_uuid(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc =
        pn_memberships_build_path(&req, &s_alloc, "key", NULL, &encoded);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(encoded);
}

static void memberships_path_rejects_null_request(void** state)
{
    (void)state;
    char*        encoded = NULL;
    pubnub_res_t rc =
        pn_memberships_build_path(NULL, &s_alloc, "key", "uuid", &encoded);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ---- Members path tests ---- */

static void members_path_populates_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc =
        pn_members_build_path(&req, &s_alloc, "sub-c-key", "my-channel", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 6);
    assert_memory_equal(req.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(req.path_segments[1].ptr, "objects", 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(req.path_segments[3].ptr, "channels", 8);
    assert_int_equal(req.path_segments[3].len, 8);
    assert_non_null(encoded);
    assert_string_equal(encoded, "my-channel");
    assert_memory_equal(req.path_segments[4].ptr, "my-channel", 10);
    assert_int_equal(req.path_segments[4].len, 10);
    assert_memory_equal(req.path_segments[5].ptr, "uuids", 5);
    assert_int_equal(req.path_segments[5].len, 5);

    s_alloc.free(&s_alloc, encoded);
}

static void members_path_encodes_special_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc =
        pn_members_build_path(&req, &s_alloc, "sub-k", "chan/test@x", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(encoded);
    assert_non_null(strstr(encoded, "%2F"));
    assert_non_null(strstr(encoded, "%40"));

    s_alloc.free(&s_alloc, encoded);
}

static void members_path_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_members_build_path(&req, &s_alloc, "key", NULL, &encoded);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(encoded);
}

/* ---- Memberships body tests ---- */

static void memberships_body_set_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_membership_input_t set_items[2] = {
        {.channel_id = "ch1", .status = "active", .type = "default"},
        {.channel_id = "ch2"},
    };

    uint8_t         buf[1024];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc =
        pn_memberships_build_body(serial, NULL, set_items, 2, NULL, 0, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    /* Parse back and verify structure. */
    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    /* "set" array should exist with 2 items. */
    pubnub_json_value_t* set_arr = serial->object_get(tree, "set", 3);
    assert_non_null(set_arr);
    assert_int_equal(serial->array_size(set_arr), 2);

    /* First item: {"channel":{"id":"ch1"}, "status":"active", "type":"default"} */
    pubnub_json_value_t* item0 = serial->array_get(set_arr, 0);
    assert_non_null(item0);
    pubnub_json_value_t* ch_obj = serial->object_get(item0, "channel", 7);
    assert_non_null(ch_obj);
    pubnub_json_value_t* id_node = serial->object_get(ch_obj, "id", 2);
    assert_non_null(id_node);
    size_t      slen = 0;
    const char* sptr = serial->value_as_string(id_node, &slen);
    assert_int_equal(slen, 3);
    assert_memory_equal(sptr, "ch1", 3);

    pubnub_json_value_t* status_node = serial->object_get(item0, "status", 6);
    assert_non_null(status_node);
    sptr = serial->value_as_string(status_node, &slen);
    assert_memory_equal(sptr, "active", 6);

    pubnub_json_value_t* type_node = serial->object_get(item0, "type", 4);
    assert_non_null(type_node);
    sptr = serial->value_as_string(type_node, &slen);
    assert_memory_equal(sptr, "default", 7);

    /* Second item: only channel id, no optional fields. */
    pubnub_json_value_t* item1 = serial->array_get(set_arr, 1);
    assert_non_null(item1);
    ch_obj = serial->object_get(item1, "channel", 7);
    assert_non_null(ch_obj);
    id_node = serial->object_get(ch_obj, "id", 2);
    assert_non_null(id_node);
    sptr = serial->value_as_string(id_node, &slen);
    assert_memory_equal(sptr, "ch2", 3);
    assert_null(serial->object_get(item1, "status", 6));
    assert_null(serial->object_get(item1, "type", 4));

    /* "remove" and "delete" should NOT exist. */
    assert_null(serial->object_get(tree, "remove", 6));
    assert_null(serial->object_get(tree, "delete", 6));

    serial->value_destroy(serial, tree);
}

static void memberships_body_remove_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_membership_input_t remove_items[1] = {
        {.channel_id = "ch-rm"},
    };

    uint8_t         buf[512];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc =
        pn_memberships_build_body(serial, NULL, NULL, 0, remove_items, 1, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    /* "set" should NOT exist. */
    assert_null(serial->object_get(tree, "set", 3));

    /* "delete" should have 1 item with channel id only. */
    pubnub_json_value_t* rm_arr = serial->object_get(tree, "delete", 6);
    assert_non_null(rm_arr);
    assert_int_equal(serial->array_size(rm_arr), 1);

    pubnub_json_value_t* item0 = serial->array_get(rm_arr, 0);
    assert_non_null(item0);
    pubnub_json_value_t* ch_obj = serial->object_get(item0, "channel", 7);
    assert_non_null(ch_obj);
    pubnub_json_value_t* id_node = serial->object_get(ch_obj, "id", 2);
    assert_non_null(id_node);
    size_t      slen = 0;
    const char* sptr = serial->value_as_string(id_node, &slen);
    assert_memory_equal(sptr, "ch-rm", 5);

    /* Remove items should not have optional fields. */
    assert_null(serial->object_get(item0, "status", 6));
    assert_null(serial->object_get(item0, "type", 4));
    assert_null(serial->object_get(item0, "custom", 6));

    serial->value_destroy(serial, tree);
}

static void memberships_body_set_and_remove(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_membership_input_t set_items[1] = {
        {.channel_id = "ch-set", .custom = "{\"k\":1}"},
    };
    pubnub_membership_input_t remove_items[1] = {
        {.channel_id = "ch-del"},
    };

    uint8_t         buf[1024];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc = pn_memberships_build_body(
        serial, NULL, set_items, 1, remove_items, 1, &body);

    assert_int_equal(rc, PUBNUB_OK);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    /* Both "set" and "delete" must exist. */
    assert_non_null(serial->object_get(tree, "set", 3));
    assert_non_null(serial->object_get(tree, "delete", 6));

    serial->value_destroy(serial, tree);
}

static void memberships_body_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_membership_input_t items[1] = {{.channel_id = "x"}};
    uint8_t                   buf[64];
    pubnub_buffer_t body = {.data = buf, .len = 0, .cap = sizeof(buf)};

    pubnub_res_t rc =
        pn_memberships_build_body(NULL, NULL, items, 1, NULL, 0, &body);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void memberships_body_rejects_null_body_buf(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial   = pn_serialization_default();
    pubnub_membership_input_t        items[1] = {{.channel_id = "x"}};

    pubnub_res_t rc =
        pn_memberships_build_body(serial, NULL, items, 1, NULL, 0, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ---- Members body tests ---- */

static void members_body_set_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_member_input_t set_items[2] = {
        {.uuid_id = "user-1", .status = "active", .type = "admin"},
        {.uuid_id = "user-2"},
    };

    uint8_t         buf[1024];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc =
        pn_members_build_body(serial, NULL, set_items, 2, NULL, 0, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    pubnub_json_value_t* set_arr = serial->object_get(tree, "set", 3);
    assert_non_null(set_arr);
    assert_int_equal(serial->array_size(set_arr), 2);

    /* First item uses "uuid" key. */
    pubnub_json_value_t* item0 = serial->array_get(set_arr, 0);
    assert_non_null(item0);
    pubnub_json_value_t* uuid_obj = serial->object_get(item0, "uuid", 4);
    assert_non_null(uuid_obj);
    pubnub_json_value_t* id_node = serial->object_get(uuid_obj, "id", 2);
    assert_non_null(id_node);
    size_t      slen = 0;
    const char* sptr = serial->value_as_string(id_node, &slen);
    assert_memory_equal(sptr, "user-1", 6);

    /* Second item: id only. */
    pubnub_json_value_t* item1 = serial->array_get(set_arr, 1);
    uuid_obj                   = serial->object_get(item1, "uuid", 4);
    assert_non_null(uuid_obj);
    id_node = serial->object_get(uuid_obj, "id", 2);
    sptr    = serial->value_as_string(id_node, &slen);
    assert_memory_equal(sptr, "user-2", 6);
    assert_null(serial->object_get(item1, "status", 6));

    assert_null(serial->object_get(tree, "remove", 6));
    assert_null(serial->object_get(tree, "delete", 6));

    serial->value_destroy(serial, tree);
}

static void members_body_remove_only(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_member_input_t remove_items[1] = {{.uuid_id = "user-rm"}};

    uint8_t         buf[512];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc =
        pn_members_build_body(serial, NULL, NULL, 0, remove_items, 1, &body);

    assert_int_equal(rc, PUBNUB_OK);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    assert_null(serial->object_get(tree, "set", 3));

    pubnub_json_value_t* rm_arr = serial->object_get(tree, "delete", 6);
    assert_non_null(rm_arr);
    assert_int_equal(serial->array_size(rm_arr), 1);

    pubnub_json_value_t* item0    = serial->array_get(rm_arr, 0);
    pubnub_json_value_t* uuid_obj = serial->object_get(item0, "uuid", 4);
    assert_non_null(uuid_obj);
    pubnub_json_value_t* id_node = serial->object_get(uuid_obj, "id", 2);
    size_t               slen    = 0;
    const char*          sptr    = serial->value_as_string(id_node, &slen);
    assert_memory_equal(sptr, "user-rm", 7);

    serial->value_destroy(serial, tree);
}

static void members_body_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_member_input_t items[1] = {{.uuid_id = "x"}};
    uint8_t               buf[64];
    pubnub_buffer_t       body = {.data = buf, .len = 0, .cap = sizeof(buf)};

    pubnub_res_t rc = pn_members_build_body(NULL, NULL, items, 1, NULL, 0, &body);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ---- Membership parse tests ---- */

static void membership_parse_full(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"channel\":{\"id\":\"ch1\",\"name\":\"General\","
                       "\"description\":\"Main channel\"},"
                       "\"status\":\"active\",\"type\":\"member\","
                       "\"updated\":\"2025-01-01T00:00:00Z\","
                       "\"eTag\":\"etag-123\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_membership_t result;
    pubnub_res_t        rc = pn_membership_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    /* Channel metadata should be populated. */
    assert_int_equal(result.channel.id.len, 3);
    assert_memory_equal(result.channel.id.ptr, "ch1", 3);
    assert_int_equal(result.channel.name.len, 7);
    assert_memory_equal(result.channel.name.ptr, "General", 7);
    assert_int_equal(result.channel.description.len, 12);
    assert_memory_equal(result.channel.description.ptr, "Main channel", 12);

    /* Relationship fields. */
    assert_int_equal(result.status.len, 6);
    assert_memory_equal(result.status.ptr, "active", 6);
    assert_int_equal(result.type.len, 6);
    assert_memory_equal(result.type.ptr, "member", 6);
    assert_int_equal(result.updated.len, 20);
    assert_memory_equal(result.updated.ptr, "2025-01-01T00:00:00Z", 20);
    assert_int_equal(result.etag.len, 8);
    assert_memory_equal(result.etag.ptr, "etag-123", 8);

    serial->value_destroy(serial, tree);
}

static void membership_parse_minimal(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"channel\":{\"id\":\"ch-only\"}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_membership_t result;
    pubnub_res_t        rc = pn_membership_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(result.channel.id.len, 7);
    assert_memory_equal(result.channel.id.ptr, "ch-only", 7);
    assert_null(result.status.ptr);
    assert_null(result.type.ptr);
    assert_null(result.custom);
    assert_null(result.updated.ptr);
    assert_null(result.etag.ptr);

    serial->value_destroy(serial, tree);
}

static void membership_parse_rejects_null_out(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      json   = "{\"channel\":{\"id\":\"x\"}}";
    pubnub_json_value_t*             tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_res_t rc = pn_membership_parse(serial, tree, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void membership_parse_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_membership_t result;
    pubnub_res_t        rc = pn_membership_parse(NULL, NULL, &result);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(result.channel.id.ptr);
}

/* ---- Member parse tests ---- */

static void member_parse_full(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"uuid\":{\"id\":\"user-1\",\"name\":\"Alice\","
                       "\"email\":\"alice@test.com\"},"
                       "\"status\":\"joined\",\"type\":\"admin\","
                       "\"updated\":\"2025-06-01T12:00:00Z\","
                       "\"eTag\":\"etag-xyz\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_member_t result;
    pubnub_res_t    rc = pn_member_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    /* UUID metadata should be populated. */
    assert_int_equal(result.uuid.id.len, 6);
    assert_memory_equal(result.uuid.id.ptr, "user-1", 6);
    assert_int_equal(result.uuid.name.len, 5);
    assert_memory_equal(result.uuid.name.ptr, "Alice", 5);
    assert_int_equal(result.uuid.email.len, 14);
    assert_memory_equal(result.uuid.email.ptr, "alice@test.com", 14);

    /* Relationship fields. */
    assert_int_equal(result.status.len, 6);
    assert_memory_equal(result.status.ptr, "joined", 6);
    assert_int_equal(result.type.len, 5);
    assert_memory_equal(result.type.ptr, "admin", 5);
    assert_int_equal(result.updated.len, 20);
    assert_memory_equal(result.updated.ptr, "2025-06-01T12:00:00Z", 20);
    assert_int_equal(result.etag.len, 8);
    assert_memory_equal(result.etag.ptr, "etag-xyz", 8);

    serial->value_destroy(serial, tree);
}

static void member_parse_minimal(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"uuid\":{\"id\":\"user-only\"}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_member_t result;
    pubnub_res_t    rc = pn_member_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(result.uuid.id.len, 9);
    assert_memory_equal(result.uuid.id.ptr, "user-only", 9);
    assert_null(result.status.ptr);
    assert_null(result.type.ptr);
    assert_null(result.custom);
    assert_null(result.updated.ptr);
    assert_null(result.etag.ptr);

    serial->value_destroy(serial, tree);
}

static void member_parse_rejects_null_out(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      json   = "{\"uuid\":{\"id\":\"x\"}}";
    pubnub_json_value_t*             tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_res_t rc = pn_member_parse(serial, tree, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void member_parse_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_member_t result;
    pubnub_res_t    rc = pn_member_parse(NULL, NULL, &result);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(result.uuid.id.ptr);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Memberships path. */
        cmocka_unit_test(memberships_path_populates_six_segments),
        cmocka_unit_test(memberships_path_encodes_special_chars),
        cmocka_unit_test(memberships_path_rejects_null_uuid),
        cmocka_unit_test(memberships_path_rejects_null_request),
        /* Members path. */
        cmocka_unit_test(members_path_populates_six_segments),
        cmocka_unit_test(members_path_encodes_special_chars),
        cmocka_unit_test(members_path_rejects_null_channel),
        /* Memberships body. */
        cmocka_unit_test(memberships_body_set_only),
        cmocka_unit_test(memberships_body_remove_only),
        cmocka_unit_test(memberships_body_set_and_remove),
        cmocka_unit_test(memberships_body_rejects_null_serial),
        cmocka_unit_test(memberships_body_rejects_null_body_buf),
        /* Members body. */
        cmocka_unit_test(members_body_set_only),
        cmocka_unit_test(members_body_remove_only),
        cmocka_unit_test(members_body_rejects_null_serial),
        /* Membership parse. */
        cmocka_unit_test(membership_parse_full),
        cmocka_unit_test(membership_parse_minimal),
        cmocka_unit_test(membership_parse_rejects_null_out),
        cmocka_unit_test(membership_parse_rejects_null_serial),
        /* Member parse. */
        cmocka_unit_test(member_parse_full),
        cmocka_unit_test(member_parse_minimal),
        cmocka_unit_test(member_parse_rejects_null_out),
        cmocka_unit_test(member_parse_rejects_null_serial),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

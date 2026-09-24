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

static void path_get_all_populates_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_uuid_metadata_build_path_get_all(&req, "sub-c-key123");

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 4);
    assert_memory_equal(req.path_segments[0].ptr, "v2", 2);
    assert_int_equal(req.path_segments[0].len, 2);
    assert_memory_equal(req.path_segments[1].ptr, "objects", 7);
    assert_int_equal(req.path_segments[1].len, 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-c-key123", 12);
    assert_int_equal(req.path_segments[2].len, 12);
    assert_memory_equal(req.path_segments[3].ptr, "uuids", 5);
    assert_int_equal(req.path_segments[3].len, 5);
}

static void path_get_all_rejects_null_request(void** state)
{
    (void)state;
    pubnub_res_t rc = pn_uuid_metadata_build_path_get_all(NULL, "key");
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void path_get_all_rejects_null_key(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();
    pubnub_res_t          rc  = pn_uuid_metadata_build_path_get_all(&req, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void path_single_populates_five_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_uuid_metadata_build_path_single(
        &req, &s_alloc, "sub-c-key", "user-123", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 5);
    assert_memory_equal(req.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(req.path_segments[1].ptr, "objects", 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(req.path_segments[3].ptr, "uuids", 5);
    /* user-123 has no special chars, should be unchanged. */
    assert_non_null(encoded);
    assert_string_equal(encoded, "user-123");
    assert_memory_equal(req.path_segments[4].ptr, "user-123", 8);
    assert_int_equal(req.path_segments[4].len, 8);

    s_alloc.free(&s_alloc, encoded);
}

static void path_single_encodes_special_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_uuid_metadata_build_path_single(
        &req, &s_alloc, "sub-c-k", "user/test@foo", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(encoded);
    /* '/' and '@' should be percent-encoded. */
    assert_non_null(strstr(encoded, "%2F"));
    assert_non_null(strstr(encoded, "%40"));

    s_alloc.free(&s_alloc, encoded);
}

static void path_single_rejects_null_uuid(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc =
        pn_uuid_metadata_build_path_single(&req, &s_alloc, "key", NULL, &encoded);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(encoded);
}

static void body_builder_all_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.uuid                            = "uuid-1";
    opts.name                            = "Alice";
    opts.external_id                     = "ext-42";
    opts.profile_url                     = "https://example.com";
    opts.email                           = "alice@example.com";
    opts.type                            = "human";
    opts.status                          = "active";
    opts.custom                          = "{\"lang\":\"en\"}";

    uint8_t         buf[512];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc = pn_uuid_metadata_build_body(serial, NULL, &opts, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    /* Parse it back to verify fields. */
    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    pubnub_json_value_t* node = serial->object_get(tree, "name", 4);
    assert_non_null(node);
    size_t      slen = 0;
    const char* sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "Alice", 5);

    node = serial->object_get(tree, "externalId", 10);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "ext-42", 6);

    node = serial->object_get(tree, "profileUrl", 10);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "https://example.com", 19);

    node = serial->object_get(tree, "email", 5);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "alice@example.com", 17);

    node = serial->object_get(tree, "type", 4);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "human", 5);

    node = serial->object_get(tree, "status", 6);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "active", 6);

    node = serial->object_get(tree, "custom", 6);
    assert_non_null(node);

    serial->value_destroy(serial, tree);
}

static void body_builder_partial_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.uuid                            = "uuid-1";
    opts.name                            = "Bob";
    /* All other fields NULL. */

    uint8_t         buf[256];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc = pn_uuid_metadata_build_body(serial, NULL, &opts, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    /* "name" should exist. */
    pubnub_json_value_t* node = serial->object_get(tree, "name", 4);
    assert_non_null(node);

    /* "email" should NOT exist. */
    node = serial->object_get(tree, "email", 5);
    assert_null(node);

    /* "externalId" should NOT exist. */
    node = serial->object_get(tree, "externalId", 10);
    assert_null(node);

    serial->value_destroy(serial, tree);
}

static void body_builder_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.name                            = "X";
    uint8_t         buf[64];
    pubnub_buffer_t body = {.data = buf, .len = 0, .cap = sizeof(buf)};

    pubnub_res_t rc = pn_uuid_metadata_build_body(NULL, NULL, &opts, &body);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void parse_extracts_all_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"id\":\"uuid-1\",\"name\":\"Alice\","
                       "\"externalId\":\"ext-42\","
                       "\"profileUrl\":\"https://example.com\","
                       "\"email\":\"alice@example.com\","
                       "\"type\":\"human\",\"status\":\"active\","
                       "\"updated\":\"2025-01-01T00:00:00Z\","
                       "\"eTag\":\"etag-abc\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_uuid_metadata_t result;
    pubnub_res_t           rc = pn_uuid_metadata_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(result.id.len, 6);
    assert_memory_equal(result.id.ptr, "uuid-1", 6);
    assert_int_equal(result.name.len, 5);
    assert_memory_equal(result.name.ptr, "Alice", 5);
    assert_int_equal(result.external_id.len, 6);
    assert_memory_equal(result.external_id.ptr, "ext-42", 6);
    assert_int_equal(result.profile_url.len, 19);
    assert_memory_equal(result.profile_url.ptr, "https://example.com", 19);
    assert_int_equal(result.email.len, 17);
    assert_memory_equal(result.email.ptr, "alice@example.com", 17);
    assert_int_equal(result.type.len, 5);
    assert_memory_equal(result.type.ptr, "human", 5);
    assert_int_equal(result.status.len, 6);
    assert_memory_equal(result.status.ptr, "active", 6);
    assert_int_equal(result.updated.len, 20);
    assert_memory_equal(result.updated.ptr, "2025-01-01T00:00:00Z", 20);
    assert_int_equal(result.etag.len, 8);
    assert_memory_equal(result.etag.ptr, "etag-abc", 8);

    serial->value_destroy(serial, tree);
}

static void parse_handles_missing_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"id\":\"uuid-2\",\"name\":\"Bob\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_uuid_metadata_t result;
    pubnub_res_t           rc = pn_uuid_metadata_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(result.id.len, 6);
    assert_memory_equal(result.id.ptr, "uuid-2", 6);
    assert_int_equal(result.name.len, 3);
    assert_memory_equal(result.name.ptr, "Bob", 3);
    /* All other fields should be zero. */
    assert_null(result.external_id.ptr);
    assert_int_equal(result.external_id.len, 0);
    assert_null(result.profile_url.ptr);
    assert_null(result.email.ptr);
    assert_null(result.type.ptr);
    assert_null(result.status.ptr);
    assert_null(result.custom);
    assert_null(result.updated.ptr);
    assert_null(result.etag.ptr);

    serial->value_destroy(serial, tree);
}

static void parse_rejects_null_out(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char*          json = "{\"id\":\"x\"}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_res_t rc = pn_uuid_metadata_parse(serial, tree, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void parse_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_uuid_metadata_t result;
    pubnub_res_t           rc = pn_uuid_metadata_parse(NULL, NULL, &result);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    /* out should be zero-initialized. */
    assert_null(result.id.ptr);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(path_get_all_populates_segments),
        cmocka_unit_test(path_get_all_rejects_null_request),
        cmocka_unit_test(path_get_all_rejects_null_key),
        cmocka_unit_test(path_single_populates_five_segments),
        cmocka_unit_test(path_single_encodes_special_chars),
        cmocka_unit_test(path_single_rejects_null_uuid),
        cmocka_unit_test(body_builder_all_fields),
        cmocka_unit_test(body_builder_partial_fields),
        cmocka_unit_test(body_builder_rejects_null_serial),
        cmocka_unit_test(parse_extracts_all_fields),
        cmocka_unit_test(parse_handles_missing_fields),
        cmocka_unit_test(parse_rejects_null_out),
        cmocka_unit_test(parse_rejects_null_serial),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

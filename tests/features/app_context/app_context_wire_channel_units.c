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

    pubnub_res_t rc = pn_channel_metadata_build_path_get_all(&req, "sub-c-abc");

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 4);
    assert_memory_equal(req.path_segments[0].ptr, "v2", 2);
    assert_int_equal(req.path_segments[0].len, 2);
    assert_memory_equal(req.path_segments[1].ptr, "objects", 7);
    assert_int_equal(req.path_segments[1].len, 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-c-abc", 9);
    assert_int_equal(req.path_segments[2].len, 9);
    assert_memory_equal(req.path_segments[3].ptr, "channels", 8);
    assert_int_equal(req.path_segments[3].len, 8);
}

static void path_get_all_rejects_null_request(void** state)
{
    (void)state;
    pubnub_res_t rc = pn_channel_metadata_build_path_get_all(NULL, "key");
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void path_get_all_rejects_null_key(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();
    pubnub_res_t rc = pn_channel_metadata_build_path_get_all(&req, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void path_single_populates_five_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_channel_metadata_build_path_single(
        &req, &s_alloc, "sub-c-key", "my-channel", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 5);
    assert_memory_equal(req.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(req.path_segments[1].ptr, "objects", 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(req.path_segments[3].ptr, "channels", 8);
    assert_non_null(encoded);
    assert_string_equal(encoded, "my-channel");
    assert_memory_equal(req.path_segments[4].ptr, "my-channel", 10);
    assert_int_equal(req.path_segments[4].len, 10);

    s_alloc.free(&s_alloc, encoded);
}

static void path_single_encodes_special_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_channel_metadata_build_path_single(
        &req, &s_alloc, "sub-c-k", "chat/room #1", &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(encoded);
    /* '/' and '#' and ' ' should be percent-encoded. */
    assert_non_null(strstr(encoded, "%2F"));
    assert_non_null(strstr(encoded, "%23"));
    assert_non_null(strstr(encoded, "%20"));

    s_alloc.free(&s_alloc, encoded);
}

static void path_single_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    char*                 encoded = NULL;

    pubnub_res_t rc = pn_channel_metadata_build_path_single(
        &req, &s_alloc, "key", NULL, &encoded);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(encoded);
}

static void body_builder_all_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel     = "ch-1";
    opts.name        = "General";
    opts.description = "General chat channel";
    opts.type        = "public";
    opts.status      = "active";
    opts.custom      = "{\"priority\":1}";

    uint8_t         buf[512];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc = pn_channel_metadata_build_body(serial, NULL, &opts, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    pubnub_json_value_t* node = serial->object_get(tree, "name", 4);
    assert_non_null(node);
    size_t      slen = 0;
    const char* sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "General", 7);

    node = serial->object_get(tree, "description", 11);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "General chat channel", 20);

    node = serial->object_get(tree, "type", 4);
    assert_non_null(node);
    sptr = serial->value_as_string(node, &slen);
    assert_memory_equal(sptr, "public", 6);

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

    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel = "ch-1";
    opts.name    = "Renamed";
    /* All other fields NULL. */

    uint8_t         buf[256];
    pubnub_buffer_t body = {
        .data    = buf,
        .len     = 0,
        .cap     = sizeof(buf),
        .purpose = PUBNUB_BUF_OBJ,
    };

    pubnub_res_t rc = pn_channel_metadata_build_body(serial, NULL, &opts, &body);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(body.len > 0);

    pubnub_json_value_t* tree = serial->parse(serial, body.data, body.len);
    assert_non_null(tree);

    pubnub_json_value_t* node = serial->object_get(tree, "name", 4);
    assert_non_null(node);

    node = serial->object_get(tree, "description", 11);
    assert_null(node);

    node = serial->object_get(tree, "type", 4);
    assert_null(node);

    serial->value_destroy(serial, tree);
}

static void body_builder_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.name = "X";
    uint8_t         buf[64];
    pubnub_buffer_t body = {.data = buf, .len = 0, .cap = sizeof(buf)};

    pubnub_res_t rc = pn_channel_metadata_build_body(NULL, NULL, &opts, &body);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void parse_extracts_all_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"id\":\"ch-1\",\"name\":\"General\","
                       "\"description\":\"A channel\","
                       "\"type\":\"public\",\"status\":\"active\","
                       "\"updated\":\"2025-06-01T12:00:00Z\","
                       "\"eTag\":\"etag-xyz\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_channel_metadata_t result;
    pubnub_res_t rc = pn_channel_metadata_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(result.id.len, 4);
    assert_memory_equal(result.id.ptr, "ch-1", 4);
    assert_int_equal(result.name.len, 7);
    assert_memory_equal(result.name.ptr, "General", 7);
    assert_int_equal(result.description.len, 9);
    assert_memory_equal(result.description.ptr, "A channel", 9);
    assert_int_equal(result.type.len, 6);
    assert_memory_equal(result.type.ptr, "public", 6);
    assert_int_equal(result.status.len, 6);
    assert_memory_equal(result.status.ptr, "active", 6);
    assert_int_equal(result.updated.len, 20);
    assert_memory_equal(result.updated.ptr, "2025-06-01T12:00:00Z", 20);
    assert_int_equal(result.etag.len, 8);
    assert_memory_equal(result.etag.ptr, "etag-xyz", 8);

    serial->value_destroy(serial, tree);
}

static void parse_handles_missing_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"id\":\"ch-2\",\"name\":\"Private\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_channel_metadata_t result;
    pubnub_res_t rc = pn_channel_metadata_parse(serial, tree, &result);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(result.id.len, 4);
    assert_memory_equal(result.id.ptr, "ch-2", 4);
    assert_int_equal(result.name.len, 7);
    assert_memory_equal(result.name.ptr, "Private", 7);
    assert_null(result.description.ptr);
    assert_int_equal(result.description.len, 0);
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

    pubnub_res_t rc = pn_channel_metadata_parse(serial, tree, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void parse_rejects_null_serial(void** state)
{
    (void)state;
    pubnub_channel_metadata_t result;
    pubnub_res_t rc = pn_channel_metadata_parse(NULL, NULL, &result);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
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
        cmocka_unit_test(path_single_rejects_null_channel),
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

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

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

#include "features/presence/presence_api_internal.h"

extern pubnub_serialization_provider_t* pn_serialization_default(void);

static void* test_allocator_alloc(pubnub_allocator_provider_t* self,
                                  size_t                       size,
                                  size_t                       align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void test_allocator_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_test_allocator = {
    .alloc       = test_allocator_alloc,
    .realloc     = NULL,
    .free        = test_allocator_free,
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

static void build_where_now_populates_6_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_where_now_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .uuid          = "user-123",
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_presence_build_where_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(6, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "presence", 8);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "uuid", 4);
    assert_memory_equal(request.path_segments[5].ptr, "user-123", 8);
}

static void build_where_now_rejects_null_uuid(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_where_now_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .uuid          = NULL,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_presence_build_where_now(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_where_now_rejects_null_subscribe_key(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_where_now_wire_inputs_t inputs = {
        .subscribe_key = NULL,
        .uuid          = "user-123",
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_presence_build_where_now(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void parse_where_now_extracts_channels(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] =
        "{\"status\":200,\"payload\":{\"channels\":[\"ch-a\",\"ch-b\"]}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_where_now_parsed_t out;
    pubnub_res_t                   rc =
        pn_presence_parse_where_now(serial, tree, &s_test_allocator, &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(2, out.channel_count);
    assert_non_null(out.channels);
    assert_int_equal(4, out.channels[0].len);
    assert_memory_equal(out.channels[0].ptr, "ch-a", 4);
    assert_int_equal(4, out.channels[1].len);
    assert_memory_equal(out.channels[1].ptr, "ch-b", 4);

    s_test_allocator.free(&s_test_allocator, out.channels);
    serial->value_destroy(serial, tree);
}

static void parse_where_now_empty_channels(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] = "{\"status\":200,\"payload\":{\"channels\":[]}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_where_now_parsed_t out;
    pubnub_res_t                   rc =
        pn_presence_parse_where_now(serial, tree, &s_test_allocator, &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, out.channel_count);
    assert_null(out.channels);

    serial->value_destroy(serial, tree);
}

static void parse_where_now_missing_payload(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] = "{\"status\":200}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_where_now_parsed_t out;
    pubnub_res_t                   rc =
        pn_presence_parse_where_now(serial, tree, &s_test_allocator, &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, out.channel_count);
    assert_null(out.channels);

    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_where_now_populates_6_segments),
        cmocka_unit_test(build_where_now_rejects_null_uuid),
        cmocka_unit_test(build_where_now_rejects_null_subscribe_key),
        cmocka_unit_test(parse_where_now_extracts_channels),
        cmocka_unit_test(parse_where_now_empty_channels),
        cmocka_unit_test(parse_where_now_missing_payload),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

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

static void build_here_now_targeted_populates_6_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(6, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "presence", 8);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "channel", 7);
    assert_memory_equal(request.path_segments[5].ptr, "ch1", 3);
}

static void build_here_now_rejects_global_no_targeting(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = NULL,
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_here_now_rejects_empty_strings(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "",
        .channel_groups = "",
        .include_uuids  = 1,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_here_now_groups_only_uses_4_segments_plus_query(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = NULL,
        .channel_groups = "g1",
        .include_uuids  = 1,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(4, request.path_segment_count);

    /* Verify channel-group query param was added. */
    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (0 == memcmp(request.query_params[i].key.ptr, "channel-group", 13)) {
            assert_memory_equal(request.query_params[i].value.ptr, "g1", 2);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_here_now_adds_disable_uuids_query(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 0,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (0 == memcmp(request.query_params[i].key.ptr, "disable_uuids", 13)) {
            assert_memory_equal(request.query_params[i].value.ptr, "1", 1);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_here_now_adds_state_query(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 1,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (request.query_params[i].key.len == 5
            && 0 == memcmp(request.query_params[i].key.ptr, "state", 5)) {
            assert_memory_equal(request.query_params[i].value.ptr, "1", 1);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_here_now_no_extra_params_by_default(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, request.query_param_count);
}

static void build_here_now_rejects_null_request(void** state)
{
    (void)state;

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channels      = "ch1",
    };

    pubnub_res_t rc = pn_presence_build_here_now(NULL, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_here_now_rejects_null_subscribe_key(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = NULL,
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_here_now_with_limit_adds_query_param(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .limit          = 5,
        .offset         = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (5 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "limit", 5)) {
            assert_memory_equal(request.query_params[i].value.ptr, "5", 1);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_here_now_with_offset_adds_query_param(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .limit          = 0,
        .offset         = 3,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (6 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "offset", 6)) {
            assert_memory_equal(request.query_params[i].value.ptr, "3", 1);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_here_now_with_zero_limit_omits_param(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .limit          = 0,
        .offset         = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (5 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "limit", 5)) {
            /* limit=0 must NOT produce a query param. */
            fail_msg("unexpected 'limit' query param when limit=0");
        }
    }
}

static void build_here_now_with_zero_offset_omits_param(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_here_now_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .include_uuids  = 1,
        .include_state  = 0,
        .limit          = 0,
        .offset         = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_here_now(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (6 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "offset", 6)) {
            /* offset=0 must NOT produce a query param. */
            fail_msg("unexpected 'offset' query param when offset=0");
        }
    }
}

static void validator_ok_for_200_normal(void** state)
{
    (void)state;
    const char body[] = "{\"status\":200,\"occupancy\":3}";

    pubnub_res_t rc =
        pn_presence_response_validator((const uint8_t*)body, sizeof(body) - 1, 200);

    assert_int_equal(PUBNUB_OK, rc);
}

static void validator_error_for_403(void** state)
{
    (void)state;
    const char body[] = "{\"status\":403,\"message\":\"Forbidden\"}";

    pubnub_res_t rc =
        pn_presence_response_validator((const uint8_t*)body, sizeof(body) - 1, 403);

    assert_int_equal(PUBNUB_ERR_SERVER, rc);
}

static void validator_error_for_error_true(void** state)
{
    (void)state;
    const char body[] = "{\"error\":true,\"message\":\"Not Found\"}";

    pubnub_res_t rc =
        pn_presence_response_validator((const uint8_t*)body, sizeof(body) - 1, 200);

    assert_int_equal(PUBNUB_ERR_SERVER, rc);
}

static void parse_here_now_single_channel_string_uuids(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] = "{\"occupancy\":2,\"uuids\":[\"alice\",\"bob\"]}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_here_now_parsed_t out;
    pubnub_res_t                  rc =
        pn_presence_parse_here_now(serial, tree, &s_test_allocator, &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(2, out.total_occupancy);
    assert_int_equal(1, out.total_channels);
    assert_int_equal(1, out.channel_count);
    assert_non_null(out.channels);
    assert_int_equal(2, out.channels[0].occupant_count);
    assert_non_null(out.channels[0].occupants);
    assert_int_equal(5, out.channels[0].occupants[0].uuid.len);
    assert_memory_equal(out.channels[0].occupants[0].uuid.ptr, "alice", 5);
    assert_int_equal(3, out.channels[0].occupants[1].uuid.len);
    assert_memory_equal(out.channels[0].occupants[1].uuid.ptr, "bob", 3);

    /* Cleanup. */
    s_test_allocator.free(&s_test_allocator, out.channels[0].occupants);
    s_test_allocator.free(&s_test_allocator, out.channels);
    serial->value_destroy(serial, tree);
}

static void parse_here_now_multi_channel(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] = "{\"payload\":{\"channels\":{\"ch1\":{\"occupancy\":1,"
                        "\"uuids\":[\"u1\"]}},\"total_channels\":1,"
                        "\"total_occupancy\":1}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_here_now_parsed_t out;
    pubnub_res_t                  rc =
        pn_presence_parse_here_now(serial, tree, &s_test_allocator, &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.total_occupancy);
    assert_int_equal(1, out.total_channels);
    assert_int_equal(1, out.channel_count);
    assert_non_null(out.channels);
    assert_int_equal(3, out.channels[0].name.len);
    assert_memory_equal(out.channels[0].name.ptr, "ch1", 3);
    assert_int_equal(1, out.channels[0].occupant_count);
    assert_non_null(out.channels[0].occupants);
    assert_int_equal(2, out.channels[0].occupants[0].uuid.len);
    assert_memory_equal(out.channels[0].occupants[0].uuid.ptr, "u1", 2);

    /* Cleanup. */
    s_test_allocator.free(&s_test_allocator, out.channels[0].occupants);
    s_test_allocator.free(&s_test_allocator, out.channels);
    serial->value_destroy(serial, tree);
}

static void parse_here_now_empty_occupancy(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] = "{\"occupancy\":0}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_here_now_parsed_t out;
    pubnub_res_t                  rc =
        pn_presence_parse_here_now(serial, tree, &s_test_allocator, &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, out.total_occupancy);
    assert_int_equal(1, out.total_channels);
    assert_int_equal(1, out.channel_count);
    assert_non_null(out.channels);
    assert_int_equal(0, out.channels[0].occupant_count);
    assert_null(out.channels[0].occupants);

    /* Cleanup. */
    s_test_allocator.free(&s_test_allocator, out.channels);
    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_here_now_targeted_populates_6_segments),
        cmocka_unit_test(build_here_now_rejects_global_no_targeting),
        cmocka_unit_test(build_here_now_rejects_empty_strings),
        cmocka_unit_test(build_here_now_groups_only_uses_4_segments_plus_query),
        cmocka_unit_test(build_here_now_adds_disable_uuids_query),
        cmocka_unit_test(build_here_now_adds_state_query),
        cmocka_unit_test(build_here_now_no_extra_params_by_default),
        cmocka_unit_test(build_here_now_rejects_null_request),
        cmocka_unit_test(build_here_now_rejects_null_subscribe_key),
        cmocka_unit_test(build_here_now_with_limit_adds_query_param),
        cmocka_unit_test(build_here_now_with_offset_adds_query_param),
        cmocka_unit_test(build_here_now_with_zero_limit_omits_param),
        cmocka_unit_test(build_here_now_with_zero_offset_omits_param),
        cmocka_unit_test(validator_ok_for_200_normal),
        cmocka_unit_test(validator_error_for_403),
        cmocka_unit_test(validator_error_for_error_true),
        cmocka_unit_test(parse_here_now_single_channel_string_uuids),
        cmocka_unit_test(parse_here_now_multi_channel),
        cmocka_unit_test(parse_here_now_empty_occupancy),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

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

#include "features/message_actions/message_actions_internal.h"

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

static void build_get_populates_5_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = NULL,
        .end           = NULL,
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(5, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "message-actions", 15);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "channel", 7);
    assert_memory_equal(request.path_segments[4].ptr, "chat", 4);
}

static void build_get_adds_start_query_param(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = "15610547826970050",
        .end           = NULL,
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, request.query_param_count);
    assert_memory_equal(request.query_params[0].key.ptr, "start", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "15610547826970050", 17);
}

static void build_get_adds_end_and_limit(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = NULL,
        .end           = "15645905639093361",
        .limit         = 25,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(2, request.query_param_count);
    assert_memory_equal(request.query_params[0].key.ptr, "end", 3);
    assert_memory_equal(request.query_params[0].value.ptr, "15645905639093361", 17);
    assert_memory_equal(request.query_params[1].key.ptr, "limit", 5);
    assert_memory_equal(request.query_params[1].value.ptr, "25", 2);
}

static void build_get_rejects_non_digit_start(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = "156105/../../x",
        .end           = NULL,
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_get_rejects_empty_start(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = "",
        .end           = NULL,
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_get_rejects_overlong_end(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = NULL,
        .end           = "12345678901234567890", /* 20 digits */
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_get_rejects_non_digit_end(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "chat",
        .start         = NULL,
        .end           = "15645905639093361&admin=1",
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_get_rejects_empty_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "",
        .start         = NULL,
        .end           = NULL,
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_get_encodes_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_get_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "a b",
        .start         = NULL,
        .end           = NULL,
        .limit         = 0,
        .timeout_ms    = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_get(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(5, request.path_segments[4].len);
    assert_memory_equal(request.path_segments[4].ptr, "a%20b", 5);
}

static void parse_get_extracts_actions_and_pagination(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json =
        "{\"status\":200,\"data\":["
        "{\"type\":\"reaction\",\"value\":\"thumbs_up\","
        "\"uuid\":\"u1\",\"actionTimetoken\":\"111\","
        "\"messageTimetoken\":\"222\"},"
        "{\"type\":\"receipt\",\"value\":\"read\","
        "\"uuid\":\"u2\",\"actionTimetoken\":\"333\","
        "\"messageTimetoken\":\"444\"}"
        "],\"more\":{\"start\":\"111\",\"end\":\"444\",\"limit\":\"2\"}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pn_message_actions_get_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_message_actions_parse_get(serial, tree, &s_test_allocator, &out);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(2, out.count);

    /* First action. */
    assert_memory_equal(out.actions[0].type.ptr, "reaction", 8);
    assert_memory_equal(out.actions[0].value.ptr, "thumbs_up", 9);
    assert_memory_equal(out.actions[0].uuid.ptr, "u1", 2);
    assert_memory_equal(out.actions[0].action_timetoken.ptr, "111", 3);
    assert_memory_equal(out.actions[0].message_timetoken.ptr, "222", 3);

    /* Second action. */
    assert_memory_equal(out.actions[1].type.ptr, "receipt", 7);
    assert_memory_equal(out.actions[1].value.ptr, "read", 4);
    assert_memory_equal(out.actions[1].uuid.ptr, "u2", 2);

    /* Pagination. */
    assert_int_equal(1, out.has_more);
    assert_memory_equal(out.more_start.ptr, "111", 3);
    assert_memory_equal(out.more_end.ptr, "444", 3);
    assert_int_equal(2, out.more_limit);

    free(out.actions);
    serial->value_destroy(serial, tree);
}

static void parse_get_handles_empty_data_array(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char* json = "{\"status\":200,\"data\":[]}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pn_message_actions_get_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_message_actions_parse_get(serial, tree, &s_test_allocator, &out);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, out.count);
    assert_null(out.actions);
    assert_int_equal(0, out.has_more);

    serial->value_destroy(serial, tree);
}

static void parse_get_no_more_field(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char* json = "{\"status\":200,\"data\":["
                       "{\"type\":\"reaction\",\"value\":\"ok\","
                       "\"uuid\":\"u1\",\"actionTimetoken\":\"1\","
                       "\"messageTimetoken\":\"2\"}"
                       "]}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pn_message_actions_get_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_message_actions_parse_get(serial, tree, &s_test_allocator, &out);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.count);
    assert_int_equal(0, out.has_more);

    free(out.actions);
    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_get_populates_5_segments),
        cmocka_unit_test(build_get_adds_start_query_param),
        cmocka_unit_test(build_get_adds_end_and_limit),
        cmocka_unit_test(build_get_rejects_non_digit_start),
        cmocka_unit_test(build_get_rejects_empty_start),
        cmocka_unit_test(build_get_rejects_overlong_end),
        cmocka_unit_test(build_get_rejects_non_digit_end),
        cmocka_unit_test(build_get_rejects_empty_channel),
        cmocka_unit_test(build_get_encodes_channel),
        cmocka_unit_test(parse_get_extracts_actions_and_pagination),
        cmocka_unit_test(parse_get_handles_empty_data_array),
        cmocka_unit_test(parse_get_no_more_field),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

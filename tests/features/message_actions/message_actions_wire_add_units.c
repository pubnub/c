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

static void build_add_populates_7_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_add_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = "chat",
        .message_timetoken = "15610547826969050",
        .type              = "reaction",
        .value             = "smiley",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_add(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(7, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "message-actions", 15);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "channel", 7);
    assert_memory_equal(request.path_segments[4].ptr, "chat", 4);
    assert_memory_equal(request.path_segments[5].ptr, "message", 7);
    assert_memory_equal(request.path_segments[6].ptr, "15610547826969050", 17);
}

static void build_add_encodes_channel_with_spaces(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_add_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = "my channel",
        .message_timetoken = "123",
        .type              = "reaction",
        .value             = "ok",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_add(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    /* The channel segment should be percent-encoded. */
    assert_true(request.path_segments[4].len > 0);
    /* Space → %20 → total len = 10 ("my%20channel") */
    assert_int_equal(12, request.path_segments[4].len);
    assert_memory_equal(request.path_segments[4].ptr, "my%20channel", 12);
}

static void build_add_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_add_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = NULL,
        .message_timetoken = "123",
        .type              = "reaction",
        .value             = "ok",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_add(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_add_rejects_empty_message_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_add_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = "chat",
        .message_timetoken = "",
        .type              = "reaction",
        .value             = "ok",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_add(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void parse_add_extracts_all_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json = "{\"status\":200,\"data\":{\"type\":\"reaction\","
                       "\"value\":\"smiley_face\",\"uuid\":\"user-42\","
                       "\"actionTimetoken\":\"15610547826970050\","
                       "\"messageTimetoken\":\"15610547826969050\"}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pn_message_actions_action_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_message_actions_parse_add(serial, tree, &s_test_allocator, &out);
    assert_int_equal(PUBNUB_OK, rc);

    assert_int_equal(8, out.type.len);
    assert_memory_equal(out.type.ptr, "reaction", 8);
    assert_int_equal(11, out.value.len);
    assert_memory_equal(out.value.ptr, "smiley_face", 11);
    assert_int_equal(7, out.uuid.len);
    assert_memory_equal(out.uuid.ptr, "user-42", 7);
    assert_int_equal(17, out.action_timetoken.len);
    assert_memory_equal(out.action_timetoken.ptr, "15610547826970050", 17);
    assert_int_equal(17, out.message_timetoken.len);
    assert_memory_equal(out.message_timetoken.ptr, "15610547826969050", 17);

    serial->value_destroy(serial, tree);
}

static void parse_add_returns_error_on_missing_data(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char* json = "{\"status\":400,\"error\":{\"message\":\"bad\"}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pn_message_actions_action_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_message_actions_parse_add(serial, tree, &s_test_allocator, &out);
    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);

    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_add_populates_7_segments),
        cmocka_unit_test(build_add_encodes_channel_with_spaces),
        cmocka_unit_test(build_add_rejects_null_channel),
        cmocka_unit_test(build_add_rejects_empty_message_timetoken),
        cmocka_unit_test(parse_add_extracts_all_fields),
        cmocka_unit_test(parse_add_returns_error_on_missing_data),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

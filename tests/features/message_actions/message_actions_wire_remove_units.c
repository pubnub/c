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

#include "pubnub/providers/transport_types.h"

#include "features/message_actions/message_actions_internal.h"

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void build_remove_populates_9_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_remove_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = "chat",
        .message_timetoken = "15610547826969050",
        .action_timetoken  = "15610547826970050",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_remove(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(9, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "message-actions", 15);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "channel", 7);
    assert_memory_equal(request.path_segments[4].ptr, "chat", 4);
    assert_memory_equal(request.path_segments[5].ptr, "message", 7);
    assert_memory_equal(request.path_segments[6].ptr, "15610547826969050", 17);
    assert_memory_equal(request.path_segments[7].ptr, "action", 6);
    assert_memory_equal(request.path_segments[8].ptr, "15610547826970050", 17);
}

static void build_remove_encodes_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_remove_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = "my channel",
        .message_timetoken = "111",
        .action_timetoken  = "222",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_remove(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(12, request.path_segments[4].len);
    assert_memory_equal(request.path_segments[4].ptr, "my%20channel", 12);
}

static void build_remove_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_remove_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = NULL,
        .message_timetoken = "111",
        .action_timetoken  = "222",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_remove(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_remove_rejects_empty_action_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_message_actions_remove_wire_inputs_t inputs = {
        .subscribe_key     = "sub-c-key",
        .channel           = "chat",
        .message_timetoken = "111",
        .action_timetoken  = "",
        .timeout_ms        = 0,
    };

    pubnub_res_t rc = pn_message_actions_build_remove(&request, &inputs);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void validator_accepts_200(void** state)
{
    (void)state;
    const char* body = "{\"status\":200,\"data\":{}}";

    pubnub_res_t rc = pn_message_actions_response_validator(
        (const uint8_t*)body, strlen(body), 200);
    assert_int_equal(PUBNUB_OK, rc);
}

static void validator_accepts_207(void** state)
{
    (void)state;
    const char* body = "{\"status\":207,\"data\":{}}";

    pubnub_res_t rc = pn_message_actions_response_validator(
        (const uint8_t*)body, strlen(body), 207);
    assert_int_equal(PUBNUB_OK, rc);
}

static void validator_rejects_403(void** state)
{
    (void)state;
    const char* body = "{\"status\":403,\"error\":true}";

    pubnub_res_t rc = pn_message_actions_response_validator(
        (const uint8_t*)body, strlen(body), 403);
    assert_int_equal(PUBNUB_ERR_SERVER, rc);
}

static void validator_detects_error_flag_in_200(void** state)
{
    (void)state;
    /* Edge case: 200 status but body contains error flag. */
    const char* body = "{\"error\":true,\"status\":200}";

    pubnub_res_t rc = pn_message_actions_response_validator(
        (const uint8_t*)body, strlen(body), 200);
    assert_int_equal(PUBNUB_ERR_SERVER, rc);
}

static void validator_ok_when_error_false(void** state)
{
    (void)state;
    const char* body = "{\"error\":false,\"status\":200,\"data\":{}}";

    pubnub_res_t rc = pn_message_actions_response_validator(
        (const uint8_t*)body, strlen(body), 200);
    assert_int_equal(PUBNUB_OK, rc);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_remove_populates_9_segments),
        cmocka_unit_test(build_remove_encodes_channel),
        cmocka_unit_test(build_remove_rejects_null_channel),
        cmocka_unit_test(build_remove_rejects_empty_action_timetoken),
        cmocka_unit_test(validator_accepts_200),
        cmocka_unit_test(validator_accepts_207),
        cmocka_unit_test(validator_rejects_403),
        cmocka_unit_test(validator_detects_error_flag_in_200),
        cmocka_unit_test(validator_ok_when_error_false),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

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

/* Internal declarations shared with the feature implementation. */
#include "features/channel_groups/channel_groups_internal.h"

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void build_path_should_produce_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc =
        pn_channel_groups_build_path(&request, "sub-c-key", "my-group", 0);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 6);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "channel-registration", 20);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "channel-group", 13);
    assert_memory_equal(request.path_segments[5].ptr, "my-group", 8);
}

static void build_path_should_produce_seven_segments_for_remove(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc =
        pn_channel_groups_build_path(&request, "sub-c-key", "my-group", 1);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 7);
    assert_memory_equal(request.path_segments[6].ptr, "remove", 6);
}

static void build_path_should_percent_encode_group_name(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc =
        pn_channel_groups_build_path(&request, "sub", "group with spaces", 0);

    assert_int_equal(rc, PUBNUB_OK);
    const char* group_seg = (const char*)request.path_segments[5].ptr;
    assert_non_null(strstr(group_seg, "%20"));
}

static void build_path_should_reject_null_arguments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_channel_groups_build_path(NULL, "sub", "grp", 0),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_channel_groups_build_path(&request, NULL, "grp", 0),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_channel_groups_build_path(&request, "sub", NULL, 0),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void validator_should_reject_http_4xx(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":403}";
    assert_int_equal(
        pn_channel_groups_response_validator(body, sizeof(body) - 1, 403),
        PUBNUB_ERR_SERVER);
}

static void validator_should_detect_error_true(void** state)
{
    (void)state;
    const uint8_t body[] =
        "{\"status\":400,\"error\":true,\"message\":\"Invalid\"}";
    assert_int_equal(
        pn_channel_groups_response_validator(body, sizeof(body) - 1, 200),
        PUBNUB_ERR_SERVER);
}

static void validator_should_accept_error_false(void** state)
{
    (void)state;
    const uint8_t body[] =
        "{\"status\":200,\"error\":false,\"payload\":{\"channels\":[]}}";
    assert_int_equal(
        pn_channel_groups_response_validator(body, sizeof(body) - 1, 200),
        PUBNUB_OK);
}

static void validator_should_accept_missing_error_field(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":200,\"payload\":{\"channels\":[]}}";
    assert_int_equal(
        pn_channel_groups_response_validator(body, sizeof(body) - 1, 200),
        PUBNUB_OK);
}

static void validator_should_tolerate_whitespace(void** state)
{
    (void)state;
    const uint8_t body[] = "{ \"error\" : true , \"message\": \"bad\" }";
    assert_int_equal(
        pn_channel_groups_response_validator(body, sizeof(body) - 1, 200),
        PUBNUB_ERR_SERVER);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_path_should_produce_six_segments),
        cmocka_unit_test(build_path_should_produce_seven_segments_for_remove),
        cmocka_unit_test(build_path_should_percent_encode_group_name),
        cmocka_unit_test(build_path_should_reject_null_arguments),
        cmocka_unit_test(validator_should_reject_http_4xx),
        cmocka_unit_test(validator_should_detect_error_true),
        cmocka_unit_test(validator_should_accept_error_false),
        cmocka_unit_test(validator_should_accept_missing_error_field),
        cmocka_unit_test(validator_should_tolerate_whitespace),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

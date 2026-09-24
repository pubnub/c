/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file time_units.c
 * @brief Unit tests for the time feature's wire helpers.
 *
 * Exercises the path builder, response validator, and response parser
 * in isolation -- no context, no transport, no network.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/time.h"
#include "pubnub/providers/transport_types.h"

/* Internal declarations shared with the feature implementation. */
#include "features/time/time_internal.h"

static void build_path_should_populate_two_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = {0};
    assert_int_equal(pn_time_build_path(&request), PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 2);
    assert_memory_equal(request.path_segments[0].ptr, "time", 4);
    assert_int_equal(request.path_segments[0].len, 4);
    assert_memory_equal(request.path_segments[1].ptr, "0", 1);
    assert_int_equal(request.path_segments[1].len, 1);
}

static void build_path_should_reject_null_request(void** state)
{
    (void)state;
    assert_int_equal(pn_time_build_path(NULL), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void validator_should_accept_200_with_digit_body(void** state)
{
    (void)state;
    const uint8_t body[] = "[15031768233408550]";
    assert_int_equal(pn_time_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void validator_should_reject_400_status(void** state)
{
    (void)state;
    const uint8_t body[] = "[15031768233408550]";
    assert_int_equal(pn_time_response_validator(body, sizeof(body) - 1, 400),
                     PUBNUB_ERR_SERVER);
}

static void validator_should_reject_empty_body_200(void** state)
{
    (void)state;
    assert_int_equal(pn_time_response_validator(NULL, 0, 200),
                     PUBNUB_ERR_SERIALIZATION);
}

static void validator_should_accept_valid_body_200(void** state)
{
    (void)state;
    static const uint8_t BODY[] = "[17191609868840930]";
    assert_int_equal(pn_time_response_validator(BODY, sizeof(BODY) - 1, 200),
                     PUBNUB_OK);
}

static void parse_response_should_extract_17_digit_timetoken(void** state)
{
    (void)state;
    const uint8_t      body[] = "[15031768233408550]";
    pubnub_timetoken_t out    = {0};
    assert_int_equal(pn_time_parse_response(body, sizeof(body) - 1, &out),
                     PUBNUB_OK);
    assert_int_equal(out.len, 17);
    assert_memory_equal(out.ptr, "15031768233408550", 17);
}

static void parse_response_should_handle_leading_whitespace(void** state)
{
    (void)state;
    const uint8_t      body[] = "[ 15031768233408550]";
    pubnub_timetoken_t out    = {0};
    assert_int_equal(pn_time_parse_response(body, sizeof(body) - 1, &out),
                     PUBNUB_OK);
    assert_int_equal(out.len, 17);
    assert_memory_equal(out.ptr, "15031768233408550", 17);
}

static void parse_response_should_reject_non_digit_after_bracket(void** state)
{
    (void)state;
    const uint8_t      body[] = "[\"abc\"]";
    pubnub_timetoken_t out    = {0};
    assert_int_equal(pn_time_parse_response(body, sizeof(body) - 1, &out),
                     PUBNUB_ERR_SERIALIZATION);
}

static void parse_response_should_reject_empty_body(void** state)
{
    (void)state;
    pubnub_timetoken_t out = {0};
    assert_int_equal(pn_time_parse_response(NULL, 0, &out),
                     PUBNUB_ERR_SERIALIZATION);
}

static void parse_response_should_reject_null_out_token(void** state)
{
    (void)state;
    const uint8_t body[] = "[15031768233408550]";
    assert_int_equal(pn_time_parse_response(body, sizeof(body) - 1, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void parse_response_should_reject_body_with_no_bracket(void** state)
{
    (void)state;
    const uint8_t      body[] = "15031768233408550";
    pubnub_timetoken_t out    = {0};
    assert_int_equal(pn_time_parse_response(body, sizeof(body) - 1, &out),
                     PUBNUB_ERR_SERIALIZATION);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_path_should_populate_two_segments),
        cmocka_unit_test(build_path_should_reject_null_request),
        cmocka_unit_test(validator_should_accept_200_with_digit_body),
        cmocka_unit_test(validator_should_reject_400_status),
        cmocka_unit_test(validator_should_reject_empty_body_200),
        cmocka_unit_test(validator_should_accept_valid_body_200),
        cmocka_unit_test(parse_response_should_extract_17_digit_timetoken),
        cmocka_unit_test(parse_response_should_handle_leading_whitespace),
        cmocka_unit_test(parse_response_should_reject_non_digit_after_bracket),
        cmocka_unit_test(parse_response_should_reject_empty_body),
        cmocka_unit_test(parse_response_should_reject_null_out_token),
        cmocka_unit_test(parse_response_should_reject_body_with_no_bracket),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

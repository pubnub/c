/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file history_wire_units.c
 * @brief Unit tests for history wire helpers (path, query, validator).
 *
 * Tests exercise path builders, query-parameter appenders, and
 * response validators in isolation -- no context, no transport, no
 * network. A small malloc/free-backed allocator provides real
 * allocation semantics for scratch-buffer encoding.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/history.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport_types.h"

#include "features/history/history_internal.h"

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

static pubnub_allocator_provider_t s_alloc = {
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

static void fetch_path_should_populate_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_string_view_t channels = {"ch1%2Cch2", 9};
    pubnub_res_t rc = pn_history_build_fetch_path(&req, "sub-key", channels, 0);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 6);
    assert_memory_equal(req.path_segments[0].ptr, "v3", 2);
    assert_memory_equal(req.path_segments[1].ptr, "history", 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(req.path_segments[4].ptr, "channel", 7);
    assert_memory_equal(req.path_segments[5].ptr, "ch1%2Cch2", 9);
}

static void fetch_path_with_actions_should_use_history_with_actions(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_string_view_t channels = {"my-channel", 10};
    pubnub_res_t rc = pn_history_build_fetch_path(&req, "sub-key", channels, 1);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 6);
    assert_memory_equal(req.path_segments[0].ptr, "v3", 2);
    assert_memory_equal(req.path_segments[1].ptr, "history-with-actions", 20);
}

static void fetch_path_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t req      = make_request();
    pubnub_string_view_t  channels = {"ch", 2};

    assert_int_equal(pn_history_build_fetch_path(NULL, "sub", channels, 0),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_build_fetch_path(&req, NULL, channels, 0),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    pubnub_string_view_t empty = {NULL, 0};
    assert_int_equal(pn_history_build_fetch_path(&req, "sub", empty, 0),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void delete_path_should_populate_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_string_view_t channel = {"my-channel", 10};
    pubnub_res_t rc = pn_history_build_delete_path(&req, "sub-key", channel);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 6);
    assert_memory_equal(req.path_segments[0].ptr, "v3", 2);
    assert_memory_equal(req.path_segments[1].ptr, "history", 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(req.path_segments[4].ptr, "channel", 7);
    assert_memory_equal(req.path_segments[5].ptr, "my-channel", 10);
}

static void delete_path_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t req     = make_request();
    pubnub_string_view_t  channel = {"ch", 2};

    assert_int_equal(pn_history_build_delete_path(NULL, "sub", channel),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_build_delete_path(&req, NULL, channel),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void counts_path_should_use_message_counts_segment(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_string_view_t channels = {"ch1%2Cch2", 9};
    pubnub_res_t rc = pn_history_build_counts_path(&req, "sub-key", channels);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.path_segment_count, 6);
    assert_memory_equal(req.path_segments[0].ptr, "v3", 2);
    assert_memory_equal(req.path_segments[1].ptr, "history", 7);
    assert_memory_equal(req.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(req.path_segments[4].ptr, "message-counts", 14);
    assert_memory_equal(req.path_segments[5].ptr, "ch1%2Cch2", 9);
}

static void counts_path_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t req      = make_request();
    pubnub_string_view_t  channels = {"ch", 2};

    assert_int_equal(pn_history_build_counts_path(NULL, "sub", channels),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_build_counts_path(&req, NULL, channels),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void fetch_query_should_add_max_when_nonzero(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.count                        = 50;

    pubnub_res_t rc = pn_history_add_fetch_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    /* max + include_uuid + include_message_type = 3 params. */
    assert_true(req.query_param_count >= 1);
    assert_memory_equal(req.query_params[0].key.ptr, "max", 3);
    assert_memory_equal(req.query_params[0].value.ptr, "50", 2);
}

static void fetch_query_should_add_start_and_end(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.start                        = "17001234567890100";
    opts.end                          = "17001234567890200";
    /* Turn off defaults to reduce param count in assertion. */
    opts.include_uuid         = 0;
    opts.include_message_type = 0;

    pubnub_res_t rc = pn_history_add_fetch_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 3);
    assert_memory_equal(req.query_params[0].key.ptr, "start", 5);
    assert_memory_equal(req.query_params[0].value.ptr, "17001234567890100", 17);
    assert_memory_equal(req.query_params[1].key.ptr, "end", 3);
    assert_memory_equal(req.query_params[1].value.ptr, "17001234567890200", 17);
    assert_memory_equal(req.query_params[2].key.ptr, "string_message_token", 20);
    assert_memory_equal(req.query_params[2].value.ptr, "true", 4);
}

static void fetch_query_should_add_all_include_flags(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.reverse                      = 1;
    opts.include_meta                 = 1;
    opts.include_uuid                 = 1;
    opts.include_message_type         = 1;
    opts.include_custom_message_type  = 1;

    pubnub_res_t rc = pn_history_add_fetch_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    /* reverse, include_meta, include_uuid, include_message_type,
     * include_custom_message_type, string_message_token = 6. */
    assert_int_equal(req.query_param_count, 6);
}

static void fetch_query_should_omit_flags_when_zero(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = {0};

    pubnub_res_t rc = pn_history_add_fetch_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    /* string_message_token is always added. */
    assert_int_equal(req.query_param_count, 1);
}

static void fetch_query_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    assert_int_equal(pn_history_add_fetch_query_params(NULL, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_add_fetch_query_params(&req, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void delete_query_should_add_start_and_end(void** state)
{
    (void)state;
    pubnub_http_request_t         req  = make_request();
    pubnub_delete_messages_opts_t opts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
    opts.start                         = "17001000000000000";
    opts.end                           = "17002000000000000";

    pubnub_res_t rc = pn_history_add_delete_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 2);
    assert_memory_equal(req.query_params[0].key.ptr, "start", 5);
    assert_memory_equal(req.query_params[1].key.ptr, "end", 3);
}

static void delete_query_should_omit_when_null(void** state)
{
    (void)state;
    pubnub_http_request_t         req  = make_request();
    pubnub_delete_messages_opts_t opts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;

    pubnub_res_t rc = pn_history_add_delete_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void counts_query_should_add_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.timetoken                    = "17001234567890123";

    pubnub_res_t rc = pn_history_add_counts_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "timetoken", 9);
    assert_memory_equal(req.query_params[0].value.ptr, "17001234567890123", 17);
}

static void counts_query_should_add_channels_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.channels_timetokens          = "170001,170002,170003";

    pubnub_res_t rc = pn_history_add_counts_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "channelsTimetoken", 17);
    assert_memory_equal(req.query_params[0].value.ptr, "170001,170002,170003", 20);
}

static void counts_query_should_omit_when_both_null(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;

    pubnub_res_t rc = pn_history_add_counts_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void validator_should_accept_http_200_with_status_200(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":200,\"channels\":{}}";

    pubnub_res_t rc = pn_history_response_validator(body, sizeof(body) - 1, 200);

    assert_int_equal(rc, PUBNUB_OK);
}

static void validator_should_reject_http_403(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":403,\"error\":true}";

    pubnub_res_t rc = pn_history_response_validator(body, sizeof(body) - 1, 403);

    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void validator_should_reject_logical_403_in_body(void** state)
{
    (void)state;
    /* HTTP 200 but the body carries a logical 403 status. */
    const uint8_t body[] =
        "{\"status\":403,\"error\":true,\"message\":\"Forbidden\"}";

    pubnub_res_t rc = pn_history_response_validator(body, sizeof(body) - 1, 200);

    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void validator_should_accept_body_without_status_field(void** state)
{
    (void)state;
    /* Some old responses might not have a "status" field. */
    const uint8_t body[] = "{\"channels\":{\"ch1\":[]}}";

    pubnub_res_t rc = pn_history_response_validator(body, sizeof(body) - 1, 200);

    assert_int_equal(rc, PUBNUB_OK);
}

static void delete_validator_should_accept_http_200(void** state)
{
    (void)state;
    const uint8_t body[] = "";

    pubnub_res_t rc = pn_history_delete_response_validator(body, 0, 200);

    assert_int_equal(rc, PUBNUB_OK);
}

static void delete_validator_should_reject_http_403(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":403}";

    pubnub_res_t rc =
        pn_history_delete_response_validator(body, sizeof(body) - 1, 403);

    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void fetch_query_should_reject_non_digit_start(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.start                        = "1700/../../admin";

    assert_int_equal(pn_history_add_fetch_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void fetch_query_should_reject_empty_start(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.start                        = "";

    assert_int_equal(pn_history_add_fetch_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void fetch_query_should_reject_overlong_start(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    /* 20 decimal digits -- exceeds the 19-digit (64-bit) bound. */
    opts.start = "12345678901234567890";

    assert_int_equal(pn_history_add_fetch_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void fetch_query_should_accept_19_digit_start(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.start                        = "1234567890123456789"; /* 19 digits */
    opts.include_uuid                 = 0;
    opts.include_message_type         = 0;

    pubnub_res_t rc = pn_history_add_fetch_query_params(&req, &opts);

    assert_int_equal(rc, PUBNUB_OK);
    assert_memory_equal(req.query_params[0].key.ptr, "start", 5);
    assert_memory_equal(req.query_params[0].value.ptr, "1234567890123456789", 19);
}

static void fetch_query_should_reject_non_digit_end(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.end                          = "17001234567890100&x=1";

    assert_int_equal(pn_history_add_fetch_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void delete_query_should_reject_non_digit_start(void** state)
{
    (void)state;
    pubnub_http_request_t         req  = make_request();
    pubnub_delete_messages_opts_t opts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
    opts.start                         = "abc";

    assert_int_equal(pn_history_add_delete_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void delete_query_should_reject_empty_end(void** state)
{
    (void)state;
    pubnub_http_request_t         req  = make_request();
    pubnub_delete_messages_opts_t opts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
    opts.end                           = "";

    assert_int_equal(pn_history_add_delete_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void counts_query_should_reject_non_digit_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.timetoken                    = "17001234567890123/../";

    assert_int_equal(pn_history_add_counts_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void counts_query_should_reject_overlong_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.timetoken                    = "12345678901234567890"; /* 20 digits */

    assert_int_equal(pn_history_add_counts_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void counts_query_should_reject_channels_timetoken_empty_segment(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    /* Consecutive commas leave an empty segment. */
    opts.channels_timetokens = "170001,,170003";

    assert_int_equal(pn_history_add_counts_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void counts_query_should_reject_channels_timetoken_non_digit(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.channels_timetokens          = "170001,17a002,170003";

    assert_int_equal(pn_history_add_counts_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void counts_query_should_reject_channels_timetoken_trailing_comma(void** state)
{
    (void)state;
    pubnub_http_request_t        req  = make_request();
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.channels_timetokens          = "170001,170002,";

    assert_int_equal(pn_history_add_counts_query_params(&req, &opts),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(fetch_path_should_populate_six_segments),
        cmocka_unit_test(fetch_path_with_actions_should_use_history_with_actions),
        cmocka_unit_test(fetch_path_should_reject_null_args),
        cmocka_unit_test(delete_path_should_populate_six_segments),
        cmocka_unit_test(delete_path_should_reject_null_args),
        cmocka_unit_test(counts_path_should_use_message_counts_segment),
        cmocka_unit_test(counts_path_should_reject_null_args),
        cmocka_unit_test(fetch_query_should_add_max_when_nonzero),
        cmocka_unit_test(fetch_query_should_add_start_and_end),
        cmocka_unit_test(fetch_query_should_add_all_include_flags),
        cmocka_unit_test(fetch_query_should_omit_flags_when_zero),
        cmocka_unit_test(fetch_query_should_reject_null_args),
        cmocka_unit_test(delete_query_should_add_start_and_end),
        cmocka_unit_test(delete_query_should_omit_when_null),
        cmocka_unit_test(counts_query_should_add_timetoken),
        cmocka_unit_test(counts_query_should_add_channels_timetoken),
        cmocka_unit_test(counts_query_should_omit_when_both_null),
        cmocka_unit_test(fetch_query_should_reject_non_digit_start),
        cmocka_unit_test(fetch_query_should_reject_empty_start),
        cmocka_unit_test(fetch_query_should_reject_overlong_start),
        cmocka_unit_test(fetch_query_should_accept_19_digit_start),
        cmocka_unit_test(fetch_query_should_reject_non_digit_end),
        cmocka_unit_test(delete_query_should_reject_non_digit_start),
        cmocka_unit_test(delete_query_should_reject_empty_end),
        cmocka_unit_test(counts_query_should_reject_non_digit_timetoken),
        cmocka_unit_test(counts_query_should_reject_overlong_timetoken),
        cmocka_unit_test(counts_query_should_reject_channels_timetoken_empty_segment),
        cmocka_unit_test(counts_query_should_reject_channels_timetoken_non_digit),
        cmocka_unit_test(counts_query_should_reject_channels_timetoken_trailing_comma),
        cmocka_unit_test(validator_should_accept_http_200_with_status_200),
        cmocka_unit_test(validator_should_reject_http_403),
        cmocka_unit_test(validator_should_reject_logical_403_in_body),
        cmocka_unit_test(validator_should_accept_body_without_status_field),
        cmocka_unit_test(delete_validator_should_accept_http_200),
        cmocka_unit_test(delete_validator_should_reject_http_403),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

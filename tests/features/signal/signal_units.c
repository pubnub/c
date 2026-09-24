/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file signal_units.c
 * @brief Unit tests for the signal feature's wire helpers.
 *
 * Exercises the URL path builder, query-parameter appender, response
 * parser, and validator in isolation -- no context, no transport, no
 * network.
 *
 * Two groups:
 *   - Wire tests (path + query) use a small malloc/free-backed
 *     allocator because they need real allocator semantics for the
 *     URL-encode heap allocation.
 *   - Parser / validator tests operate on byte spans only.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/signal.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

/* Internal declarations shared with the feature implementation. */
#include "features/signal/signal_internal.h"

/* Provided by the linked serialization provider. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* Real malloc/free-backed allocator for the build_path wire tests,
 * which need genuine alloc/free semantics for the URL-encode
 * heap allocation. */
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

/* Zero-initialised request the builders can fill. */
static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void build_path_should_populate_seven_segments_for_plain_channel(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    const uint8_t                 serialized[] = "\"hello\"";
    const pn_signal_path_inputs_t inputs       = {
              .publish_key    = "pub-c-key",
              .subscribe_key  = "sub-c-key",
              .channel        = "my-channel",
              .serialized     = serialized,
              .serialized_len = sizeof(serialized) - 1,
    };
    pn_signal_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_signal_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    /* Segments: /signal / pub / sub / 0 / channel / 0 / payload */
    assert_int_equal(request.path_segment_count, 7);
    assert_memory_equal(request.path_segments[0].ptr, "signal", 6);
    assert_memory_equal(request.path_segments[1].ptr, "pub-c-key", 9);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "0", 1);
    /* "my-channel" contains only unreserved characters. */
    assert_memory_equal(request.path_segments[4].ptr, "my-channel", 10);
    assert_memory_equal(request.path_segments[5].ptr, "0", 1);
    /* "\"hello\"" -> quotes percent-encode to %22. */
    assert_non_null(strstr((const char*)request.path_segments[6].ptr, "%22hello%22"));

    allocator->free(allocator, url_encoded.message);
}

static void build_path_should_percent_encode_channel_with_reserved_chars(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    const uint8_t                 serialized[] = "\"x\"";
    const pn_signal_path_inputs_t inputs       = {
              .publish_key   = "pub",
              .subscribe_key = "sub",
        /* Space + slash + hash all require percent-encoding. */
              .channel        = "room/topic #1",
              .serialized     = serialized,
              .serialized_len = sizeof(serialized) - 1,
    };
    pn_signal_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_signal_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    const char* ch = (const char*)request.path_segments[4].ptr;
    assert_non_null(strstr(ch, "%20"));
    assert_true(NULL != strstr(ch, "%2F") || NULL != strstr(ch, "%2f"));
    assert_true(NULL != strstr(ch, "%23"));

    allocator->free(allocator, url_encoded.message);
}

static void build_path_should_percent_encode_message_payload(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    const uint8_t                 serialized[] = "\"hello world\"";
    const pn_signal_path_inputs_t inputs       = {
              .publish_key    = "pub",
              .subscribe_key  = "sub",
              .channel        = "ch",
              .serialized     = serialized,
              .serialized_len = sizeof(serialized) - 1,
    };
    pn_signal_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_signal_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    const char* msg = (const char*)request.path_segments[6].ptr;
    /* Space encodes as %20, quotes as %22. */
    assert_non_null(strstr(msg, "%22hello%20world%22"));

    allocator->free(allocator, url_encoded.message);
}

static void build_path_should_reject_null_publish_key(void** state)
{
    (void)state;
    pubnub_http_request_t        request     = make_request();
    pubnub_allocator_provider_t* allocator   = &s_test_allocator;
    pn_signal_url_encoded_t      url_encoded = {0};

    const pn_signal_path_inputs_t inputs = {
        .publish_key    = NULL,
        .subscribe_key  = "sub",
        .channel        = "ch",
        .serialized     = (const uint8_t*)"\"m\"",
        .serialized_len = 3,
    };
    assert_int_equal(pn_signal_build_path(&request, allocator, &inputs, &url_encoded),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void build_path_should_reject_null_channel(void** state)
{
    (void)state;
    pubnub_http_request_t        request     = make_request();
    pubnub_allocator_provider_t* allocator   = &s_test_allocator;
    pn_signal_url_encoded_t      url_encoded = {0};

    const pn_signal_path_inputs_t inputs = {
        .publish_key    = "pub",
        .subscribe_key  = "sub",
        .channel        = NULL,
        .serialized     = (const uint8_t*)"\"m\"",
        .serialized_len = 3,
    };
    assert_int_equal(pn_signal_build_path(&request, allocator, &inputs, &url_encoded),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void build_path_should_reject_null_serialized(void** state)
{
    (void)state;
    pubnub_http_request_t        request     = make_request();
    pubnub_allocator_provider_t* allocator   = &s_test_allocator;
    pn_signal_url_encoded_t      url_encoded = {0};

    const pn_signal_path_inputs_t inputs = {
        .publish_key    = "pub",
        .subscribe_key  = "sub",
        .channel        = "ch",
        .serialized     = NULL,
        .serialized_len = 0,
    };
    assert_int_equal(pn_signal_build_path(&request, allocator, &inputs, &url_encoded),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void add_query_params_should_not_append_when_no_custom_message_type(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_signal_add_query_params(&request, NULL), PUBNUB_OK);
    assert_int_equal(request.query_param_count, 0);
}

static void add_query_params_should_append_custom_message_type(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_signal_add_query_params(&request, "typing_v1"), PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "custom_message_type", 19);
    assert_memory_equal(request.query_params[0].value.ptr, "typing_v1", 9);
}

static void validator_should_accept_status_one(void** state)
{
    (void)state;
    const uint8_t body[] = "[1,\"Sent\",\"17001234567890123\"]";
    assert_int_equal(pn_signal_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void validator_should_reject_status_zero(void** state)
{
    (void)state;
    const uint8_t body[] = "[0,\"Error message\"]";
    assert_int_equal(pn_signal_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_ERR_SERVER);
}

static void validator_should_accept_empty_body(void** state)
{
    (void)state;
    /* The probe accepts NULL/empty body (unknown format -> let lazy
     * parser decide). */
    assert_int_equal(pn_signal_response_validator(NULL, 0, 200), PUBNUB_OK);
}

static pubnub_json_value_t* parse_body(pubnub_serialization_provider_t* serial,
                                       const char*                      body)
{
    return serial->parse(serial, (const uint8_t*)body, strlen(body));
}

static void parse_response_should_decode_success(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*          body = "[1,\"Sent\",\"17001234567890123\"]";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_signal_parsed_t parsed = {0};
    assert_int_equal(pn_signal_parse_response(serial, tree, &parsed), PUBNUB_OK);
    assert_non_null(parsed.timetoken.ptr);
    assert_int_equal(parsed.timetoken.len, 17);
    assert_memory_equal(parsed.timetoken.ptr, "17001234567890123", 17);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_handle_two_element_error(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "[0,\"Forbidden\"]";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_signal_parsed_t parsed = {0};
    assert_int_equal(pn_signal_parse_response(serial, tree, &parsed), PUBNUB_OK);
    assert_null(parsed.timetoken.ptr);
    assert_int_equal(parsed.timetoken.len, 0);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_reject_null_out(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*          body = "[1,\"Sent\",\"17001234567890123\"]";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    assert_int_equal(pn_signal_parse_response(serial, tree, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_path_should_populate_seven_segments_for_plain_channel),
        cmocka_unit_test(build_path_should_percent_encode_channel_with_reserved_chars),
        cmocka_unit_test(build_path_should_percent_encode_message_payload),
        cmocka_unit_test(build_path_should_reject_null_publish_key),
        cmocka_unit_test(build_path_should_reject_null_channel),
        cmocka_unit_test(build_path_should_reject_null_serialized),
        cmocka_unit_test(
            add_query_params_should_not_append_when_no_custom_message_type),
        cmocka_unit_test(add_query_params_should_append_custom_message_type),
        cmocka_unit_test(validator_should_accept_status_one),
        cmocka_unit_test(validator_should_reject_status_zero),
        cmocka_unit_test(validator_should_accept_empty_body),
        cmocka_unit_test(parse_response_should_decode_success),
        cmocka_unit_test(parse_response_should_handle_two_element_error),
        cmocka_unit_test(parse_response_should_reject_null_out),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

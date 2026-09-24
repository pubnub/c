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
#include "pubnub/providers/transport_types.h"

#include "features/signal/signal_internal.h"

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

static void build_path_populates_7_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const char              message[] = "{\"text\":\"hello\"}";
    pn_signal_path_inputs_t inputs    = {
           .publish_key    = "pub-c-key",
           .subscribe_key  = "sub-c-key",
           .channel        = "my-channel",
           .serialized     = (const uint8_t*)message,
           .serialized_len = sizeof(message) - 1,
    };

    pn_signal_url_encoded_t encoded;
    pubnub_res_t            rc =
        pn_signal_build_path(&request, &s_test_allocator, &inputs, &encoded);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(7, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "signal", 6);
    assert_memory_equal(request.path_segments[1].ptr, "pub-c-key", 9);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "0", 1);
    assert_memory_equal(request.path_segments[4].ptr, "my-channel", 10);
    assert_memory_equal(request.path_segments[5].ptr, "0", 1);
    /* Segment 6 is the URL-encoded message (heap-allocated). */
    assert_non_null(request.path_segments[6].ptr);
    assert_true(request.path_segments[6].len > 0);

    /* Cleanup allocated message buffer. */
    if (NULL != encoded.message) {
        s_test_allocator.free(&s_test_allocator, encoded.message);
    }
}

static void build_path_url_encodes_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const char              message[] = "{}";
    pn_signal_path_inputs_t inputs    = {
           .publish_key    = "pub-c-key",
           .subscribe_key  = "sub-c-key",
           .channel        = "channel with spaces",
           .serialized     = (const uint8_t*)message,
           .serialized_len = sizeof(message) - 1,
    };

    pn_signal_url_encoded_t encoded;
    pubnub_res_t            rc =
        pn_signal_build_path(&request, &s_test_allocator, &inputs, &encoded);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(7, request.path_segment_count);

    /* Channel segment should be URL-encoded (spaces → %20). */
    const char* channel_seg = request.path_segments[4].ptr;
    assert_non_null(channel_seg);
    assert_true(request.path_segments[4].len > 0);
    /* Check that spaces are encoded. */
    assert_non_null(strstr(channel_seg, "%20"));

    /* Cleanup. */
    if (NULL != encoded.message) {
        s_test_allocator.free(&s_test_allocator, encoded.message);
    }
}

static void build_path_url_encodes_message(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const char              message[] = "{\"key\":\"value with spaces\"}";
    pn_signal_path_inputs_t inputs    = {
           .publish_key    = "pub-c-key",
           .subscribe_key  = "sub-c-key",
           .channel        = "ch",
           .serialized     = (const uint8_t*)message,
           .serialized_len = sizeof(message) - 1,
    };

    pn_signal_url_encoded_t encoded;
    pubnub_res_t            rc =
        pn_signal_build_path(&request, &s_test_allocator, &inputs, &encoded);

    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(encoded.message);

    /* Message should be URL-encoded (spaces → %20). */
    assert_non_null(strstr(encoded.message, "%20"));

    /* Cleanup. */
    s_test_allocator.free(&s_test_allocator, encoded.message);
}

static void add_query_params_custom_message_type(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_signal_add_query_params(&request, "typing");

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, request.query_param_count);
    assert_memory_equal(request.query_params[0].key.ptr, "custom_message_type", 19);
    /* Value should be URL-encoded "typing" — in scratch. */
    assert_non_null(request.query_params[0].value.ptr);
    assert_true(request.query_params[0].value.len > 0);
}

static void add_query_params_null_custom_message_type(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_signal_add_query_params(&request, NULL);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, request.query_param_count);
}

static void build_path_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const char              message[] = "{}";
    pn_signal_path_inputs_t inputs    = {
           .publish_key    = "pub-c-key",
           .subscribe_key  = "sub-c-key",
           .channel        = NULL,
           .serialized     = (const uint8_t*)message,
           .serialized_len = sizeof(message) - 1,
    };

    pn_signal_url_encoded_t encoded;
    pubnub_res_t            rc =
        pn_signal_build_path(&request, &s_test_allocator, &inputs, &encoded);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_path_rejects_null_serialized(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_signal_path_inputs_t inputs = {
        .publish_key    = "pub-c-key",
        .subscribe_key  = "sub-c-key",
        .channel        = "ch",
        .serialized     = NULL,
        .serialized_len = 0,
    };

    pn_signal_url_encoded_t encoded;
    pubnub_res_t            rc =
        pn_signal_build_path(&request, &s_test_allocator, &inputs, &encoded);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_path_populates_7_segments),
        cmocka_unit_test(build_path_url_encodes_channel),
        cmocka_unit_test(build_path_url_encodes_message),
        cmocka_unit_test(add_query_params_custom_message_type),
        cmocka_unit_test(add_query_params_null_custom_message_type),
        cmocka_unit_test(build_path_rejects_null_channel),
        cmocka_unit_test(build_path_rejects_null_serialized),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/features/push.h"
#include "pubnub/providers/transport_types.h"
#include "features/push/push_internal.h"

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void add_channels_fcm_path_has_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pn_push_path_inputs_t in      = {
             .subscribe_key = "sub-c-key",
             .device        = "fcm-token-123",
             .gateway       = PUBNUB_PUSH_FCM,
             .append_remove = 0,
    };
    pubnub_res_t rc = pn_push_build_path(&request, &in);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 6);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "push", 4);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "devices", 7);
    assert_memory_equal(request.path_segments[5].ptr, "fcm-token-123", 13);
}

static void add_channels_apns2_path_has_six_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pn_push_path_inputs_t in      = {
             .subscribe_key = "sub-c-key",
             .device        = "apns-device-hex",
             .gateway       = PUBNUB_PUSH_APNS2,
             .append_remove = 0,
    };
    pubnub_res_t rc = pn_push_build_path(&request, &in);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 6);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "push", 4);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "devices-apns2", 13);
    assert_memory_equal(request.path_segments[5].ptr, "apns-device-hex", 15);
}

static void add_channels_param_sets_add_key(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t rc = pn_push_add_channels_param(&request, "ch1%2Cch2");
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "add", 3);
    assert_memory_equal(request.query_params[0].value.ptr, "ch1%2Cch2", 9);
}

static void gateway_params_fcm_only_type(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t          rc      = pn_push_add_gateway_params(
        &request, PUBNUB_PUSH_FCM, PUBNUB_PUSH_ENV_DEVELOPMENT, NULL);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "type", 4);
    assert_memory_equal(request.query_params[0].value.ptr, "fcm", 3);
}

static void gateway_params_apns2_all(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t          rc      = pn_push_add_gateway_params(
        &request, PUBNUB_PUSH_APNS2, PUBNUB_PUSH_ENV_PRODUCTION, "com.example.app");
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 3);
    assert_memory_equal(request.query_params[0].key.ptr, "type", 4);
    assert_memory_equal(request.query_params[0].value.ptr, "apns2", 5);
    assert_memory_equal(request.query_params[1].key.ptr, "environment", 11);
    assert_memory_equal(request.query_params[1].value.ptr, "production", 10);
    assert_memory_equal(request.query_params[2].key.ptr, "topic", 5);
    assert_memory_equal(request.query_params[2].value.ptr, "com.example.app", 15);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(add_channels_fcm_path_has_six_segments),
        cmocka_unit_test(add_channels_apns2_path_has_six_segments),
        cmocka_unit_test(add_channels_param_sets_add_key),
        cmocka_unit_test(gateway_params_fcm_only_type),
        cmocka_unit_test(gateway_params_apns2_all),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

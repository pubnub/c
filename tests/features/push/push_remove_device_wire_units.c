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

static void remove_device_fcm_path_has_seven_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pn_push_path_inputs_t in      = {
             .subscribe_key = "sub-c-key",
             .device        = "fcm-token",
             .gateway       = PUBNUB_PUSH_FCM,
             .append_remove = 1,
    };
    pubnub_res_t rc = pn_push_build_path(&request, &in);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 7);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "push", 4);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "devices", 7);
    assert_memory_equal(request.path_segments[5].ptr, "fcm-token", 9);
    assert_memory_equal(request.path_segments[6].ptr, "remove", 6);
}

static void remove_device_apns2_path_has_seven_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pn_push_path_inputs_t in      = {
             .subscribe_key = "sub-c-key",
             .device        = "apns-hex",
             .gateway       = PUBNUB_PUSH_APNS2,
             .append_remove = 1,
    };
    pubnub_res_t rc = pn_push_build_path(&request, &in);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 7);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "push", 4);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "devices-apns2", 13);
    assert_memory_equal(request.path_segments[5].ptr, "apns-hex", 8);
    assert_memory_equal(request.path_segments[6].ptr, "remove", 6);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(remove_device_fcm_path_has_seven_segments),
        cmocka_unit_test(remove_device_apns2_path_has_seven_segments),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

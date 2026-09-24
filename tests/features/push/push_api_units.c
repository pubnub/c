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

static void build_path_rejects_null_request(void** state)
{
    (void)state;
    pn_push_path_inputs_t in = {
        .subscribe_key = "sub-c-key",
        .device        = "device-token",
        .gateway       = PUBNUB_PUSH_FCM,
        .append_remove = 0,
    };
    assert_int_equal(pn_push_build_path(NULL, &in), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void build_path_rejects_null_inputs(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    assert_int_equal(pn_push_build_path(&request, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void build_path_rejects_null_device(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pn_push_path_inputs_t in      = {
             .subscribe_key = "sub-c-key",
             .device        = NULL,
             .gateway       = PUBNUB_PUSH_FCM,
             .append_remove = 0,
    };
    assert_int_equal(pn_push_build_path(&request, &in), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void add_gateway_params_rejects_null_request(void** state)
{
    (void)state;
    assert_int_equal(pn_push_add_gateway_params(
                         NULL, PUBNUB_PUSH_FCM, PUBNUB_PUSH_ENV_DEVELOPMENT, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void mutation_validator_rejects_http_error(void** state)
{
    (void)state;
    const uint8_t body[] = "[0,\"error\"]";
    assert_int_equal(pn_push_mutation_response_validator(body, sizeof(body) - 1, 403),
                     PUBNUB_ERR_SERVER);
}

static void mutation_validator_accepts_success(void** state)
{
    (void)state;
    const uint8_t body[] = "[1, \"Modified Channels\"]";
    assert_int_equal(pn_push_mutation_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void mutation_validator_rejects_logical_failure(void** state)
{
    (void)state;
    const uint8_t body[] = "[0, \"Invalid device token\"]";
    assert_int_equal(pn_push_mutation_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_ERR_SERVER);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_path_rejects_null_request),
        cmocka_unit_test(build_path_rejects_null_inputs),
        cmocka_unit_test(build_path_rejects_null_device),
        cmocka_unit_test(add_gateway_params_rejects_null_request),
        cmocka_unit_test(mutation_validator_rejects_http_error),
        cmocka_unit_test(mutation_validator_accepts_success),
        cmocka_unit_test(mutation_validator_rejects_logical_failure),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

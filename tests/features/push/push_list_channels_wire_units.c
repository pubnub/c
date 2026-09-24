/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/features/push.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"
#include "features/push/push_internal.h"

extern pubnub_serialization_provider_t* pn_serialization_default(void);

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void add_list_params_with_start_and_count(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t rc = pn_push_add_list_params(&request, "token123", 100);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 2);
    assert_memory_equal(request.query_params[0].key.ptr, "start", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "token123", 8);
    assert_memory_equal(request.query_params[1].key.ptr, "count", 5);
    assert_memory_equal(request.query_params[1].value.ptr, "100", 3);
}

static void add_list_params_with_only_count(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t          rc      = pn_push_add_list_params(&request, NULL, 50);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "count", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "50", 2);
}

static void add_list_params_clamps_count_to_max(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t          rc = pn_push_add_list_params(&request, NULL, 5000);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "count", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "1000", 4);
}

static void add_list_params_omits_count_when_zero(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t          rc      = pn_push_add_list_params(&request, NULL, 0);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 0);
}

static void list_validator_accepts_array(void** state)
{
    (void)state;
    const uint8_t body[] = "[\"ch1\",\"ch2\"]";
    assert_int_equal(pn_push_list_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void list_validator_accepts_empty_array(void** state)
{
    (void)state;
    const uint8_t body[] = "[]";
    assert_int_equal(pn_push_list_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void list_validator_rejects_error_array(void** state)
{
    (void)state;
    const uint8_t body[] = "[0,\"error\"]";
    assert_int_equal(pn_push_list_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_ERR_SERVER);
}

static void list_validator_rejects_http_error(void** state)
{
    (void)state;
    const uint8_t body[] = "[\"ch1\"]";
    assert_int_equal(pn_push_list_response_validator(body, sizeof(body) - 1, 400),
                     PUBNUB_ERR_SERVER);
}

static void list_parse_extracts_channel_count(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    if (NULL == serial || NULL == serial->parse) {
        skip();
    }
    const uint8_t        body[] = "[\"ch1\",\"ch2\",\"ch3\"]";
    pubnub_json_value_t* tree   = serial->parse(serial, body, sizeof(body) - 1);
    assert_non_null(tree);

    pn_push_list_parsed_t out = {0};
    pubnub_res_t          rc  = pn_push_list_parse_response(serial, tree, &out);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 3);
    assert_ptr_equal(out.tree, tree);

    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(add_list_params_with_start_and_count),
        cmocka_unit_test(add_list_params_with_only_count),
        cmocka_unit_test(add_list_params_clamps_count_to_max),
        cmocka_unit_test(add_list_params_omits_count_when_zero),
        cmocka_unit_test(list_validator_accepts_array),
        cmocka_unit_test(list_validator_accepts_empty_array),
        cmocka_unit_test(list_validator_rejects_error_array),
        cmocka_unit_test(list_validator_rejects_http_error),
        cmocka_unit_test(list_parse_extracts_channel_count),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

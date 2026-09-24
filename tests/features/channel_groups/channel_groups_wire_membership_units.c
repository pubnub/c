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
#include "core/runtime/middleware/middleware_internal.h"

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void query_param_should_preserve_commas(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_request_add_query_param(
        &request, "add", "ch1,ch2,ch3", PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "add", 3);
    assert_int_equal(request.query_params[0].value.len, 11);
    assert_memory_equal(request.query_params[0].value.ptr, "ch1,ch2,ch3", 11);
}

static void query_param_should_handle_single_channel(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_request_add_query_param(
        &request, "remove", "only-one", PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "remove", 6);
    assert_memory_equal(request.query_params[0].value.ptr, "only-one", 8);
}

static void query_param_should_reject_null_value(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(
        pn_request_add_query_param(&request, "add", NULL, PN_ENCODE_KEEP_COMMAS),
        PUBNUB_ERR_INVALID_ARGUMENT);
}

static void query_param_should_encode_special_chars(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pubnub_res_t rc = pn_request_add_query_param(
        &request, "add", "ch 1,ch&2", PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    /* Space -> %20, ampersand -> %26, comma preserved. */
    assert_int_equal(request.query_params[0].value.len, 13);
    assert_memory_equal(request.query_params[0].value.ptr, "ch%201,ch%262", 13);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(query_param_should_preserve_commas),
        cmocka_unit_test(query_param_should_handle_single_channel),
        cmocka_unit_test(query_param_should_reject_null_value),
        cmocka_unit_test(query_param_should_encode_special_chars),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

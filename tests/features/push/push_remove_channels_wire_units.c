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

static void remove_channels_param_sets_remove_key(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    pubnub_res_t rc = pn_push_remove_channels_param(&request, "ch1%2Cch2");
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "remove", 6);
    assert_memory_equal(request.query_params[0].value.ptr, "ch1%2Cch2", 9);
}

static void remove_channels_param_rejects_null(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    assert_int_equal(pn_push_remove_channels_param(&request, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_push_remove_channels_param(NULL, "ch1"),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(remove_channels_param_sets_remove_key),
        cmocka_unit_test(remove_channels_param_rejects_null),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

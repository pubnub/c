/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/error.h"
#include "pubnub/features/time.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#include "it_context.h"
#include "it_env.h"

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    it_test_state_t* s = it_state_create(env);
    if (NULL == s) {
        return -1;
    }
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

static void time_returns_17_digit_timetoken(void** state)
{
    it_test_state_t* s   = *state;
    pubnub_future_t  fut = pubnub_time(s->ctx);
    pubnub_res_t     st  = pubnub_await(fut);

    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("time failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
    assert_int_equal(17, (int)tt.len);
    for (size_t i = 0U; i < tt.len; ++i) {
        assert_true(tt.ptr[i] >= '0' && tt.ptr[i] <= '9');
    }
    pubnub_future_release(fut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            time_returns_17_digit_timetoken, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/error.h"
#include "pubnub/features/signal.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

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

static void signal_returns_ok_and_timetoken(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_signal_opts_t opts = PUBNUB_SIGNAL_OPTS_INIT;
    opts.channel              = s->channel;
    opts.message              = "\"ping\"";

    pubnub_future_t fut = pubnub_signal(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("signal failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_timetoken_t tt = pubnub_signal_result_timetoken(fut);
    assert_int_equal(17, (int)tt.len);
    pubnub_future_release(fut);
}

static void signal_with_custom_message_type_returns_ok(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_signal_opts_t opts = PUBNUB_SIGNAL_OPTS_INIT;
    opts.channel              = s->channel;
    opts.message              = "\"ping\"";
    opts.custom_message_type  = "sig-type";

    pubnub_future_t fut = pubnub_signal(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("signal custom_message_type failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

static void signal_payload_too_long_returns_error(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    char long_payload[66] = {0};
    memset(long_payload, 'x', 65);

    pubnub_signal_opts_t opts = PUBNUB_SIGNAL_OPTS_INIT;
    opts.channel              = s->channel;
    opts.message              = long_payload;

    pubnub_future_t fut = pubnub_signal(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    assert_int_not_equal(PUBNUB_OK, st);
    assert_int_equal(400, pubnub_response_status_code(fut));
    pubnub_future_release(fut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            signal_returns_ok_and_timetoken, setup, teardown),
        cmocka_unit_test_setup_teardown(
            signal_with_custom_message_type_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            signal_payload_too_long_returns_error, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/error.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/features/publish.h"
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

/** Publish one message; copy timetoken into out_tt as NUL-terminated string.
 *  out_tt must point to a buffer of at least 18 bytes. */
static void publish_one(pubnub_context_t* ctx,
                        const char*       channel,
                        const char*       msg,
                        char              out_tt[18])
{
    pubnub_future_t fut = pubnub_publish(
        ctx, &(pubnub_publish_opts_t){.channel = channel, .message = msg});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
    size_t             n  = tt.len < 17U ? tt.len : 17U;
    memcpy(out_tt, tt.ptr, n);
    out_tt[n] = '\0';
    pubnub_future_release(fut);
}

/** Add one action; copy action timetoken into out_att when non-NULL.
 *  out_att must point to a buffer of at least 18 bytes when non-NULL. */
static void add_one_action(pubnub_context_t* ctx,
                           const char*       channel,
                           const char*       msg_tt,
                           const char*       type,
                           const char*       value,
                           char*             out_att)
{
    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = channel;
    opts.message_timetoken                = msg_tt;
    opts.type                             = type;
    opts.value                            = value;

    pubnub_future_t fut = pubnub_add_message_action(ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("add_message_action failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    if (NULL != out_att) {
        pubnub_add_message_action_result_t res =
            pubnub_add_message_action_result(fut);
        size_t n = res.action.action_timetoken.len < 17U
                     ? res.action.action_timetoken.len
                     : 17U;
        memcpy(out_att, res.action.action_timetoken.ptr, n);
        out_att[n] = '\0';
    }
    pubnub_future_release(fut);
}

static void add_message_action_returns_ok_and_timetoken(void** state)
{
    it_test_state_t* s          = *state;
    char             msg_tt[18] = {0};
    print_message("channel: %s", s->channel);

    publish_one(s->ctx, s->channel, "\"reaction target\"", msg_tt);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = s->channel;
    opts.message_timetoken                = msg_tt;
    opts.type                             = "reaction";
    opts.value                            = "thumbsup";

    pubnub_future_t fut = pubnub_add_message_action(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("add_message_action failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_add_message_action_result_t res = pubnub_add_message_action_result(fut);
    assert_true(0U < res.action.action_timetoken.len);
    pubnub_future_release(fut);
}

static void get_message_actions_returns_added_action(void** state)
{
    it_test_state_t* s          = *state;
    char             msg_tt[18] = {0};
    print_message("channel: %s", s->channel);

    publish_one(s->ctx, s->channel, "\"get target\"", msg_tt);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_add_message_action_opts_t aopts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    aopts.channel           = s->channel;
    aopts.message_timetoken = msg_tt;
    aopts.type              = "reaction";
    aopts.value             = "thumbsup";

    pubnub_future_t afut = pubnub_add_message_action(s->ctx, &aopts);
    pubnub_res_t    ast  = pubnub_await(afut);
    if (PUBNUB_OK != ast) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(afut);
        print_error("add_message_action failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(ast),
                    pubnub_response_status_code(afut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, ast);
    pubnub_future_release(afut);

    pn_test_sleep_ms(IT_DELAY_MESSAGE_ACTION_MS);

    pubnub_get_message_actions_opts_t gopts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    gopts.channel = s->channel;

    pubnub_future_t gfut = pubnub_get_message_actions(s->ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    if (PUBNUB_OK != gst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(gfut);
        print_error("get_message_actions failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(gst),
                    pubnub_response_status_code(gfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_get_message_actions_result_t res =
        pubnub_get_message_actions_result(gfut);
    assert_true(0U < res.count);

    pubnub_message_action_t a =
        pubnub_get_message_actions_result_action_at(gfut, 0U);
    assert_int_equal((int)strlen("reaction"), (int)a.type.len);
    assert_memory_equal("reaction", a.type.ptr, a.type.len);
    assert_int_equal((int)strlen("thumbsup"), (int)a.value.len);
    assert_memory_equal("thumbsup", a.value.ptr, a.value.len);
    pubnub_future_release(gfut);
}

static void remove_message_action_returns_ok(void** state)
{
    it_test_state_t* s          = *state;
    char             msg_tt[18] = {0};
    char             act_tt[18] = {0};
    print_message("channel: %s", s->channel);

    publish_one(s->ctx, s->channel, "\"remove target\"", msg_tt);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);
    add_one_action(s->ctx, s->channel, msg_tt, "reaction", "thumbsup", act_tt);

    pubnub_remove_message_action_opts_t ropts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;
    ropts.channel           = s->channel;
    ropts.message_timetoken = msg_tt;
    ropts.action_timetoken  = act_tt;

    pubnub_future_t fut = pubnub_remove_message_action(s->ctx, &ropts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("remove_message_action failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

static void after_remove_action_gone_from_get(void** state)
{
    it_test_state_t* s          = *state;
    char             msg_tt[18] = {0};
    char             act_tt[18] = {0};
    print_message("channel: %s", s->channel);

    publish_one(s->ctx, s->channel, "\"gone target\"", msg_tt);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);
    add_one_action(s->ctx, s->channel, msg_tt, "reaction", "thumbsup", act_tt);

    /* Brief pause: action storage is eventually consistent on loaded runners;
     * an immediate remove can race the write and return a transient error. */
    pn_test_sleep_ms(IT_DELAY_MESSAGE_ACTION_MS);

    pubnub_remove_message_action_opts_t ropts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;
    ropts.channel           = s->channel;
    ropts.message_timetoken = msg_tt;
    ropts.action_timetoken  = act_tt;

    pubnub_future_t rfut = pubnub_remove_message_action(s->ctx, &ropts);
    pubnub_res_t    rst  = pubnub_await(rfut);
    if (PUBNUB_OK != rst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(rfut);
        print_error("remove_message_action failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(rst),
                    pubnub_response_status_code(rfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, rst);
    pubnub_future_release(rfut);

    pn_test_sleep_ms(IT_DELAY_MESSAGE_ACTION_REMOVE_MS);

    pubnub_get_message_actions_opts_t gopts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    gopts.channel = s->channel;

    pubnub_future_t gfut = pubnub_get_message_actions(s->ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    if (PUBNUB_OK != gst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(gfut);
        print_error("get_message_actions failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(gst),
                    pubnub_response_status_code(gfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_get_message_actions_result_t res =
        pubnub_get_message_actions_result(gfut);
    assert_int_equal(0, (int)res.count);
    pubnub_future_release(gfut);
}

static void add_duplicate_action_returns_409(void** state)
{
    it_test_state_t* s          = *state;
    char             msg_tt[18] = {0};
    print_message("channel: %s", s->channel);

    publish_one(s->ctx, s->channel, "\"dup target\"", msg_tt);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = s->channel;
    opts.message_timetoken                = msg_tt;
    opts.type                             = "reaction";
    opts.value                            = "thumbsup";

    pubnub_future_t fut1 = pubnub_add_message_action(s->ctx, &opts);
    pubnub_res_t    st1  = pubnub_await(fut1);
    if (PUBNUB_OK != st1) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut1);
        print_error("first add_message_action failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st1),
                    pubnub_response_status_code(fut1),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st1);
    pubnub_future_release(fut1);

    pubnub_future_t fut2 = pubnub_add_message_action(s->ctx, &opts);
    pubnub_res_t    st2  = pubnub_await(fut2);
    assert_int_equal(PUBNUB_ERR_SERVER, st2);
    assert_int_equal(409, pubnub_response_status_code(fut2));
    pubnub_future_release(fut2);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            add_message_action_returns_ok_and_timetoken, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_message_actions_returns_added_action, setup, teardown),
        cmocka_unit_test_setup_teardown(
            remove_message_action_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            after_remove_action_gone_from_get, setup, teardown),
        cmocka_unit_test_setup_teardown(
            add_duplicate_action_returns_409, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

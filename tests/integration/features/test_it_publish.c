/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/history.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
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

static int setup_pam(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    SKIP_IF_NO_PAM_KEYS(env);
    it_test_state_t* s = it_state_create(env);
    if (NULL == s) {
        return -1;
    }
    it_state_add_pam_ctx(s);
    if (NULL == s->pam_ctx) {
        it_state_destroy(s);
        return -1;
    }
    *state = s;
    return 0;
}

static int teardown_pam(void** state)
{
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

static void publish_string_returns_ok_and_timetoken(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut = pubnub_publish(s->ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"hello from c\"",
                                         });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
    assert_int_equal(17, (int)tt.len);
    pubnub_future_release(fut);
}

static void publish_json_object_returns_timetoken(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut =
        pubnub_publish(s->ctx,
                       &(pubnub_publish_opts_t){
                           .channel = s->channel,
                           .message = "{\"k\":1,\"v\":\"test\"}",
                       });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
    assert_int_equal(17, (int)tt.len);
    pubnub_future_release(fut);
}

static void publish_with_store_false_absent_from_history(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut = pubnub_publish(s->ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"ephemeral\"",
                                             .store   = PUBNUB_PUBLISH_STORE_NO,
                                         });

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish store_no failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t hopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    hopts.channels                     = s->channel;
    hopts.count                        = 10U;

    pubnub_future_t hfut = pubnub_fetch_messages(s->ctx, &hopts);
    pubnub_res_t    hst  = pubnub_await(hfut);
    if (PUBNUB_OK != hst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(hfut);
        print_error("fetch_messages failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(hst),
                    pubnub_response_status_code(hfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, hst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(hfut);
    uint32_t                       msg_count = 0U;
    if (0U < res.channel_count) {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(hfut, 0U);
        msg_count = ch.message_count;
    }
    pubnub_future_release(hfut);
    assert_int_equal(0, (int)msg_count);
}

static void publish_with_meta_returns_ok(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut = pubnub_publish(s->ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"meta test\"",
                                             .meta = "{\"region\":\"us-east\"}",
                                         });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish with meta failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

static void publish_with_custom_message_type_returns_ok(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut = pubnub_publish(s->ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"typed message\"",
                                             .custom_message_type = "test-type",
                                         });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish custom_message_type failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

static void publish_with_ttl_returns_ok(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut = pubnub_publish(s->ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"ttl test\"",
                                             .store = PUBNUB_PUBLISH_STORE_YES,
                                             .ttl   = 10U,
                                         });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish with ttl failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

static void fire_message_absent_from_history(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    /* Fire semantics: publish with no persistence. */
    pubnub_future_t fut = pubnub_publish(s->ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"fire ephemeral\"",
                                             .store   = PUBNUB_PUBLISH_STORE_NO,
                                         });

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("fire publish failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t hopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    hopts.channels                     = s->channel;
    hopts.count                        = 10U;

    pubnub_future_t hfut = pubnub_fetch_messages(s->ctx, &hopts);
    pubnub_res_t    hst  = pubnub_await(hfut);
    if (PUBNUB_OK != hst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(hfut);
        print_error("fetch_messages failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(hst),
                    pubnub_response_status_code(hfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, hst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(hfut);
    uint32_t                       msg_count = 0U;
    if (0U < res.channel_count) {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(hfut, 0U);
        msg_count = ch.message_count;
    }
    pubnub_future_release(hfut);
    assert_int_equal(0, (int)msg_count);
}

/**
 * @brief Publish via POST with an explicit compression preference and
 *        verify the stored payload through Message Persistence.
 *
 * Whatever the SDK does to the request body on the wire, the message the
 * server hands back must be byte-identical to what the caller passed in.
 * That makes this the round-trip check for both the compressed and the
 * uncompressed paths.
 */
static void publish_post_and_verify_delivered_payload(it_test_state_t* s,
                                                      pubnub_publish_compress_t compress,
                                                      const char* json_message,
                                                      const char* expected_payload)
{
    print_message("channel: %s", s->channel);

    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = s->channel;
    opts.message               = json_message;
    opts.method                = PUBNUB_PUBLISH_METHOD_POST;
    opts.compress              = compress;

    pubnub_future_t fut = pubnub_publish(s->ctx, &opts);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish POST failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t hopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    hopts.channels                     = s->channel;
    hopts.count                        = 10U;

    pubnub_future_t hfut = pubnub_fetch_messages(s->ctx, &hopts);
    pubnub_res_t    hst  = pubnub_await(hfut);
    if (PUBNUB_OK != hst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(hfut);
        print_error("fetch_messages failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(hst),
                    pubnub_response_status_code(hfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, hst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(hfut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(hfut, 0U);
    assert_true(0U < ch.message_count);

    pubnub_history_message_result_t msg =
        pubnub_fetch_messages_result_message_at(hfut, 0U, ch.message_count - 1U);
    assert_non_null(msg.message);

    pubnub_serialization_provider_t* serial = pubnub_serialization(s->ctx);
    assert_non_null(serial);
    size_t      slen = 0U;
    const char* sptr = serial->value_as_string(msg.message, &slen);
    assert_non_null(sptr);

    const size_t expected_len = strlen(expected_payload);
    assert_int_equal((int)expected_len, (int)slen);
    assert_memory_equal(expected_payload, sptr, expected_len);

    pubnub_future_release(hfut);
}

/** @brief POST with the default preference compresses and round-trips. */
static void publish_with_post_method_delivers_correct_content(void** state)
{
    it_test_state_t* s = *state;

    if (!PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }

    publish_post_and_verify_delivered_payload(s,
                                              PUBNUB_PUBLISH_COMPRESS_DEFAULT,
                                              "\"hello-compressed\"",
                                              "hello-compressed");
}

/** @brief POST with COMPRESS_YES round-trips a gzip-encoded body. */
static void publish_with_compress_yes_delivers_correct_content(void** state)
{
    it_test_state_t* s = *state;

    if (!PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }

    publish_post_and_verify_delivered_payload(s,
                                              PUBNUB_PUBLISH_COMPRESS_YES,
                                              "\"hello-compress-yes\"",
                                              "hello-compress-yes");
}

/**
 * @brief POST with COMPRESS_NO round-trips an uncompressed body.
 *
 * Runs on every build: opting out must work regardless of whether the
 * compile-time compression toggle is enabled.
 */
static void publish_with_compress_no_delivers_correct_content(void** state)
{
    it_test_state_t* s = *state;

    publish_post_and_verify_delivered_payload(
        s, PUBNUB_PUBLISH_COMPRESS_NO, "\"hello-compress-no\"", "hello-compress-no");
}

static void publish_with_pam_secret_key_accepted_by_server(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_future_t fut = pubnub_publish(s->pam_ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = s->channel,
                                             .message = "\"hello-pam\"",
                                         });

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish with PAM failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

static void publish_with_pam_and_compression_accepted_by_server(void** state)
{
    it_test_state_t* s = *state;

    if (!PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }
    print_message("channel: %s", s->channel);

    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = s->channel;
    opts.message               = "\"hello-pam-compressed\"";
    opts.method                = PUBNUB_PUBLISH_METHOD_POST;

    pubnub_future_t fut = pubnub_publish(s->pam_ctx, &opts);

    pubnub_res_t st = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("publish PAM+compressed failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            publish_string_returns_ok_and_timetoken, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_json_object_returns_timetoken, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_store_false_absent_from_history, setup, teardown),
        cmocka_unit_test_setup_teardown(publish_with_meta_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_custom_message_type_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(publish_with_ttl_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fire_message_absent_from_history, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_post_method_delivers_correct_content, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_compress_yes_delivers_correct_content, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_compress_no_delivers_correct_content, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_pam_secret_key_accepted_by_server, setup_pam, teardown_pam),
        cmocka_unit_test_setup_teardown(
            publish_with_pam_and_compression_accepted_by_server, setup_pam, teardown_pam),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

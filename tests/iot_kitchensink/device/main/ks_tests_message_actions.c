/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/history.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static volatile uint8_t s_ma_event_received;

static void ma_channel(const ks_runner_t* runner,
                       const char*        suffix,
                       char*              out,
                       size_t             out_len)
{
    snprintf(out, out_len, "iot-ks-%s-ma-%s", runner->run_id, suffix);
}

static void pump_subscribe_until(pubnub_context_t* ctx,
                                 volatile uint8_t* flag,
                                 uint32_t          timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (!*flag) {
        if (esp_timer_get_time() >= deadline) {
            break;
        }
        pubnub_process(ctx);
        vTaskDelay(1);
    }
}

static void wait_subscribe_connected(pubnub_context_t* ctx, uint32_t timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(ctx)) {
        if (esp_timer_get_time() >= deadline) {
            break;
        }
        pubnub_process(ctx);
        vTaskDelay(1);
    }
}

static pubnub_res_t
publish_and_get_tt(ks_runner_t* r, const char* ch, char* tt_buf, size_t tt_cap)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    pubnub_res_t          rc;
    pubnub_timetoken_t    tt;
    size_t                copy;

    opts.channel = ch;
    opts.message = "\"action test\"";
    fut          = pubnub_publish(r->ctx, &opts);
    rc = ks_pump_until_ready(r->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        return rc;
    }
    tt = pubnub_publish_result_timetoken(fut);
    if (NULL == tt.ptr || 0 == tt.len) {
        pubnub_future_release(fut);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    copy = tt.len < tt_cap - 1 ? tt.len : tt_cap - 1;
    memcpy(tt_buf, tt.ptr, copy);
    tt_buf[copy] = '\0';
    pubnub_future_release(fut);
    return PUBNUB_OK;
}

static void cleanup_sub(pubnub_subscription_t*   sub,
                        pubnub_entity_t*         entity,
                        pubnub_listener_handle_t handle)
{
    if (NULL != *sub) {
        pubnub_subscription_unsubscribe(*sub);
        if (PUBNUB_LISTENER_HANDLE_INVALID != handle) {
            pubnub_subscription_remove_listener(*sub, handle);
        }
        pubnub_subscription_destroy(*sub);
        *sub = NULL;
    }
    if (NULL != *entity) {
        pubnub_entity_destroy(*entity);
        *entity = NULL;
    }
}

static void on_ma_event(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    (void)event;
    s_ma_event_received = 1;
}

static ks_result_t test_ma_add_event_to_device(ks_runner_t* runner)
{
    char                        ch[48]       = {0};
    char                        msg_tt[24]   = {0};
    char                        payload[192] = {0};
    pubnub_entity_t             entity       = NULL;
    pubnub_subscription_t       sub          = NULL;
    pubnub_subscription_opts_t  sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener     = {0};
    pubnub_listener_handle_t    handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_ma_event_received = 0;

    ma_channel(runner, "ev.add", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, msg_tt, sizeof(msg_tt));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_message_action = on_ma_event;
    handle = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    wait_subscribe_connected(runner->ctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(runner->ctx)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not connect");
    }

    snprintf(payload,
             sizeof(payload),
             "{\"message_timetoken\":\"%s\","
             "\"action_type\":\"reaction\","
             "\"action_value\":\"thumbs_up\"}",
             msg_tt);

    if (!ks_ask_companion(runner,
                          "message_actions/add_event_to_device",
                          "add_message_action",
                          ch,
                          payload,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion add_message_action failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_ma_event_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_ma_event_received) {
        KS_RETURN_FAIL("message_action event not received");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_ma_add_event_to_companion(ks_runner_t* runner)
{
    char            ch[48]       = {0};
    char            msg_tt[24]   = {0};
    char            payload[256] = {0};
    pubnub_res_t    rc;
    pubnub_future_t fut;
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;

    ma_channel(runner, "ev.comp", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, msg_tt, sizeof(msg_tt));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    snprintf(payload,
             sizeof(payload),
             "{\"action_event\":\"added\","
             "\"expected_type\":\"reaction\","
             "\"expected_value\":\"spark\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "message_actions/add_event_to_companion",
                                   "subscribe_message_action_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    add_opts.channel           = ch;
    add_opts.message_timetoken = msg_tt;
    add_opts.type              = "reaction";
    add_opts.value             = "spark";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add action failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify failed");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_ma_remove_event_to_companion(ks_runner_t* runner)
{
    char                               ch[48]       = {0};
    char                               msg_tt[24]   = {0};
    char                               act_tt[24]   = {0};
    char                               payload[256] = {0};
    pubnub_res_t                       rc;
    pubnub_future_t                    fut;
    pubnub_add_message_action_result_t add_result;
    size_t                             copy;
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    pubnub_remove_message_action_opts_t rm_opts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;

    ma_channel(runner, "ev.rm", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, msg_tt, sizeof(msg_tt));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    add_opts.channel           = ch;
    add_opts.message_timetoken = msg_tt;
    add_opts.type              = "reaction";
    add_opts.value             = "star";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("add action failed: %s", pubnub_res_str(rc));
    }

    add_result = pubnub_add_message_action_result(fut);
    if (NULL == add_result.action.action_timetoken.ptr
        || 0 == add_result.action.action_timetoken.len) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("no action_timetoken in add result");
    }

    copy = add_result.action.action_timetoken.len < sizeof(act_tt) - 1
             ? add_result.action.action_timetoken.len
             : sizeof(act_tt) - 1;
    memcpy(act_tt, add_result.action.action_timetoken.ptr, copy);
    act_tt[copy] = '\0';
    pubnub_future_release(fut);

    snprintf(payload,
             sizeof(payload),
             "{\"action_event\":\"removed\","
             "\"expected_type\":\"reaction\","
             "\"expected_value\":\"star\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "message_actions/remove_event_to_companion",
                                   "subscribe_message_action_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    rm_opts.channel           = ch;
    rm_opts.message_timetoken = msg_tt;
    rm_opts.action_timetoken  = act_tt;

    fut = pubnub_remove_message_action(runner->ctx, &rm_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("remove action failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify failed");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_message_actions_get(ks_runner_t* runner)
{
    char                                ch[48]     = {0};
    char                                msg_tt[24] = {0};
    pubnub_res_t                        rc;
    pubnub_future_t                     fut;
    pubnub_get_message_actions_result_t get_result;
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    pubnub_get_message_actions_opts_t get_opts =
        PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;

    ma_channel(runner, "get", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, msg_tt, sizeof(msg_tt));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    add_opts.channel           = ch;
    add_opts.message_timetoken = msg_tt;
    add_opts.type              = "reaction";
    add_opts.value             = "heart";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add action failed: %s", pubnub_res_str(rc));
    }

    /* Allow action to propagate before fetching. */
    vTaskDelay(pdMS_TO_TICKS(500));

    get_opts.channel = ch;

    fut = pubnub_get_message_actions(runner->ctx, &get_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("get actions failed: %s", pubnub_res_str(rc));
    }

    get_result = pubnub_get_message_actions_result(fut);
    pubnub_future_release(fut);

    if (0 == get_result.count) {
        KS_RETURN_FAIL("expected at least 1 action, got 0");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_message_actions_pagination(ks_runner_t* runner)
{
    char                                ch[48]     = {0};
    char                                msg_tt[24] = {0};
    pubnub_res_t                        rc;
    pubnub_future_t                     fut;
    pubnub_get_message_actions_result_t get_result;
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    pubnub_get_message_actions_opts_t get_opts =
        PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;

    ma_channel(runner, "pg", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, msg_tt, sizeof(msg_tt));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    add_opts.channel           = ch;
    add_opts.message_timetoken = msg_tt;
    add_opts.type              = "reaction";
    add_opts.value             = "thumbsup";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add action 1 failed: %s", pubnub_res_str(rc));
    }

    add_opts.value = "heart";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add action 2 failed: %s", pubnub_res_str(rc));
    }

    /* Allow actions to propagate before fetching. */
    vTaskDelay(pdMS_TO_TICKS(500));

    get_opts.channel = ch;
    get_opts.limit   = 1;

    fut = pubnub_get_message_actions(runner->ctx, &get_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("get actions failed: %s", pubnub_res_str(rc));
    }

    get_result = pubnub_get_message_actions_result(fut);
    pubnub_future_release(fut);

    if (0 == get_result.count) {
        KS_RETURN_FAIL("expected at least 1 action, got 0");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_ma_history_with_actions(ks_runner_t* runner)
{
    char                                   ch[48]       = {0};
    char                                   msg_tt[24]   = {0};
    char                                   payload[256] = {0};
    pubnub_res_t                           rc;
    pubnub_future_t                        fut;
    pubnub_fetch_messages_result_t         fm_result;
    pubnub_fetch_messages_channel_result_t ch_result;
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    pubnub_fetch_messages_opts_t fm_opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    ma_channel(runner, "hist", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, msg_tt, sizeof(msg_tt));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    snprintf(payload,
             sizeof(payload),
             "{\"action_event\":\"added\","
             "\"expected_type\":\"reaction\","
             "\"expected_value\":\"history_check\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "message_actions/history_with_actions",
                                   "subscribe_message_action_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    add_opts.channel           = ch;
    add_opts.message_timetoken = msg_tt;
    add_opts.type              = "reaction";
    add_opts.value             = "history_check";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add action failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify failed");
    }

    fm_opts.channels                = ch;
    fm_opts.include_message_actions = 1;

    fut = pubnub_fetch_messages(runner->ctx, &fm_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("fetch_messages failed: %s", pubnub_res_str(rc));
    }

    fm_result = pubnub_fetch_messages_result(fut);
    if (0 == fm_result.channel_count) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("no channels in fetch result");
    }

    ch_result = pubnub_fetch_messages_result_channel_at(fut, 0);
    if (0 == ch_result.message_count) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("no messages in fetch result");
    }

    if (NULL == pubnub_fetch_messages_result_actions_at(fut, 0, 0)) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("no actions on message");
    }

    pubnub_future_release(fut);
    KS_RETURN_PASS();
}

const ks_test_entry_t ks_message_actions_tests[] = {
    {"message_actions/add_event_to_device",       test_ma_add_event_to_device,       1},
    {"message_actions/add_event_to_companion",    test_ma_add_event_to_companion,    1},
    {"message_actions/remove_event_to_companion", test_ma_remove_event_to_companion, 1},
    {"message_actions/get",                       test_message_actions_get,          0},
    {"message_actions/pagination",                test_message_actions_pagination,   0},
    {"message_actions/history_with_actions",      test_ma_history_with_actions,      1},
};

const size_t ks_message_actions_test_count =
    sizeof(ks_message_actions_tests) / sizeof(ks_message_actions_tests[0]);

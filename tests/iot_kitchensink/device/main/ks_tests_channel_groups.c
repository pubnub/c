/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/channel_groups.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static volatile uint8_t s_cg_msg_received;

static void cg_name(const ks_runner_t* runner, const char* suffix, char* out, size_t out_len)
{
    snprintf(out, out_len, "iot-ks-%s-cg-%s", runner->run_id, suffix);
}

static pubnub_res_t add_channels_to_group(ks_runner_t* r,
                                          const char*  group,
                                          const char*  channels)
{
    pubnub_channel_group_add_opts_t opts = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    pubnub_future_t                 fut;
    pubnub_res_t                    rc;

    opts.channel_group = group;
    opts.channels      = channels;

    fut = pubnub_channel_group_add_channels(r->ctx, &opts);
    rc  = ks_pump_until_ready(r->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    return rc;
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

static void on_cg_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)event;
    (void)user_data;
    s_cg_msg_received = 1;
}

static ks_result_t test_channel_groups_add(ks_runner_t* runner)
{
    char         group[48] = {0};
    pubnub_res_t rc;

    cg_name(runner, "add", group, sizeof(group));

    rc = add_channels_to_group(runner, group, "ch-a,ch-b");
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add channels failed: %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

static ks_result_t test_channel_groups_list(ks_runner_t* runner)
{
    char         group[48] = {0};
    pubnub_res_t rc;
    pubnub_channel_group_list_opts_t list_opts = PUBNUB_CHANNEL_GROUP_LIST_OPTS_INIT;
    pubnub_future_t                    fut;
    pubnub_channel_group_list_result_t list_result;

    cg_name(runner, "list", group, sizeof(group));

    rc = add_channels_to_group(runner, group, "ch-a,ch-b");
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add channels failed: %s", pubnub_res_str(rc));
    }

    list_opts.channel_group = group;
    fut = pubnub_channel_group_list_channels(runner->ctx, &list_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("list channels failed: %s", pubnub_res_str(rc));
    }

    list_result = pubnub_channel_group_list_result(fut);
    pubnub_future_release(fut);

    if (list_result.count < 2) {
        KS_RETURN_FAIL("expected >=2 channels, got %u", (unsigned)list_result.count);
    }

    KS_RETURN_PASS();
}

static ks_result_t test_channel_groups_remove(ks_runner_t* runner)
{
    char                               group[48] = {0};
    pubnub_res_t                       rc;
    pubnub_channel_group_remove_opts_t rm_opts =
        PUBNUB_CHANNEL_GROUP_REMOVE_OPTS_INIT;
    pubnub_future_t fut;

    cg_name(runner, "rm", group, sizeof(group));

    rc = add_channels_to_group(runner, group, "ch-a,ch-b");
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add channels failed: %s", pubnub_res_str(rc));
    }

    rm_opts.channel_group = group;
    rm_opts.channels      = "ch-a";

    fut = pubnub_channel_group_remove_channels(runner->ctx, &rm_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("remove channels failed: %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

static ks_result_t test_channel_groups_delete_group(ks_runner_t* runner)
{
    char                                     group[48] = {0};
    pubnub_res_t                             rc;
    pubnub_channel_group_remove_group_opts_t del_opts =
        PUBNUB_CHANNEL_GROUP_REMOVE_GROUP_OPTS_INIT;
    pubnub_future_t fut;

    cg_name(runner, "del", group, sizeof(group));

    rc = add_channels_to_group(runner, group, "ch-a,ch-b");
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add channels failed: %s", pubnub_res_str(rc));
    }

    del_opts.channel_group = group;

    fut = pubnub_channel_group_remove(runner->ctx, &del_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("delete group failed: %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

static ks_result_t test_channel_groups_subscribe_via_group(ks_runner_t* runner)
{
    char                        group[48] = {0};
    char                        ch[64]    = {0};
    pubnub_entity_t             entity    = NULL;
    pubnub_subscription_t       sub       = NULL;
    pubnub_subscription_opts_t  sub_opts  = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener  = {0};
    pubnub_listener_handle_t    handle    = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;
    pubnub_channel_group_remove_group_opts_t del_opts =
        PUBNUB_CHANNEL_GROUP_REMOVE_GROUP_OPTS_INIT;
    pubnub_future_t fut;

    cg_name(runner, "subg", group, sizeof(group));
    snprintf(ch, sizeof(ch), "iot-ks-%s-cg-sub", runner->run_id);

    rc = add_channels_to_group(runner, group, ch);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add channel to group failed: %s", pubnub_res_str(rc));
    }

    /* Brief delay for server-side propagation. */
    vTaskDelay(pdMS_TO_TICKS(500));

    entity = pubnub_channel_group(runner->ctx, group);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel_group failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscription create failed");
    }

    listener.on_message = on_cg_message;
    handle              = pubnub_subscription_add_listener(sub, &listener);

    s_cg_msg_received = 0;

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        if (PUBNUB_LISTENER_HANDLE_INVALID != handle) {
            pubnub_subscription_remove_listener(sub, handle);
        }
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    wait_subscribe_connected(runner->ctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(runner->ctx)) {
        pubnub_subscription_unsubscribe(sub);
        if (PUBNUB_LISTENER_HANDLE_INVALID != handle) {
            pubnub_subscription_remove_listener(sub, handle);
        }
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscribe did not connect");
    }

    if (!ks_ask_companion(runner,
                          "channel_groups/subscribe_via_group",
                          "publish",
                          ch,
                          "\"group msg\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        pubnub_subscription_unsubscribe(sub);
        if (PUBNUB_LISTENER_HANDLE_INVALID != handle) {
            pubnub_subscription_remove_listener(sub, handle);
        }
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("companion publish failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_cg_msg_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    pubnub_subscription_unsubscribe(sub);
    if (PUBNUB_LISTENER_HANDLE_INVALID != handle) {
        pubnub_subscription_remove_listener(sub, handle);
    }
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(entity);

    /* Clean up the group. */
    del_opts.channel_group = group;
    fut = pubnub_channel_group_remove(runner->ctx, &del_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (!s_cg_msg_received) {
        KS_RETURN_FAIL("no message received via group subscription");
    }

    KS_RETURN_PASS();
}

/* clang-format off */
const ks_test_entry_t ks_channel_groups_tests[] = {
    {"channel_groups/add",                 test_channel_groups_add,                 0},
    {"channel_groups/list",                test_channel_groups_list,                0},
    {"channel_groups/remove",              test_channel_groups_remove,              0},
    {"channel_groups/delete_group",        test_channel_groups_delete_group,        0},
    {"channel_groups/subscribe_via_group", test_channel_groups_subscribe_via_group, 1},
};
/* clang-format on */

const size_t ks_channel_groups_test_count =
    sizeof(ks_channel_groups_tests) / sizeof(ks_channel_groups_tests[0]);

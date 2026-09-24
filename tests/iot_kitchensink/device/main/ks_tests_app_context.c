/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/app_context.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static volatile uint8_t s_obj_event_received;

static void on_app_context_event(const pubnub_subscribe_event_t* event,
                                 void*                           user_data)
{
    (void)event;
    (void)user_data;
    s_obj_event_received = 1;
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

static void pump_subscribe_until(pubnub_context_t*       ctx,
                                 volatile const uint8_t* flag,
                                 uint32_t                timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (0 == *flag) {
        if (esp_timer_get_time() >= deadline) {
            break;
        }
        pubnub_process(ctx);
        vTaskDelay(1);
    }
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

static ks_result_t test_app_context_set_user(ks_runner_t* runner)
{
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;
    pubnub_res_t                    rc;
    pubnub_uuid_metadata_t          result;

    opts.uuid = NULL;
    opts.name = "KS Device";

    fut = pubnub_set_uuid_metadata(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("set uuid metadata failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_set_uuid_metadata_result(fut);
    pubnub_future_release(fut);

    if (NULL == result.id.ptr || 0 == result.id.len) {
        KS_RETURN_FAIL("result id is empty");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_app_context_get_user(ks_runner_t* runner)
{
    pubnub_set_uuid_metadata_opts_t set_opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_get_uuid_metadata_opts_t get_opts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t        fut;
    pubnub_res_t           rc;
    pubnub_uuid_metadata_t result;

    /* Ensure metadata exists. */
    set_opts.uuid = NULL;
    set_opts.name = "KS Device Get";

    fut = pubnub_set_uuid_metadata(runner->ctx, &set_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set uuid metadata failed: %s", pubnub_res_str(rc));
    }

    /* Get metadata. */
    get_opts.uuid = NULL;

    fut = pubnub_get_uuid_metadata(runner->ctx, &get_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("get uuid metadata failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_get_uuid_metadata_result(fut);
    pubnub_future_release(fut);

    if (NULL == result.name.ptr || 0 == result.name.len) {
        KS_RETURN_FAIL("result name is empty");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_app_context_remove_user(ks_runner_t* runner)
{
    pubnub_set_uuid_metadata_opts_t set_opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_remove_uuid_metadata_opts_t rm_opts =
        PUBNUB_REMOVE_UUID_METADATA_OPTS_INIT;
    pubnub_future_t fut;
    pubnub_res_t    rc;

    /* Ensure metadata exists. */
    set_opts.uuid = NULL;
    set_opts.name = "KS Device Rm";

    fut = pubnub_set_uuid_metadata(runner->ctx, &set_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set uuid metadata failed: %s", pubnub_res_str(rc));
    }

    /* Remove metadata. */
    rm_opts.uuid = NULL;

    fut = pubnub_remove_uuid_metadata(runner->ctx, &rm_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("remove uuid metadata failed: %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

static ks_result_t test_app_context_set_channel(ks_runner_t* runner)
{
    char ch[48] = {0};
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t           fut;
    pubnub_res_t              rc;
    pubnub_channel_metadata_t result;

    snprintf(ch, sizeof(ch), "iot-ks-%s-meta", runner->run_id);

    opts.channel = ch;
    opts.name    = "Test Channel";

    fut = pubnub_set_channel_metadata(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("set channel metadata failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_set_channel_metadata_result(fut);
    pubnub_future_release(fut);

    if (NULL == result.id.ptr || 0 == result.id.len) {
        KS_RETURN_FAIL("result id is empty");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_app_context_get_channel(ks_runner_t* runner)
{
    char                               ch[48] = {0};
    pubnub_set_channel_metadata_opts_t set_opts =
        PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_get_channel_metadata_opts_t get_opts =
        PUBNUB_GET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t           fut;
    pubnub_res_t              rc;
    pubnub_channel_metadata_t result;

    snprintf(ch, sizeof(ch), "iot-ks-%s-getm", runner->run_id);

    /* Ensure metadata exists. */
    set_opts.channel = ch;
    set_opts.name    = "Test Get Channel";

    fut = pubnub_set_channel_metadata(runner->ctx, &set_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set channel metadata failed: %s", pubnub_res_str(rc));
    }

    /* Get metadata. */
    get_opts.channel = ch;

    fut = pubnub_get_channel_metadata(runner->ctx, &get_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("get channel metadata failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_get_channel_metadata_result(fut);
    pubnub_future_release(fut);

    if (NULL == result.name.ptr || 0 == result.name.len) {
        KS_RETURN_FAIL("result name is empty");
    }

    KS_RETURN_PASS();
}

/**
 * app_context/uuid_event_from_companion: companion sets UUID metadata
 * for the device UUID. Device subscribes and verifies an app_context
 * event arrives.
 */
static ks_result_t test_app_context_uuid_event_from_companion(ks_runner_t* runner)
{
    char                        ch[48]       = {0};
    char                        payload[256] = {0};
    pubnub_entity_t             entity       = NULL;
    pubnub_subscription_t       sub          = NULL;
    pubnub_subscription_opts_t  sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_listener_handle_t    handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_subscribe_listener_t listener     = {0};
    pubnub_res_t                rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-uuid-ev", runner->run_id);

    entity = pubnub_channel(runner->ctx, CONFIG_PUBNUB_KS_USER_ID);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_app_context = on_app_context_event;
    listener.user_data      = NULL;
    handle                  = pubnub_subscription_add_listener(sub, &listener);

    s_obj_event_received = 0;

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
             "{\"uuid\":\"%s\",\"name\":\"Companion Updated\"}",
             CONFIG_PUBNUB_KS_USER_ID);

    if (!ks_ask_companion(runner,
                          "app_context/uuid_event_from_companion",
                          "set_uuid_metadata",
                          ch,
                          payload,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("ks_ask_companion failed");
    }

    pump_subscribe_until(runner->ctx, &s_obj_event_received, 10000);

    if (0 == s_obj_event_received) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("did not receive app_context event");
    }

    cleanup_sub(&sub, &entity, handle);
    KS_RETURN_PASS();
}

/**
 * app_context/channel_event_from_companion: companion sets channel
 * metadata. Device subscribes and verifies an app_context event
 * arrives.
 */
static ks_result_t test_app_context_channel_event_from_companion(ks_runner_t* runner)
{
    char                        ch[48]       = {0};
    char                        payload[256] = {0};
    pubnub_entity_t             entity       = NULL;
    pubnub_subscription_t       sub          = NULL;
    pubnub_subscription_opts_t  sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_listener_handle_t    handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_subscribe_listener_t listener     = {0};
    pubnub_res_t                rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-meta-ev", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_app_context = on_app_context_event;
    listener.user_data      = NULL;
    handle                  = pubnub_subscription_add_listener(sub, &listener);

    s_obj_event_received = 0;

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
             "{\"channel_id\":\"%s\",\"name\":\"Companion Channel\"}",
             ch);

    if (!ks_ask_companion(runner,
                          "app_context/channel_event_from_companion",
                          "set_channel_metadata",
                          ch,
                          payload,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("ks_ask_companion failed");
    }

    pump_subscribe_until(runner->ctx, &s_obj_event_received, 10000);

    if (0 == s_obj_event_received) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("did not receive app_context event");
    }

    cleanup_sub(&sub, &entity, handle);
    KS_RETURN_PASS();
}

/**
 * app_context/uuid_to_companion: device sets UUID metadata.
 * Companion subscribes and verifies it receives the OBJECT event.
 */
static ks_result_t test_app_context_uuid_to_companion(ks_runner_t* runner)
{
    char                            ch[48]       = {0};
    char                            payload[256] = {0};
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;
    pubnub_res_t                    rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-uuid-tc", runner->run_id);

    snprintf(payload,
             sizeof(payload),
             "{\"object_type\":\"uuid\",\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "app_context/uuid_to_companion",
                                   "subscribe_object_and_verify",
                                   CONFIG_PUBNUB_KS_USER_ID,
                                   payload,
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    opts.uuid = NULL;
    opts.name = "KS Device UUID Test";

    fut = pubnub_set_uuid_metadata(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set uuid metadata failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * app_context/channel_to_companion: device sets channel metadata.
 * Companion subscribes and verifies it receives the OBJECT event.
 */
static ks_result_t test_app_context_channel_to_companion(ks_runner_t* runner)
{
    char ch[48]       = {0};
    char payload[256] = {0};
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t fut;
    pubnub_res_t    rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-ch-tc", runner->run_id);

    snprintf(payload,
             sizeof(payload),
             "{\"object_type\":\"channel\",\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "app_context/channel_to_companion",
                                   "subscribe_object_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    opts.channel = ch;
    opts.name    = "KS Device Channel Test";

    fut = pubnub_set_channel_metadata(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set channel metadata failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * app_context/remove_channel: set channel metadata, then remove it.
 * Verify both operations succeed.
 */
static ks_result_t test_app_context_remove_channel(ks_runner_t* runner)
{
    char                               ch[48] = {0};
    pubnub_set_channel_metadata_opts_t set_opts =
        PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_remove_channel_metadata_opts_t rm_opts =
        PUBNUB_REMOVE_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t fut;
    pubnub_res_t    rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-rmch", runner->run_id);

    /* Ensure metadata exists. */
    set_opts.channel = ch;
    set_opts.name    = "Channel To Remove";

    fut = pubnub_set_channel_metadata(runner->ctx, &set_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set channel metadata failed: %s", pubnub_res_str(rc));
    }

    /* Remove metadata. */
    rm_opts.channel = ch;

    fut = pubnub_remove_channel_metadata(runner->ctx, &rm_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("remove channel metadata failed: %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

/* clang-format off */
const ks_test_entry_t ks_app_context_tests[] = {
    {"app_context/set_user",                       test_app_context_set_user,                       0},
    {"app_context/get_user",                       test_app_context_get_user,                       0},
    {"app_context/remove_user",                    test_app_context_remove_user,                    0},
    {"app_context/set_channel",                    test_app_context_set_channel,                    0},
    {"app_context/get_channel",                    test_app_context_get_channel,                    0},
    {"app_context/uuid_event_from_companion",      test_app_context_uuid_event_from_companion,      1},
    {"app_context/channel_event_from_companion",   test_app_context_channel_event_from_companion,   1},
    {"app_context/uuid_to_companion",              test_app_context_uuid_to_companion,              1},
    {"app_context/channel_to_companion",           test_app_context_channel_to_companion,           1},
    {"app_context/remove_channel",                 test_app_context_remove_channel,                 0},
};
/* clang-format on */

const size_t ks_app_context_test_count =
    sizeof(ks_app_context_tests) / sizeof(ks_app_context_tests[0]);

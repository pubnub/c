/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "ks_protocol.h"

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

#define PRESENCE_TIMEOUT_MS 20000

/** Fire a companion control message without blocking for action_done.
 *  Used when the device needs to start polling for presence events
 *  immediately — blocking for action_done would advance the subscribe
 *  timetoken past the presence event. */
static uint8_t ks_fire_companion(ks_runner_t* runner,
                                 const char*  test_id,
                                 const char*  action,
                                 const char*  channel)
{
    char                  ctrl_ch[48] = {0};
    pubnub_publish_opts_t opts        = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    pubnub_res_t          rc;

    ks_protocol_ctrl_channel(runner->run_id, ctrl_ch, sizeof(ctrl_ch));

    runner->companion_seq_counter++;

    opts.channel = ctrl_ch;
    opts.message = ks_protocol_request_msg(
        test_id, action, channel, NULL, runner->companion_seq_counter);

    fut = pubnub_publish(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    return PUBNUB_OK == rc;
}

static pubnub_context_t* s_sub_ctx;

static volatile uint8_t s_sub_status_connected;
static volatile uint8_t s_sub_msg_received;
static volatile uint8_t s_sub_sig_received;
static volatile uint8_t s_sub_presence_received;
static volatile uint8_t s_sub_ma_received;
static volatile uint8_t s_sub_file_received;
static volatile uint8_t s_sub_obj_received;
static volatile uint8_t s_sub_mc_a_received;
static volatile uint8_t s_sub_mc_b_received;
static char             s_sub_rx_publisher[64];
static char             s_sub_presence_uuid[64];
static int              s_sub_presence_action;
static char             s_sub_changed_channels[256];

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

static void on_status_subscription_changed(const pubnub_subscribe_status_event_t* event,
                                           void* user_data)
{
    size_t copy;
    if (NULL == event) {
        return;
    }
    if (PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED != event->status
        && PUBNUB_SUBSCRIBE_STATUS_CONNECTED != event->status) {
        return;
    }
    if (0 < event->channels.len
        && event->channels.len < sizeof(s_sub_changed_channels)) {
        copy = event->channels.len;
        memcpy(s_sub_changed_channels, event->channels.ptr, copy);
        s_sub_changed_channels[copy] = '\0';
    } else {
        s_sub_changed_channels[0] = '\0';
    }
    *((volatile uint8_t*)user_data) = 1;
}

static int wait_subscription_changed(pubnub_context_t* ctx,
                                     const char*       expected_channel,
                                     uint32_t          timeout_ms)
{
    volatile uint8_t            fired = 0;
    pubnub_subscribe_listener_t lst   = {0};
    pubnub_listener_handle_t    h;

    s_sub_changed_channels[0] = '\0';
    lst.on_status             = on_status_subscription_changed;
    lst.user_data             = (void*)&fired;
    h                         = pubnub_add_listener(ctx, &lst);

    pump_subscribe_until(ctx, &fired, timeout_ms);

    pubnub_remove_listener(ctx, h);

    if (!fired) {
        return 0;
    }

    /* Presence leaves and heartbeats triggered by the subscription change are
     * dispatched in the same SDK tick as EMIT_STATUS.  They occupy slots 1-3
     * while the new subscribe occupies slot 0; any control publish dispatched
     * immediately after would be dropped.  Yield here so the transport task
     * can drive those presence requests to completion before we return.
     * vTaskDelay is safe: on this target the transport runs on its own task. */
    vTaskDelay(pdMS_TO_TICKS(2500));

    return NULL != strstr(s_sub_changed_channels, expected_channel);
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

static void cleanup_ctx_listener(pubnub_context_t*         ctx,
                                 pubnub_listener_handle_t* handle)
{
    if (PUBNUB_LISTENER_HANDLE_INVALID != *handle) {
        pubnub_remove_listener(ctx, *handle);
        *handle = PUBNUB_LISTENER_HANDLE_INVALID;
    }
}

static void on_status_connected(const pubnub_subscribe_status_event_t* event,
                                void* user_data)
{
    (void)user_data;
    if (NULL == event) {
        return;
    }
    if (PUBNUB_SUBSCRIBE_STATUS_CONNECTED == event->status
        || PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED == event->status) {
        s_sub_status_connected = 1;
    }
}

static void on_msg_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    size_t copy;
    (void)user_data;
    if (NULL == event) {
        return;
    }

    copy = event->publisher.len < sizeof(s_sub_rx_publisher) - 1
             ? event->publisher.len
             : sizeof(s_sub_rx_publisher) - 1;
    if (NULL != event->publisher.ptr && 0 < copy) {
        memcpy(s_sub_rx_publisher, event->publisher.ptr, copy);
    }
    s_sub_rx_publisher[copy] = '\0';

    s_sub_msg_received = 1;
}

static void on_sig_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    (void)event;
    s_sub_sig_received = 1;
}

static void on_presence_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    pubnub_subscribe_presence_event_t pres = {0};
    size_t                            copy;
    (void)user_data;
    if (NULL == event || NULL == s_sub_ctx) {
        return;
    }

    if (PUBNUB_OK != pubnub_subscribe_event_presence(s_sub_ctx, event, &pres)) {
        return;
    }

    s_sub_presence_action = (int)pres.action;

    copy = pres.uuid.len < sizeof(s_sub_presence_uuid) - 1
             ? pres.uuid.len
             : sizeof(s_sub_presence_uuid) - 1;
    if (NULL != pres.uuid.ptr && 0 < copy) {
        memcpy(s_sub_presence_uuid, pres.uuid.ptr, copy);
    }
    s_sub_presence_uuid[copy] = '\0';

    s_sub_presence_received = 1;
}

static void on_ma_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    (void)event;
    s_sub_ma_received = 1;
}

static void on_file_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    (void)event;
    s_sub_file_received = 1;
}

static void on_obj_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    (void)event;
    s_sub_obj_received = 1;
}

static void on_mc_flag_store(const pubnub_subscribe_event_t* event, void* user_data)
{
    volatile uint8_t* flag = (volatile uint8_t*)user_data;
    (void)event;
    if (NULL != flag) {
        *flag = 1;
    }
}

static ks_result_t test_subscribe_connected_status(ks_runner_t* runner)
{
    char                        ch[64]     = {0};
    pubnub_entity_t             entity     = NULL;
    pubnub_subscription_t       sub        = NULL;
    pubnub_subscription_opts_t  sub_opts   = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener   = {0};
    pubnub_listener_handle_t    ctx_handle = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_status_connected = 0;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-status", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_status = on_status_connected;
    ctx_handle         = pubnub_add_listener(runner->ctx, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_ctx_listener(runner->ctx, &ctx_handle);
        cleanup_sub(&sub, &entity, PUBNUB_LISTENER_HANDLE_INVALID);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_status_connected, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_ctx_listener(runner->ctx, &ctx_handle);
    cleanup_sub(&sub, &entity, PUBNUB_LISTENER_HANDLE_INVALID);

    if (!s_sub_status_connected) {
        KS_RETURN_FAIL("on_status CONNECTED never fired");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_message_event(ks_runner_t* runner)
{
    char                        ch[64]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_msg_received    = 0;
    s_sub_rx_publisher[0] = '\0';

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-msg", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_message = on_msg_store;
    handle              = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    if (!ks_ask_companion(runner,
                          "subscribe/message_event",
                          "publish",
                          ch,
                          "\"hello sub\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion publish request failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_msg_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_msg_received) {
        KS_RETURN_FAIL("no message received");
    }
    if (NULL == strstr(s_sub_rx_publisher, "ks-companion")) {
        KS_RETURN_FAIL("unexpected publisher: %s", s_sub_rx_publisher);
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_signal_event(ks_runner_t* runner)
{
    char                        ch[64]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_sig_received = 0;
    s_sub_msg_received = 0;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-sig", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_signal  = on_sig_store;
    listener.on_message = on_msg_store;
    handle              = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    if (!ks_ask_companion(runner,
                          "subscribe/signal_event",
                          "signal",
                          ch,
                          "\"sig-test\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion signal request failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_sig_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_sig_received) {
        KS_RETURN_FAIL("signal not received");
    }
    if (s_sub_msg_received) {
        KS_RETURN_FAIL("on_message fired for signal event");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_presence_join_event(ks_runner_t* runner)
{
    char                        ch[64]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_presence_received = 0;
    s_sub_presence_uuid[0]  = '\0';
    s_sub_presence_action   = -1;
    s_sub_ctx               = runner->ctx;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-pjoin", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub_opts.with_presence = 1;
    sub                    = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_presence = on_presence_store;
    handle               = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    /* Step 1: wait for own JOIN — confirms -pnpres subscription is
     * active and delivering presence events before we involve the
     * companion. */
    pump_subscribe_until(runner->ctx, &s_sub_presence_received, PRESENCE_TIMEOUT_MS);
    if (!s_sub_presence_received) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("own JOIN presence event not received");
    }

    /* Step 2: reset and tell companion to subscribe. */
    s_sub_presence_received = 0;
    s_sub_presence_uuid[0]  = '\0';
    s_sub_presence_action   = -1;

    if (!ks_fire_companion(
            runner, "subscribe/presence_join_event", "subscribe_to_channel", ch)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion subscribe request publish failed");
    }

    /* Step 3: wait for companion's JOIN presence event. */
    pump_subscribe_until(runner->ctx, &s_sub_presence_received, PRESENCE_TIMEOUT_MS);

    /* Cleanup: tell companion to unsubscribe. */
    ks_fire_companion(
        runner, "subscribe/presence_join_event", "unsubscribe_from_channel", ch);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_presence_received) {
        KS_RETURN_FAIL("no presence event received");
    }
    if (PUBNUB_PRESENCE_JOIN != (pubnub_presence_action_t)s_sub_presence_action) {
        KS_RETURN_FAIL("expected JOIN, got action=%d", s_sub_presence_action);
    }
    if (NULL == strstr(s_sub_presence_uuid, "ks-companion")) {
        KS_RETURN_FAIL("unexpected uuid: %s", s_sub_presence_uuid);
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_presence_leave_event(ks_runner_t* runner)
{
    char                        ch[64]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_presence_received = 0;
    s_sub_presence_uuid[0]  = '\0';
    s_sub_presence_action   = -1;
    s_sub_ctx               = runner->ctx;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-pleave", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub_opts.with_presence = 1;
    sub                    = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_presence = on_presence_store;
    handle               = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    /* Step 1: wait for own JOIN — confirms pnpres is delivering. */
    pump_subscribe_until(runner->ctx, &s_sub_presence_received, PRESENCE_TIMEOUT_MS);
    if (!s_sub_presence_received) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("own JOIN presence event not received");
    }

    /* Step 2: tell companion to subscribe and wait for its JOIN. */
    s_sub_presence_received = 0;
    s_sub_presence_uuid[0]  = '\0';
    s_sub_presence_action   = -1;

    if (!ks_fire_companion(
            runner, "subscribe/presence_leave_event", "subscribe_to_channel", ch)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion subscribe request publish failed");
    }

    /* Wait for companion JOIN, filtering out own UUID echoes. */
    {
        int64_t deadline =
            esp_timer_get_time() + (int64_t)PRESENCE_TIMEOUT_MS * 1000;
        while (esp_timer_get_time() < deadline) {
            pubnub_process(runner->ctx);
            vTaskDelay(1);
            if (s_sub_presence_received) {
                if (NULL != strstr(s_sub_presence_uuid, CONFIG_PUBNUB_KS_USER_ID)) {
                    s_sub_presence_received = 0;
                    s_sub_presence_uuid[0]  = '\0';
                    continue;
                }
                break;
            }
        }
    }

    if (!s_sub_presence_received
        || PUBNUB_PRESENCE_JOIN != (pubnub_presence_action_t)s_sub_presence_action) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion JOIN not received");
    }

    /* Step 3: wait 5s (server throttles rapid subscribe/unsubscribe),
     * then tell companion to unsubscribe. */
    s_sub_presence_received = 0;
    s_sub_presence_action   = -1;
    s_sub_presence_uuid[0]  = '\0';
    vTaskDelay(pdMS_TO_TICKS(5000));

    if (!ks_fire_companion(
            runner, "subscribe/presence_leave_event", "unsubscribe_from_channel", ch)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion unsubscribe request publish failed");
    }

    /* Step 4: wait for companion's LEAVE presence event. */
    pump_subscribe_until(runner->ctx, &s_sub_presence_received, PRESENCE_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_presence_received) {
        KS_RETURN_FAIL("LEAVE event not received");
    }
    if (PUBNUB_PRESENCE_LEAVE != (pubnub_presence_action_t)s_sub_presence_action) {
        KS_RETURN_FAIL("expected LEAVE, got action=%d", s_sub_presence_action);
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_message_action_event(ks_runner_t* runner)
{
    char                        ch[64]       = {0};
    char                        msg_tt[24]   = {0};
    char                        payload[192] = {0};
    pubnub_entity_t             entity       = NULL;
    pubnub_subscription_t       sub          = NULL;
    pubnub_subscription_opts_t  sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener     = {0};
    pubnub_listener_handle_t    handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_publish_opts_t       pub_opts     = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t             fut;
    pubnub_timetoken_t          tt;
    pubnub_res_t                rc;
    size_t                      copy;

    s_sub_ma_received = 0;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-ma", runner->run_id);

    pub_opts.channel = ch;
    pub_opts.message = "\"action target\"";
    fut              = pubnub_publish(runner->ctx, &pub_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    tt = pubnub_publish_result_timetoken(fut);
    if (NULL == tt.ptr || 0 == tt.len) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("no timetoken from publish");
    }

    copy = tt.len < sizeof(msg_tt) - 1U ? tt.len : sizeof(msg_tt) - 1U;
    memcpy(msg_tt, tt.ptr, copy);
    msg_tt[copy] = '\0';
    pubnub_future_release(fut);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_message_action = on_ma_store;
    handle = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    snprintf(payload,
             sizeof(payload),
             "{\"message_timetoken\":\"%s\","
             "\"action_type\":\"reaction\","
             "\"action_value\":\"thumbs_up\"}",
             msg_tt);

    if (!ks_ask_companion(runner,
                          "subscribe/message_action_event",
                          "add_message_action",
                          ch,
                          payload,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion add_message_action failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_ma_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_ma_received) {
        KS_RETURN_FAIL("message_action event not received");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_file_event(ks_runner_t* runner)
{
    char                        ch[64]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_file_received = 0;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-file", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_file = on_file_store;
    handle           = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    if (!ks_ask_companion(runner,
                          "subscribe/file_event",
                          "upload_file",
                          ch,
                          "{\"file_name\":\"companion_test.txt\","
                          "\"file_content\":"
                          "\"hello from companion\"}",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion upload_file request failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_file_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_file_received) {
        KS_RETURN_FAIL("file event not received");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_object_event(ks_runner_t* runner)
{
    char                        ch[64]       = {0};
    char                        payload[192] = {0};
    pubnub_entity_t             entity       = NULL;
    pubnub_subscription_t       sub          = NULL;
    pubnub_subscription_opts_t  sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener     = {0};
    pubnub_listener_handle_t    handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_obj_received = 0;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-obj", runner->run_id);

    entity = pubnub_channel(runner->ctx, CONFIG_PUBNUB_KS_USER_ID);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_app_context = on_obj_store;
    handle                  = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx,
                                   CONFIG_PUBNUB_KS_USER_ID,
                                   CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    snprintf(payload,
             sizeof(payload),
             "{\"uuid\":\"%s\","
             "\"name\":\"Companion Updated\"}",
             CONFIG_PUBNUB_KS_USER_ID);

    if (!ks_ask_companion(runner,
                          "subscribe/object_event",
                          "set_uuid_metadata",
                          ch,
                          payload,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion set_uuid_metadata failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_obj_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub, &entity, handle);

    if (!s_sub_obj_received) {
        KS_RETURN_FAIL("app_context event not received");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_multiple_channels(ks_runner_t* runner)
{
    char                        ch_a[64]   = {0};
    char                        ch_b[64]   = {0};
    pubnub_entity_t             entity_a   = NULL;
    pubnub_entity_t             entity_b   = NULL;
    pubnub_subscription_t       sub_a      = NULL;
    pubnub_subscription_t       sub_b      = NULL;
    pubnub_subscription_opts_t  sub_opts   = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener_a = {0};
    pubnub_subscribe_listener_t listener_b = {0};
    pubnub_listener_handle_t    handle_a   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_listener_handle_t    handle_b   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sub_mc_a_received = 0;
    s_sub_mc_b_received = 0;

    snprintf(ch_a, sizeof(ch_a), "iot-ks-%s-sub-mc-a", runner->run_id);
    snprintf(ch_b, sizeof(ch_b), "iot-ks-%s-sub-mc-b", runner->run_id);

    entity_a = pubnub_channel(runner->ctx, ch_a);
    entity_b = pubnub_channel(runner->ctx, ch_b);
    if (NULL == entity_a || NULL == entity_b) {
        if (NULL != entity_a) {
            pubnub_entity_destroy(entity_a);
        }
        if (NULL != entity_b) {
            pubnub_entity_destroy(entity_b);
        }
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub_a = pubnub_subscription_create(entity_a, &sub_opts);
    sub_b = pubnub_subscription_create(entity_b, &sub_opts);
    if (NULL == sub_a || NULL == sub_b) {
        cleanup_sub(&sub_a, &entity_a, PUBNUB_LISTENER_HANDLE_INVALID);
        cleanup_sub(&sub_b, &entity_b, PUBNUB_LISTENER_HANDLE_INVALID);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener_a.on_message = on_mc_flag_store;
    listener_a.user_data  = (void*)&s_sub_mc_a_received;
    handle_a = pubnub_subscription_add_listener(sub_a, &listener_a);

    listener_b.on_message = on_mc_flag_store;
    listener_b.user_data  = (void*)&s_sub_mc_b_received;
    handle_b = pubnub_subscription_add_listener(sub_b, &listener_b);

    rc = pubnub_subscription_subscribe(sub_a);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub_a, &entity_a, handle_a);
        cleanup_sub(&sub_b, &entity_b, handle_b);
        KS_RETURN_FAIL("subscribe sub_a failed: %s", pubnub_res_str(rc));
    }

    rc = pubnub_subscription_subscribe(sub_b);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub_a, &entity_a, handle_a);
        cleanup_sub(&sub_b, &entity_b, handle_b);
        KS_RETURN_FAIL("subscribe sub_b failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(
            runner->ctx, ch_b, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub_a, &entity_a, handle_a);
        cleanup_sub(&sub_b, &entity_b, handle_b);
        KS_RETURN_FAIL("subscribe did not settle with channels");
    }

    if (!ks_ask_companion(runner,
                          "subscribe/multiple_channels",
                          "publish",
                          ch_a,
                          "\"msg-a\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub_a, &entity_a, handle_a);
        cleanup_sub(&sub_b, &entity_b, handle_b);
        KS_RETURN_FAIL("companion publish to ch_a failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_mc_a_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (!ks_ask_companion(runner,
                          "subscribe/multiple_channels",
                          "publish",
                          ch_b,
                          "\"msg-b\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub_a, &entity_a, handle_a);
        cleanup_sub(&sub_b, &entity_b, handle_b);
        KS_RETURN_FAIL("companion publish to ch_b failed");
    }

    pump_subscribe_until(
        runner->ctx, &s_sub_mc_b_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sub(&sub_a, &entity_a, handle_a);
    cleanup_sub(&sub_b, &entity_b, handle_b);

    if (!s_sub_mc_a_received) {
        KS_RETURN_FAIL("no message received on channel A");
    }
    if (!s_sub_mc_b_received) {
        KS_RETURN_FAIL("no message received on channel B");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_subscribe_unsubscribe_disconnects(ks_runner_t* runner)
{
    char                       ch[64]   = {0};
    pubnub_entity_t            entity   = NULL;
    pubnub_subscription_t      sub      = NULL;
    pubnub_subscription_opts_t sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_res_t               rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sub-unsub", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, PUBNUB_LISTENER_HANDLE_INVALID);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    if (!wait_subscription_changed(runner->ctx, ch, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, PUBNUB_LISTENER_HANDLE_INVALID);
        KS_RETURN_FAIL("subscribe did not settle with channel");
    }

    rc = pubnub_subscription_unsubscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, PUBNUB_LISTENER_HANDLE_INVALID);
        KS_RETURN_FAIL("unsubscribe failed: %s", pubnub_res_str(rc));
    }

    /* Verify this subscription is no longer in the active list.
     * The global state remains CONNECTED because the companion
     * channel subscription (from setup_companion) stays active. */
    {
        pubnub_subscription_t active[16] = {0};
        size_t                count      = 0;
        size_t                i;
        uint8_t               still_active = 0;

        pubnub_subscriptions(runner->ctx, active, 16, &count);
        for (i = 0; i < count; i++) {
            if (active[i] == sub) {
                still_active = 1;
                break;
            }
        }

        cleanup_sub(&sub, &entity, PUBNUB_LISTENER_HANDLE_INVALID);

        if (still_active) {
            KS_RETURN_FAIL("subscription still active after unsubscribe");
        }
    }
    KS_RETURN_PASS();
}

const ks_test_entry_t ks_subscribe_tests[] = {
    {"subscribe/connected_status",        test_subscribe_connected_status,        0},
    {"subscribe/message_event",           test_subscribe_message_event,           1},
    {"subscribe/signal_event",            test_subscribe_signal_event,            1},
    {"subscribe/presence_join_event",     test_subscribe_presence_join_event,     1},
    {"subscribe/presence_leave_event",    test_subscribe_presence_leave_event,    1},
    {"subscribe/message_action_event",    test_subscribe_message_action_event,    1},
    {"subscribe/file_event",              test_subscribe_file_event,              1},
    {"subscribe/object_event",            test_subscribe_object_event,            1},
    {"subscribe/multiple_channels",       test_subscribe_multiple_channels,       1},
    {"subscribe/unsubscribe_disconnects", test_subscribe_unsubscribe_disconnects, 0},
};

const size_t ks_subscribe_test_count =
    sizeof(ks_subscribe_tests) / sizeof(ks_subscribe_tests[0]);

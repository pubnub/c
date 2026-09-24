/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/signal.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static volatile uint8_t s_sig_rx_signal;
static volatile uint8_t s_sig_rx_message;

static void on_signal_flag(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)event;
    (void)user_data;
    s_sig_rx_signal = 1;
}

static void on_message_flag(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)event;
    (void)user_data;
    s_sig_rx_message = 1;
}

static void pump_sig_until(pubnub_context_t* ctx,
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

static void wait_sig_connected(pubnub_context_t* ctx, uint32_t timeout_ms)
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

static void cleanup_sig_sub(pubnub_subscription_t*   sub,
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

/**
 * signal/send_verified_by_companion: device sends a signal,
 * companion verifies it arrived as a SIGNAL event.
 */
static ks_result_t test_signal_send_verified(ks_runner_t* runner)
{
    char ch[64]              = {0};
    char verify_payload[256] = {0};

    snprintf(ch, sizeof(ch), "iot-ks-%s-sig-sv", runner->run_id);

    snprintf(verify_payload,
             sizeof(verify_payload),
             "{\"event_type\":\"signal\","
             "\"expected_payload\":\"{\\\"t\\\":42}\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "signal/send_verified_by_companion",
                                   "subscribe_and_verify",
                                   ch,
                                   verify_payload,
                                   5000)) {
        KS_RETURN_FAIL("companion READY failed");
    }

    {
        pubnub_signal_opts_t opts = PUBNUB_SIGNAL_OPTS_INIT;
        pubnub_future_t      fut;
        pubnub_res_t         rc;

        opts.channel = ch;
        opts.message = "{\"t\":42}";

        fut = pubnub_signal(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("signal failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * signal/receive_from_companion: device subscribes with on_signal
 * listener; companion sends signal; device verifies on_signal fired
 * and on_message did NOT fire.
 */
static ks_result_t test_signal_receive(ks_runner_t* runner)
{
    char                        ch[64]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_sig_rx_signal  = 0;
    s_sig_rx_message = 0;

    snprintf(ch, sizeof(ch), "iot-ks-%s-sig-rx", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscription_create failed");
    }

    listener.on_signal  = on_signal_flag;
    listener.on_message = on_message_flag;
    handle              = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_sig_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    wait_sig_connected(runner->ctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(runner->ctx)) {
        cleanup_sig_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("subscribe did not connect");
    }

    if (!ks_ask_companion(runner,
                          "signal/receive_from_companion",
                          "signal",
                          ch,
                          "\"companion-sig\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_sig_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion signal request failed");
    }

    pump_sig_until(runner->ctx, &s_sig_rx_signal, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_sig_sub(&sub, &entity, handle);

    if (!s_sig_rx_signal) {
        KS_RETURN_FAIL("on_signal never fired");
    }
    if (s_sig_rx_message) {
        KS_RETURN_FAIL("on_message fired for a signal event");
    }

    KS_RETURN_PASS();
}

/**
 * signal/type_distinction: device sends both a message and a signal
 * on the same channel. Companion verifies the signal arrived as type
 * "signal" (not "message").
 */
static ks_result_t test_signal_type_distinction(ks_runner_t* runner)
{
    char ch[64]              = {0};
    char verify_payload[256] = {0};

    snprintf(ch, sizeof(ch), "iot-ks-%s-sig-td", runner->run_id);

    snprintf(verify_payload,
             sizeof(verify_payload),
             "{\"event_type\":\"signal\","
             "\"expected_payload\":\"{\\\"kind\\\":\\\"sig\\\"}\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "signal/type_distinction",
                                   "subscribe_and_verify",
                                   ch,
                                   verify_payload,
                                   5000)) {
        KS_RETURN_FAIL("companion READY failed");
    }

    /* Publish a message first, then a signal. */
    {
        pubnub_publish_opts_t pub_opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;
        pubnub_res_t          rc;

        pub_opts.channel = ch;
        pub_opts.message = "{\"kind\":\"msg\"}";

        fut = pubnub_publish(runner->ctx, &pub_opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
        }
    }

    {
        pubnub_signal_opts_t sig_opts = PUBNUB_SIGNAL_OPTS_INIT;
        pubnub_future_t      fut;
        pubnub_res_t         rc;

        sig_opts.channel = ch;
        sig_opts.message = "{\"kind\":\"sig\"}";

        fut = pubnub_signal(runner->ctx, &sig_opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("signal failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * signal/too_large: send a signal whose payload exceeds the 64-byte
 * limit and verify the SDK rejects it.
 */
static ks_result_t test_signal_too_large(ks_runner_t* runner)
{
    char                 ch[64] = {0};
    pubnub_signal_opts_t opts   = PUBNUB_SIGNAL_OPTS_INIT;
    pubnub_future_t      fut;
    pubnub_res_t         rc;

    /* 100-byte payload (well over the 64-byte signal limit). */
    const char* big = "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      "aaaaaaaaaaaaaaaaaaaaaa\"";

    snprintf(ch, sizeof(ch), "iot-ks-%s-sig-big", runner->run_id);

    opts.channel = ch;
    opts.message = big;

    fut = pubnub_signal(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    /* Accept any error; the SDK may reject locally or the server
     * may return 400. Either way, it should not be PUBNUB_OK. */
    if (PUBNUB_OK == rc) {
        KS_RETURN_FAIL("expected error for oversized signal");
    }

    KS_RETURN_PASS();
}

const ks_test_entry_t ks_signal_tests[] = {
    {"signal/send_verified_by_companion", test_signal_send_verified,    1},
    {"signal/receive_from_companion",     test_signal_receive,          1},
    {"signal/type_distinction",           test_signal_type_distinction, 1},
    {"signal/too_large",                  test_signal_too_large,        0},
};

const size_t ks_signal_test_count =
    sizeof(ks_signal_tests) / sizeof(ks_signal_tests[0]);

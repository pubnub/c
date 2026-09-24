/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"
#include "pubnub/json.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static volatile uint8_t s_pub_rx_received;
static char             s_pub_rx_payload[128];
static char             s_pub_rx_cmt[64];

static void pub_channel(const ks_runner_t* runner,
                        const char*        suffix,
                        char*              out,
                        size_t             out_len)
{
    snprintf(out, out_len, "iot-ks-%s-pub-%s", runner->run_id, suffix);
}

static void pump_pub_until(pubnub_context_t* ctx,
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

static void wait_pub_connected(pubnub_context_t* ctx, uint32_t timeout_ms)
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

static void on_pub_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    pubnub_context_t*                ctx = (pubnub_context_t*)user_data;
    pubnub_serialization_provider_t* serial;
    size_t                           copy_len;

    if (NULL == event || NULL == event->payload) {
        return;
    }

    serial = pubnub_serialization(ctx);
    if (NULL != serial && NULL != serial->serialize) {
        size_t len = 0;
        (void)serial->serialize(serial,
                                event->payload,
                                (uint8_t*)s_pub_rx_payload,
                                sizeof(s_pub_rx_payload) - 1U,
                                &len);
        s_pub_rx_payload[len] = '\0';
    }

    copy_len = event->custom_message_type.len < sizeof(s_pub_rx_cmt) - 1
                 ? event->custom_message_type.len
                 : sizeof(s_pub_rx_cmt) - 1;
    if (NULL != event->custom_message_type.ptr && 0 < copy_len) {
        memcpy(s_pub_rx_cmt, event->custom_message_type.ptr, copy_len);
    }
    s_pub_rx_cmt[copy_len] = '\0';

    s_pub_rx_received = 1;
}

static void cleanup_pub_sub(pubnub_subscription_t*   sub,
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
 * Helper: subscribe to a channel with an on_message listener, wait
 * for CONNECTED, then ask the companion to publish. Pumps until the
 * listener fires or timeout. Returns 1 on message receipt.
 */
static uint8_t subscribe_and_receive(ks_runner_t* runner,
                                     const char*  test_id,
                                     const char*  action,
                                     const char*  ch,
                                     const char*  companion_payload,
                                     char*        detail,
                                     size_t       detail_len)
{
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    s_pub_rx_received   = 0;
    s_pub_rx_payload[0] = '\0';
    s_pub_rx_cmt[0]     = '\0';

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        snprintf(detail, detail_len, "pubnub_channel failed");
        return 0;
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        snprintf(detail, detail_len, "subscription_create failed");
        return 0;
    }

    listener.on_message = on_pub_message;
    listener.user_data  = runner->ctx;
    handle              = pubnub_subscription_add_listener(sub, &listener);

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        cleanup_pub_sub(&sub, &entity, handle);
        snprintf(detail, detail_len, "subscribe failed: %s", pubnub_res_str(rc));
        return 0;
    }

    wait_pub_connected(runner->ctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(runner->ctx)) {
        cleanup_pub_sub(&sub, &entity, handle);
        snprintf(detail, detail_len, "subscribe did not connect");
        return 0;
    }

    if (!ks_ask_companion(
            runner, test_id, action, ch, companion_payload, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        cleanup_pub_sub(&sub, &entity, handle);
        snprintf(detail, detail_len, "companion %s request failed", action);
        return 0;
    }

    pump_pub_until(runner->ctx, &s_pub_rx_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    cleanup_pub_sub(&sub, &entity, handle);

    if (!s_pub_rx_received) {
        snprintf(detail, detail_len, "no message received");
        return 0;
    }

    return 1;
}

/**
 * publish/text_to_companion: device publishes text, companion verifies.
 */
static ks_result_t test_publish_text_to_companion(ks_runner_t* runner)
{
    char ch[64]              = {0};
    char verify_payload[256] = {0};

    pub_channel(runner, "text", ch, sizeof(ch));

    snprintf(verify_payload,
             sizeof(verify_payload),
             "{\"event_type\":\"message\","
             "\"expected_payload\":\"hello-pub-text\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "publish/text_to_companion",
                                   "subscribe_and_verify",
                                   ch,
                                   verify_payload,
                                   5000)) {
        KS_RETURN_FAIL("companion READY failed");
    }

    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;
        pubnub_res_t          rc;

        opts.channel = ch;
        opts.message = "\"hello-pub-text\"";

        fut = pubnub_publish(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * publish/json_to_companion: device publishes JSON object, companion
 * verifies.
 */
static ks_result_t test_publish_json_to_companion(ks_runner_t* runner)
{
    char ch[64]              = {0};
    char verify_payload[256] = {0};

    pub_channel(runner, "json", ch, sizeof(ch));

    snprintf(verify_payload,
             sizeof(verify_payload),
             "{\"event_type\":\"message\","
             "\"expected_payload\":"
             "\"{\\\"sensor\\\":\\\"dht22\\\",\\\"temp\\\":22.5}\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "publish/json_to_companion",
                                   "subscribe_and_verify",
                                   ch,
                                   verify_payload,
                                   5000)) {
        KS_RETURN_FAIL("companion READY failed");
    }

    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;
        pubnub_res_t          rc;

        opts.channel = ch;
        opts.message = "{\"sensor\":\"dht22\",\"temp\":22.5}";

        fut = pubnub_publish(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * publish/meta_verified: device publishes with meta, companion
 * verifies payload arrived.
 */
static ks_result_t test_publish_meta_verified(ks_runner_t* runner)
{
    char ch[64]              = {0};
    char verify_payload[256] = {0};

    pub_channel(runner, "meta", ch, sizeof(ch));

    snprintf(verify_payload,
             sizeof(verify_payload),
             "{\"event_type\":\"message\","
             "\"expected_payload\":\"meta-test-msg\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "publish/meta_verified",
                                   "subscribe_and_verify",
                                   ch,
                                   verify_payload,
                                   5000)) {
        KS_RETURN_FAIL("companion READY failed");
    }

    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;
        pubnub_res_t          rc;

        opts.channel = ch;
        opts.message = "\"meta-test-msg\"";
        opts.meta    = "{\"region\":\"eu-west\"}";

        fut = pubnub_publish(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("publish with meta failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * publish/custom_type_to_companion: device publishes with
 * custom_message_type, companion verifies it.
 */
static ks_result_t test_publish_custom_type(ks_runner_t* runner)
{
    char ch[64]              = {0};
    char verify_payload[256] = {0};

    pub_channel(runner, "ctype", ch, sizeof(ch));

    snprintf(verify_payload,
             sizeof(verify_payload),
             "{\"event_type\":\"message\","
             "\"expected_payload\":\"type-test\","
             "\"expected_custom_message_type\":\"sensor_reading\","
             "\"timeout_ms\":10000}");

    if (!ks_companion_begin_verify(runner,
                                   "publish/custom_type_to_companion",
                                   "subscribe_and_verify",
                                   ch,
                                   verify_payload,
                                   5000)) {
        KS_RETURN_FAIL("companion READY failed");
    }

    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;
        pubnub_res_t          rc;

        opts.channel             = ch;
        opts.message             = "\"type-test\"";
        opts.custom_message_type = "sensor_reading";

        fut = pubnub_publish(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        KS_RETURN_FAIL("companion verify: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * publish/from_companion_verified: device subscribes, companion
 * publishes text, device verifies receipt.
 */
static ks_result_t test_publish_from_companion(ks_runner_t* runner)
{
    char ch[64]      = {0};
    char detail[128] = {0};

    pub_channel(runner, "from_comp", ch, sizeof(ch));

    if (!subscribe_and_receive(runner,
                               "publish/from_companion_verified",
                               "publish",
                               ch,
                               "\"hello-from-comp\"",
                               detail,
                               sizeof(detail))) {
        KS_RETURN_FAIL("%s", detail);
    }

    if (0 != strcmp(s_pub_rx_payload, "\"hello-from-comp\"")) {
        KS_RETURN_FAIL("payload mismatch: %s", s_pub_rx_payload);
    }

    KS_RETURN_PASS();
}

/**
 * publish/from_companion_json_verified: device subscribes, companion
 * publishes JSON object, device verifies receipt.
 */
static ks_result_t test_publish_from_companion_json(ks_runner_t* runner)
{
    char ch[64]      = {0};
    char detail[128] = {0};

    pub_channel(runner, "from_json", ch, sizeof(ch));

    if (!subscribe_and_receive(runner,
                               "publish/from_companion_json_verified",
                               "publish",
                               ch,
                               "{\"from\":\"companion\",\"seq\":1}",
                               detail,
                               sizeof(detail))) {
        KS_RETURN_FAIL("%s", detail);
    }

    /* Verify we received a non-empty payload. Exact JSON field
     * ordering may vary, so just check it contains "companion". */
    if (NULL == strstr(s_pub_rx_payload, "companion")) {
        KS_RETURN_FAIL("payload missing 'companion': %s", s_pub_rx_payload);
    }

    KS_RETURN_PASS();
}

/**
 * publish/from_companion_with_custom_type: device subscribes,
 * companion publishes with custom_message_type, device verifies the
 * custom_message_type field in the received event.
 */
static ks_result_t test_publish_from_companion_cmt(ks_runner_t* runner)
{
    char ch[64]      = {0};
    char detail[128] = {0};

    pub_channel(runner, "from_cmt", ch, sizeof(ch));

    if (!subscribe_and_receive(runner,
                               "publish/from_companion_with_custom_type",
                               "publish_cmt",
                               ch,
                               "\"cmt-payload\"",
                               detail,
                               sizeof(detail))) {
        KS_RETURN_FAIL("%s", detail);
    }

    if ('\0' == s_pub_rx_cmt[0]) {
        KS_RETURN_FAIL("custom_message_type is empty");
    }

    KS_RETURN_PASS();
}

/**
 * publish/invalid_channel: publish to an empty channel name and
 * verify that the SDK rejects it with a validation error.
 */
static ks_result_t test_publish_invalid_channel(ks_runner_t* runner)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    pubnub_res_t          rc;

    opts.channel = "";
    opts.message = "\"should fail\"";

    fut = pubnub_publish(runner->ctx, &opts);
    rc  = pubnub_future_status(fut);
    pubnub_future_release(fut);

    if (PUBNUB_OK == rc || PUBNUB_IN_PROGRESS == rc) {
        KS_RETURN_FAIL("expected validation error, got %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

const ks_test_entry_t ks_publish_tests[] = {
    {"publish/text_to_companion",               test_publish_text_to_companion,   1},
    {"publish/json_to_companion",               test_publish_json_to_companion,   1},
    {"publish/meta_verified",                   test_publish_meta_verified,       1},
    {"publish/custom_type_to_companion",        test_publish_custom_type,         1},
    {"publish/from_companion_verified",         test_publish_from_companion,      1},
    {"publish/from_companion_json_verified",    test_publish_from_companion_json, 1},
    {"publish/from_companion_with_custom_type", test_publish_from_companion_cmt,  1},
    {"publish/invalid_channel",                 test_publish_invalid_channel,     0},
};

const size_t ks_publish_test_count =
    sizeof(ks_publish_tests) / sizeof(ks_publish_tests[0]);

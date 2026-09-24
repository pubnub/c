/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/presence.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

/* Presence events may be delayed up to one heartbeat interval
   (120s in kitchensink config). 20s timeout is generous enough
   for initial join/leave. */
#define PRES_COMPANION_TIMEOUT_MS 20000

static void pres_channel(const ks_runner_t* runner,
                         const char*        suffix,
                         char*              out,
                         size_t             out_len)
{
    snprintf(out, out_len, "iot-ks-%s-pres-%s", runner->run_id, suffix);
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

static pubnub_context_t* s_hn_ctx;
static volatile uint8_t  s_hn_own_join;

static void on_presence_hn_join(const pubnub_subscribe_event_t* event, void* user_data)
{
    pubnub_subscribe_presence_event_t pres = {0};
    (void)user_data;
    if (NULL == event || NULL == s_hn_ctx) {
        return;
    }
    if (PUBNUB_OK != pubnub_subscribe_event_presence(s_hn_ctx, event, &pres)) {
        return;
    }
    if (PUBNUB_PRESENCE_JOIN != pres.action) {
        return;
    }
    if (0 == pres.uuid.len || NULL == pres.uuid.ptr) {
        return;
    }
    {
        size_t uid_len = strlen(CONFIG_PUBNUB_KS_USER_ID);
        if (pres.uuid.len >= uid_len
            && 0 == memcmp(pres.uuid.ptr, CONFIG_PUBNUB_KS_USER_ID, uid_len)) {
            s_hn_own_join = 1;
        }
    }
}

/**
 * presence/here_now_self: subscribe to a channel with presence,
 * wait for own JOIN event, call here_now, verify own UUID is among
 * occupants.
 */
static ks_result_t test_presence_here_now_self(ks_runner_t* runner)
{
    char                        ch[48]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_here_now_opts_t      opts     = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_here_now_result_t    result;
    pubnub_future_t             fut;
    pubnub_res_t                rc;
    int64_t                     deadline;

    s_hn_own_join = 0;
    s_hn_ctx      = runner->ctx;
    pres_channel(runner, "hn", ch, sizeof(ch));

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

    listener.on_presence = on_presence_hn_join;
    handle               = pubnub_subscription_add_listener(sub, &listener);

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

    /* Wait for own JOIN presence event — confirms presence is registered
     * on the server side before querying here_now. Falls back to 10s
     * timeout if the event is not delivered. */
    deadline = esp_timer_get_time() + (int64_t)10000 * 1000;
    while (!s_hn_own_join && esp_timer_get_time() < deadline) {
        pubnub_process(runner->ctx);
        vTaskDelay(1);
    }

    /* Extra settle after join event for presence propagation. */
    vTaskDelay(pdMS_TO_TICKS(3000));

    opts.channels = ch;

    fut = pubnub_here_now(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("here_now failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_here_now_result(fut);
    pubnub_future_release(fut);
    cleanup_sub(&sub, &entity, handle);

    if (0 == result.total_occupancy) {
        KS_RETURN_FAIL("occupancy is 0, expected > 0");
    }

    KS_RETURN_PASS();
}

/**
 * presence/join_event_at_companion: device subscribes with presence.
 * Companion verifies it receives the device's JOIN event.
 */
static ks_result_t test_presence_join_event_at_companion(ks_runner_t* runner)
{
    char                       ch[48]       = {0};
    char                       payload[192] = {0};
    pubnub_entity_t            entity       = NULL;
    pubnub_subscription_t      sub          = NULL;
    pubnub_subscription_opts_t sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_listener_handle_t   handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t               rc;

    pres_channel(runner, "join", ch, sizeof(ch));

    snprintf(payload,
             sizeof(payload),
             "{\"presence_event\":\"join\","
             "\"expected_uuid\":\"%s\","
             "\"timeout_ms\":20000}",
             CONFIG_PUBNUB_KS_USER_ID);

    if (!ks_companion_begin_verify(runner,
                                   "presence/join_event_at_companion",
                                   "subscribe_presence_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

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

    if (!ks_companion_end_verify(runner, PRES_COMPANION_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion: %s", runner->companion_result_detail);
    }

    cleanup_sub(&sub, &entity, handle);
    KS_RETURN_PASS();
}

/**
 * presence/leave_event_at_companion: device subscribes, then
 * unsubscribes. Companion verifies it receives the LEAVE event.
 */
static ks_result_t test_presence_leave_event_at_companion(ks_runner_t* runner)
{
    char                       ch[48]       = {0};
    char                       payload[192] = {0};
    pubnub_entity_t            entity       = NULL;
    pubnub_subscription_t      sub          = NULL;
    pubnub_subscription_opts_t sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_listener_handle_t   handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t               rc;

    pres_channel(runner, "leave", ch, sizeof(ch));

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

    /* Wait for join to propagate before triggering leave. */
    vTaskDelay(pdMS_TO_TICKS(2000));

    snprintf(payload,
             sizeof(payload),
             "{\"presence_event\":\"leave\","
             "\"expected_uuid\":\"%s\","
             "\"timeout_ms\":20000}",
             CONFIG_PUBNUB_KS_USER_ID);

    if (!ks_companion_begin_verify(runner,
                                   "presence/leave_event_at_companion",
                                   "subscribe_presence_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    /* Unsubscribe triggers the leave event. */
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    sub = NULL;
    pubnub_entity_destroy(entity);
    entity = NULL;

    if (!ks_companion_end_verify(runner, PRES_COMPANION_TIMEOUT_MS)) {
        KS_RETURN_FAIL("companion: %s", runner->companion_result_detail);
    }

    KS_RETURN_PASS();
}

/**
 * presence/set_state_verified: device sets presence state.
 * Companion verifies STATE_CHANGE presence event.
 */
static ks_result_t test_presence_set_state_verified(ks_runner_t* runner)
{
    char                       ch[48]       = {0};
    char                       payload[192] = {0};
    pubnub_entity_t            entity       = NULL;
    pubnub_subscription_t      sub          = NULL;
    pubnub_subscription_opts_t sub_opts     = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_listener_handle_t   handle       = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_set_state_opts_t    state_opts   = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_future_t            fut;
    pubnub_res_t               rc;

    pres_channel(runner, "state", ch, sizeof(ch));

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

    /* Presence registration needs time to propagate before
       the companion can observe state-change events. */
    vTaskDelay(pdMS_TO_TICKS(2000));

    snprintf(payload,
             sizeof(payload),
             "{\"presence_event\":\"state-change\","
             "\"expected_uuid\":\"%s\","
             "\"timeout_ms\":20000}",
             CONFIG_PUBNUB_KS_USER_ID);

    if (!ks_companion_begin_verify(runner,
                                   "presence/set_state_verified",
                                   "subscribe_presence_and_verify",
                                   ch,
                                   payload,
                                   5000)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    state_opts.channels = ch;
    state_opts.state    = "{\"mode\":\"testing\",\"battery\":85}";

    fut = pubnub_set_state(runner->ctx, &state_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("set_state failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, PRES_COMPANION_TIMEOUT_MS)) {
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("companion: %s", runner->companion_result_detail);
    }

    cleanup_sub(&sub, &entity, handle);
    KS_RETURN_PASS();
}

/**
 * presence/get_state: set state, then get_state and verify
 * the server returns at least one channel entry.
 */
static ks_result_t test_presence_get_state(ks_runner_t* runner)
{
    char                      ch[48] = {0};
    pubnub_future_t           fut;
    pubnub_res_t              rc;
    pubnub_set_state_opts_t   set_opts = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_get_state_opts_t   get_opts = PUBNUB_GET_STATE_OPTS_INIT;
    pubnub_get_state_result_t result;

    pres_channel(runner, "gs", ch, sizeof(ch));

    set_opts.channels = ch;
    set_opts.state    = "{\"temp\":42}";

    fut = pubnub_set_state(runner->ctx, &set_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("set_state failed: %s", pubnub_res_str(rc));
    }

    /* Allow state to propagate before querying. */
    vTaskDelay(pdMS_TO_TICKS(1500));

    get_opts.channels = ch;

    fut = pubnub_get_state(runner->ctx, &get_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("get_state failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_get_state_result(fut);
    pubnub_future_release(fut);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("get_state returned 0 channels");
    }

    KS_RETURN_PASS();
}

/**
 * presence/where_now: subscribe to a channel, call where_now,
 * verify our channel appears in the result.
 */
static ks_result_t test_presence_where_now(ks_runner_t* runner)
{
    char                       ch[48]   = {0};
    pubnub_entity_t            entity   = NULL;
    pubnub_subscription_t      sub      = NULL;
    pubnub_subscription_opts_t sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_listener_handle_t   handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_where_now_opts_t    opts     = PUBNUB_WHERE_NOW_OPTS_INIT;
    pubnub_where_now_result_t  result;
    pubnub_future_t            fut;
    pubnub_res_t               rc;

    pres_channel(runner, "wn", ch, sizeof(ch));

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

    /* Presence registration can take 2-5s to propagate. */
    vTaskDelay(pdMS_TO_TICKS(3000));

    fut = pubnub_where_now(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        cleanup_sub(&sub, &entity, handle);
        KS_RETURN_FAIL("where_now failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_where_now_result(fut);
    pubnub_future_release(fut);
    cleanup_sub(&sub, &entity, handle);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("where_now returned 0 channels");
    }

    KS_RETURN_PASS();
}

const ks_test_entry_t ks_presence_tests[] = {
    {"presence/here_now_self",            test_presence_here_now_self,            0},
    {"presence/join_event_at_companion",  test_presence_join_event_at_companion,  1},
    {"presence/leave_event_at_companion", test_presence_leave_event_at_companion, 1},
    {"presence/set_state_verified",       test_presence_set_state_verified,       1},
    {"presence/get_state",                test_presence_get_state,                0},
    {"presence/where_now",                test_presence_where_now,                0},
};

const size_t ks_presence_test_count =
    sizeof(ks_presence_tests) / sizeof(ks_presence_tests[0]);

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/history.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static void hist_channel(const ks_runner_t* runner,
                         const char*        suffix,
                         char*              out,
                         size_t             out_len)
{
    snprintf(out, out_len, "iot-ks-%s-hist-%s", runner->run_id, suffix);
}

/** Publish a message and copy its timetoken into @p tt_buf. */
static pubnub_res_t publish_and_get_tt(ks_runner_t* runner,
                                       const char*  channel,
                                       const char*  message,
                                       char*        tt_buf,
                                       size_t       tt_buf_len)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    pubnub_res_t          rc;
    pubnub_timetoken_t    tt;

    opts.channel = channel;
    opts.message = message;

    fut = pubnub_publish(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK == rc && NULL != tt_buf) {
        tt = pubnub_publish_result_timetoken(fut);
        if (NULL != tt.ptr && 0 != tt.len) {
            size_t copy = tt.len < tt_buf_len - 1 ? tt.len : tt_buf_len - 1;
            memcpy(tt_buf, tt.ptr, copy);
            tt_buf[copy] = '\0';
        } else {
            tt_buf[0] = '\0';
        }
    }

    pubnub_future_release(fut);
    return rc;
}

/**
 * history/fetch_recent: publish a message, wait for persistence,
 * then fetch and verify at least one channel in the result.
 */
static ks_result_t test_history_fetch_recent(ks_runner_t* runner)
{
    char                           ch[48] = {0};
    pubnub_res_t                   rc;
    pubnub_future_t                fut;
    pubnub_fetch_messages_result_t result;
    pubnub_fetch_messages_opts_t   opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    hist_channel(runner, "fr", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, "\"recent test\"", NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    opts.channels = ch;
    opts.count    = 5;

    fut = pubnub_fetch_messages(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("fetch failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_fetch_messages_result(fut);
    pubnub_future_release(fut);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("fetch returned 0 channels");
    }

    KS_RETURN_PASS();
}

/**
 * history/with_timetoken: publish two messages, capture timetokens,
 * then fetch with start bound and verify the result.
 */
static ks_result_t test_history_with_timetoken(ks_runner_t* runner)
{
    char                           ch[48]  = {0};
    char                           tt1[24] = {0};
    pubnub_res_t                   rc;
    pubnub_future_t                fut;
    pubnub_fetch_messages_result_t result;
    pubnub_fetch_messages_opts_t   opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    hist_channel(runner, "tt", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, "\"first\"", tt1, sizeof(tt1));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish 1 failed: %s", pubnub_res_str(rc));
    }

    rc = publish_and_get_tt(runner, ch, "\"second\"", NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish 2 failed: %s", pubnub_res_str(rc));
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    /* Fetch messages from the first message's timetoken onwards.
     * end is an inclusive lower bound: returns messages with
     * timetoken >= tt1, which covers both "first" and "second". */
    opts.channels = ch;
    opts.count    = 5;
    opts.end      = tt1;

    fut = pubnub_fetch_messages(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("fetch with tt failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_fetch_messages_result(fut);
    pubnub_future_release(fut);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("fetch returned 0 channels");
    }

    KS_RETURN_PASS();
}

/**
 * history/count: publish two messages, fetch with count=1, and
 * verify the fetch succeeds.
 */
static ks_result_t test_history_count(ks_runner_t* runner)
{
    char                           ch[48] = {0};
    pubnub_res_t                   rc;
    pubnub_future_t                fut;
    pubnub_fetch_messages_result_t result;
    pubnub_fetch_messages_opts_t   opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    hist_channel(runner, "c1", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, "\"count msg 1\"", NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish 1 failed: %s", pubnub_res_str(rc));
    }

    rc = publish_and_get_tt(runner, ch, "\"count msg 2\"", NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish 2 failed: %s", pubnub_res_str(rc));
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    opts.channels = ch;
    opts.count    = 1;

    fut = pubnub_fetch_messages(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("fetch count=1 failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_fetch_messages_result(fut);
    pubnub_future_release(fut);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("fetch returned 0 channels");
    }

    KS_RETURN_PASS();
}

/**
 * history/message_counts: publish two messages, then verify
 * pubnub_message_counts() reports at least 2.
 */
static ks_result_t test_history_message_counts(ks_runner_t* runner)
{
    char                                   ch[48] = {0};
    pubnub_res_t                           rc;
    pubnub_future_t                        fut;
    pubnub_message_counts_result_t         result;
    pubnub_message_counts_channel_result_t ch_result;
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;

    hist_channel(runner, "mc", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, "\"mc msg 1\"", NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish 1 failed: %s", pubnub_res_str(rc));
    }

    rc = publish_and_get_tt(runner, ch, "\"mc msg 2\"", NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish 2 failed: %s", pubnub_res_str(rc));
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    opts.channels  = ch;
    opts.timetoken = "1";

    fut = pubnub_message_counts(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("message_counts failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_message_counts_result(fut);
    if (0 == result.channel_count) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("message_counts returned 0 channels");
    }

    ch_result = pubnub_message_counts_result_channel_at(fut, 0);
    pubnub_future_release(fut);

    if (ch_result.count < 2) {
        KS_RETURN_FAIL("expected >= 2, got %u", (unsigned)ch_result.count);
    }

    KS_RETURN_PASS();
}

/**
 * history/fetch_with_message_actions: publish a message, add an
 * action, then fetch with include_message_actions=1.
 */
static ks_result_t test_history_fetch_with_message_actions(ks_runner_t* runner)
{
    char                           ch[48]     = {0};
    char                           tt_buf[24] = {0};
    pubnub_res_t                   rc;
    pubnub_future_t                fut;
    pubnub_fetch_messages_result_t result;
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    pubnub_fetch_messages_opts_t fetch_opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    hist_channel(runner, "wa", ch, sizeof(ch));

    rc = publish_and_get_tt(runner, ch, "\"action target\"", tt_buf, sizeof(tt_buf));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("publish failed: %s", pubnub_res_str(rc));
    }

    if ('\0' == tt_buf[0]) {
        KS_RETURN_FAIL("publish returned no timetoken");
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    /* Add a message action. */
    add_opts.channel           = ch;
    add_opts.message_timetoken = tt_buf;
    add_opts.type              = "reaction";
    add_opts.value             = "thumbsup";

    fut = pubnub_add_message_action(runner->ctx, &add_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("add_action failed: %s", pubnub_res_str(rc));
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    /* Fetch with message actions included. */
    fetch_opts.channels                = ch;
    fetch_opts.count                   = 1;
    fetch_opts.include_message_actions = 1;

    fut = pubnub_fetch_messages(runner->ctx, &fetch_opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("fetch_with_actions failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_fetch_messages_result(fut);
    pubnub_future_release(fut);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("fetch returned 0 channels");
    }

    KS_RETURN_PASS();
}

/**
 * history/fetch_companion_message: companion publishes to a
 * channel, device fetches history and verifies the message appears.
 */
static ks_result_t test_history_fetch_companion_message(ks_runner_t* runner)
{
    char                           ch[48] = {0};
    pubnub_res_t                   rc;
    pubnub_future_t                fut;
    pubnub_fetch_messages_result_t result;
    pubnub_fetch_messages_opts_t   opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;

    hist_channel(runner, "comp", ch, sizeof(ch));

    if (!ks_ask_companion(runner,
                          "history/fetch_companion_message",
                          "publish",
                          ch,
                          "\"ks-hist-from-companion\"",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        KS_RETURN_FAIL("companion publish request failed");
    }

    vTaskDelay(pdMS_TO_TICKS(1500));

    opts.channels = ch;
    opts.count    = 5;

    fut = pubnub_fetch_messages(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("fetch failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_fetch_messages_result(fut);
    pubnub_future_release(fut);

    if (0 == result.channel_count) {
        KS_RETURN_FAIL("fetch returned 0 channels");
    }

    KS_RETURN_PASS();
}

const ks_test_entry_t ks_history_tests[] = {
    {"history/fetch_recent",               test_history_fetch_recent,               0},
    {"history/with_timetoken",             test_history_with_timetoken,             0},
    {"history/count",                      test_history_count,                      0},
    {"history/message_counts",             test_history_message_counts,             0},
    {"history/fetch_with_message_actions", test_history_fetch_with_message_actions, 0},
    {"history/fetch_companion_message",    test_history_fetch_companion_message,    1},
};

const size_t ks_history_test_count =
    sizeof(ks_history_tests) / sizeof(ks_history_tests[0]);

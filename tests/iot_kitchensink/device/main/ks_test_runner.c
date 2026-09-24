/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "ks_protocol.h"

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/response.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include <stdio.h>
#include <string.h>
#include <string.h>

#define KS_INTER_TEST_SETTLE_MS             1500U
#define KS_PUBLISH_TRANSPORT_RETRIES        3U
#define KS_PUBLISH_TRANSPORT_RETRY_DELAY_MS 300U

/**
 * @brief Listener callback for messages arriving on the result channel.
 *
 * Serializes the JSON payload back to text, parses it with the
 * companion protocol parser, and updates the runner's companion state.
 */
static void result_listener_on_message(const pubnub_subscribe_event_t* event,
                                       void* user_data)
{
    ks_runner_t*                     r = (ks_runner_t*)user_data;
    pubnub_serialization_provider_t* serial;
    uint8_t                          buf[512];
    size_t                           len = 0;
    pubnub_res_t                     rc;
    ks_msg_t                         msg;

    if (NULL == event || NULL == event->payload) {
        return;
    }

    serial = pubnub_serialization(r->ctx);
    if (NULL == serial || NULL == serial->serialize) {
        return;
    }

    memset(buf, 0, sizeof(buf));
    rc = serial->serialize(serial, event->payload, buf, sizeof(buf) - 1, &len);
    if (PUBNUB_OK != rc || 0 == len) {
        return;
    }
    buf[len] = '\0';

    memset(&msg, 0, sizeof(msg));
    if (0 != ks_protocol_parse((const char*)buf, len, &msg)) {
        return;
    }

    if (KS_MSG_HANDSHAKE_ACK == msg.type) {
        r->companion_handshake_acked = 1;
        printf("[KS] Received handshake ack from companion\n");
    } else if (KS_MSG_READY == msg.type) {
        if (msg.seq == r->companion_current_seq) {
            r->companion_ready = 1;
            printf("[KS] Companion READY (seq=%u)\n", (unsigned)msg.seq);
        }
    } else if (KS_MSG_ACTION_DONE == msg.type || KS_MSG_ACTION_FAIL == msg.type) {
        r->companion_result_pass = msg.pass;
        if ('\0' != msg.detail[0]) {
            memcpy(r->companion_result_detail,
                   msg.detail,
                   sizeof(r->companion_result_detail));
        }
        /* Write seq last so the main loop sees a consistent snapshot. */
        r->companion_result_seq = msg.seq;
    }
}

/**
 * @brief Set up the companion subscription and attempt a handshake.
 *
 * Subscribes to the result channel, publishes a handshake on the
 * control channel, and waits for the companion's ack. Sets
 * r->companion_online accordingly.
 */
static void setup_companion(ks_runner_t* r)
{
    char                        result_ch[48] = {0};
    char                        ctrl_ch[48]   = {0};
    pubnub_subscription_opts_t  sub_opts      = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener      = {0};
    pubnub_res_t                rc;
    int64_t                     deadline;
    const char*                 msg;
    pubnub_publish_opts_t       pub_opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t             fut;

    ks_protocol_result_channel(r->run_id, result_ch, sizeof(result_ch));
    /* Handshake is published to the fixed discovery channel, not the
     * per-run control channel, so the companion can find it without
     * knowing the run_id in advance. */
    ks_protocol_handshake_channel(ctrl_ch, sizeof(ctrl_ch));

    r->result_entity = pubnub_channel(r->ctx, result_ch);
    if (NULL == r->result_entity) {
        printf("[KS] Failed to create result channel entity\n");
        return;
    }

    r->result_sub = pubnub_subscription_create(r->result_entity, &sub_opts);
    if (NULL == r->result_sub) {
        printf("[KS] Failed to create result subscription\n");
        return;
    }

    listener.on_message       = result_listener_on_message;
    listener.user_data        = r;
    r->result_listener_handle = pubnub_add_listener(r->ctx, &listener);

    rc = pubnub_subscription_subscribe(r->result_sub);
    if (PUBNUB_OK != rc) {
        printf("[KS] Subscription subscribe failed: %s\n", pubnub_res_str(rc));
        return;
    }

    /* Pump until the subscribe engine connects or times out. */
    deadline = esp_timer_get_time() + 15000LL * 1000;
    while (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(r->ctx)) {
        if (esp_timer_get_time() >= deadline) {
            printf("[KS] Subscribe connect timed out\n");
            return;
        }
        pubnub_process(r->ctx);
        vTaskDelay(1);
    }

    /* Publish handshake on the control channel. */
    msg = ks_protocol_handshake_msg(r->run_id, CONFIG_PUBNUB_KS_USER_ID);
    pub_opts.channel = ctrl_ch;
    pub_opts.message = msg;

    printf("[KS] Publishing handshake on %s\n", ctrl_ch);
    fut = pubnub_publish(r->ctx, &pub_opts);
    rc = ks_pump_until_ready(r->ctx, fut, CONFIG_PUBNUB_KS_COMPANION_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_string_view_t srv_msg = pubnub_response_error_message(fut);
        if (NULL != srv_msg.ptr && 0 < srv_msg.len) {
            printf("[KS] Handshake publish failed: %s — server: %.*s\n",
                   pubnub_res_str(rc),
                   (int)srv_msg.len,
                   srv_msg.ptr);
        } else {
            printf("[KS] Handshake publish failed: %s\n", pubnub_res_str(rc));
        }
        pubnub_future_release(fut);
        return;
    }
    pubnub_future_release(fut);

    /* Wait for the companion's handshake ack. */
    deadline = esp_timer_get_time()
             + (int64_t)CONFIG_PUBNUB_KS_COMPANION_TIMEOUT_MS * 1000;
    while (!r->companion_handshake_acked) {
        if (esp_timer_get_time() >= deadline) {
            printf("[KS] Companion handshake timed out\n");
            return;
        }
        pubnub_process(r->ctx);
        vTaskDelay(1);
    }

    r->companion_online = 1;
}

/** @brief Tear down the companion subscription and listener. */
static void teardown_companion(ks_runner_t* r)
{
    if (NULL != r->result_sub) {
        pubnub_subscription_unsubscribe(r->result_sub);
        pubnub_subscription_destroy(r->result_sub);
        r->result_sub = NULL;
    }
    if (NULL != r->result_entity) {
        pubnub_entity_destroy(r->result_entity);
        r->result_entity = NULL;
    }
    if (PUBNUB_LISTENER_HANDLE_INVALID != r->result_listener_handle) {
        pubnub_remove_listener(r->ctx, r->result_listener_handle);
        r->result_listener_handle = PUBNUB_LISTENER_HANDLE_INVALID;
    }
}

void ks_runner_init(ks_runner_t*           r,
                    pubnub_context_t*      ctx,
                    const ks_test_entry_t* tests,
                    size_t                 count)
{
    uint32_t seed;

    memset(r, 0, sizeof(*r));
    r->ctx                    = ctx;
    r->tests                  = tests;
    r->test_count             = count;
    r->result_listener_handle = PUBNUB_LISTENER_HANDLE_INVALID;

    /* Generate an 8-hex-char run ID from the low bits of esp_timer. */
    seed = (uint32_t)(esp_timer_get_time() & 0xFFFFFFFFUL);
    snprintf(r->run_id, sizeof(r->run_id), "%08x", (unsigned)seed);
}

static const char* status_label(ks_test_status_t s)
{
    switch (s) {
    case KS_STATUS_PASS: return "PASS";
    case KS_STATUS_FAIL: return "FAIL";
    case KS_STATUS_SKIP: return "SKIP";
    default: return "????";
    }
}

void ks_runner_run_all(ks_runner_t* r)
{
    printf("[KS] === Starting kitchensink run %s (%u tests) ===\n",
           r->run_id,
           (unsigned)r->test_count);

    setup_companion(r);

    if (r->companion_online) {
        printf("[KS] Companion online\n");
    } else {
        printf("[KS] Companion not available; "
               "companion-dependent tests will be skipped\n");
    }

    r->current_idx = 0;
    while (r->current_idx < r->test_count) {
        const ks_test_entry_t* entry  = &r->tests[r->current_idx];
        ks_result_t            result = {0};

        if (0U < r->current_idx) {
            /* Brief settle: presence leave requests need ~500ms each
             * on a fresh TLS connection. Without this, rapid
             * subscribe/unsubscribe cycles accumulate in-flight leaves
             * and can saturate the lwIP socket table. */
            vTaskDelay(pdMS_TO_TICKS(KS_INTER_TEST_SETTLE_MS));
        }

#ifdef KS_TEST_FILTER
        if (NULL == strstr(entry->name, KS_TEST_FILTER)) {
            r->current_idx++;
            continue;
        }
#endif

        printf("[KS] >>> %s\n", entry->name);

        if (entry->needs_companion && !r->companion_online) {
            result.status = KS_STATUS_SKIP;
            snprintf(result.detail, sizeof(result.detail), "%s", "companion not online");
        } else {
            int64_t start_us = esp_timer_get_time();
            int64_t end_us;
            result            = entry->fn(r);
            end_us            = esp_timer_get_time();
            result.elapsed_ms = (uint32_t)((end_us - start_us) / 1000);
        }

        switch (result.status) {
        case KS_STATUS_PASS: r->pass_count++; break;
        case KS_STATUS_FAIL: r->fail_count++; break;
        case KS_STATUS_SKIP: r->skip_count++; break;
        default: r->fail_count++; break;
        }

        if ('\0' != result.detail[0]) {
            printf("[KS] [%s] %s: %s (%u ms)\n",
                   status_label(result.status),
                   entry->name,
                   result.detail,
                   (unsigned)result.elapsed_ms);
        } else {
            printf("[KS] [%s] %s (%u ms)\n",
                   status_label(result.status),
                   entry->name,
                   (unsigned)result.elapsed_ms);
        }

        r->current_idx++;
    }

    teardown_companion(r);
}

void ks_runner_print_summary(const ks_runner_t* r)
{
    printf("[KS] === Summary: %u pass, %u fail, %u skip "
           "(run %s) ===\n",
           (unsigned)r->pass_count,
           (unsigned)r->fail_count,
           (unsigned)r->skip_count,
           r->run_id);
}

pubnub_res_t ks_pump_until_ready(pubnub_context_t* ctx,
                                 pubnub_future_t   fut,
                                 uint32_t          timeout_ms)
{
    int64_t deadline_us = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    while (!pubnub_future_is_ready(fut)) {
        if (esp_timer_get_time() >= deadline_us) {
            return PUBNUB_ERR_TIMEOUT;
        }
        pubnub_process(ctx);
        vTaskDelay(1);
    }

    return pubnub_future_status(fut);
}

uint8_t ks_ask_companion(ks_runner_t* runner,
                         const char*  test_id,
                         const char*  action,
                         const char*  channel,
                         const char*  payload,
                         uint32_t     timeout_ms)
{
    char                  ctrl_ch[48] = {0};
    uint32_t              seq;
    const char*           msg;
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    /* Seeded with TRANSPORT error so the retry while-loop body runs on the
     * first iteration without a special-case before the loop. */
    pubnub_res_t rc       = PUBNUB_ERR_TRANSPORT;
    uint8_t      attempts = 0;
    int64_t      deadline;

    ks_protocol_ctrl_channel(runner->run_id, ctrl_ch, sizeof(ctrl_ch));

    runner->companion_seq_counter++;
    seq = runner->companion_seq_counter;

    /* Clear previous result before publishing. */
    runner->companion_result_seq       = 0;
    runner->companion_result_pass      = 0;
    runner->companion_result_detail[0] = '\0';

    msg = ks_protocol_request_msg(test_id, action, channel, payload, seq);
    opts.channel = ctrl_ch;
    opts.message = msg;

    while ((PUBNUB_ERR_TRANSPORT == rc || PUBNUB_ERR_QUEUE_FULL == rc)
           && attempts <= KS_PUBLISH_TRANSPORT_RETRIES) {
        if (0U != attempts) {
            vTaskDelay(pdMS_TO_TICKS(KS_PUBLISH_TRANSPORT_RETRY_DELAY_MS));
        }
        fut = pubnub_publish(runner->ctx, &opts);
        rc  = ks_pump_until_ready(runner->ctx, fut, timeout_ms);
        pubnub_future_release(fut);
        attempts++;
    }

    if (PUBNUB_OK != rc) {
        printf("[KS] Companion request publish failed: %s\n", pubnub_res_str(rc));
        return 0;
    }

    /* Poll until the companion responds with a matching seq. */
    deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (runner->companion_result_seq != seq) {
        if (esp_timer_get_time() >= deadline) {
            printf("[KS] Companion response timed out (seq=%u)\n", (unsigned)seq);
            return 0;
        }
        pubnub_process(runner->ctx);
        vTaskDelay(1);
    }

    return runner->companion_result_pass;
}

uint8_t ks_companion_begin_verify(ks_runner_t* runner,
                                  const char*  test_id,
                                  const char*  action,
                                  const char*  channel,
                                  const char*  payload,
                                  uint32_t     ready_timeout_ms)
{
    char                  ctrl_ch[48] = {0};
    uint32_t              seq;
    const char*           msg;
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    /* Seeded with TRANSPORT error so the retry while-loop body runs on the
     * first iteration without a special-case before the loop. */
    pubnub_res_t rc       = PUBNUB_ERR_TRANSPORT;
    uint8_t      attempts = 0;
    int64_t      deadline;

    ks_protocol_ctrl_channel(runner->run_id, ctrl_ch, sizeof(ctrl_ch));

    runner->companion_seq_counter++;
    seq                           = runner->companion_seq_counter;
    runner->companion_current_seq = seq;

    /* Clear state for the new two-phase request. */
    runner->companion_ready            = 0;
    runner->companion_result_seq       = 0;
    runner->companion_result_pass      = 0;
    runner->companion_result_detail[0] = '\0';

    msg = ks_protocol_request_msg(test_id, action, channel, payload, seq);
    opts.channel = ctrl_ch;
    opts.message = msg;

    while ((PUBNUB_ERR_TRANSPORT == rc || PUBNUB_ERR_QUEUE_FULL == rc)
           && attempts <= KS_PUBLISH_TRANSPORT_RETRIES) {
        if (0U != attempts) {
            vTaskDelay(pdMS_TO_TICKS(KS_PUBLISH_TRANSPORT_RETRY_DELAY_MS));
        }
        fut = pubnub_publish(runner->ctx, &opts);
        rc  = ks_pump_until_ready(runner->ctx, fut, ready_timeout_ms);
        pubnub_future_release(fut);
        attempts++;
    }

    if (PUBNUB_OK != rc) {
        printf("[KS] begin_verify publish failed: %s\n", pubnub_res_str(rc));
        return 0;
    }

    /* Poll until READY or timeout. */
    deadline = esp_timer_get_time() + (int64_t)ready_timeout_ms * 1000;
    while (!runner->companion_ready) {
        if (esp_timer_get_time() >= deadline) {
            printf("[KS] Companion READY timed out (seq=%u)\n", (unsigned)seq);
            return 0;
        }
        pubnub_process(runner->ctx);
        vTaskDelay(1);
    }

    return 1;
}

uint8_t ks_companion_end_verify(ks_runner_t* runner, uint32_t result_timeout_ms)
{
    uint32_t seq = runner->companion_current_seq;
    int64_t  deadline;

    deadline = esp_timer_get_time() + (int64_t)result_timeout_ms * 1000;
    while (runner->companion_result_seq != seq) {
        if (esp_timer_get_time() >= deadline) {
            printf("[KS] Companion verify result timed out (seq=%u)\n",
                   (unsigned)seq);
            return 0;
        }
        pubnub_process(runner->ctx);
        vTaskDelay(1);
    }

    return runner->companion_result_pass;
}

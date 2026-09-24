/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/files.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void files_channel(const ks_runner_t* runner, char* out, size_t out_len)
{
    snprintf(out, out_len, "iot-ks-%s-files", runner->run_id);
}

/**
 * @brief Upload a small test file, copying result strings to caller buffers.
 *
 * Shared helper for tests that need a file to already exist on the
 * channel before exercising list/download/delete. String data is
 * copied into @p id_out / @p name_out before the future is released,
 * avoiding dangling string_view pointers.
 */
static pubnub_res_t upload_test_file(ks_runner_t* runner,
                                     const char*  ch,
                                     char*        id_out,
                                     size_t       id_cap,
                                     char*        name_out,
                                     size_t       name_cap)
{
    static const uint8_t    data[] = "hello file";
    pubnub_send_file_opts_t opts   = PUBNUB_SEND_FILE_OPTS_INIT;
    pubnub_future_t         fut;
    pubnub_res_t            rc;

    opts.channel   = ch;
    opts.file_name = "test.txt";
    opts.data      = data;
    opts.data_len  = sizeof(data) - 1;

    fut = pubnub_send_file(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK == rc) {
        pubnub_send_file_result_t r = pubnub_send_file_result(fut);
        if (NULL != id_out && NULL != r.id.ptr) {
            size_t c = r.id.len < id_cap - 1U ? r.id.len : id_cap - 1U;
            memcpy(id_out, r.id.ptr, c);
            id_out[c] = '\0';
        }
        if (NULL != name_out && NULL != r.name.ptr) {
            size_t c = r.name.len < name_cap - 1U ? r.name.len : name_cap - 1U;
            memcpy(name_out, r.name.ptr, c);
            name_out[c] = '\0';
        }
    }
    pubnub_future_release(fut);
    return rc;
}

static void wait_sub_connected(pubnub_context_t* ctx, uint32_t timeout_ms)
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

static void pump_until_flag(pubnub_context_t* ctx,
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

static volatile uint8_t s_file_event_received;

static void on_file_event(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    if (NULL == event) {
        return;
    }
    s_file_event_received = 1;
}

static ks_result_t test_files_upload(ks_runner_t* runner)
{
    char         ch[48]        = {0};
    char         file_id[64]   = {0};
    char         file_name[64] = {0};
    pubnub_res_t rc;

    files_channel(runner, ch, sizeof(ch));

    rc = upload_test_file(
        runner, ch, file_id, sizeof(file_id), file_name, sizeof(file_name));

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("send_file failed: %s", pubnub_res_str(rc));
    }
    if ('\0' == file_id[0]) {
        KS_RETURN_FAIL("no file id in result");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_files_list(ks_runner_t* runner)
{
    char                       ch[48] = {0};
    pubnub_res_t               rc;
    pubnub_list_files_result_t result;
    pubnub_future_t            fut;
    pubnub_list_files_opts_t   opts = PUBNUB_LIST_FILES_OPTS_INIT;

    files_channel(runner, ch, sizeof(ch));

    rc = upload_test_file(runner, ch, NULL, 0, NULL, 0);
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("upload for list test failed: %s", pubnub_res_str(rc));
    }

    /* Brief delay for server-side indexing. */
    vTaskDelay(pdMS_TO_TICKS(500));

    opts.channel = ch;

    fut = pubnub_list_files(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("list_files failed: %s", pubnub_res_str(rc));
    }

    result = pubnub_list_files_result(fut);
    pubnub_future_release(fut);

    if (0 == result.count) {
        KS_RETURN_FAIL("expected at least 1 file, got 0");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_files_download(ks_runner_t* runner)
{
    char                          ch[48]        = {0};
    char                          file_id[64]   = {0};
    char                          file_name[64] = {0};
    pubnub_res_t                  rc;
    pubnub_future_t               fut;
    pubnub_download_file_result_t dl;
    pubnub_download_file_opts_t   opts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;

    files_channel(runner, ch, sizeof(ch));

    rc = upload_test_file(
        runner, ch, file_id, sizeof(file_id), file_name, sizeof(file_name));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("upload for download test failed: %s", pubnub_res_str(rc));
    }

    if ('\0' == file_id[0] || '\0' == file_name[0]) {
        KS_RETURN_FAIL("upload result missing id/name");
    }

    opts.channel   = ch;
    opts.file_id   = file_id;
    opts.file_name = file_name;

    fut = pubnub_download_file(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("download failed: %s", pubnub_res_str(rc));
    }

    dl = pubnub_download_file_result(fut);
    if (0 == dl.data_len || NULL == dl.data) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("downloaded data is empty");
    }
    pubnub_future_release(fut);

    KS_RETURN_PASS();
}

static ks_result_t test_files_delete(ks_runner_t* runner)
{
    char                      ch[48]        = {0};
    char                      file_id[64]   = {0};
    char                      file_name[64] = {0};
    pubnub_res_t              rc;
    pubnub_future_t           fut;
    pubnub_delete_file_opts_t opts = PUBNUB_DELETE_FILE_OPTS_INIT;

    files_channel(runner, ch, sizeof(ch));

    rc = upload_test_file(
        runner, ch, file_id, sizeof(file_id), file_name, sizeof(file_name));
    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("upload for delete test failed: %s", pubnub_res_str(rc));
    }

    if ('\0' == file_id[0] || '\0' == file_name[0]) {
        KS_RETURN_FAIL("upload result missing id/name");
    }

    opts.channel   = ch;
    opts.file_id   = file_id;
    opts.file_name = file_name;

    fut = pubnub_delete_file(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("delete failed: %s", pubnub_res_str(rc));
    }

    KS_RETURN_PASS();
}

static ks_result_t test_files_upload_verified_by_companion(ks_runner_t* runner)
{
    char                    ch[48]        = {0};
    char                    file_id[64]   = {0};
    char                    file_name[64] = {0};
    char                    payload[384]  = {0};
    pubnub_send_file_opts_t opts          = PUBNUB_SEND_FILE_OPTS_INIT;
    pubnub_future_t         fut;
    pubnub_res_t            rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-files-uv", runner->run_id);

    opts.channel   = ch;
    opts.file_name = "ks_test.txt";
    opts.data      = (const uint8_t*)"PubNub kitchensink test file content";
    opts.data_len  = strlen("PubNub kitchensink test file content");

    fut = pubnub_send_file(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("send_file failed: %s", pubnub_res_str(rc));
    }

    {
        pubnub_send_file_result_t r = pubnub_send_file_result(fut);
        size_t                    c;

        if (NULL != r.id.ptr) {
            c = r.id.len < sizeof(file_id) - 1U ? r.id.len : sizeof(file_id) - 1U;
            memcpy(file_id, r.id.ptr, c);
            file_id[c] = '\0';
        }
        if (NULL != r.name.ptr) {
            c = r.name.len < sizeof(file_name) - 1U ? r.name.len
                                                    : sizeof(file_name) - 1U;
            memcpy(file_name, r.name.ptr, c);
            file_name[c] = '\0';
        }
    }
    pubnub_future_release(fut);

    if ('\0' == file_id[0] || '\0' == file_name[0]) {
        KS_RETURN_FAIL("upload result missing id/name");
    }

    snprintf(payload,
             sizeof(payload),
             "{\"file_id\":\"%s\","
             "\"file_name\":\"%s\","
             "\"expected_content\":"
             "\"PubNub kitchensink test file content\","
             "\"decrypt\":false}",
             file_id,
             file_name);

    if (!ks_ask_companion(runner,
                          "files/upload_verified_by_companion",
                          "download_and_verify",
                          ch,
                          payload,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        KS_RETURN_FAIL("companion download_and_verify failed");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_files_file_event_verified(ks_runner_t* runner)
{
    char                    ch[48] = {0};
    pubnub_send_file_opts_t opts   = PUBNUB_SEND_FILE_OPTS_INIT;
    pubnub_future_t         fut;
    pubnub_res_t            rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-files-ev", runner->run_id);

    if (!ks_companion_begin_verify(runner,
                                   "files/file_event_verified",
                                   "subscribe_file_and_verify",
                                   ch,
                                   "{\"timeout_ms\":15000}",
                                   5000)) {
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    opts.channel   = ch;
    opts.file_name = "event_test.txt";
    opts.data      = (const uint8_t*)"file event content";
    opts.data_len  = strlen("file event content");

    fut = pubnub_send_file(runner->ctx, &opts);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    pubnub_future_release(fut);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("send_file failed: %s", pubnub_res_str(rc));
    }

    if (!ks_companion_end_verify(runner, 15000)) {
        KS_RETURN_FAIL("companion end_verify failed");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_files_companion_upload_event(ks_runner_t* runner)
{
    char                        ch[48]   = {0};
    pubnub_entity_t             entity   = NULL;
    pubnub_subscription_t       sub      = NULL;
    pubnub_subscription_opts_t  sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    handle   = PUBNUB_LISTENER_HANDLE_INVALID;
    pubnub_res_t                rc;

    snprintf(ch, sizeof(ch), "iot-ks-%s-files-cue", runner->run_id);

    entity = pubnub_channel(runner->ctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("pubnub_channel failed");
    }

    sub = pubnub_subscription_create(entity, &sub_opts);
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("pubnub_subscription_create failed");
    }

    listener.on_file = on_file_event;
    handle           = pubnub_subscription_add_listener(sub, &listener);

    s_file_event_received = 0;

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        pubnub_subscription_remove_listener(sub, handle);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    wait_sub_connected(runner->ctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(runner->ctx)) {
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_remove_listener(sub, handle);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscribe did not connect");
    }

    if (!ks_ask_companion(runner,
                          "files/companion_upload_event",
                          "upload_file",
                          ch,
                          "{\"file_name\":\"companion_upload.txt\","
                          "\"file_content\":\"hello from companion\"}",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_remove_listener(sub, handle);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("companion upload_file failed");
    }

    pump_until_flag(runner->ctx, &s_file_event_received, 15000);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_remove_listener(sub, handle);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(entity);

    if (!s_file_event_received) {
        KS_RETURN_FAIL("file event not received");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_files_download_from_companion(ks_runner_t* runner)
{
    char                          ch[48]        = {0};
    char                          file_id[64]   = {0};
    char                          file_name[64] = {0};
    pubnub_future_t               fut;
    pubnub_res_t                  rc;
    pubnub_list_files_result_t    list_result;
    pubnub_download_file_result_t dl;

    snprintf(ch, sizeof(ch), "iot-ks-%s-files-dlc", runner->run_id);

    if (!ks_ask_companion(runner,
                          "files/download_from_companion",
                          "upload_file",
                          ch,
                          "{\"file_name\":\"for_device.txt\","
                          "\"file_content\":\"download me please\"}",
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        KS_RETURN_FAIL("companion upload_file failed");
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    /* List files on the channel. */
    {
        pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
        opts.channel                  = ch;

        fut = pubnub_list_files(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

        if (PUBNUB_OK != rc) {
            pubnub_future_release(fut);
            KS_RETURN_FAIL("list_files failed: %s", pubnub_res_str(rc));
        }

        list_result = pubnub_list_files_result(fut);
        if (0 == list_result.count) {
            pubnub_future_release(fut);
            KS_RETURN_FAIL("no files found after companion upload");
        }

        {
            pubnub_file_info_t info = pubnub_list_files_result_file_at(fut, 0);
            size_t             c;

            if (NULL != info.id.ptr) {
                c = info.id.len < sizeof(file_id) - 1U ? info.id.len
                                                       : sizeof(file_id) - 1U;
                memcpy(file_id, info.id.ptr, c);
                file_id[c] = '\0';
            }
            if (NULL != info.name.ptr) {
                c = info.name.len < sizeof(file_name) - 1U
                      ? info.name.len
                      : sizeof(file_name) - 1U;
                memcpy(file_name, info.name.ptr, c);
                file_name[c] = '\0';
            }
        }
        pubnub_future_release(fut);
    }

    if ('\0' == file_id[0] || '\0' == file_name[0]) {
        KS_RETURN_FAIL("listed file missing id/name");
    }

    /* Download the file. */
    {
        pubnub_download_file_opts_t opts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
        opts.channel                     = ch;
        opts.file_id                     = file_id;
        opts.file_name                   = file_name;

        fut = pubnub_download_file(runner->ctx, &opts);
        rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

        if (PUBNUB_OK != rc) {
            pubnub_future_release(fut);
            KS_RETURN_FAIL("download failed: %s", pubnub_res_str(rc));
        }

        dl = pubnub_download_file_result(fut);
    }

    if (0 == dl.data_len || NULL == dl.data) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("downloaded data is empty");
    }

    {
        char   tmp[128] = {0};
        size_t copy_len =
            dl.data_len < sizeof(tmp) - 1U ? dl.data_len : sizeof(tmp) - 1U;
        memcpy(tmp, dl.data, copy_len);
        pubnub_future_release(fut);
        if (NULL == strstr(tmp, "download me please")) {
            KS_RETURN_FAIL("downloaded data does not contain expected text");
        }
    }

    KS_RETURN_PASS();
}

const ks_test_entry_t ks_files_tests[] = {
    {"files/upload",                       test_files_upload,                       0},
    {"files/list",                         test_files_list,                         0},
    {"files/download",                     test_files_download,                     0},
    {"files/delete",                       test_files_delete,                       0},
    {"files/upload_verified_by_companion", test_files_upload_verified_by_companion, 1},
    {"files/file_event_verified",          test_files_file_event_verified,          1},
    {"files/companion_upload_event",       test_files_companion_upload_event,       1},
    {"files/download_from_companion",      test_files_download_from_companion,      1},
};

const size_t ks_files_test_count =
    sizeof(ks_files_tests) / sizeof(ks_files_tests[0]);

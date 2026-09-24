/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/send_file_async.c
 * @brief Asynchronous callback-driven file upload.
 *
 * Registers a completion callback via pubnub_async(). On platforms
 * with threading support (PUBNUB_CFG_THREAD_SAFETY=1), this starts a
 * background thread that drives I/O automatically — pubnub_process()
 * becomes a no-op and the main thread simply waits for the callback.
 *
 * On embedded targets without threads, pubnub_async() still registers
 * the callback but does not start a thread. The caller must continue
 * driving pubnub_process() in a loop for the callback to fire.
 *
 * All file operations (list, download, delete, publish_file_message)
 * support the same async pattern shown here.
 *
 * Build: cmake --build build/full --target example_files_send_file_async
 * Run:   ./build/full/examples/files/example_files_send_file_async
 */

// snippet.filesSendFileAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>
#include <string.h>

static volatile int s_done;

static void on_send_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        pubnub_send_file_result_t r = pubnub_send_file_result(future);
        printf("  [callback] Sent OK\n");
        printf("  [callback] id:        %.*s\n", (int)r.id.len, r.id.ptr);
        printf("  [callback] name:      %.*s\n", (int)r.name.len, r.name.ptr);
        printf("  [callback] timetoken: %.*s\n",
               (int)r.timetoken.len,
               r.timetoken.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("  [callback] send_file failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    pubnub_future_release(future);
    s_done = 1;
}

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-send-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Submit the file upload. */
    static const char content[] = "Hello PubNub Files (async)!";

    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = "demo_channel";
    opts.file_name               = "greeting_async.txt";
    opts.data                    = (const uint8_t*)content;
    opts.data_len                = strlen(content);
    opts.content_type            = "text/plain";

    pubnub_future_t fut = pubnub_send_file(ctx, &opts);

    /* 3. Register the async callback. */
    pubnub_res_t rc = pubnub_async(fut, on_send_complete, NULL);
    if (PUBNUB_OK != rc) {
        printf("pubnub_async failed: %s\n", pubnub_res_str(rc));
        pubnub_future_release(fut);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 4. Wait for the callback to fire.
     *    On threaded platforms the background thread drives I/O.
     *    On embedded without threads, replace PUBNUB_EXAMPLE_SLEEP_MS
     *    with pubnub_process(ctx) to drive I/O cooperatively. */
    while (!s_done) {
        PUBNUB_EXAMPLE_SLEEP_MS(50);
    }

    /* 5. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

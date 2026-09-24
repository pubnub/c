/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/send_file.c
 * @brief Upload a file using cooperative polling.
 *
 * See send_file_async.c for the callback-driven variant. Blocking
 * await via pubnub_await() is also supported — see publish/sync.c
 * for the pattern.
 *
 * Build: cmake --build build/full --target example_files_send_file
 * Run:   ./build/full/examples/files/example_files_send_file
 */

// snippet.filesSendFile

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-send";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Send a file to a channel. */
    static const char content[] = "Hello PubNub Files!";

    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = "demo_channel";
    opts.file_name               = "greeting.txt";
    opts.data                    = (const uint8_t*)content;
    opts.data_len                = strlen(content);
    opts.content_type            = "text/plain";

    pubnub_future_t fut = pubnub_send_file(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_send_file_result_t r = pubnub_send_file_result(fut);
        printf("Sent OK\n");
        printf("  id:        %.*s\n", (int)r.id.len, r.id.ptr);
        printf("  name:      %.*s\n", (int)r.name.len, r.name.ptr);
        printf("  timetoken: %.*s\n", (int)r.timetoken.len, r.timetoken.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("send_file failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

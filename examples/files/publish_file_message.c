/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/publish_file_message.c
 * @brief Publish a file message for an already-uploaded file.
 *
 * pubnub_send_file() performs three steps: fetch an upload URL, PUT the
 * bytes to storage, then publish a file message announcing them. This
 * call is only the third step, so use it when the upload already
 * happened and you need to announce it separately.
 *
 * Build: cmake --build build/full --target example_files_publish_file_message
 * Run:   ./build/full/examples/files/example_files_publish_file_message
 */

// snippet.filesPublishFileMessage

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Both keys are required: the file message goes out over publish. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-publish-message";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. The initializer sets store to 1, matching the REST default.
     * file_id and file_name identify the uploaded object; message is the
     * JSON payload subscribers receive alongside it. */
    pubnub_publish_file_message_opts_t opts = PUBNUB_PUBLISH_FILE_MESSAGE_OPTS_INIT;
    opts.channel             = "demo_channel";
    opts.file_id             = "d7d5f0e0-0d1a-4f4c-8b1e-6a9f0c2b3d4e";
    opts.file_name           = "greeting.txt";
    opts.message             = "{\"caption\":\"Q4 report\"}";
    opts.custom_message_type = "file-share";
    opts.ttl                 = 60;

    pubnub_future_t fut = pubnub_publish_file_message(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the publish timetoken. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_publish_file_message_result_t r =
            pubnub_publish_file_message_result(fut);
        printf("File message published at %.*s\n",
               (int)r.timetoken.len,
               r.timetoken.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("publish_file_message failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

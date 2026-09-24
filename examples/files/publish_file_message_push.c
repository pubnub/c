/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/publish_file_message_push.c
 * @brief Trigger a mobile push notification from a file message.
 *
 * A file message is an ordinary published message, so the reserved
 * pn_apns and pn_fcm keys work exactly as they do for pubnub_publish().
 * Put them in the message JSON alongside your own content and PubNub
 * forwards the payload to APNs and FCM.
 *
 * Build: cmake --build build/full --target example_files_publish_file_message_push
 * Run:   ./build/full/examples/files/example_files_publish_file_message_push
 */

// snippet.filesPublishFileMessagePush

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-push";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. pn_apns and pn_fcm sit at the top level of the message JSON,
     * next to your own fields. Devices must already be registered for
     * the channel through pubnub_push_add_channels(). */
    static const char message[] =
        "{\"file\":{\"description\":\"Q4 report\"},"
        "\"pn_apns\":{\"aps\":{\"alert\":\"New file: report.pdf\"}},"
        "\"pn_fcm\":{\"notification\":"
        "{\"title\":\"New file\",\"body\":\"report.pdf\"}}}";

    pubnub_publish_file_message_opts_t opts = PUBNUB_PUBLISH_FILE_MESSAGE_OPTS_INIT;
    opts.channel   = "demo_channel";
    opts.file_id   = "d7d5f0e0-0d1a-4f4c-8b1e-6a9f0c2b3d4e";
    opts.file_name = "report.pdf";
    opts.message   = message;

    pubnub_future_t fut = pubnub_publish_file_message(ctx, &opts);

    /* 2. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    if (PUBNUB_OK == pubnub_future_status(fut)) {
        printf("Published with a push payload.\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("publish_file_message failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 3. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

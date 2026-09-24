/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/push/publish_with_payload.c
 * @brief Publish a message carrying APNs and FCM push payloads.
 *
 * There is no dedicated push-publish call. Mobile push is triggered by
 * the reserved pn_apns and pn_fcm keys inside an ordinary published
 * message. PubNub strips them before delivering the message to
 * subscribers and forwards their contents to the gateways.
 *
 * Devices only receive the notification if they were registered for the
 * channel with pubnub_push_add_channels() first (see add_channels.c).
 *
 * Build: cmake --build build/full --target example_push_publish_with_payload
 * Run:   ./build/full/examples/push/example_push_publish_with_payload
 */

// snippet.pushPublishWithPayload

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-push-publish";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. pn_apns follows the APNs aps structure. pn_fcm follows the FCM
     * message structure. Everything outside those two keys is your own
     * payload and reaches subscribers unchanged. */
    static const char message[] =
        "{\"text\":\"Sensor 4 offline\","
        "\"pn_apns\":{\"aps\":{\"alert\":\"Sensor 4 offline\",\"badge\":1,"
        "\"sound\":\"default\"}},"
        "\"pn_fcm\":{\"notification\":{\"title\":\"Alert\","
        "\"body\":\"Sensor 4 offline\"},\"data\":{\"sensor\":\"4\"}}}";

    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = "alerts";
    opts.message               = message;
    opts.custom_message_type   = "alert";

    pubnub_future_t fut = pubnub_publish(ctx, &opts);

    /* 2. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        printf("Published with push payloads at %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("publish failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    /* 3. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

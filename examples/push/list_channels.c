/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/push/list_channels.c
 * @brief List channels registered for push using cooperative polling.
 *
 * Build: cmake --build build/full --target example_push_list_channels
 * Run:   ./build/full/examples/push/example_push_list_channels
 */

// snippet.pushListChannels

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-push-list";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. List channels registered for push on this device. */
    pubnub_future_t fut =
        pubnub_push_list_channels(ctx,
                                  &(pubnub_push_list_channels_opts_t){
                                      .device  = "dXh7YzE:APA91bGExample",
                                      .gateway = PUBNUB_PUSH_FCM,
                                  });

    /* 3. Cooperative poll: drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result and iterate channels. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_push_list_channels_result_t result =
            pubnub_push_list_channels_result(fut);
        printf("Registered channels (%u):\n", result.channel_count);
        for (uint32_t i = 0; i < result.channel_count; ++i) {
            pubnub_string_view_t ch =
                pubnub_push_list_channels_result_channel_at(fut, (size_t)i);
            printf("  %.*s\n", (int)ch.len, ch.ptr);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

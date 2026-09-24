/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/push/remove_channels.c
 * @brief Unregister device from push channels using cooperative polling.
 *
 * Build: cmake --build build/full --target example_push_remove_channels
 * Run:   ./build/full/examples/push/example_push_remove_channels
 */

// snippet.pushRemoveChannels

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-push-remove";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Remove channels from push on this device (APNS2). */
    pubnub_future_t fut =
        pubnub_push_remove_channels(ctx,
                                    &(pubnub_push_remove_channels_opts_t){
                                        .device   = "apns-hex-device-token",
                                        .gateway  = PUBNUB_PUSH_APNS2,
                                        .channels = "alerts",
                                        .topic    = "com.example.myapp",
                                        .environment = PUBNUB_PUSH_ENV_PRODUCTION,
                                    });

    /* 3. Cooperative poll: drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        printf("Channels removed from push OK\n");
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

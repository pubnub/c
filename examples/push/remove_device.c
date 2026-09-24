/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/push/remove_device.c
 * @brief Remove device from all push channels using cooperative polling.
 *
 * Build: cmake --build build/full --target example_push_remove_device
 * Run:   ./build/full/examples/push/example_push_remove_device
 */

// snippet.pushRemoveDevice

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-push-remove-device";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Remove device from all push channels. */
    pubnub_future_t fut =
        pubnub_push_remove_device(ctx,
                                  &(pubnub_push_remove_device_opts_t){
                                      .device  = "dXh7YzE:APA91bGExample",
                                      .gateway = PUBNUB_PUSH_FCM,
                                  });

    /* 3. Cooperative poll: drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        printf("Device removed from all push channels OK\n");
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

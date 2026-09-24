/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/publish/cooperative.c
 * @brief Publish a single message using cooperative polling.
 *
 * Demonstrates the "caller owns the thread" pattern: submit a publish,
 * then drive I/O with pubnub_process() until the future is ready.
 *
 * Build: cmake --build build/full --target example_publish_cooperative
 * Run:   ./build/full/examples/publish/example_publish_cooperative
 */

// snippet.publishCooperative

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-cooperative";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Start a publish — returns a future immediately. */
    pubnub_future_t fut = pubnub_publish(ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = "demo_channel",
                                             .message = "\"hello from C\"",
                                         });

    /* 3. Cooperative poll: drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        printf("Published OK, timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Publish failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

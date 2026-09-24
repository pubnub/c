/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/time/cooperative.c
 * @brief Fetch PubNub server time using cooperative polling.
 *
 * Demonstrates the "caller owns the thread" pattern: submit a time
 * request, then drive I/O with pubnub_process() until the future is
 * ready.
 *
 * All time calls also support blocking await (pubnub_await) and
 * async callback (pubnub_async) completion styles.
 *
 * Build: cmake --build build/full --target example_time_cooperative
 * Run:   ./build/full/examples/time/example_time_cooperative
 */

// snippet.timeCooperative

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-time-cooperative";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Request server time. */
    pubnub_future_t fut = pubnub_time(ctx);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Process result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
        printf("Server time: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Time request failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

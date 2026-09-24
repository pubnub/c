/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/signal/cooperative.c
 * @brief Send a signal using cooperative polling.
 *
 * Demonstrates the "caller owns the thread" pattern: submit a signal,
 * then drive I/O with pubnub_process() until the future is ready.
 *
 * All signal calls also support blocking await (pubnub_await) and
 * async callback (pubnub_async) completion styles.
 *
 * Build: cmake --build build/full --target example_signal_cooperative
 * Run:   ./build/full/examples/signal/example_signal_cooperative
 */

// snippet.signalCooperative

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-signal-cooperative";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build and submit the signal request. */
    pubnub_signal_opts_t opts = PUBNUB_SIGNAL_OPTS_INIT;
    opts.channel              = "typing-indicator";
    opts.message              = "{\"typing\":true}";

    pubnub_future_t fut = pubnub_signal(ctx, &opts);

    /* 3. Wait for the response. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read and print the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_timetoken_t tt = pubnub_signal_result_timetoken(fut);
        printf("Signal sent, timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Signal failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

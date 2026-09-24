/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/presence/set_state.c
 * @brief Set presence state using a raw JSON string.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see here_now_async.c and publish/sync.c for those patterns.
 *
 * Build: cmake --build build/full --target example_presence_set_state
 * Run:   ./build/full/examples/presence/example_presence_set_state
 */

// snippet.presenceSetState

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-set-state";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Set presence state with a raw JSON string. */
    pubnub_set_state_opts_t opts = PUBNUB_SET_STATE_OPTS_INIT;
    opts.channels                = "demo_channel";
    opts.state                   = "{\"mood\":\"happy\",\"score\":42}";

    pubnub_future_t fut = pubnub_set_state(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the confirmed state. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_set_state_result_t        r      = pubnub_set_state_result(fut);
        pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
        if (NULL != r.state && NULL != serial) {
            char buf[256];
            pubnub_json_to_debug_string(serial, r.state, buf, sizeof(buf));
            printf("State set: %s\n", buf);
        } else {
            printf("State set (no echo)\n");
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("set_state failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

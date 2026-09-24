/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/presence/get_state.c
 * @brief Retrieve presence state for a user on channels.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see here_now_async.c and publish/sync.c for those patterns.
 *
 * Build: cmake --build build/full --target example_presence_get_state
 * Run:   ./build/full/examples/presence/example_presence_get_state
 */

// snippet.presenceGetState

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-get-state";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Get state for a user on multiple channels. */
    pubnub_get_state_opts_t opts = PUBNUB_GET_STATE_OPTS_INIT;
    opts.channels                = "ch1,ch2";
    opts.uuid                    = "target-user-42";

    pubnub_future_t fut = pubnub_get_state(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the per-channel state. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_get_state_result_t        r      = pubnub_get_state_result(fut);
        pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
        for (size_t i = 0; i < r.channel_count; ++i) {
            pubnub_get_state_channel_result_t entry =
                pubnub_get_state_result_channel_at(fut, i);
            printf("  %.*s => ", (int)entry.channel.len, entry.channel.ptr);
            if (NULL != entry.state) {
                char buf[256];
                pubnub_json_to_debug_string(serial, entry.state, buf, sizeof(buf));
                printf("%s", buf);
            } else {
                printf("(none)");
            }
            printf("\n");
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("get_state failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

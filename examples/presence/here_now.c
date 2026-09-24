/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/presence/here_now.c
 * @brief Query channel occupancy using cooperative polling.
 *
 * See here_now_async.c for the callback-driven variant. Blocking
 * await via pubnub_await() is also supported — see publish/sync.c
 * for the pattern.
 *
 * Build: cmake --build build/full --target example_presence_here_now
 * Run:   ./build/full/examples/presence/example_presence_here_now
 */

// snippet.presenceHereNow

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-here-now";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Query presence on a channel. */
    pubnub_here_now_opts_t opts = PUBNUB_HERE_NOW_OPTS_INIT;
    opts.channels               = "demo_channel";
    opts.include_state          = 1;

    pubnub_future_t fut = pubnub_here_now(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_here_now_result_t r = pubnub_here_now_result(fut);
        printf("Total occupancy: %u\n", r.total_occupancy);

        for (size_t i = 0; i < r.channel_count; ++i) {
            pubnub_here_now_channel_result_t ch =
                pubnub_here_now_result_channel_at(fut, i);
            printf("  %.*s: %u occupants\n", (int)ch.name.len, ch.name.ptr, ch.occupancy);

            for (size_t j = 0; j < ch.occupant_count; ++j) {
                pubnub_here_now_occupant_result_t occ =
                    pubnub_here_now_result_occupant_at(fut, i, j);
                printf("    uuid: %.*s", (int)occ.uuid.len, occ.uuid.ptr);
                if (NULL != occ.state.ptr) {
                    printf("  state: %.*s", (int)occ.state.len, occ.state.ptr);
                }
                printf("\n");
            }
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("here_now failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

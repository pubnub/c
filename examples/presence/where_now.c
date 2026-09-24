/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/presence/where_now.c
 * @brief Query which channels a user is present on.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see here_now_async.c and publish/sync.c for those patterns.
 *
 * Build: cmake --build build/full --target example_presence_where_now
 * Run:   ./build/full/examples/presence/example_presence_where_now
 */

// snippet.presenceWhereNow

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-where-now";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Query channels for a specific user (NULL = own user_id). */
    pubnub_where_now_opts_t opts = PUBNUB_WHERE_NOW_OPTS_INIT;
    opts.uuid                    = "target-user-42";

    pubnub_future_t fut = pubnub_where_now(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_where_now_result_t r = pubnub_where_now_result(fut);
        printf("User is on %u channel(s):\n", r.channel_count);
        for (size_t i = 0; i < r.channel_count; ++i) {
            pubnub_string_view_t ch = pubnub_where_now_result_channel_at(fut, i);
            printf("  %.*s\n", (int)ch.len, ch.ptr);
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("where_now failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

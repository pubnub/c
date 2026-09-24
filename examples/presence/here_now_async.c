/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/presence/here_now_async.c
 * @brief Asynchronous callback-driven here-now query.
 *
 * Registers a completion callback via pubnub_async(). On platforms
 * with threading support (PUBNUB_CFG_THREAD_SAFETY=1), this starts a
 * background thread that drives I/O automatically — pubnub_process()
 * becomes a no-op and the main thread simply waits for the callback.
 *
 * On embedded targets without threads, pubnub_async() still registers
 * the callback but does not start a thread. The caller must continue
 * driving pubnub_process() in a loop for the callback to fire.
 *
 * All presence operations (where_now, set_state, get_state) support
 * the same async pattern shown here.
 *
 * Build: cmake --build build/full --target example_presence_here_now_async
 * Run:   ./build/full/examples/presence/example_presence_here_now_async
 */

// snippet.presenceHereNowAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>

static volatile int s_done;

static void on_here_now_complete(pubnub_future_t future,
                                 pubnub_res_t    status,
                                 void*           user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        pubnub_here_now_result_t r = pubnub_here_now_result(future);
        printf("  [callback] Total occupancy: %u\n", r.total_occupancy);

        for (size_t i = 0; i < r.channel_count; ++i) {
            pubnub_here_now_channel_result_t ch =
                pubnub_here_now_result_channel_at(future, i);
            printf("  [callback] %.*s: %u occupants\n",
                   (int)ch.name.len,
                   ch.name.ptr,
                   ch.occupancy);

            for (size_t j = 0; j < ch.occupant_count; ++j) {
                pubnub_here_now_occupant_result_t occ =
                    pubnub_here_now_result_occupant_at(future, i, j);
                printf("    uuid: %.*s", (int)occ.uuid.len, occ.uuid.ptr);
                if (NULL != occ.state.ptr) {
                    printf("  state: %.*s", (int)occ.state.len, occ.state.ptr);
                }
                printf("\n");
            }
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("  [callback] here_now failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    pubnub_future_release(future);
    s_done = 1;
}

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-here-now-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Submit the here-now query. */
    pubnub_here_now_opts_t opts = PUBNUB_HERE_NOW_OPTS_INIT;
    opts.channels               = "demo_channel";
    opts.include_state          = 1;

    pubnub_future_t fut = pubnub_here_now(ctx, &opts);

    /* 3. Register the async callback. */
    pubnub_res_t rc = pubnub_async(fut, on_here_now_complete, NULL);
    if (PUBNUB_OK != rc) {
        printf("pubnub_async failed: %s\n", pubnub_res_str(rc));
        pubnub_future_release(fut);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 4. Wait for the callback to fire.
     *    On threaded platforms the background thread drives I/O.
     *    On embedded without threads, replace PUBNUB_EXAMPLE_SLEEP_MS
     *    with pubnub_process(ctx) to drive I/O cooperatively. */
    while (!s_done) {
        PUBNUB_EXAMPLE_SLEEP_MS(50);
    }

    /* 5. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

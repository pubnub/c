/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/get_message_actions_async.c
 * @brief Fetch message actions using async callback.
 *
 * Registers a completion callback via pubnub_async(). On platforms
 * with threading support (PUBNUB_CFG_THREAD_SAFETY=1), this starts a
 * background thread that drives I/O automatically.
 *
 * On embedded targets without threads, pubnub_async() registers the
 * callback but does not start a thread. The caller must continue
 * driving pubnub_process() in a loop for the callback to fire.
 *
 * All message_actions operations support this pattern.
 *
 * Build: cmake --build build/full --target example_message_actions_get_message_actions_async
 * Run: ./build/full/examples/message_actions/example_message_actions_get_message_actions_async
 */

// snippet.messageActionsGetMessageActionsAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>

static volatile int s_done;

static void on_get_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        pubnub_get_message_actions_result_t r =
            pubnub_get_message_actions_result(future);
        printf("  [callback] Got %u actions\n", r.count);

        for (uint32_t i = 0; i < r.count; ++i) {
            pubnub_message_action_t a =
                pubnub_get_message_actions_result_action_at(future, i);
            printf("    [%u] %.*s: %.*s (by %.*s)\n",
                   i,
                   (int)a.type.len,
                   a.type.ptr,
                   (int)a.value.len,
                   a.value.ptr,
                   (int)a.uuid.len,
                   a.uuid.ptr);
        }

        if (r.has_more) {
            printf("  [callback] More pages available (start=%.*s)\n",
                   (int)r.more_start.len,
                   r.more_start.ptr);
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("  [callback] get_message_actions failed: %s (%.*s)\n",
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
    cfg.user_id         = "example-get-actions-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Submit the get request. */
    pubnub_get_message_actions_opts_t opts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    opts.channel = "demo_channel";
    opts.limit   = 5;

    pubnub_future_t fut = pubnub_get_message_actions(ctx, &opts);

    /* 3. Register the async callback. */
    pubnub_res_t rc = pubnub_async(fut, on_get_complete, NULL);
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

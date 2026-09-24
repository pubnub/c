/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/add_message_action_blocking.c
 * @brief Add a message action with blocking await.
 *
 * pubnub_await() drives pubnub_process() internally and returns the final
 * pubnub_res_t, so the caller writes no polling loop. It is the shortest
 * of the three completion styles and the right one when the calling
 * thread has nothing else to do. See add_message_action.c for cooperative
 * polling and get_message_actions_async.c for the callback style.
 *
 * Build: cmake --build build/full --target example_message_actions_add_message_action_blocking
 * Run: ./build/full/examples/message_actions/example_message_actions_add_message_action_blocking
 */

// snippet.messageActionsAddMessageActionBlocking

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.publish_key     = "demo";
    cfg.user_id         = "example-add-action-blocking";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Add a reaction to the message at that publish timetoken. */
    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = "demo_channel";
    opts.message_timetoken                = "15610547826969050";
    opts.type                             = "reaction";
    opts.value                            = "thumbs_up";

    pubnub_future_t fut = pubnub_add_message_action(ctx, &opts);

    /* 3. Block until the operation finishes. No pubnub_process() loop is
     * needed and no pubnub_future_is_ready() check either: the return
     * value is the final status. */
    const pubnub_res_t status = pubnub_await(fut);

    /* 4. Read the result. */
    if (PUBNUB_OK == status) {
        const pubnub_add_message_action_result_t r =
            pubnub_add_message_action_result(fut);
        printf("Action added at %.*s\n",
               (int)r.action.action_timetoken.len,
               r.action.action_timetoken.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("add_message_action failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    /* 5. Cleanup. Releasing the future invalidates every string view it
     * handed out. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/remove_message_action.c
 * @brief Remove a message action using cooperative polling.
 *
 * Demonstrates removing an action by specifying the channel, parent
 * message timetoken, and the action's own timetoken. Only the user
 * who originally added the action may remove it.
 *
 * Build: cmake --build build/full --target example_message_actions_remove_message_action
 * Run: ./build/full/examples/message_actions/example_message_actions_remove_message_action
 */

// snippet.messageActionsRemoveMessageAction

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.publish_key     = "demo";
    cfg.user_id         = "example-remove-action";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Remove a specific action. */
    pubnub_remove_message_action_opts_t opts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;
    opts.channel           = "demo_channel";
    opts.message_timetoken = "15610547826969050";
    opts.action_timetoken  = "15610547826970050";

    pubnub_future_t fut = pubnub_remove_message_action(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check status. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        printf("Action removed successfully.\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("remove_message_action failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

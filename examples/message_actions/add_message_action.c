/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/add_message_action.c
 * @brief Add a message action using cooperative polling.
 *
 * Demonstrates adding a "reaction" type action with value "thumbs_up"
 * to a specific message on a channel.
 *
 * Build: cmake --build build/full --target example_message_actions_add_message_action
 * Run: ./build/full/examples/message_actions/example_message_actions_add_message_action
 */

// snippet.messageActionsAddMessageAction

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.publish_key     = "demo";
    cfg.user_id         = "example-add-action";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Add a reaction to a message. */
    pubnub_add_message_action_opts_t opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    opts.channel                          = "demo_channel";
    opts.message_timetoken                = "15610547826969050";
    opts.type                             = "reaction";
    opts.value                            = "thumbs_up";

    pubnub_future_t fut = pubnub_add_message_action(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_add_message_action_result_t r =
            pubnub_add_message_action_result(fut);
        printf("Action added successfully.\n");
        printf("  type:              %.*s\n",
               (int)r.action.type.len,
               r.action.type.ptr);
        printf("  value:             %.*s\n",
               (int)r.action.value.len,
               r.action.value.ptr);
        printf("  uuid:              %.*s\n",
               (int)r.action.uuid.len,
               r.action.uuid.ptr);
        printf("  action_timetoken:  %.*s\n",
               (int)r.action.action_timetoken.len,
               r.action.action_timetoken.ptr);
        printf("  message_timetoken: %.*s\n",
               (int)r.action.message_timetoken.len,
               r.action.message_timetoken.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("add_message_action failed: %s (%.*s)\n",
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

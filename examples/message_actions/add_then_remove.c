/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/add_then_remove.c
 * @brief Chain an add result into a remove.
 *
 * Removing an action needs the action_timetoken the server assigned when
 * the action was added. That value lives in future-owned memory, so it
 * has to be copied out before pubnub_future_release() invalidates it.
 * Getting that ordering wrong is the usual bug here.
 *
 * Build: cmake --build build/full --target example_message_actions_add_then_remove
 * Run: ./build/full/examples/message_actions/example_message_actions_add_then_remove
 */

// snippet.messageActionsAddThenRemove

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <string.h>

/* Timetokens are 17 digits, so 24 bytes covers the value plus a NUL. */
#define TIMETOKEN_CAPACITY 24

int main(void)
{
    const char* channel           = "demo_channel";
    const char* message_timetoken = "15610547826969050";

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.publish_key     = "demo";
    cfg.user_id         = "example-add-then-remove";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. Add the action. */
    pubnub_add_message_action_opts_t add_opts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    add_opts.channel           = channel;
    add_opts.message_timetoken = message_timetoken;
    add_opts.type              = "reaction";
    add_opts.value             = "thumbs_up";

    pubnub_future_t    add_fut = pubnub_add_message_action(ctx, &add_opts);
    const pubnub_res_t added   = pubnub_await(add_fut);
    if (PUBNUB_OK != added) {
        const pubnub_string_view_t err = pubnub_response_error_message(add_fut);
        printf("add_message_action failed: %s (%.*s)\n",
               pubnub_res_str(added),
               (int)err.len,
               err.ptr);
        pubnub_future_release(add_fut);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 2. Copy the action_timetoken out of the result. The view aliases
     * memory owned by add_fut and dies with it. */
    const pubnub_add_message_action_result_t r =
        pubnub_add_message_action_result(add_fut);
    char action_timetoken[TIMETOKEN_CAPACITY];
    if (r.action.action_timetoken.len >= sizeof(action_timetoken)) {
        printf("Unexpected action_timetoken length\n");
        pubnub_future_release(add_fut);
        pubnub_destroy(ctx);
        return 1;
    }
    memcpy(action_timetoken,
           r.action.action_timetoken.ptr,
           r.action.action_timetoken.len);
    action_timetoken[r.action.action_timetoken.len] = '\0';

    /* 3. Only now is it safe to release the add future. */
    pubnub_future_release(add_fut);
    printf("Added action at %s\n", action_timetoken);

    /* 4. Remove it. All three identifiers are required: the channel, the
     * parent message timetoken, and the action timetoken. */
    pubnub_remove_message_action_opts_t rm_opts =
        PUBNUB_REMOVE_MESSAGE_ACTION_OPTS_INIT;
    rm_opts.channel           = channel;
    rm_opts.message_timetoken = message_timetoken;
    rm_opts.action_timetoken  = action_timetoken;

    pubnub_future_t    rm_fut  = pubnub_remove_message_action(ctx, &rm_opts);
    const pubnub_res_t removed = pubnub_await(rm_fut);
    if (PUBNUB_OK == removed) {
        printf("Removed action %s\n", action_timetoken);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(rm_fut);
        printf("remove_message_action failed: %s (%.*s)\n",
               pubnub_res_str(removed),
               (int)err.len,
               err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(rm_fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

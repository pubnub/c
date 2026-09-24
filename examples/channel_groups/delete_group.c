/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/channel_groups/delete_group.c
 * @brief Delete a channel group using cooperative polling.
 *
 * All channel-group operations also support async callbacks
 * (pubnub_async) and blocking await (pubnub_await). See async.c
 * for the callback pattern.
 *
 * Build: cmake --build build/full --target example_channel_groups_delete_group
 * Run: ./build/full/examples/channel_groups/example_channel_groups_delete_group
 */

// snippet.channelGroupsDeleteGroup

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-delete-group";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Delete the channel group. */
    pubnub_future_t fut =
        pubnub_channel_group_remove(ctx,
                                    &(pubnub_channel_group_remove_group_opts_t){
                                        .channel_group = "demo-group",
                                    });

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    if (PUBNUB_OK == pubnub_future_status(fut)) {
        printf("Group deleted.\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Delete group failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

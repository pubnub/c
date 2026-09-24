/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/channel_groups/add_channels.c
 * @brief Add channels to a channel group using cooperative polling.
 *
 * All channel-group operations also support async callbacks
 * (pubnub_async) and blocking await (pubnub_await). See async.c
 * for the callback pattern.
 *
 * Build: cmake --build build/full --target example_channel_groups_add_channels
 * Run: ./build/full/examples/channel_groups/example_channel_groups_add_channels
 */

// snippet.channelGroupsAddChannels

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-add-channels";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Add channels to a group. */
    pubnub_future_t fut =
        pubnub_channel_group_add_channels(ctx,
                                          &(pubnub_channel_group_add_opts_t){
                                              .channel_group = "demo-group",
                                              .channels      = "ch1,ch2,ch3",
                                          });

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    if (PUBNUB_OK == pubnub_future_status(fut)) {
        printf("Channels added to group.\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Add failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

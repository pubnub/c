/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/channel_groups/list_channels.c
 * @brief List channels in a channel group using cooperative polling.
 *
 * All channel-group operations also support async callbacks
 * (pubnub_async) and blocking await (pubnub_await). See async.c
 * for the callback pattern.
 *
 * Build: cmake --build build/full --target example_channel_groups_list_channels
 * Run: ./build/full/examples/channel_groups/example_channel_groups_list_channels
 */

// snippet.channelGroupsListChannels

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-list-channels";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. List channels in a group. */
    pubnub_future_t fut =
        pubnub_channel_group_list_channels(ctx,
                                           &(pubnub_channel_group_list_opts_t){
                                               .channel_group = "demo-group",
                                           });

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    if (PUBNUB_OK == pubnub_future_status(fut)) {
        pubnub_channel_group_list_result_t result =
            pubnub_channel_group_list_result(fut);
        printf("Channels in group (%u):\n", result.count);
        for (uint32_t i = 0; i < result.count; ++i) {
            pubnub_string_view_t ch =
                pubnub_channel_group_list_result_channel_at(fut, i);
            printf("  %.*s\n", (int)ch.len, ch.ptr);
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("List failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

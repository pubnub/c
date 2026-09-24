/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/channel_groups/list_channels_async.c
 * @brief List channels in a group using async callback.
 *
 * Same operation as list_channels.c but driven by pubnub_async()
 * instead of cooperative polling. On threaded builds the background
 * thread drives I/O; on cooperative targets the main loop pumps
 * pubnub_process() for the callback to fire.
 *
 * All channel-group operations (add, remove, list, delete) support
 * the same async pattern shown here.
 *
 * Build: cmake --build build/full --target example_channel_groups_list_channels_async
 * Run: ./build/full/examples/channel_groups/example_channel_groups_list_channels_async
 */

// snippet.channelGroupsListChannelsAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>

static volatile int s_done;

static void on_list_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        pubnub_channel_group_list_result_t result =
            pubnub_channel_group_list_result(future);
        printf("  [callback] Channels in group (%u):\n", result.count);
        for (uint32_t i = 0; i < result.count; ++i) {
            pubnub_string_view_t ch =
                pubnub_channel_group_list_result_channel_at(future, i);
            printf("    %.*s\n", (int)ch.len, ch.ptr);
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("  [callback] list failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    pubnub_future_release(future);
    s_done = 1;
}

static void wait_ready(pubnub_context_t* ctx, pubnub_future_t fut)
{
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }
}

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-channel-groups-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Add channels to a group (cooperative wait, setup step). */
    pubnub_future_t add_fut =
        pubnub_channel_group_add_channels(ctx,
                                          &(pubnub_channel_group_add_opts_t){
                                              .channel_group = "demo-group",
                                              .channels      = "ch1,ch2,ch3",
                                          });

    wait_ready(ctx, add_fut);

    if (PUBNUB_OK != pubnub_future_status(add_fut)) {
        printf("Add channels failed\n");
        pubnub_future_release(add_fut);
        pubnub_destroy(ctx);
        return 1;
    }
    printf("Channels added, listing via async callback...\n");
    pubnub_future_release(add_fut);

    /* 3. List channels via async callback. */
    pubnub_future_t list_fut =
        pubnub_channel_group_list_channels(ctx,
                                           &(pubnub_channel_group_list_opts_t){
                                               .channel_group = "demo-group",
                                           });

    pubnub_res_t rc = pubnub_async(list_fut, on_list_complete, NULL);
    if (PUBNUB_OK != rc) {
        printf("pubnub_async registration failed: %s\n", pubnub_res_str(rc));
        pubnub_future_release(list_fut);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 4. Wait for the callback to fire.
     *    On threaded platforms the background thread drives I/O.
     *    On embedded without threads, replace PUBNUB_EXAMPLE_SLEEP_MS
     *    with pubnub_process(ctx) to drive I/O cooperatively. */
    while (!s_done) {
        PUBNUB_EXAMPLE_SLEEP_MS(10);
    }

    /* 5. Cleanup: delete the group. */
    pubnub_future_t del_fut =
        pubnub_channel_group_remove(ctx,
                                    &(pubnub_channel_group_remove_group_opts_t){
                                        .channel_group = "demo-group",
                                    });

    wait_ready(ctx, del_fut);
    pubnub_future_release(del_fut);

    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

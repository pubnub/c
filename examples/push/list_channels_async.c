/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/push/list_channels_async.c
 * @brief List push channels with asynchronous callback.
 *
 * Build: cmake --build build/full --target example_push_list_channels_async
 * Run:   ./build/full/examples/push/example_push_list_channels_async
 */

// snippet.pushListChannelsAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>
#include <stdlib.h>

static volatile int s_done;

static void on_list_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        pubnub_push_list_channels_result_t result =
            pubnub_push_list_channels_result(future);
        printf("  [callback] channels (%u):\n", result.channel_count);
        for (uint32_t i = 0; i < result.channel_count; ++i) {
            pubnub_string_view_t ch =
                pubnub_push_list_channels_result_channel_at(future, (size_t)i);
            printf("    %.*s\n", (int)ch.len, ch.ptr);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("  [callback] failed: %s (%.*s)\n",
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
    cfg.user_id         = "example-push-list-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. List channels registered for push on this device. */
    printf("Listing push channels (async)...\n");

    pubnub_future_t fut =
        pubnub_push_list_channels(ctx,
                                  &(pubnub_push_list_channels_opts_t){
                                      .device  = "dXh7YzE:APA91bGExample",
                                      .gateway = PUBNUB_PUSH_FCM,
                                  });

    /* 3. Register async callback — background thread drives I/O. */
    pubnub_res_t rc = pubnub_async(fut, on_list_complete, NULL);
    if (PUBNUB_OK != rc) {
        printf("pubnub_async registration failed: %s\n", pubnub_res_str(rc));
        pubnub_future_release(fut);
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

    /* 5. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

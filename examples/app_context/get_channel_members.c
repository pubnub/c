/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/get_channel_members.c
 * @brief Retrieve members of a channel using cooperative polling.
 *
 * Build: cmake --build build/full --target example_app_context_get_channel_members
 * Run: ./build/full/examples/app_context/example_app_context_get_channel_members
 */

// snippet.appContextGetChannelMembers

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-app-context";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build and submit the request. */
    pubnub_get_channel_members_opts_t opts = PUBNUB_GET_CHANNEL_MEMBERS_OPTS_INIT;
    opts.channel = "example-channel";
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_UUID | PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                 | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit = 10;

    pubnub_future_t fut = pubnub_get_channel_members(ctx, &opts);

    /* 3. Wait for the response. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read and print the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page =
            pubnub_get_channel_members_result(fut);

        printf("Total members: %u, Page items: %u\n", page.total_count, page.count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_member_t m =
                pubnub_get_channel_members_result_member_at(fut, i);
            printf("  [%u] UUID: %.*s", i, (int)m.uuid.id.len, m.uuid.id.ptr);
            if (0 != m.uuid.name.len) {
                printf(" (%.*s)", (int)m.uuid.name.len, m.uuid.name.ptr);
            }
            printf("\n");
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Get channel members failed: %s (%.*s)\n",
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

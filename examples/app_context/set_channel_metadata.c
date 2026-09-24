/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/set_channel_metadata.c
 * @brief Set channel metadata using cooperative polling.
 *
 * Demonstrates creating or updating a channel's App Context metadata
 * with name, description, and raw JSON custom data.
 *
 * Build: cmake --build build/full --target example_app_context_set_channel_metadata
 * Run: ./build/full/examples/app_context/example_app_context_set_channel_metadata
 */

// snippet.appContextSetChannelMetadata

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-app-context";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Set channel metadata with description and custom JSON. */
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel     = "announcements";
    opts.name        = "Announcements";
    opts.description = "Company-wide announcements channel";
    opts.type        = "public";
    opts.status      = "active";
    opts.custom      = "{\"topic\":\"general\",\"max_members\":500}";
    opts.include     = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM;

    pubnub_future_t fut = pubnub_set_channel_metadata(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_channel_metadata_t result =
            pubnub_set_channel_metadata_result(fut);

        printf("Set channel metadata OK\n");
        printf("  ID:          %.*s\n", (int)result.id.len, result.id.ptr);
        printf("  Name:        %.*s\n", (int)result.name.len, result.name.ptr);
        if (0 != result.description.len) {
            printf("  Description: %.*s\n",
                   (int)result.description.len,
                   result.description.ptr);
        }
        if (NULL != result.custom) {
            char                             buf[256];
            pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
            size_t                           n = pubnub_json_to_debug_string(
                serial, result.custom, buf, sizeof(buf));
            if (n > 0) {
                printf("  Custom:      %s\n", buf);
            }
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Set channel metadata failed: %s (%.*s)\n",
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

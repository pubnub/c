/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/get_all_channel_metadata.c
 * @brief Paginated list of all channel metadata using cooperative polling.
 *
 * Build: cmake --build build/full --target example_app_context_get_all_channel_metadata
 * Run: ./build/full/examples/app_context/example_app_context_get_all_channel_metadata
 */

// snippet.appContextGetAllChannelMetadata

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-app-context";
    //! [subscribe_basic_usage]
    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build and submit the request. */
    pubnub_get_all_channel_metadata_opts_t opts =
        PUBNUB_GET_ALL_CHANNEL_METADATA_OPTS_INIT;
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                 | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit = 5;

    pubnub_future_t fut = pubnub_get_all_channel_metadata(ctx, &opts);

    /* 3. Wait for the response. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read and print the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page =
            pubnub_get_all_channel_metadata_result(fut);

        printf("Total: %u, Page items: %u\n", page.total_count, page.count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_channel_metadata_t ch =
                pubnub_get_all_channel_metadata_result_channel_at(fut, i);
            printf("  [%u] %.*s", i, (int)ch.id.len, ch.id.ptr);
            if (0 != ch.name.len) {
                printf(" — %.*s", (int)ch.name.len, ch.name.ptr);
            }
            printf("\n");
        }

        if (0 != page.next.len) {
            printf("Next cursor: %.*s\n", (int)page.next.len, page.next.ptr);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Get all channel metadata failed: %s (%.*s)\n",
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

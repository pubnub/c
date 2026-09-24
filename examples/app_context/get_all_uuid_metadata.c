/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/get_all_uuid_metadata.c
 * @brief List all UUID metadata with pagination using cooperative polling.
 *
 * Demonstrates paginated listing with include flags, filter
 * expression, sort order, and cursor-based iteration.
 *
 * Build: cmake --build build/full --target example_app_context_get_all_uuid_metadata
 * Run: ./build/full/examples/app_context/example_app_context_get_all_uuid_metadata
 */

// snippet.appContextGetAllUuidMetadata

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

    /* 2. Request first page of UUID metadata.
     *    - limit: 5 items per page
     *    - include total count for knowing how many exist
     *    - filter: only active UUIDs
     *    - sort: alphabetically by name */
    pubnub_get_all_uuid_metadata_opts_t opts =
        PUBNUB_GET_ALL_UUID_METADATA_OPTS_INIT;
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                 | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit  = 5;
    opts.filter = "status == \"active\"";
    opts.sort   = "name:asc";

    pubnub_future_t fut = pubnub_get_all_uuid_metadata(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Process result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page =
            pubnub_get_all_uuid_metadata_result(fut);

        printf("UUID Metadata (page of %u, total: %u)\n", page.count, page.total_count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_uuid_metadata_t m =
                pubnub_get_all_uuid_metadata_result_uuid_at(fut, i);
            printf("  [%u] id=%.*s name=%.*s\n",
                   i,
                   (int)m.id.len,
                   m.id.ptr,
                   (int)m.name.len,
                   m.name.ptr);
        }

        /* Show pagination cursors for the next page. */
        if (0 != page.next.len) {
            printf("\nNext cursor: %.*s\n", (int)page.next.len, page.next.ptr);
            printf("Pass this as opts.start to fetch the next page.\n");
        } else {
            printf("\nNo more pages.\n");
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Get all UUID metadata failed: %s (%.*s)\n",
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

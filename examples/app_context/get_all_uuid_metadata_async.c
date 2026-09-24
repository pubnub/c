/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/get_all_uuid_metadata_async.c
 * @brief List all UUID metadata using asynchronous callback.
 *
 * Demonstrates the async callback pattern with pubnub_async(). On
 * threaded builds, a background thread drives I/O and the callback
 * fires without manual pubnub_process() pumping. On cooperative
 * builds, pubnub_process() must still be called for the callback
 * to fire.
 *
 * Any App Context operation can use cooperative polling,
 * blocking await (pubnub_await), or async callbacks -- this
 * example shows the callback style.
 *
 * Build: cmake --build build/full --target example_app_context_get_all_uuid_metadata_async
 * Run: ./build/full/examples/app_context/example_app_context_get_all_uuid_metadata_async
 */

// snippet.appContextGetAllUuidMetadataAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>

static volatile int s_done;

static void on_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page =
            pubnub_get_all_uuid_metadata_result(future);

        printf("[callback] Got %u UUIDs (total: %u)\n", page.count, page.total_count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_uuid_metadata_t m =
                pubnub_get_all_uuid_metadata_result_uuid_at(future, i);
            printf("  [%u] %.*s", i, (int)m.id.len, m.id.ptr);
            if (0 != m.name.len) {
                printf(" (%.*s)", (int)m.name.len, m.name.ptr);
            }
            printf("\n");
        }

        if (0 != page.next.len) {
            printf("  (more pages available)\n");
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("[callback] Error: %s (%.*s)\n",
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
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-app-context-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Request paginated UUID metadata. */
    pubnub_get_all_uuid_metadata_opts_t opts =
        PUBNUB_GET_ALL_UUID_METADATA_OPTS_INIT;
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                 | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit = 10;
    opts.sort  = "updated:desc";

    pubnub_future_t fut = pubnub_get_all_uuid_metadata(ctx, &opts);

    /* 3. Register the async callback.
     *    On threaded builds the background thread drives I/O --
     *    no pubnub_process() loop is needed. On cooperative builds
     *    we still pump as a fallback. */
    pubnub_res_t rc = pubnub_async(fut, on_complete, NULL);
    if (PUBNUB_OK != rc) {
        printf("pubnub_async failed: %s\n", pubnub_res_str(rc));
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

    /* 5. Cleanup -- future was released in callback. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

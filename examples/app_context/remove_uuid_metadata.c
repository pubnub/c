/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/remove_uuid_metadata.c
 * @brief Remove metadata for a UUID using cooperative polling.
 *
 * Build: cmake --build build/full --target example_app_context_remove_uuid_metadata
 * Run: ./build/full/examples/app_context/example_app_context_remove_uuid_metadata
 */

// snippet.appContextRemoveUuidMetadata

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
    pubnub_remove_uuid_metadata_opts_t opts = PUBNUB_REMOVE_UUID_METADATA_OPTS_INIT;
    opts.uuid = "example-app-context";

    pubnub_future_t fut = pubnub_remove_uuid_metadata(ctx, &opts);

    /* 3. Wait for the response. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check and print the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        printf("UUID metadata removed successfully.\n");
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Remove UUID metadata failed: %s (%.*s)\n",
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

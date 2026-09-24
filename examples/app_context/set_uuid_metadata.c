/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/set_uuid_metadata.c
 * @brief Set UUID metadata using cooperative polling.
 *
 * Demonstrates creating or updating a UUID's App Context metadata
 * with string fields and a raw JSON custom data object.
 *
 * Build: cmake --build build/full --target example_app_context_set_uuid_metadata
 * Run: ./build/full/examples/app_context/example_app_context_set_uuid_metadata
 */

// snippet.appContextSetUuidMetadata

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

    /* 2. Set metadata fields on the context's user_id.
     *    Only non-NULL fields are sent (partial PATCH). */
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.uuid    = NULL; /* NULL = use context user_id */
    opts.name    = "Example User";
    opts.email   = "user@example.com";
    opts.type    = "human";
    opts.status  = "active";
    opts.custom  = "{\"role\":\"developer\",\"level\":42}";
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM;

    pubnub_future_t fut = pubnub_set_uuid_metadata(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_uuid_metadata_t result = pubnub_set_uuid_metadata_result(fut);

        printf("Set UUID metadata OK\n");
        printf("  ID:     %.*s\n", (int)result.id.len, result.id.ptr);
        printf("  Name:   %.*s\n", (int)result.name.len, result.name.ptr);
        printf("  Email:  %.*s\n", (int)result.email.len, result.email.ptr);
        if (NULL != result.custom) {
            char                             buf[256];
            pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
            size_t                           n = pubnub_json_to_debug_string(
                serial, result.custom, buf, sizeof(buf));
            if (n > 0) {
                printf("  Custom: %s\n", buf);
            }
        }
        if (0 != result.updated.len) {
            printf("  Updated: %.*s\n", (int)result.updated.len, result.updated.ptr);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Set UUID metadata failed: %s (%.*s)\n",
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

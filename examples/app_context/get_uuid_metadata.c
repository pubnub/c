/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/get_uuid_metadata.c
 * @brief Retrieve metadata for a single UUID using cooperative polling.
 *
 * Demonstrates fetching a UUID's App Context metadata with include
 * flags for custom data, type, and status fields.
 *
 * Build: cmake --build build/full --target example_app_context_get_uuid_metadata
 * Run: ./build/full/examples/app_context/example_app_context_get_uuid_metadata
 */

// snippet.appContextGetUuidMetadata

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

    /* 2. Request UUID metadata with custom/type/status included. */
    pubnub_get_uuid_metadata_opts_t opts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    opts.uuid                            = "example-app-context";
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM | PUBNUB_APP_CONTEXT_INCLUDE_TYPE
                 | PUBNUB_APP_CONTEXT_INCLUDE_STATUS;

    pubnub_future_t fut = pubnub_get_uuid_metadata(ctx, &opts);

    /* 3. Cooperative poll: drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_uuid_metadata_t result = pubnub_get_uuid_metadata_result(fut);

        printf("UUID:  %.*s\n", (int)result.id.len, result.id.ptr);
        printf("Name:  %.*s\n", (int)result.name.len, result.name.ptr);

        if (0 != result.email.len) {
            printf("Email: %.*s\n", (int)result.email.len, result.email.ptr);
        }
        if (0 != result.type.len) {
            printf("Type:  %.*s\n", (int)result.type.len, result.type.ptr);
        }
        if (NULL != result.custom) {
            char                             buf[256];
            pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
            size_t                           n = pubnub_json_to_debug_string(
                serial, result.custom, buf, sizeof(buf));
            if (n > 0) {
                printf("Custom: %s\n", buf);
            }
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Get UUID metadata failed: %s (%.*s)\n",
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

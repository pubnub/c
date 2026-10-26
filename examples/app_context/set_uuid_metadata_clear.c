/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/set_uuid_metadata_clear.c
 * @brief Clear UUID metadata fields with PUBNUB_CLEAR_VALUE.
 *
 * A NULL field is omitted from the request and keeps its stored
 * value. Passing PUBNUB_CLEAR_VALUE sends an explicit JSON null, which
 * clears the field on the server.
 *
 * Build: cmake --build build/full --target example_app_context_set_uuid_metadata_clear
 * Run: ./build/full/examples/app_context/example_app_context_set_uuid_metadata_clear
 */

// snippet.appContextClearUuidFields

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

    /* 2. Clear the email and custom fields.
     *    Fields left NULL (such as name) keep their stored value. */
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.email  = PUBNUB_CLEAR_VALUE;
    opts.custom = PUBNUB_CLEAR_VALUE;

    pubnub_future_t fut = pubnub_set_uuid_metadata(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_uuid_metadata_t result = pubnub_set_uuid_metadata_result(fut);

        printf("Cleared UUID metadata fields for %.*s\n",
               (int)result.id.len,
               result.id.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Clear UUID metadata failed: %s (%.*s)\n",
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

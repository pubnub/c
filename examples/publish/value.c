/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/publish/value.c
 * @brief Publish a structured message built from C data using the
 *        JSON value tree API.
 *
 * Demonstrates:
 *   1. Building a JSON object from C values (no manual formatting).
 *   2. Publishing via the message_value path.
 *   3. Cooperative polling until the future is ready.
 *
 * Build: cmake --build build/full --target example_publish_value
 * Run:   ./build/full/examples/publish/example_publish_value
 */

// snippet.publishValue

#include "pubnub/pubnub.h"

#include "pubnub/json_macros.h"
#include "pubnub/providers/serialization.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-value";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build a JSON message from C data. */
    pubnub_serialization_provider_t* json = pubnub_serialization(ctx);

    pubnub_json_value_t* msg =
        PUBNUB_JSON_OBJ(json,
                        PUBNUB_JSON_KV_STR(json, "device", "sensor-01"),
                        PUBNUB_JSON_KV_INT(json, "temp_c", 42),
                        PUBNUB_JSON_KV_BOOL(json, "alarm", 0));

    if (NULL == msg) {
        printf("failed to build message\n");
        pubnub_destroy(ctx);
        return 1;
    }

    /* 3. Publish the value tree — the SDK serializes it to JSON. */
    pubnub_future_t fut = pubnub_publish(ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel       = "demo_channel",
                                             .message_value = msg,
                                         });
    pubnub_json_destroy(json, msg);

    /* 4. Cooperative poll until done. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 5. Check result and cleanup. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        printf("Published OK, timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Publish failed: %.*s\n", (int)err.len, err.ptr);
    }

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

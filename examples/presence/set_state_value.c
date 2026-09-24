/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/presence/set_state_value.c
 * @brief Set presence state using a JSON value tree.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see here_now_async.c and publish/sync.c for those patterns.
 *
 * Build: cmake --build build/full --target example_presence_set_state_value
 * Run:   ./build/full/examples/presence/example_presence_set_state_value
 */

// snippet.presenceSetStateValue

#include "pubnub/pubnub.h"

#include "pubnub/json_macros.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-set-state-value";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build state as a JSON value tree. */
    pubnub_serialization_provider_t* json = pubnub_serialization(ctx);
    pubnub_json_value_t*             st =
        PUBNUB_JSON_OBJ(json,
                        PUBNUB_JSON_KV_STR(json, "mood", "happy"),
                        PUBNUB_JSON_KV_INT(json, "score", 42),
                        PUBNUB_JSON_KV_BOOL(json, "typing", 0));

    /* 3. Set presence state with the value tree. */
    pubnub_set_state_opts_t opts = PUBNUB_SET_STATE_OPTS_INIT;
    opts.channels                = "demo_channel";
    opts.state_value             = st;

    pubnub_future_t fut = pubnub_set_state(ctx, &opts);

    /* 4. Tree is borrowed during the call — safe to destroy now. */
    pubnub_json_destroy(json, st);

    /* 5. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 6. Read the confirmed state. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_set_state_result_t r = pubnub_set_state_result(fut);
        if (NULL != r.state) {
            char buf[256];
            pubnub_json_to_debug_string(json, r.state, buf, sizeof(buf));
            printf("State set: %s\n", buf);
        } else {
            printf("State set (no echo)\n");
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("set_state failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 7. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

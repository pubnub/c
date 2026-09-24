/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/access/grant_token.c
 * @brief Grant an access token with multiple channels and a pattern.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see grant_token_async.c and publish/sync.c for those
 * patterns.
 *
 * Build: cmake --build build/full --target example_access_grant_token
 * Run:   ./build/full/examples/access/example_access_grant_token
 */

// snippet.accessGrantToken

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.secret_key      = "demo";
    cfg.user_id         = "admin-user";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build the grant-token request. */
    /* Multiple exact channel permissions. */
    pubnub_access_resource_permission_t channels[] = {
        {"chat.room-1",   PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE},
        {"chat.room-2",   PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE},
        {"notifications", PUBNUB_ACCESS_READ                      },
    };

    /* Pattern: all channels matching "chat.room-*" get read access. */
    pubnub_access_resource_permission_t channel_patterns[] = {
        {"^chat\\.room-.*$", PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE},
    };

    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 60;
    opts.channels                  = channels;
    opts.channel_count             = 3;
    opts.channel_patterns          = channel_patterns;
    opts.channel_pattern_count     = 1;
    opts.authorized_uuid           = "client-user-123";

    pubnub_future_t fut = pubnub_grant_token(ctx, &opts);

    /* 3. Wait for the response. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read and print the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_grant_token_result_t r = pubnub_grant_token_result(fut);
        printf("Token: %.*s\n", (int)r.token.len, r.token.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Grant failed: %s (%.*s)\n",
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

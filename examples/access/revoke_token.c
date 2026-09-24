/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/access/revoke_token.c
 * @brief Revoke a previously granted access token.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see grant_token_async.c for the callback pattern.
 *
 * Build: cmake --build build/full --target example_access_revoke_token
 * Run:   ./build/full/examples/access/example_access_revoke_token
 */

// snippet.accessRevokeToken

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.secret_key      = "demo";
    cfg.user_id         = "admin-user";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Build and submit the revoke request. */
    pubnub_revoke_token_opts_t opts = PUBNUB_REVOKE_TOKEN_OPTS_INIT;
    opts.token                      = "p0thisIsATokenToRevoke...";

    pubnub_future_t fut = pubnub_revoke_token(ctx, &opts);

    /* 3. Wait for the response. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Check and print the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        printf("Token revoked successfully.\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Revoke failed: %s (%.*s)\n",
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

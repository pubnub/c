/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/access/grant_token_async.c
 * @brief Grant an access token using async callback completion.
 *
 * pubnub_async() lazily starts a background I/O thread — no manual
 * pubnub_process() loop is needed. The main thread just waits for
 * the callback to fire.
 *
 * Build: cmake --build build/full --target example_access_grant_token_async
 * Run:   ./build/full/examples/access/example_access_grant_token_async
 */

// snippet.accessGrantTokenAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>

static volatile int s_done;

static void on_grant(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        pubnub_grant_token_result_t r = pubnub_grant_token_result(future);
        printf("Token: %.*s\n", (int)r.token.len, r.token.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("Grant failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    pubnub_future_release(future);
    s_done = 1;
}

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
    pubnub_access_resource_permission_t channels[] = {
        {"my-channel", PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE},
    };

    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 15;
    opts.channels                  = channels;
    opts.channel_count             = 1;

    pubnub_future_t fut = pubnub_grant_token(ctx, &opts);

    /* 3. Register the async callback. */
    pubnub_res_t rc = pubnub_async(fut, on_grant, NULL);
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

    /* 5. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

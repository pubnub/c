/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/access/grant_token_categories.c
 * @brief Grant a token that can list all channel and all UUID metadata.
 *
 * Category permissions let a token enumerate every channel metadata
 * object or every UUID metadata object on the subscribe key with
 * App Context. They need no resources or patterns, and PUBNUB_ACCESS_GET
 * is the only permission they accept.
 *
 * Build: cmake --build build/full --target example_access_grant_token_categories
 * Run:   ./build/full/examples/access/example_access_grant_token_categories
 */

// snippet.accessGrantTokenCategories

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

    /* 2. Build the grant-token request. A category permission alone is
     * a valid request, so no channels, groups, or UUIDs are set. */
    pubnub_grant_token_opts_t opts     = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET; /* list all channel metadata */
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET; /* list all UUID metadata */
    opts.authorized_uuid               = "client-user-123";

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

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/get_memberships.c
 * @brief Retrieve UUID memberships using cooperative polling.
 *
 * Demonstrates querying which channels a UUID belongs to, with
 * include flags to also fetch the associated channel metadata.
 *
 * Build: cmake --build build/full --target example_app_context_get_memberships
 * Run:   ./build/full/examples/app_context/example_app_context_get_memberships
 */

// snippet.appContextGetMemberships

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

    /* 2. Get memberships for the context's own user_id.
     *    Include channel metadata so we see channel names. */
    pubnub_get_memberships_opts_t opts = PUBNUB_GET_MEMBERSHIPS_OPTS_INIT;
    opts.uuid                          = NULL; /* NULL = use context user_id */
    opts.include                       = PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL
                 | PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL_CUSTOM
                 | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit = 20;
    opts.sort  = "channel.name:asc";

    pubnub_future_t fut = pubnub_get_memberships(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Process result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page = pubnub_get_memberships_result(fut);

        printf("Memberships for user_id (total: %u)\n", page.total_count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_membership_t m =
                pubnub_get_memberships_result_membership_at(fut, i);

            printf("  [%u] channel=%.*s", i, (int)m.channel.id.len, m.channel.id.ptr);

            if (0 != m.channel.name.len) {
                printf(" (%.*s)", (int)m.channel.name.len, m.channel.name.ptr);
            }
            if (0 != m.status.len) {
                printf(" status=%.*s", (int)m.status.len, m.status.ptr);
            }
            printf("\n");
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Get memberships failed: %s (%.*s)\n",
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

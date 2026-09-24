/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/set_memberships.c
 * @brief Add and remove a user's channel memberships in one call.
 *
 * Memberships are the user-to-channel side of the same relationship that
 * members (set_members.c) express channel-to-user. The set and remove
 * arrays are applied together, and the response is the resulting page of
 * memberships.
 *
 * Build: cmake --build build/full --target example_app_context_set_memberships
 * Run:   ./build/full/examples/app_context/example_app_context_set_memberships
 */

// snippet.appContextSetMemberships

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

    /* 2. Join two channels and leave one. For removals only channel_id
     * is read, so the other fields can be omitted. */
    const pubnub_membership_input_t to_set[] = {
        {.channel_id = "announcements", .status = "active", .custom = "{\"muted\":false}"},
        {.channel_id = "support",       .status = "active", .type = "agent"              },
    };

    const pubnub_membership_input_t to_remove[] = {
        {.channel_id = "archive-2024"},
    };

    /* Leaving uuid NULL targets the context's configured user_id. */
    pubnub_set_memberships_opts_t opts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    opts.uuid                          = "user-alice";
    opts.set                           = to_set;
    opts.set_count                     = sizeof(to_set) / sizeof(to_set[0]);
    opts.remove                        = to_remove;
    opts.remove_count = sizeof(to_remove) / sizeof(to_remove[0]);
    opts.include      = PUBNUB_APP_CONTEXT_INCLUDE_CHANNEL
                      | PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                      | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit        = 25;

    pubnub_future_t fut = pubnub_set_memberships(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. The response is the membership list after both operations. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page = pubnub_set_memberships_result(fut);
        printf("Memberships updated (total: %u)\n", page.total_count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_membership_t m =
                pubnub_set_memberships_result_membership_at(fut, i);
            printf("  [%u] channel=%.*s", i, (int)m.channel.id.len, m.channel.id.ptr);
            if (0 != m.status.len) {
                printf(" status=%.*s", (int)m.status.len, m.status.ptr);
            }
            printf("\n");
        }

        /* page.next is the cursor for opts.start on the following call. */
        if (0 != page.next.len) {
            printf("  next page cursor: %.*s\n", (int)page.next.len, page.next.ptr);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("set_memberships failed: %s (%.*s)\n",
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

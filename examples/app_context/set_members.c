/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/set_members.c
 * @brief Set channel members using cooperative polling.
 *
 * Demonstrates adding and removing members from a channel in a
 * single request using the set/remove arrays.
 *
 * Build: cmake --build build/full --target example_app_context_set_members
 * Run:   ./build/full/examples/app_context/example_app_context_set_members
 */

// snippet.appContextSetMembers

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

    /* 2. Add two members and remove one in a single call. */
    const pubnub_member_input_t members_to_set[] = {
        {.uuid_id = "user-alice", .status = "active", .custom = "{\"role\":\"admin\"}"},
        {.uuid_id = "user-bob",   .status = "active", .type = "member"                },
    };

    const pubnub_member_input_t members_to_remove[] = {
        {.uuid_id = "user-charlie"},
    };

    pubnub_set_channel_members_opts_t opts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    opts.channel      = "announcements";
    opts.set          = members_to_set;
    opts.set_count    = 2;
    opts.remove       = members_to_remove;
    opts.remove_count = 1;
    opts.include =
        PUBNUB_APP_CONTEXT_INCLUDE_UUID | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    opts.limit = 10;

    pubnub_future_t fut = pubnub_set_channel_members(ctx, &opts);

    /* 3. Cooperative poll. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Process result -- the response contains the current member
     *    list after applying set + remove operations. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_app_context_page_t page =
            pubnub_set_channel_members_result(fut);

        printf("Channel members updated (total: %u)\n", page.total_count);

        for (uint32_t i = 0; i < page.count; ++i) {
            const pubnub_member_t m =
                pubnub_set_channel_members_result_member_at(fut, i);

            printf("  [%u] uuid=%.*s", i, (int)m.uuid.id.len, m.uuid.id.ptr);

            if (0 != m.status.len) {
                printf(" status=%.*s", (int)m.status.len, m.status.ptr);
            }
            if (NULL != m.custom) {
                char buf[128];
                pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
                size_t n = pubnub_json_to_debug_string(
                    serial, m.custom, buf, sizeof(buf));
                if (n > 0) {
                    printf(" custom=%s", buf);
                }
            }
            printf("\n");
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Set channel members failed: %s (%.*s)\n",
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

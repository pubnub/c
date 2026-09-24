/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/get_message_actions_page.c
 * @brief Fetch a single page of message actions.
 *
 * The boundaries are half-open: start excludes its own timetoken, end
 * includes it. Formally, results are the actions whose timetoken is
 * less than start and greater than or equal to end.
 *
 * See get_message_actions.c for the loop that walks every page using
 * has_more, more_start, and more_end.
 *
 * Build: cmake --build build/full --target example_message_actions_get_message_actions_page
 * Run: ./build/full/examples/message_actions/example_message_actions_get_message_actions_page
 */

// snippet.messageActionsGetMessageActionsPage

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-get-actions-page";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. Ask for one page. Omit start and end to get the newest actions
     * on the channel. */
    pubnub_get_message_actions_opts_t opts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    opts.channel = "demo_channel";
    opts.start   = "15610547826969051";
    opts.end     = "15610547826969000";
    opts.limit   = 25;

    pubnub_future_t fut = pubnub_get_message_actions(ctx, &opts);

    /* 2. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 3. Read the page. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        const pubnub_get_message_actions_result_t r =
            pubnub_get_message_actions_result(fut);

        printf("%u actions in this page\n", r.count);
        for (uint32_t i = 0; i < r.count; ++i) {
            const pubnub_message_action_t a =
                pubnub_get_message_actions_result_action_at(fut, i);
            printf("  [%u] %.*s=%.*s by %.*s on message %.*s\n",
                   i,
                   (int)a.type.len,
                   a.type.ptr,
                   (int)a.value.len,
                   a.value.ptr,
                   (int)a.uuid.len,
                   a.uuid.ptr,
                   (int)a.message_timetoken.len,
                   a.message_timetoken.ptr);
        }

        /* has_more says the server truncated the page. more_start and
         * more_end are the cursors for the next call. */
        if (r.has_more) {
            printf("More available from start=%.*s end=%.*s\n",
                   (int)r.more_start.len,
                   r.more_start.ptr,
                   (int)r.more_end.len,
                   r.more_end.ptr);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("get_message_actions failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    /* 4. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

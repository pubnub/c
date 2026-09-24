/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/message_actions/get_message_actions.c
 * @brief Fetch message actions with pagination using cooperative polling.
 *
 * Demonstrates iterating through all actions on a channel by following
 * the server's pagination cursors until no more pages remain.
 *
 * Build: cmake --build build/full --target example_message_actions_get_message_actions
 * Run: ./build/full/examples/message_actions/example_message_actions_get_message_actions
 */

// snippet.messageActionsGetMessageActions

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-get-actions";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Fetch actions page by page. */
    pubnub_get_message_actions_opts_t opts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    opts.channel = "demo_channel";
    opts.limit   = 10;

    int  page          = 0;
    int  more          = 1;
    char start_buf[24] = {0};
    char end_buf[24]   = {0};

    while (more) {
        pubnub_future_t fut = pubnub_get_message_actions(ctx, &opts);

        while (!pubnub_future_is_ready(fut)) {
            pubnub_process(ctx);
        }

        const pubnub_res_t status = pubnub_future_status(fut);
        if (PUBNUB_OK != status) {
            pubnub_string_view_t err = pubnub_response_error_message(fut);
            printf("get_message_actions failed: %s (%.*s)\n",
                   pubnub_res_str(status),
                   (int)err.len,
                   err.ptr);
            pubnub_future_release(fut);
            break;
        }

        pubnub_get_message_actions_result_t r =
            pubnub_get_message_actions_result(fut);

        printf("--- Page %d: %u actions ---\n", ++page, r.count);

        for (uint32_t i = 0; i < r.count; ++i) {
            pubnub_message_action_t a =
                pubnub_get_message_actions_result_action_at(fut, i);
            printf("  [%u] type=%.*s value=%.*s uuid=%.*s att=%.*s\n",
                   i,
                   (int)a.type.len,
                   a.type.ptr,
                   (int)a.value.len,
                   a.value.ptr,
                   (int)a.uuid.len,
                   a.uuid.ptr,
                   (int)a.action_timetoken.len,
                   a.action_timetoken.ptr);
        }

        if (r.has_more && NULL != r.more_start.ptr) {
            /* Copy cursor strings before releasing the future, since
             * the view data is only valid until pubnub_future_release. */
            size_t slen = r.more_start.len < 23 ? r.more_start.len : 23;
            memcpy(start_buf, r.more_start.ptr, slen);
            start_buf[slen] = '\0';
            opts.start      = start_buf;

            if (NULL != r.more_end.ptr) {
                size_t elen = r.more_end.len < 23 ? r.more_end.len : 23;
                memcpy(end_buf, r.more_end.ptr, elen);
                end_buf[elen] = '\0';
                opts.end      = end_buf;
            }
        } else {
            more = 0;
        }

        pubnub_future_release(fut);
    }

    /* 3. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

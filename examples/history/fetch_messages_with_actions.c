/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/history/fetch_messages_with_actions.c
 * @brief Fetch stored messages together with their message actions.
 *
 * Setting include_message_actions routes the request to the
 * history-with-actions endpoint, which imposes two extra limits: exactly
 * one channel, and a count clamped to 25. The actions come back as a raw
 * JSON tree per message rather than as a typed array.
 *
 * Build: cmake --build build/full --target example_history_fetch_messages_with_actions
 * Run: ./build/full/examples/history/example_history_fetch_messages_with_actions
 */

// snippet.historyFetchMessagesWithActions

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-history-actions";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. One channel only, and count is clamped to 25 server-side. */
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "demo_channel";
    opts.count                        = 25;
    opts.include_message_actions      = 1;
    opts.include_meta                 = 1;

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);

    /* 2. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK != status) {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("fetch_messages failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
        pubnub_future_release(fut);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 3. Walk channels, then messages within each channel. */
    pubnub_serialization_provider_t*     serial = pubnub_serialization(ctx);
    const pubnub_fetch_messages_result_t r = pubnub_fetch_messages_result(fut);

    for (uint32_t c = 0; c < r.channel_count; ++c) {
        const pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(fut, c);
        printf("Channel %.*s: %u messages\n",
               (int)ch.name.len,
               ch.name.ptr,
               ch.message_count);

        for (uint32_t m = 0; m < ch.message_count; ++m) {
            const pubnub_history_message_result_t msg =
                pubnub_fetch_messages_result_message_at(fut, c, m);
            printf("  [%.*s]", (int)msg.timetoken.len, msg.timetoken.ptr);

            /* crypto_result reports per-message decrypt failure. The
             * whole call still succeeds and msg.message holds the raw
             * bytes, so a single bad message does not lose the page. */
            if (PUBNUB_OK != msg.crypto_result) {
                printf(" [decrypt failed: %s]", pubnub_res_str(msg.crypto_result));
            }

            /* 4. Actions arrive as a borrowed JSON tree, or NULL when the
             * message has none. Never destroy it. */
            const pubnub_json_value_t* actions =
                pubnub_fetch_messages_result_actions_at(fut, c, m);
            if (NULL != actions) {
                char   buf[256];
                size_t n =
                    pubnub_json_to_debug_string(serial, actions, buf, sizeof(buf));
                if (n > 0) {
                    printf(" actions=%s", buf);
                }
            }
            printf("\n");
        }
    }

    /* 5. r.next is the cursor for paging older messages. It, and every
     * view above, dies with the future. */
    if (0 != r.next.len) {
        printf("Next page from %.*s\n", (int)r.next.len, r.next.ptr);
    }

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

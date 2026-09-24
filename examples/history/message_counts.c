/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/history/message_counts.c
 * @brief Get unread message counts using blocking await.
 *
 * Demonstrates pubnub_await() for a simple history query that
 * returns per-channel message counts since a given timetoken.
 *
 * Build: cmake --build build/full --target example_history_message_counts
 * Run:   ./build/full/examples/history/example_history_message_counts
 */

// snippet.historyMessageCounts

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>

static const char* env_or_default(const char* name, const char* fallback)
{
    const char* value = getenv(name);
    return (NULL != value && '\0' != value[0]) ? value : fallback;
}

int main(void)
{
    const char* sub_key = env_or_default("PUBNUB_SUBSCRIBE_KEY", "demo");
    const char* user_id = env_or_default("PUBNUB_USER_ID", "example-history");

    /* 1. Create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = sub_key;
    cfg.user_id         = user_id;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Request message counts. */
    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.channels                     = "ch1,ch2,ch3";
    opts.timetoken                    = "17001234567890123";

    pubnub_future_t fut = pubnub_message_counts(ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);

    /* 3. Read results. */
    if (PUBNUB_OK == st) {
        pubnub_message_counts_result_t r = pubnub_message_counts_result(fut);
        for (size_t i = 0; i < r.channel_count; ++i) {
            pubnub_message_counts_channel_result_t ch =
                pubnub_message_counts_result_channel_at(fut, i);
            printf("[%.*s] unread: %u\n", (int)ch.name.len, ch.name.ptr, ch.count);
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("counts failed: %s (%.*s)\n", pubnub_res_str(st), (int)err.len, err.ptr);
    }

    /* 4. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

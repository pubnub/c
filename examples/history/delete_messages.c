/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/history/delete_messages.c
 * @brief Delete messages from channel history using blocking await.
 *
 * Demonstrates pubnub_await() for a destructive history operation.
 * No result data is returned — success is indicated by the future
 * status alone.
 *
 * Build: cmake --build build/full --target example_history_delete_messages
 * Run:   ./build/full/examples/history/example_history_delete_messages
 */

// snippet.historyDeleteMessages

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

    /* 2. Delete messages older than a timetoken. */
    pubnub_delete_messages_opts_t opts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
    opts.channel                       = "my-channel";
    opts.end                           = "17001234567890123";

    pubnub_future_t fut = pubnub_delete_messages(ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);

    /* 3. Check result. */
    if (PUBNUB_OK == st) {
        printf("Delete OK\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("delete failed: %s (%.*s)\n", pubnub_res_str(st), (int)err.len, err.ptr);
    }

    /* 4. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

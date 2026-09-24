/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/history/fetch_messages_async.c
 * @brief Fetch message history using async callback.
 *
 * Build: cmake --build build/full --target example_history_fetch_messages_async
 * Run:   ./build/full/examples/history/example_history_fetch_messages_async
 */

// snippet.historyFetchMessagesAsync

#include "pubnub/pubnub.h"

#include "pubnub/providers/serialization.h"

#include "../example_common.h"

#include <stdio.h>
#include <stdlib.h>

static volatile int s_done;

static void on_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    pubnub_context_t* ctx = (pubnub_context_t*)user_data;

    if (PUBNUB_OK != status) {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("fetch failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
        pubnub_future_release(future);
        s_done = 1;
        return;
    }

    pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
    pubnub_fetch_messages_result_t   r = pubnub_fetch_messages_result(future);

    for (size_t i = 0; i < r.channel_count; ++i) {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(future, i);
        printf("[%.*s] %u messages\n", (int)ch.name.len, ch.name.ptr, ch.message_count);

        for (size_t j = 0; j < ch.message_count; ++j) {
            pubnub_history_message_result_t msg =
                pubnub_fetch_messages_result_message_at(future, i, j);

            if (NULL != msg.message && NULL != serial
                && NULL != serial->value_as_string) {
                size_t      mlen = 0;
                const char* mptr = serial->value_as_string(msg.message, &mlen);
                if (NULL != mptr) {
                    printf("  %.*s: %.*s\n",
                           (int)msg.timetoken.len,
                           msg.timetoken.ptr,
                           (int)mlen,
                           mptr);
                }
            }
        }
    }

    pubnub_future_release(future);
    s_done = 1;
}

static const char* env_or_default(const char* name, const char* fallback)
{
    const char* value = getenv(name);
    return (NULL != value && '\0' != value[0]) ? value : fallback;
}

int main(void)
{
    const char* sub_key = env_or_default("PUBNUB_SUBSCRIBE_KEY", "demo");
    const char* user_id = env_or_default("PUBNUB_USER_ID", "example-history");
    const char* channel = env_or_default("PUBNUB_CHANNEL", "demo_channel");

    /* 1. Create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = sub_key;
    cfg.user_id         = user_id;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Submit the fetch-messages request. */
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = channel;
    opts.count                        = 25;

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);

    /* 3. Register the async callback. */
    pubnub_res_t rc = pubnub_async(fut, on_complete, ctx);
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

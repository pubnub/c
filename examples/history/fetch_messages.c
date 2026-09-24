/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/history/fetch_messages.c
 * @brief Fetch message history using cooperative polling.
 *
 * Demonstrates batch multi-channel fetch with metadata and
 * file-message detection driven by pubnub_process().
 *
 * Build: cmake --build build/full --target example_history_fetch_messages
 * Run:   ./build/full/examples/history/example_history_fetch_messages
 */

// snippet.historyFetchMessages

#include "pubnub/pubnub.h"

#include "pubnub/providers/serialization.h"

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

    /* 2. Fetch messages from two channels. */
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1,ch2";
    opts.count                        = 10;
    opts.include_meta                 = 1;

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 3. Read results. */
    if (PUBNUB_OK == pubnub_future_status(fut)) {
        pubnub_fetch_messages_result_t r = pubnub_fetch_messages_result(fut);
        for (size_t i = 0; i < r.channel_count; ++i) {
            pubnub_fetch_messages_channel_result_t ch =
                pubnub_fetch_messages_result_channel_at(fut, i);
            printf("[%.*s] %u messages\n", (int)ch.name.len, ch.name.ptr, ch.message_count);

            for (size_t j = 0; j < ch.message_count; ++j) {
                pubnub_history_message_result_t msg =
                    pubnub_fetch_messages_result_message_at(fut, i, j);

                if (PUBNUB_EVENT_TYPE_FILE == msg.event_type) {
                    pubnub_history_file_result_t file =
                        pubnub_fetch_messages_result_file_at(fut, i, j);
                    printf("  FILE %.*s (id=%.*s)\n",
                           (int)file.name.len,
                           file.name.ptr,
                           (int)file.id.len,
                           file.id.ptr);
                } else {
                    pubnub_serialization_provider_t* serial =
                        pubnub_serialization(ctx);
                    if (NULL != msg.message && NULL != serial
                        && NULL != serial->value_as_string) {
                        size_t      mlen = 0;
                        const char* mptr =
                            serial->value_as_string(msg.message, &mlen);
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
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("fetch failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 4. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

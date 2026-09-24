/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/publish/sync.c
 * @brief Blocking-await publish demo.
 *
 * Publishes a single JSON message to a PubNub channel using the
 * blocking `pubnub_await()` API. On platforms with sync primitives
 * this blocks efficiently; on cooperative targets it falls back to a
 * tight `pubnub_process()` loop internally.
 *
 * ## Configuration
 *
 *   PUBNUB_PUBLISH_KEY    (default: demo)
 *   PUBNUB_SUBSCRIBE_KEY  (default: demo)
 *   PUBNUB_USER_ID        (default: example-sync)
 *   PUBNUB_CHANNEL        (default: example_channel)
 *
 * ## Message
 *
 * The first positional argument is the message body (valid JSON):
 *
 *   ./example_publish_sync '"hello from sync"'
 *   ./example_publish_sync '{"text":"hey","ts":1}'
 *
 * Build: cmake --build build/full --target example_publish_sync
 * Run:   ./build/full/examples/publish/example_publish_sync
 */

// snippet.publishSync

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long long monotonic_ms(void)
{
    struct timespec ts;
    if (0 != clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0;
    }
    return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

static const char* env_or_default(const char* name, const char* fallback)
{
    const char* value = getenv(name);
    return (NULL != value && '\0' != value[0]) ? value : fallback;
}

int main(int argc, char** argv)
{
    /* 1. Configure and create the client. */
    const char* pub_key = env_or_default("PUBNUB_PUBLISH_KEY", "demo");
    const char* sub_key = env_or_default("PUBNUB_SUBSCRIBE_KEY", "demo");
    const char* user_id = env_or_default("PUBNUB_USER_ID", "example-sync");
    const char* channel = env_or_default("PUBNUB_CHANNEL", "example_channel");
    const char* message = (argc > 1) ? argv[1] : "\"hello from sync\"";

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = pub_key;
    cfg.subscribe_key   = sub_key;
    cfg.user_id         = user_id;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    printf("Publishing to %s as %s:\n", channel, user_id);
    printf("  message: %s\n", message);

    /* 2. Submit the publish request. */
    const long long submit_ms = monotonic_ms();

    pubnub_future_t fut = pubnub_publish(ctx,
                                         &(pubnub_publish_opts_t){
                                             .channel = channel,
                                             .message = message,
                                         });

    /* 3. Block until complete (pubnub_await drives the process loop internally). */
    const pubnub_res_t status  = pubnub_await(fut);
    const long long    done_ms = monotonic_ms();

    /* 4. Read and print the result. */
    if (PUBNUB_OK == status) {
        printf("Published OK!\n");
        const pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        printf("  timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("publish failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    printf("  elapsed: %lld ms\n", done_ms - submit_ms);

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

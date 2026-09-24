/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/signal/async.c
 * @brief Asynchronous callback signal demo.
 *
 * Sends a signal using `pubnub_async()` to register a completion
 * callback. The callback fires exactly once when the future
 * transitions to a terminal state.
 *
 * On platforms that support threads (PUBNUB_CFG_THREAD_SAFETY=1 and
 * platform->thread_create != NULL), `pubnub_async()` lazily starts
 * a background processing thread -- no manual `pubnub_process()`
 * loop is needed. The main thread simply waits for the callback to
 * fire.
 *
 * On cooperative targets without threads, the user must still drive
 * `pubnub_process()` manually for the callback to fire. This example
 * detects that case and falls back to a process loop.
 *
 * All signal calls also support cooperative polling (pubnub_process
 * loop) and blocking await (pubnub_await) completion styles.
 *
 * ## Configuration
 *
 *   PUBNUB_PUBLISH_KEY    (default: demo)
 *   PUBNUB_SUBSCRIBE_KEY  (default: demo)
 *   PUBNUB_USER_ID        (default: example-signal-async)
 *   PUBNUB_CHANNEL        (default: typing-indicator)
 *
 * ## Message
 *
 * The first positional argument is the message body (valid JSON):
 *
 *   ./example_signal_async '{"typing":true}'
 *
 * Build: cmake --build build/full --target example_signal_async
 * Run:   ./build/full/examples/signal/example_signal_async
 */

// snippet.signalAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static volatile int s_done;
static long long    s_complete_ms;

static long long monotonic_ms(void)
{
    struct timespec ts;
    if (0 != clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0;
    }
    return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

static void on_signal_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;
    s_complete_ms = monotonic_ms();

    if (PUBNUB_OK == status) {
        printf("  [callback] Signal sent!\n");
        const pubnub_timetoken_t tt = pubnub_signal_result_timetoken(future);
        printf("  [callback] timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("  [callback] signal failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    pubnub_future_release(future);
    s_done = 1;
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
    const char* user_id = env_or_default("PUBNUB_USER_ID", "example-signal-async");
    const char* channel = env_or_default("PUBNUB_CHANNEL", "typing-indicator");
    const char* message = (argc > 1) ? argv[1] : "{\"typing\":true}";

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = pub_key;
    cfg.subscribe_key   = sub_key;
    cfg.user_id         = user_id;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    printf("Signalling on %s as %s:\n", channel, user_id);
    printf("  message: %s\n", message);

    /* 2. Submit the signal request. */
    const long long submit_ms = monotonic_ms();

    pubnub_signal_opts_t opts = PUBNUB_SIGNAL_OPTS_INIT;
    opts.channel              = channel;
    opts.message              = message;

    pubnub_future_t fut = pubnub_signal(ctx, &opts);

    /* 3. Register the async callback. */
    pubnub_res_t rc = pubnub_async(fut, on_signal_complete, NULL);
    if (PUBNUB_OK != rc) {
        printf("pubnub_async registration failed: %s\n", pubnub_res_str(rc));
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

    printf("  elapsed: %lld ms\n", s_complete_ms - submit_ms);

    /* 5. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/time/async.c
 * @brief Fetch PubNub server time using async callback completion.
 *
 * Demonstrates pubnub_async(): register a callback, then pump I/O
 * until the callback fires. With PUBNUB_CFG_THREAD_SAFETY=1 a
 * background thread drives I/O automatically; otherwise the caller
 * must call pubnub_process() in a loop.
 *
 * Cooperative polling (pubnub_process) and blocking await
 * (pubnub_await) are equally valid completion styles.
 *
 * Build: cmake --build build/full --target example_time_async
 * Run:   ./build/full/examples/time/example_time_async
 */

// snippet.timeAsync

#include "pubnub/pubnub.h"

#include "../example_common.h"

#include <stdio.h>

static volatile int s_done;

static void on_time_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;

    if (PUBNUB_OK == status) {
        const pubnub_timetoken_t tt = pubnub_time_result_timetoken(future);
        printf("Server time: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("Time request failed (%s): %.*s\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    pubnub_future_release(future);
    s_done = 1;
}

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-time-async";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Request server time. */
    pubnub_future_t fut = pubnub_time(ctx);

    /* 3. Register the async callback.
     *    On threaded builds the background thread drives I/O --
     *    no pubnub_process() loop is needed. On cooperative builds
     *    we still pump as a fallback. */
    const pubnub_res_t rc = pubnub_async(fut, on_time_complete, NULL);
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
        pubnub_process(ctx);
        PUBNUB_EXAMPLE_SLEEP_MS(10);
    }

    /* 5. Cleanup -- future was released in callback. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

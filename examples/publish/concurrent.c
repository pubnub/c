/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/publish/concurrent.c
 * @brief Publish multiple messages concurrently and wait for all to
 *        complete using cooperative polling.
 *
 * Demonstrates:
 *   1. Configuring a PubNub client context.
 *   2. Submitting several publishes back-to-back (concurrent dispatch).
 *   3. Driving a cooperative poll loop until every future is ready.
 *
 * Build: cmake --build build/full --target example_publish_concurrent
 * Run:   ./build/full/examples/publish/example_publish_concurrent
 */

// snippet.publishConcurrent

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <string.h>

#define MESSAGE_COUNT 3

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-concurrent";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Submit several publishes before polling. Each call returns a
     *    future immediately; the requests fly concurrently up to the
     *    PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS limit. */
    pubnub_future_t futures[MESSAGE_COUNT];
    char            messages[MESSAGE_COUNT][48];

    for (int i = 0; i < MESSAGE_COUNT; i++) {
        snprintf(
            messages[i], sizeof(messages[i]), "{\"idx\":%d,\"msg\":\"hello\"}", i);
        futures[i] = pubnub_publish(ctx,
                                    &(pubnub_publish_opts_t){
                                        .channel = "demo_channel",
                                        .message = messages[i],
                                    });
    }

    /* 3. Cooperative poll loop: drive I/O until every future is done. */
    int remaining = MESSAGE_COUNT;
    int completed[MESSAGE_COUNT];
    memset(completed, 0, sizeof(completed));

    while (remaining > 0) {
        pubnub_process(ctx);

        for (int i = 0; i < MESSAGE_COUNT; i++) {
            if (!completed[i] && pubnub_future_is_ready(futures[i])) {
                completed[i] = 1;
                remaining--;
            }
        }
    }

    /* 4. Check results and release futures. */
    for (int i = 0; i < MESSAGE_COUNT; i++) {
        const pubnub_res_t status = pubnub_future_status(futures[i]);
        if (PUBNUB_OK == status) {
            printf("publish %d: OK\n", i);
        } else {
            printf("publish %d: error %d\n", i, (int)status);
        }
        pubnub_future_release(futures[i]);
    }

    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

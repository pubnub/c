/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/getting_started/getting_started.c
 * @brief The end-to-end getting-started program: configure, listen,
 *        subscribe, publish, receive, shut down.
 *
 * Six contiguous, non-overlapping snippets cover the whole file in
 * order. Request one for a single tutorial step, or all six in sequence
 * for the complete program:
 *
 *   gettingStartedIncludes
 *   gettingStartedListener
 *   gettingStartedConfigure
 *   gettingStartedSubscribe
 *   gettingStartedPublish
 *   gettingStartedTeardown
 *
 * The snippet extractor cannot nest markers, which is why there is no
 * separate whole-program id.
 *
 * See subscribe/callback.c for a richer version that also handles
 * presence and App Context events and reads its keys from the
 * environment.
 *
 * Build: cmake --build build/full --target example_getting_started
 * Run:   ./build/full/examples/getting_started/example_getting_started
 */

// snippet.gettingStartedIncludes

#include "pubnub/pubnub.h"

#include "pubnub/providers/serialization.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// snippet.gettingStartedListener

/** State threaded through the listener callbacks via user_data. */
typedef struct app_state {
    pubnub_context_t* ctx;
    int               connected;
    int               message_received;
} app_state_t;

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    app_state_t* state = (app_state_t*)user_data;

    /* Only a context-global listener receives status events. */
    if (PUBNUB_SUBSCRIBE_STATUS_CONNECTED == event->status) {
        printf("STATUS: connected\n");
        state->connected = 1;
    } else {
        printf("STATUS: %d (%s)\n", (int)event->status, pubnub_res_str(event->reason));
        state->connected = 0;
    }
}

static void on_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    app_state_t* state      = (app_state_t*)user_data;
    state->message_received = 1;

    /* The generic event carries a discriminant. The typed extractor
     * checks it and decodes the payload. */
    pubnub_subscribe_message_event_t msg;
    if (PUBNUB_OK != pubnub_subscribe_event_message(state->ctx, event, &msg)) {
        printf("MSG [parse error]\n");
        return;
    }

    printf("MSG [%.*s]: ", (int)msg.channel.len, msg.channel.ptr);

    /* Payloads are JSON nodes, read through the serialization vtable.
     * Every vtable entry is individually optional, so NULL-check each
     * one, and copy any bytes you need before this callback returns. */
    if (NULL != msg.message) {
        pubnub_serialization_provider_t* serial = pubnub_serialization(state->ctx);
        if (NULL != serial && NULL != serial->value_as_string) {
            size_t      len = 0;
            const char* val = serial->value_as_string(msg.message, &len);
            if (NULL != val) {
                printf("%.*s", (int)len, val);
            }
        }
    }
    printf("\n");
}

// snippet.gettingStartedConfigure

int main(void)
{
    int         status = 0;
    app_state_t state  = {.ctx = NULL, .connected = 0, .message_received = 0};

    /* 1. Configure and create the client. pubnub_config_defaults() seeds
     * timeouts, keepalive, the retry policy, and the log level. It does
     * not set the keys or the user id, so those are always yours. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "my_unique_user_id";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return EXIT_FAILURE;
    }
    state.ctx = ctx;

    // snippet.gettingStartedSubscribe

    /* 2. Register the listener before subscribing so no event is missed. */
    pubnub_subscribe_listener_t listener = {
        .on_status  = on_status,
        .on_message = on_message,
        .user_data  = &state,
    };

    pubnub_listener_handle_t lh = pubnub_add_listener(ctx, &listener);
    if (PUBNUB_LISTENER_HANDLE_INVALID == lh) {
        printf("Failed to register listener\n");
        status = 1;
        goto cleanup_context;
    }

    /* 3. Create a channel entity, then a subscription from it. The entity
     * is only an input to the subscription and can be destroyed at once. */
    pubnub_entity_t entity = pubnub_channel(ctx, "my_channel");
    if (NULL == entity) {
        printf("Failed to create channel entity\n");
        status = 1;
        goto cleanup_listener;
    }

    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    if (NULL == sub) {
        printf("Failed to create subscription\n");
        status = 1;
        goto cleanup_listener;
    }

    /* 4. Activate it, then drive the event loop until on_status reports
     * that the handshake completed. */
    pubnub_res_t rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        printf("subscribe failed: %s\n", pubnub_res_str(rc));
        status = 1;
        goto cleanup_subscription;
    }

    {
        const struct timespec nap = {.tv_sec = 0, .tv_nsec = 10000000L};
        const time_t          handshake_start = time(NULL);
        while (!state.connected) {
            pubnub_process(ctx);
            if (difftime(time(NULL), handshake_start) > 10.0) {
                printf("Handshake timeout, giving up.\n");
                status = 1;
                goto cleanup_subscription;
            }
            nanosleep(&nap, NULL);
        }
    }

    // snippet.gettingStartedPublish

    /* 5. Publish. The message echoes back through the subscribe stream
     * and reaches on_message above. pubnub_await() drives
     * pubnub_process() internally, so no polling loop is needed here. */
    pubnub_future_t pub_future =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel = "my_channel",
                           .message = "\"Hello, world!\"",
                       });

    const pubnub_res_t pub_rc = pubnub_await(pub_future);
    if (PUBNUB_OK != pub_rc) {
        printf("publish failed: %s\n", pubnub_res_str(pub_rc));
    }
    pubnub_future_release(pub_future);

    // snippet.gettingStartedTeardown

    /* 6. Wait for the echo to arrive. */
    {
        const struct timespec nap        = {.tv_sec = 0, .tv_nsec = 10000000L};
        const time_t          wait_start = time(NULL);
        while (!state.message_received) {
            pubnub_process(ctx);
            if (difftime(time(NULL), wait_start) > 5.0) {
                printf("Timed out waiting for the message.\n");
                break;
            }
            nanosleep(&nap, NULL);
        }
    }

    /* 7. Shut down in order: unsubscribe, destroy the subscription,
     * remove the listener, destroy the context. */
    pubnub_subscription_unsubscribe(sub);
cleanup_subscription:
    pubnub_subscription_destroy(sub);
cleanup_listener:
    pubnub_remove_listener(ctx, lh);
cleanup_context:
    pubnub_destroy(ctx);

    return status;
}

// snippet.end

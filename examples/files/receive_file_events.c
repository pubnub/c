/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/receive_file_events.c
 * @brief Receive file-share events through the subscribe stream.
 *
 * A file message arrives on the on_file listener callback as a generic
 * pubnub_subscribe_event_t. pubnub_subscribe_event_file() checks the
 * discriminant is PUBNUB_SUBSCRIBE_FILE and decodes it into the typed
 * struct. Every string view and the message JSON node are valid only
 * inside the callback, so copy anything you need to keep.
 *
 * Build: cmake --build build/full --target example_files_receive_file_events
 * Run:   ./build/full/examples/files/example_files_receive_file_events
 */

// snippet.filesReceiveFileEvents

#include "pubnub/pubnub.h"

#include <stdio.h>

#define WAIT_ITERATIONS 200000

static void on_file(const pubnub_subscribe_event_t* event, void* user_data)
{
    pubnub_context_t* ctx = (pubnub_context_t*)user_data;

    /* The extractor rejects any event whose type is not
     * PUBNUB_SUBSCRIBE_FILE, so this doubles as the type check. */
    pubnub_subscribe_file_event_t file;
    if (PUBNUB_OK != pubnub_subscribe_event_file(ctx, event, &file)) {
        printf("FILE [decode error]\n");
        return;
    }

    printf("FILE [%.*s] from %.*s: %.*s (id=%.*s) at %.*s\n",
           (int)file.channel.len,
           file.channel.ptr,
           (int)file.publisher.len,
           file.publisher.ptr,
           (int)file.file_name.len,
           file.file_name.ptr,
           (int)file.file_id.len,
           file.file_id.ptr,
           (int)file.timetoken.len,
           file.timetoken.ptr);

    /* file.message is the JSON the publisher attached, or NULL. Read it
     * through the serialization provider vtable. */
    if (NULL != file.message) {
        pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
        if (NULL != serial && NULL != serial->object_get
            && NULL != serial->value_as_string) {
            const pubnub_json_value_t* caption =
                serial->object_get(file.message, "caption", 7);
            size_t      len = 0;
            const char* val =
                (NULL != caption) ? serial->value_as_string(caption, &len) : NULL;
            if (NULL != val) {
                printf("  caption = %.*s\n", (int)len, val);
            }
        }
    }
}

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-events";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. Register a listener with only the file callback set. Unset
     * callbacks are simply never invoked. */
    pubnub_subscribe_listener_t listener = {0};
    listener.on_file                     = on_file;
    listener.user_data                   = ctx;

    pubnub_listener_handle_t lh = pubnub_add_listener(ctx, &listener);
    if (PUBNUB_LISTENER_HANDLE_INVALID == lh) {
        printf("Failed to register listener\n");
        pubnub_destroy(ctx);
        return 1;
    }

    /* 2. Subscribe to the channel that carries the file messages. */
    pubnub_entity_t       entity = pubnub_channel(ctx, "demo_channel");
    pubnub_subscription_t sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);

    pubnub_subscription_subscribe(sub);

    /* 3. Drive the event loop so callbacks can fire. */
    for (long i = 0; i < WAIT_ITERATIONS; ++i) {
        pubnub_process(ctx);
    }

    /* 4. Cleanup. */
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(ctx, lh);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

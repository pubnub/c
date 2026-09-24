/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/subscribe/callback.c
 * @brief Listener callback subscribe demo with publish echo.
 *
 * Subscribes to a channel, then publishes several messages to the
 * same channel and observes them arriving back through the subscribe
 * stream. Demonstrates:
 *
 *   - Typed listener callbacks for message, presence, objects, and
 *     status events.
 *   - Using typed event accessors (pubnub_subscribe_event_message,
 *     pubnub_subscribe_event_presence, pubnub_subscribe_event_app_context).
 *   - Blocking `pubnub_await()` for the publish operations.
 *   - Cooperative polling to receive subscribe events.
 *   - Using publish and subscribe on the same context.
 *
 * ## Configuration
 *
 *   PUBNUB_PUBLISH_KEY    (default: demo)
 *   PUBNUB_SUBSCRIBE_KEY  (default: demo)
 *   PUBNUB_USER_ID        (default: example-subscribe-cb)
 *   PUBNUB_CHANNEL        (default: echo-channel)
 *
 * ## Expected output
 *
 *   [callback] Subscribing to "echo-channel"...
 *   STATUS: connected
 *   [callback] Publishing 3 messages...
 *   MSG [echo-channel]: "Hello #1"
 *   MSG [echo-channel]: "Hello #2"
 *   MSG [echo-channel]: "Hello #3"
 *   [callback] Received 3/3 messages. Done.
 *
 * Build: cmake --build build/full --target example_subscribe_callback
 * Run:   ./build/full/examples/subscribe/example_subscribe_callback
 */

// snippet.subscribeCallback

#include "pubnub/pubnub.h"

#include "pubnub/providers/serialization.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_MESSAGES 3
#define WAIT_SECONDS 5

/** Application state shared between callbacks and main. */
typedef struct app_state {
    pubnub_context_t* ctx;
    int               connected;
    int               messages_received;
} app_state_t;

static const char* env_or_default(const char* name, const char* fallback)
{
    const char* value = getenv(name);
    return (NULL != value && '\0' != value[0]) ? value : fallback;
}

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    app_state_t* state = (app_state_t*)user_data;

    switch (event->status) {
    case PUBNUB_SUBSCRIBE_STATUS_CONNECTED:
        printf("STATUS: connected\n");
        state->connected = 1;
        break;
    case PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED:
        printf("STATUS: disconnected\n");
        state->connected = 0;
        break;
    case PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY:
        printf("STATUS: disconnected unexpectedly (%s)\n",
               pubnub_res_str(event->reason));
        state->connected = 0;
        break;
    case PUBNUB_SUBSCRIBE_STATUS_CONNECTION_ERROR:
        printf("STATUS: connection error (%s)\n", pubnub_res_str(event->reason));
        state->connected = 0;
        break;
    case PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED:
        printf("STATUS: subscription changed\n");
        break;
    }
}

static void on_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    app_state_t* state = (app_state_t*)user_data;
    state->messages_received++;

    pubnub_subscribe_message_event_t msg;
    if (PUBNUB_OK != pubnub_subscribe_event_message(state->ctx, event, &msg)) {
        printf("MSG [parse error]\n");
        return;
    }

    printf("MSG [%.*s] from \"%.*s\": ",
           (int)msg.channel.len,
           msg.channel.ptr,
           (int)msg.publisher.len,
           msg.publisher.ptr);

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

static void on_presence(const pubnub_subscribe_event_t* event, void* user_data)
{
    app_state_t* state = (app_state_t*)user_data;

    pubnub_subscribe_presence_event_t pres;
    if (PUBNUB_OK != pubnub_subscribe_event_presence(state->ctx, event, &pres)) {
        printf("PRES [parse error]\n");
        return;
    }

    switch (pres.action) {
    case PUBNUB_PRESENCE_JOIN:
        printf("PRES [%.*s]: join by %.*s (occupancy: %u)\n",
               (int)pres.channel.len,
               pres.channel.ptr,
               (int)pres.uuid.len,
               pres.uuid.ptr,
               (unsigned)pres.occupancy);
        break;
    case PUBNUB_PRESENCE_LEAVE:
        printf("PRES [%.*s]: leave by %.*s (occupancy: %u)\n",
               (int)pres.channel.len,
               pres.channel.ptr,
               (int)pres.uuid.len,
               pres.uuid.ptr,
               (unsigned)pres.occupancy);
        break;
    case PUBNUB_PRESENCE_TIMEOUT:
        printf("PRES [%.*s]: timeout for %.*s (occupancy: %u)\n",
               (int)pres.channel.len,
               pres.channel.ptr,
               (int)pres.uuid.len,
               pres.uuid.ptr,
               (unsigned)pres.occupancy);
        break;
    case PUBNUB_PRESENCE_STATE_CHANGE:
        printf("PRES [%.*s]: state-change by %.*s\n",
               (int)pres.channel.len,
               pres.channel.ptr,
               (int)pres.uuid.len,
               pres.uuid.ptr);
        /* Access user-set state via the serialization vtable. */
        if (NULL != pres.state) {
            pubnub_serialization_provider_t* serial =
                pubnub_serialization(state->ctx);
            if (NULL != serial && NULL != serial->object_get) {
                const pubnub_json_value_t* mood =
                    serial->object_get(pres.state, "mood", 4);
                if (NULL != mood) {
                    size_t      len = 0;
                    const char* val = serial->value_as_string(mood, &len);
                    if (NULL != val) {
                        printf("  state.mood = %.*s\n", (int)len, val);
                    }
                }
            }
        }
        break;
    case PUBNUB_PRESENCE_INTERVAL:
        printf("PRES [%.*s]: interval (occupancy: %u)\n",
               (int)pres.channel.len,
               pres.channel.ptr,
               (unsigned)pres.occupancy);
        /* Access joined UUIDs from interval event. */
        if (NULL != pres.joined) {
            pubnub_serialization_provider_t* serial =
                pubnub_serialization(state->ctx);
            if (NULL != serial && NULL != serial->array_size) {
                size_t count = serial->array_size(pres.joined);
                printf("  %zu joined: ", count);
                for (size_t i = 0; i < count && NULL != serial->array_get; i++) {
                    const pubnub_json_value_t* elem =
                        serial->array_get(pres.joined, i);
                    size_t      len = 0;
                    const char* val = serial->value_as_string(elem, &len);
                    if (NULL != val) {
                        printf("%.*s ", (int)len, val);
                    }
                }
                printf("\n");
            }
        }
        break;
    }
}

static void on_app_context(const pubnub_subscribe_event_t* event, void* user_data)
{
    app_state_t* state = (app_state_t*)user_data;

    pubnub_subscribe_app_context_event_t obj;
    if (PUBNUB_OK != pubnub_subscribe_event_app_context(state->ctx, event, &obj)) {
        printf("OBJ [parse error]\n");
        return;
    }

    const char* action = (PUBNUB_APP_CONTEXT_SET == obj.event) ? "set" : "removed";
    const char* type_str;
    switch (obj.object_type) {
    case PUBNUB_APP_CONTEXT_OBJECT_UUID: type_str = "uuid"; break;
    case PUBNUB_APP_CONTEXT_OBJECT_CHANNEL: type_str = "channel"; break;
    case PUBNUB_APP_CONTEXT_OBJECT_MEMBERSHIP: type_str = "membership"; break;
    default: type_str = "unknown"; break;
    }

    printf("OBJ [%.*s]: %s %s\n", (int)obj.channel.len, obj.channel.ptr, action, type_str);

    /* Access the data node for the object's fields. */
    if (NULL != obj.data) {
        pubnub_serialization_provider_t* serial = pubnub_serialization(state->ctx);
        if (NULL != serial && NULL != serial->object_get) {
            const pubnub_json_value_t* id_node =
                serial->object_get(obj.data, "id", 2);
            if (NULL != id_node) {
                size_t      len = 0;
                const char* val = serial->value_as_string(id_node, &len);
                if (NULL != val) {
                    printf("  id = %.*s\n", (int)len, val);
                }
            }
        }
    }
}

int main(void)
{
    /* 1. Configure and create the client. */
    const char* pub_key = env_or_default("PUBNUB_PUBLISH_KEY", "demo");
    const char* sub_key = env_or_default("PUBNUB_SUBSCRIBE_KEY", "demo");
    const char* user_id = env_or_default("PUBNUB_USER_ID", "example-subscribe-cb");
    const char* channel = env_or_default("PUBNUB_CHANNEL", "echo-channel");
    int         status  = 0;

    app_state_t state = {.ctx = NULL, .connected = 0, .messages_received = 0};

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = pub_key;
    cfg.subscribe_key   = sub_key;
    cfg.user_id         = user_id;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("[callback] pubnub_create failed\n");
        return 1;
    }
    state.ctx = ctx;

    /* 2. Register event listeners. */
    pubnub_subscribe_listener_t listener = {
        .on_status      = on_status,
        .on_message     = on_message,
        .on_presence    = on_presence,
        .on_app_context = on_app_context,
        .user_data      = &state,
    };

    pubnub_listener_handle_t lh = pubnub_add_listener(ctx, &listener);
    if (PUBNUB_LISTENER_HANDLE_INVALID == lh) {
        printf("[callback] Failed to register listener\n");
        status = 1;
        goto cleanup_context;
    }

    /* 3. Create a channel entity and subscription. */
    pubnub_entity_t entity = pubnub_channel(ctx, channel);
    if (NULL == entity) {
        printf("[callback] Failed to create channel entity\n");
        status = 1;
        goto cleanup_listener;
    }

    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    if (NULL == sub) {
        printf("[callback] Failed to create subscription\n");
        status = 1;
        goto cleanup_listener;
    }

    /* 4. Subscribe and wait for the handshake. */
    printf("[callback] Subscribing to \"%s\"...\n", channel);

    pubnub_res_t rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        printf("[callback] subscribe failed: %s\n", pubnub_res_str(rc));
        status = 1;
        goto cleanup_subscription;
    }

    /* Wait for the handshake to complete (status=CONNECTED).
     * Drive pubnub_process() until the on_status callback sets the
     * connected flag. */
    const struct timespec nap = {.tv_sec = 0, .tv_nsec = 10000000L};
    {
        const time_t handshake_start = time(NULL);
        while (!state.connected) {
            pubnub_process(ctx);
            if (difftime(time(NULL), handshake_start) > 10.0) {
                printf("[callback] Handshake timeout — giving up.\n");
                status = 1;
                goto cleanup_subscription;
            }
            nanosleep(&nap, NULL);
        }
    }

    /* 5. Publish messages (they echo back via subscribe). */
    printf("[callback] Publishing %d messages...\n", NUM_MESSAGES);

    const char* messages[NUM_MESSAGES] = {
        "\"Hello #1\"",
        "\"Hello #2\"",
        "\"Hello #3\"",
    };

    for (int i = 0; i < NUM_MESSAGES; i++) {
        pubnub_future_t fut = pubnub_publish(ctx,
                                             &(pubnub_publish_opts_t){
                                                 .channel = channel,
                                                 .message = messages[i],
                                             });

        /* Block until the publish completes. pubnub_await() drives
         * pubnub_process() internally. */
        pubnub_res_t pub_rc = pubnub_await(fut);
        if (PUBNUB_OK != pub_rc) {
            printf("[callback] Publish #%d failed: %s\n",
                   i + 1,
                   pubnub_res_str(pub_rc));
        }
        pubnub_future_release(fut);
    }

    /* 6. Wait for all messages to arrive through subscribe. */
    const time_t wait_start = time(NULL);
    while (state.messages_received < NUM_MESSAGES) {
        pubnub_process(ctx);
        if (difftime(time(NULL), wait_start) > (double)WAIT_SECONDS) {
            break;
        }
        nanosleep(&nap, NULL);
    }

    printf("[callback] Received %d/%d messages. Done.\n",
           state.messages_received,
           NUM_MESSAGES);

    /* 7. Clean shutdown. */
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

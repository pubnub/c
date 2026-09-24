/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * Arena allocator integration demo — subscribe/publish loop.
 *
 * Subscribes to arena-echo-in; on each received message publishes the
 * received timetoken to arena-echo-out. Runs in a cooperative event loop
 * with zero heap allocations — the context struct itself is carved from
 * the static arena pool.
 *
 * Build:
 *   cmake --preset embedded -DPUBNUB_BUILD_EXAMPLES=ON
 *   cmake --build build/embedded --target example_arena_echo
 */

// snippet.arenaEcho

#include "pubnub/client.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/providers/allocator_arena.h"
#include <stdio.h>
#include <string.h>

// snippet.hide
#if !defined(PUBNUB_PLATFORM_FREERTOS) && !defined(ESP_PLATFORM) \
    && !defined(FREERTOS)
/* On hosted builds (Linux/macOS/Windows CI), the embedded preset selects the
 * freertos provider, which returns an all-NULL stub. Explicitly set
 * cfg.platform to POSIX (linked via CMakeLists.txt) so init succeeds. */
extern pubnub_platform_provider_t* pn_platform_default(void);
#endif
// snippet.show

#define ECHO_CHANNEL_IN  "arena-echo-in"
#define ECHO_CHANNEL_OUT "arena-echo-out"
#define USER_ID          "arena-echo-device-01"

/* Static arena backing pool — no malloc anywhere. */
static uint8_t                  s_pool[PUBNUB_CFG_ARENA_POOL_SIZE];
static pubnub_arena_allocator_t s_arena;

/* Static context storage — size determined at CMake configure time.
 * PUBNUB_ALIGNAS ensures the buffer satisfies struct alignment on all
 * targets; without it, casting to pubnub_context_t* is UB on
 * Cortex-M0 and other strictly-aligned architectures.
 * PUBNUB_STATIC_ASSERT in client.c validates PUBNUB_CONTEXT_SIZE
 * stays above sizeof(struct pubnub_context). */
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

/** App state threaded through listener callbacks. */
typedef struct echo_state {
    pubnub_context_t* ctx;
    volatile int      running;
} echo_state_t;

static void on_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    echo_state_t* state = (echo_state_t*)user_data;

    /* LED control messages: no LED on hosted builds — skip silently. */
    if (3 == event->custom_message_type.len
        && NULL != event->custom_message_type.ptr
        && 0 == memcmp(event->custom_message_type.ptr, "led", 3)) {
        return;
    }

    /* Echo back the received payload verbatim. */
    if (NULL == event->payload) {
        return; /* message was dropped (OOM parse) */
    }
    pubnub_serialization_provider_t* serial = pubnub_serialization(state->ctx);
    if (NULL == serial || NULL == serial->serialize) {
        return;
    }
    char   response[512];
    size_t len = 0;
    if (PUBNUB_OK
            != serial->serialize(
                serial, event->payload, (uint8_t*)response, sizeof(response) - 1, &len)
        || 0 == len) {
        return;
    }
    response[len] = '\0';

    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = ECHO_CHANNEL_OUT;
    opts.message               = response;
    opts.message_len           = len;

    pubnub_future_t pub = pubnub_publish(state->ctx, &opts);
    if (PUBNUB_IN_PROGRESS != pub.status) {
        printf("[echo] publish dropped: queue full\n");
    }
    pubnub_future_release(pub);
}

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    (void)user_data;
    if (PUBNUB_OK != event->reason) {
        /* Log or handle connection errors here. */
    }
}

int main(void)
{
    /* Initialise arena-backed allocator from a static pool. */
    pubnub_allocator_provider_t* alloc =
        pubnub_arena_allocator_init(&s_arena, s_pool, sizeof(s_pool));

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.publish_key     = "demo";
    cfg.user_id         = USER_ID;
    cfg.allocator       = alloc;

    // snippet.hide
#if !defined(PUBNUB_PLATFORM_FREERTOS) && !defined(ESP_PLATFORM) \
    && !defined(FREERTOS)
    cfg.platform = pn_platform_default();
#endif
    // snippet.show

    /* Use caller-provided static storage: no heap call, no arena slice. */
    pubnub_context_t* ctx = (pubnub_context_t*)s_ctx_mem;
    if (sizeof(s_ctx_mem) < pubnub_context_size()) {
        return 1; /* PUBNUB_CONTEXT_SIZE too small — rebuild needed */
    }
    pubnub_res_t rc = pubnub_init(ctx, &cfg);
    if (PUBNUB_OK != rc) {
        return 1;
    }

    echo_state_t state = {.ctx = ctx, .running = 1};

    /* Register message and status listeners. */
    pubnub_subscribe_listener_t listener = {0};
    listener.on_message                  = on_message;
    listener.on_status                   = on_status;
    listener.user_data                   = &state;
    pubnub_listener_handle_t lh          = pubnub_add_listener(ctx, &listener);

    /* Create channel entity and subscription. */
    pubnub_entity_t       entity = pubnub_channel(ctx, ECHO_CHANNEL_IN);
    pubnub_subscription_t sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);

    pubnub_subscription_subscribe(sub);

    /* Cooperative event loop — replace with vTaskDelay on FreeRTOS. */
    while (state.running) {
        pubnub_process(ctx);
    }

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(ctx, lh);
    pubnub_deinit(ctx);
    return 0;
}

// snippet.end

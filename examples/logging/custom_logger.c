/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/logging/custom_logger.c
 * @brief Implement and register a custom logger provider.
 *
 * Two snippets live here:
 *
 *   loggingCustomLogger -- the pubnub_logger_provider_t vtable, with a
 *       ring buffer standing in for a real sink.
 *   loggingRegisterLogger -- pubnub_logger_add, pubnub_logger_remove,
 *       and pubnub_logger_remove_all.
 *
 * The logger is a shared provider: the SDK never allocates it, frees it,
 * or calls lifecycle hooks on it. You own it and it must outlive every
 * context that holds a reference, or be removed first.
 *
 * Build: cmake --build build/full --target example_logging_custom_logger
 * Run:   ./build/full/examples/logging/example_logging_custom_logger
 */

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <string.h>

// snippet.loggingCustomLogger

#define RING_CAPACITY    16
#define SUMMARY_CAPACITY 64

/* The vtable must be the first member so `self` can be cast back to this
 * type inside the callbacks. */
typedef struct ring_logger {
    pubnub_logger_provider_t base;
    char                     summaries[RING_CAPACITY][SUMMARY_CAPACITY];
    pubnub_log_level_t       levels[RING_CAPACITY];
    size_t                   next;
    size_t                   total;
} ring_logger_t;

static void ring_log(pubnub_logger_provider_t* self, const pubnub_log_entry_t* entry)
{
    ring_logger_t* ring = (ring_logger_t*)self;
    const char*    text = NULL;

    /* Dispatch on entry->type and down-cast. Every concrete entry type
     * carries pubnub_log_entry_t as its first member. */
    switch (entry->type) {
    case PUBNUB_LOG_ENTRY_TEXT:
        text = ((const pubnub_log_entry_text_t*)entry)->message;
        break;
    case PUBNUB_LOG_ENTRY_OBJECT:
        text = ((const pubnub_log_entry_object_t*)entry)->label;
        break;
    case PUBNUB_LOG_ENTRY_ERROR:
        text = ((const pubnub_log_entry_error_t*)entry)->error_message;
        break;
    case PUBNUB_LOG_ENTRY_NET_REQ:
        text = ((const pubnub_log_entry_net_request_t*)entry)->url;
        break;
    case PUBNUB_LOG_ENTRY_NET_RESP:
        text = ((const pubnub_log_entry_net_response_t*)entry)->url;
        break;
    default: break;
    }

    /* The entry and everything it points at die when this call returns,
     * so copy rather than store the pointer. */
    ring->levels[ring->next] = entry->level;
    if (NULL != text) {
        strncpy(ring->summaries[ring->next], text, SUMMARY_CAPACITY - 1);
        ring->summaries[ring->next][SUMMARY_CAPACITY - 1] = '\0';
    } else {
        ring->summaries[ring->next][0] = '\0';
    }
    ring->next = (ring->next + 1) % RING_CAPACITY;
    ring->total++;

    /* The per-context mutex may be held here. Never call back into the
     * SDK on this context: printf, a write(2), a ring-buffer enqueue, or
     * a semaphore signal to a logging thread are the safe options. */
}

static void ring_set_level(pubnub_logger_provider_t* self,
                           pubnub_log_level_t        min_level)
{
    /* Optional. The SDK already applied its runtime threshold before
     * calling log(), so a provider that does no filtering of its own can
     * leave this NULL instead. */
    (void)self;
    (void)min_level;
}

// snippet.end

// snippet.loggingRegisterLogger

int main(void)
{
    ring_logger_t ring  = {0};
    ring.base.log       = ring_log;
    ring.base.set_level = ring_set_level;

    /* 1. cfg.logger registers a provider at creation time, alongside the
     * compiled-in default. Setting it is equivalent to calling
     * pubnub_logger_add() immediately after pubnub_create(). */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-logging-custom";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Add the provider. Every registered provider receives every
     * entry that passes the runtime threshold. PUBNUB_ERR_QUEUE_FULL
     * means the context already holds PUBNUB_CFG_MAX_LOGGERS providers. */
    pubnub_res_t rc = pubnub_logger_add(ctx, &ring.base);
    if (PUBNUB_OK != rc) {
        printf("logger_add failed: %s\n", pubnub_res_str(rc));
        pubnub_destroy(ctx);
        return 1;
    }

    pubnub_log_text(ctx, PUBNUB_LOG_LEVEL_INFO, "client initialized");
    pubnub_log_error(ctx, (int)PUBNUB_ERR_TIMEOUT, "publish timed out", NULL);

    printf("Captured %zu entries:\n", ring.total);
    for (size_t i = 0; i < ring.total && i < RING_CAPACITY; ++i) {
        printf("  [0x%02X] %s\n", (unsigned)ring.levels[i], ring.summaries[i]);
    }

    /* 3. Remove before the provider goes out of scope. Use
     * pubnub_logger_remove_all() to drop every sink at once, or
     * pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_NONE) to go quiet
     * without unregistering anything. */
    pubnub_logger_remove(ctx, &ring.base);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

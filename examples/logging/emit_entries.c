/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/logging/emit_entries.c
 * @brief Emit application log entries through the context's logger.
 *
 * Two snippets live here:
 *
 *   loggingEmitEntries -- the four entry-emitting calls in pubnub/log.h.
 *   loggingStructuredValues -- building a pubnub_log_value_t map for
 *       pubnub_log_object() without allocating.
 *
 * Every call is a no-op when the context is NULL or when the level was
 * stripped by PUBNUB_CFG_LOG_LEVEL_COMPILED, so no guard is required for
 * correctness. Guard anyway when building the value tree costs work you
 * would rather not pay on a stack-constrained target.
 *
 * Build: cmake --build build/full --target example_logging_emit_entries
 * Run:   ./build/full/examples/logging/example_logging_emit_entries
 */

#include "pubnub/pubnub.h"

#include <stdio.h>

// snippet.loggingStructuredValues

/* Log a map of request parameters. Every node lives on this frame: the
 * logger reads the tree during the call and never retains a pointer into
 * it, so stack storage is correct and no allocation is needed. */
static void log_request_params(pubnub_context_t* ctx,
                               const char*       channel,
                               int               store,
                               unsigned          ttl)
{
#if PUBNUB_LOG_ENABLED(DEBUG)
    /* A map is a linked list of entry nodes, so the head starts NULL.
     * The PUBNUB_LOG_MAP_SET_* macros declare the node pair for you and
     * prepend it, which is why each key must be a valid identifier. */
    pubnub_log_value_t* head = pubnub_log_value_map_init();
    PUBNUB_LOG_MAP_SET_STRING(head, channel, channel)
    PUBNUB_LOG_MAP_SET_NUMBER(head, (int64_t)store, store)
    PUBNUB_LOG_MAP_SET_BOOL(head, 0 != ttl, has_ttl)

    pubnub_log_object(ctx, PUBNUB_LOG_LEVEL_DEBUG, "publish params", head);
#else
    (void)ctx;
    (void)channel;
    (void)store;
    (void)ttl;
#endif
}

// snippet.end

// snippet.loggingEmitEntries

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-logging-emit";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. A plain text entry. */
    pubnub_log_text(ctx, PUBNUB_LOG_LEVEL_INFO, "device firmware 2.4.1 starting");

    /* 2. printf-style formatting into a stack buffer of
     * PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE bytes. Longer messages are
     * truncated, not dropped. The call is absent when that size is 0. */
#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
    pubnub_log_text_formatted(
        ctx, PUBNUB_LOG_LEVEL_WARNING, "retrying %s after %d ms", "publish", 250);
#endif

    /* 3. An error entry. error_code is an int, so pass a pubnub_res_t
     * through a cast, or pass a system errno value. details may be NULL. */
    pubnub_log_error(ctx, (int)PUBNUB_ERR_TIMEOUT, "publish timed out", NULL);

    /* 4. A structured entry. See log_request_params above. */
    log_request_params(ctx, "demo_channel", 1, 60);

    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

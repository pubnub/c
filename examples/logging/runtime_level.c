/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/logging/runtime_level.c
 * @brief Set and query the per-context log level.
 *
 * Two thresholds decide whether an entry is emitted. The compile-time
 * mask PUBNUB_CFG_LOG_LEVEL_COMPILED strips whole levels out of the
 * binary. The runtime threshold, seeded from pubnub_config_t::log_level
 * and changed with pubnub_set_log_level(), drops entries below it before
 * any provider's log() callback runs. Raising the runtime level cannot
 * bring back a level that was compiled out.
 *
 * Build: cmake --build build/full --target example_logging_runtime_level
 * Run:   ./build/full/examples/logging/example_logging_runtime_level
 */

// snippet.loggingRuntimeLevel

#include "pubnub/pubnub.h"

#include <stdio.h>

static const char* level_name(pubnub_log_level_t level)
{
    switch (level) {
    case PUBNUB_LOG_LEVEL_TRACE: return "TRACE";
    case PUBNUB_LOG_LEVEL_DEBUG: return "DEBUG";
    case PUBNUB_LOG_LEVEL_INFO: return "INFO";
    case PUBNUB_LOG_LEVEL_WARNING: return "WARNING";
    case PUBNUB_LOG_LEVEL_ERROR: return "ERROR";
    case PUBNUB_LOG_LEVEL_NONE: return "NONE";
    default: return "?";
    }
}

int main(void)
{
    /* 1. pubnub_config_defaults() seeds log_level to
     * PUBNUB_LOG_LEVEL_INFO. Set the field to start the context at a
     * different threshold without a follow-up call. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-logging-level";
    cfg.log_level       = PUBNUB_LOG_LEVEL_WARNING;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    printf("Level after create: %s\n", level_name(pubnub_logger_log_level(ctx)));

    /* 2. Raise verbosity for troubleshooting. The parameter is an
     * unsigned int, so any pubnub_log_level_t value passes through. */
    pubnub_res_t rc = pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_DEBUG);
    if (PUBNUB_OK != rc) {
        printf("set_log_level failed: %s\n", pubnub_res_str(rc));
        pubnub_destroy(ctx);
        return 1;
    }
    printf("Level after raise: %s\n", level_name(pubnub_logger_log_level(ctx)));

    /* 3. DEBUG only reaches a sink when it survived compilation.
     * PUBNUB_LOG_ENABLED takes the short level name and works in #if. */
    if (!PUBNUB_LOG_ENABLED(DEBUG)) {
        printf("DEBUG is stripped from this build "
               "(PUBNUB_CFG_LOG_LEVEL_COMPILED = 0x%X), so DEBUG entries are "
               "no-ops regardless of the runtime level.\n",
               (unsigned)PUBNUB_CFG_LOG_LEVEL_COMPILED);
    }

    /* 4. Silence the context without unregistering its providers. */
    pubnub_set_log_level(ctx, PUBNUB_LOG_LEVEL_NONE);
    printf("Level after silencing: %s\n", level_name(pubnub_logger_log_level(ctx)));

    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

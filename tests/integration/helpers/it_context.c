/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "it_context.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pubnub/providers/logger_types.h"

#include "core/pn_string.h"
#include "providers/provider_internal.h"

#include "it_channel.h"

#if !PUBNUB_CFG_THREAD_SAFETY
/** Polls ctx2 (always) and optionally ctx at 1 ms intervals when
 *  PUBNUB_CFG_THREAD_SAFETY is 0 (no SDK-internal async I/O thread).
 *
 *  ctx is driven only when s->pump_ctx is non-zero. Tests that call
 *  pubnub_await() on ctx must leave pump_ctx at 0 — driving ctx from this
 *  thread concurrently with pubnub_await() from the main thread would race
 *  on the transport layer. Set pump_ctx = 1 only in tests where ctx is
 *  exclusively used for subscribe with no concurrent pubnub_await() calls.
 */
static void* it_process_driver(void* arg)
{
    it_test_state_t* s   = (it_test_state_t*)arg;
    struct timespec  nap = {.tv_sec = 0, .tv_nsec = 1000000L}; /* 1 ms */

    while (s->driver_running) {
        if (0 != s->pump_ctx && NULL != s->ctx) {
            (void)pubnub_process(s->ctx);
        }
        if (NULL != s->ctx2) {
            (void)pubnub_process(s->ctx2);
        }
        for (int i = 0; i < 4; i++) {
            pubnub_context_t* ec = s->extra_ctx[i];
            if (NULL != ec) {
                (void)pubnub_process(ec);
            }
        }
        s->driver_tick++;
        nanosleep(&nap, NULL);
    }
    return NULL;
}
#endif

/** Build and initialize a context from an explicit config. */
static pubnub_context_t* create_ctx(pubnub_config_t* cfg)
{
    pubnub_context_t* ctx;

    ctx = pubnub_create(cfg);
    if (NULL == ctx) {
        return NULL;
    }

    /* pubnub_create already registers the default logger at slot 0 via
     * pn_logger_default(); adding it again here would emit every message
     * twice. Just apply the runtime log-level filter. */
    {
        /* PUBNUB_IT_LOG_LEVEL env var overrides the default WARNING level.
         * Accepted values: TRACE, DEBUG, INFO, WARNING, ERROR */
        pubnub_log_level_t level   = PUBNUB_LOG_LEVEL_WARNING;
        const char*        env_lvl = getenv("PUBNUB_IT_LOG_LEVEL");
        if (NULL != env_lvl) {
            if (0 == strcmp(env_lvl, "TRACE")) {
                level = PUBNUB_LOG_LEVEL_TRACE;
            } else if (0 == strcmp(env_lvl, "DEBUG")) {
                level = PUBNUB_LOG_LEVEL_DEBUG;
            } else if (0 == strcmp(env_lvl, "INFO")) {
                level = PUBNUB_LOG_LEVEL_INFO;
            } else if (0 == strcmp(env_lvl, "ERROR")) {
                level = PUBNUB_LOG_LEVEL_ERROR;
            }
        }
        pubnub_set_log_level(ctx, level);
    }

    return ctx;
}

it_test_state_t* it_state_create(const it_env_t* env)
{
    it_test_state_t* s;
    pubnub_config_t  cfg;

    s = calloc(1U, sizeof(*s));
    if (NULL == s) {
        return NULL;
    }

    s->env = env;
    pn_strlcpy(s->channel, it_unique_name("main"), sizeof(s->channel));
    pn_strlcpy(s->channel2, it_unique_name("secondary"), sizeof(s->channel2));
    pn_strlcpy(s->user_id, it_unique_name("user"), sizeof(s->user_id));

    cfg                            = pubnub_config_defaults();
    cfg.subscribe_key              = env->subscribe_key;
    cfg.publish_key                = env->publish_key;
    cfg.user_id                    = s->user_id;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.presence_timeout           = 30;

    s->ctx = create_ctx(&cfg);
    if (NULL == s->ctx) {
        free(s);
        return NULL;
    }

#if !PUBNUB_CFG_THREAD_SAFETY
    s->driver_running = 1;
    if (0 != pthread_create(&s->driver_thread, NULL, it_process_driver, s)) {
        s->driver_running = 0;
        /* Non-fatal: driver failed to start; tests that rely on async
         * will time out rather than crash. */
    }
#endif

    return s;
}

void it_state_add_ctx2(it_test_state_t* s)
{
    pubnub_config_t cfg;

    if (NULL == s || NULL != s->ctx2) {
        return;
    }

    pn_strlcpy(s->user_id2, it_unique_name("user2"), sizeof(s->user_id2));

    cfg                            = pubnub_config_defaults();
    cfg.subscribe_key              = s->env->subscribe_key;
    cfg.publish_key                = s->env->publish_key;
    cfg.user_id                    = s->user_id2;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.presence_timeout           = 30;

    s->ctx2 = create_ctx(&cfg);
}

int it_state_pump_ctx(it_test_state_t* s, pubnub_context_t* ctx)
{
#if !PUBNUB_CFG_THREAD_SAFETY
    if (NULL == s || NULL == ctx) {
        return -1;
    }
    for (int i = 0; i < 4; i++) {
        if (NULL == s->extra_ctx[i]) {
            s->extra_ctx[i] = ctx;
            return 0;
        }
    }
#else
    (void)s;
    (void)ctx;
#endif
    return -1;
}

void it_state_unpump_ctx(it_test_state_t* s, pubnub_context_t* ctx)
{
#if !PUBNUB_CFG_THREAD_SAFETY
    struct timespec nap = {.tv_sec = 0, .tv_nsec = 1000000L};
    uint32_t        tick_before;

    if (NULL == s || NULL == ctx) {
        return;
    }
    for (int i = 0; i < 4; i++) {
        if (s->extra_ctx[i] == ctx) {
            s->extra_ctx[i] = NULL;
            break;
        }
    }
    /* Wait for the driver to complete its current iteration so it is
     * no longer inside pubnub_process() for the removed context. */
    tick_before = s->driver_tick;
    while (s->driver_running && s->driver_tick == tick_before) {
        nanosleep(&nap, NULL);
    }
#else
    (void)s;
    (void)ctx;
#endif
}

void it_state_add_pam_ctx(it_test_state_t* s)
{
    pubnub_config_t cfg;

    if (NULL == s || NULL != s->pam_ctx) {
        return;
    }
    if (NULL == s->env->pam_subscribe_key || NULL == s->env->pam_publish_key
        || NULL == s->env->pam_secret_key) {
        return;
    }

    pn_strlcpy(s->user_id_pam, it_unique_name("pam"), sizeof(s->user_id_pam));

    cfg                            = pubnub_config_defaults();
    cfg.subscribe_key              = s->env->pam_subscribe_key;
    cfg.publish_key                = s->env->pam_publish_key;
    cfg.secret_key                 = s->env->pam_secret_key;
    cfg.user_id                    = s->user_id_pam;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    s->pam_ctx = create_ctx(&cfg);
}

void it_state_destroy(it_test_state_t* s)
{
    if (NULL == s) {
        return;
    }

#if !PUBNUB_CFG_THREAD_SAFETY
    if (0 != s->driver_running) {
        s->driver_running = 0;
        (void)pthread_join(s->driver_thread, NULL);
    }
#endif

    it_cleanup_run(&s->cleanup, s->ctx);

    if (NULL != s->pam_ctx) {
        pubnub_destroy(s->pam_ctx);
    }
    if (NULL != s->ctx2) {
        pubnub_destroy(s->ctx2);
    }
    pubnub_destroy(s->ctx);

    free(s);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "pubnub/config.h"

#include "core/pn_feature_registry.h"
#include "core/pn_lock.h"
#include "providers/provider_internal.h"
#include "support/test_threads.h"

#if PUBNUB_CFG_THREAD_SAFETY

#define RACE_ITERATIONS 20000

/** Counting lock used by the deterministic test. */
static int s_lock_depth;
static int s_acquires;
static int s_tick_saw_lock_held;
static int s_ticks;

static void counting_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
    s_lock_depth++;
    s_acquires++;
}

static void counting_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
    s_lock_depth--;
}

static int counting_tick(void* state)
{
    (void)state;
    s_ticks++;
    if (0 != s_lock_depth) {
        s_tick_saw_lock_held = 1;
    }
    return 1;
}

static void test_tick_all_reads_under_lock_and_ticks_outside(void** state)
{
    (void)state;

    pn_feature_registry_t      reg      = {0};
    pubnub_platform_provider_t platform = {0};
    pubnub_lock_t*             lock     = (pubnub_lock_t*)&reg;
    int                        marker   = 0;

    platform.lock_acquire = counting_acquire;
    platform.lock_release = counting_release;
    s_lock_depth          = 0;
    s_acquires            = 0;
    s_tick_saw_lock_held  = 0;
    s_ticks               = 0;

    pn_feature_registry_init(&reg);
    pn_feature_register(&reg, PUBNUB_FEATURE_PUBLISH, &marker, NULL);
    pn_feature_registry_set_tick(&reg, PUBNUB_FEATURE_PUBLISH, counting_tick);

    assert_int_equal(1, pn_feature_registry_tick_all(&reg, &platform, lock));
    assert_int_equal(1, s_ticks);
    assert_int_equal(0, s_tick_saw_lock_held);
    assert_int_equal(0, s_lock_depth);
    /* One critical section reaches the tickable slot, one finds no more. */
    assert_int_equal(2, s_acquires);
}

static pn_feature_registry_t       s_reg;
static pubnub_platform_provider_t* s_platform;
static pubnub_lock_t*              s_lock;
static int                         s_dummy_state;
static pn_test_atomic_t            s_stop;

static int race_tick(void* state)
{
    (void)state;
    return 0;
}

static void registrar_thread(void* arg)
{
    int i;

    (void)arg;
    for (i = 0; i < RACE_ITERATIONS; i++) {
        pn_ctx_lock(s_platform, s_lock);
        pn_feature_register(&s_reg, PUBNUB_FEATURE_SUBSCRIBE, &s_dummy_state, NULL);
        pn_feature_registry_set_tick(&s_reg, PUBNUB_FEATURE_SUBSCRIBE, race_tick);
        pn_ctx_unlock(s_platform, s_lock);
    }
    pn_test_atomic_store(&s_stop, 1);
}

static void test_register_races_tick_all_cleanly(void** state)
{
    (void)state;

    pubnub_platform_provider_t* platform = pn_platform_default();
    pn_test_thread_t            th;

    assert_non_null(platform);
    assert_non_null(platform->lock_size);
    s_platform = platform;
    s_lock     = (pubnub_lock_t*)calloc(1, platform->lock_size(platform));
    assert_non_null(s_lock);
    assert_int_equal(0, platform->lock_init(platform, s_lock));

    memset(&s_reg, 0, sizeof(s_reg));
    pn_feature_registry_init(&s_reg);
    pn_test_atomic_store(&s_stop, 0);

    assert_int_equal(0, pn_test_thread_create(&th, registrar_thread, NULL));
    while (0 == pn_test_atomic_load(&s_stop)) {
        (void)pn_feature_registry_tick_all(&s_reg, platform, s_lock);
    }
    assert_int_equal(0, pn_test_thread_join(&th));

    platform->lock_destroy(platform, s_lock);
    free(s_lock);
}

#endif /* PUBNUB_CFG_THREAD_SAFETY */

int main(void)
{
#if PUBNUB_CFG_THREAD_SAFETY
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tick_all_reads_under_lock_and_ticks_outside),
        cmocka_unit_test(test_register_races_tick_all_cleanly),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
#else
    return 0;
#endif
}

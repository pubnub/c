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

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"

#include "core/core_internal.h"
#include "providers/provider_internal.h"
#include "support/test_threads.h"

#if PUBNUB_CFG_THREAD_SAFETY && PUBNUB_ENABLE_PUBLISH && !PUBNUB_CFG_NO_HEAP

/** User threads running the dispatch -> await -> release loop. */
#define STRESS_THREADS    2
#define STRESS_ITERATIONS 5000
/** Every Nth iteration cancels the future before awaiting it. */
#define STRESS_CANCEL_EVERY 7
/** Upper bound on simultaneously live transport handles. */
#define STRESS_MAX_HANDLES 64

#define STRESS_BODY "[1,\"Sent\",\"17000000000000000\"]"

#define HANDLE_LIVE 0x4c495645U
#define HANDLE_DEAD 0xdeadbeefU

typedef struct stress_handle {
    uint32_t                magic;
    pubnub_http_response_t* response;
} stress_handle_t;

/* Transport bookkeeping: touched only by the owning thread, on purpose, so
 * ThreadSanitizer reports any other thread that enters the transport. */
static stress_handle_t*    s_table[STRESS_MAX_HANDLES];
static pn_test_thread_id_t s_owner;
static int                 s_owner_set;

static pn_test_atomic_t    s_in_call;
static pn_test_atomic_t    s_violations;
static pn_test_atomic_t    s_sends;
static pn_test_atomic_t    s_cancels;
static pn_test_atomic_t    s_wakes;
static pn_test_atomic_t    s_live;
static pn_test_atomic_t    s_teardown;
static pn_test_thread_id_t s_main;

static void atomic_inc(pn_test_atomic_t* counter)
{
    pn_test_atomic_add(counter, 1);
}

static int atomic_load_int(pn_test_atomic_t* counter)
{
    return pn_test_atomic_load(counter);
}

static void transport_enter(void)
{
    if (0 != pn_test_atomic_fetch_add(&s_in_call, 1)) {
        atomic_inc(&s_violations);
    }
    if (!s_owner_set) {
        s_owner     = pn_test_thread_self();
        s_owner_set = 1;
    } else if (!pn_test_thread_id_equal(s_owner, pn_test_thread_self())) {
        /* After the background thread is joined, the thread tearing the
         * context down legitimately becomes the transport's only user. */
        if (!(atomic_load_int(&s_teardown)
              && pn_test_thread_id_equal(s_main, pn_test_thread_self()))) {
            atomic_inc(&s_violations);
        }
    }
}

static void transport_leave(void)
{
    pn_test_atomic_add(&s_in_call, -1);
}

static void tiny_sleep(unsigned long microseconds)
{
    pn_test_pause_us(microseconds);
}

static void stress_sleep_ms(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    (void)ms;
    tiny_sleep(200UL);
}

static pubnub_transport_handle_t* stress_send(pubnub_transport_provider_t* self,
                                              pubnub_http_request_t*  request,
                                              pubnub_http_response_t* response)
{
    stress_handle_t* handle;
    size_t           i;

    (void)self;
    (void)request;
    transport_enter();

    handle = (stress_handle_t*)malloc(sizeof(*handle));
    if (NULL == handle) {
        atomic_inc(&s_violations);
        transport_leave();
        return NULL;
    }
    handle->magic    = HANDLE_LIVE;
    handle->response = response;
    for (i = 0; i < STRESS_MAX_HANDLES; i++) {
        if (NULL == s_table[i]) {
            s_table[i] = handle;
            break;
        }
    }
    if (STRESS_MAX_HANDLES == i) {
        atomic_inc(&s_violations);
    }
    atomic_inc(&s_sends);
    atomic_inc(&s_live);
    transport_leave();
    return (pubnub_transport_handle_t*)handle;
}

static int stress_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    int    completed = 0;
    size_t i;

    (void)self;
    (void)timeout_ms;
    transport_enter();
    for (i = 0; i < STRESS_MAX_HANDLES; i++) {
        stress_handle_t* handle = s_table[i];

        if (NULL == handle) {
            continue;
        }
        if (HANDLE_LIVE != handle->magic) {
            atomic_inc(&s_violations);
            continue;
        }
        if (PUBNUB_HTTP_PENDING == handle->response->completion) {
            handle->response->status_code = 200;
            handle->response->body        = (const uint8_t*)STRESS_BODY;
            handle->response->body_len    = sizeof(STRESS_BODY) - 1U;
            handle->response->completion  = PUBNUB_HTTP_COMPLETE;
            completed++;
        }
    }
    tiny_sleep(50UL);
    transport_leave();
    return completed;
}

static void stress_cancel(pubnub_transport_provider_t* self,
                          pubnub_transport_handle_t*   transport_handle)
{
    stress_handle_t* handle = (stress_handle_t*)transport_handle;
    size_t           i;

    (void)self;
    transport_enter();
    if (NULL == handle || HANDLE_LIVE != handle->magic) {
        atomic_inc(&s_violations);
        transport_leave();
        return;
    }
    for (i = 0; i < STRESS_MAX_HANDLES; i++) {
        if (s_table[i] == handle) {
            s_table[i] = NULL;
            break;
        }
    }
    if (STRESS_MAX_HANDLES == i) {
        atomic_inc(&s_violations);
    }
    handle->magic = HANDLE_DEAD;
    free(handle);
    atomic_inc(&s_cancels);
    pn_test_atomic_add(&s_live, -1);
    transport_leave();
}

static void stress_wake(pubnub_transport_provider_t* self)
{
    (void)self;
    atomic_inc(&s_wakes);
}

static pubnub_transport_provider_t s_stress_transport = {
    .send   = stress_send,
    .poll   = stress_poll,
    .cancel = stress_cancel,
    .wake   = stress_wake,
};

static pubnub_platform_provider_t s_stress_platform;

typedef struct stress_worker {
    pubnub_context_t* ctx;
    int               completed;
    int               rejected;
} stress_worker_t;

static void stress_user_thread(void* arg)
{
    stress_worker_t* worker = (stress_worker_t*)arg;
    int              i;

    for (i = 0; i < STRESS_ITERATIONS; i++) {
        pubnub_future_t fut = pubnub_publish(worker->ctx,
                                             &(pubnub_publish_opts_t){
                                                 .channel = "stress-ch",
                                                 .message = "\"m\"",
                                             });

        if (PUBNUB_IN_PROGRESS != fut.status) {
            /* Pool and pending queue both full while slots are awaiting
             * their deferred reclaim: back off and retry. */
            worker->rejected++;
            tiny_sleep(100UL);
            continue;
        }
        if (0 == i % STRESS_CANCEL_EVERY) {
            (void)pubnub_future_cancel(fut);
        }
        (void)pubnub_await(fut);
        pubnub_future_release(fut);
        worker->completed++;
    }
}

static void release_from_user_threads_never_enters_transport(void** state)
{
    (void)state;
    pn_test_thread_t  threads[STRESS_THREADS];
    stress_worker_t   workers[STRESS_THREADS];
    pubnub_config_t   cfg = pubnub_config_defaults();
    pubnub_context_t* ctx;
    int               i;
    int               total    = 0;
    int               rejected = 0;

    s_stress_platform          = *pn_platform_default();
    s_stress_platform.sleep_ms = stress_sleep_ms;
    cfg.publish_key            = "pub";
    cfg.subscribe_key          = "sub";
    cfg.user_id                = "stress";
    cfg.transport              = &s_stress_transport;
    cfg.platform               = &s_stress_platform;

    ctx = pubnub_create(&cfg);
    assert_non_null(ctx);
    assert_int_equal(PUBNUB_OK, pn_context_start_bg_thread(ctx));
    assert_true(pn_context_has_bg_thread(ctx));

    for (i = 0; i < STRESS_THREADS; i++) {
        workers[i].ctx       = ctx;
        workers[i].completed = 0;
        workers[i].rejected  = 0;
        assert_int_equal(
            0, pn_test_thread_create(&threads[i], stress_user_thread, &workers[i]));
    }
    for (i = 0; i < STRESS_THREADS; i++) {
        assert_int_equal(0, pn_test_thread_join(&threads[i]));
        total += workers[i].completed;
        rejected += workers[i].rejected;
    }

    s_main = pn_test_thread_self();
    pn_test_atomic_store(&s_teardown, 1);
    pubnub_destroy(ctx);

    assert_int_equal(0, atomic_load_int(&s_violations));
    assert_int_equal(STRESS_THREADS * STRESS_ITERATIONS, total + rejected);
    assert_true(total > 0);
    assert_true(atomic_load_int(&s_sends) > 0);
    assert_int_equal(0, atomic_load_int(&s_live));
    assert_int_equal(atomic_load_int(&s_sends), atomic_load_int(&s_cancels));
    assert_true(atomic_load_int(&s_wakes) > 0);
}

static int stress_setup(void** state)
{
    (void)state;
    memset(s_table, 0, sizeof(s_table));
    s_owner_set  = 0;
    s_in_call    = 0;
    s_violations = 0;
    s_sends      = 0;
    s_cancels    = 0;
    s_wakes      = 0;
    s_live       = 0;
    s_teardown   = 0;
    return 0;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(release_from_user_threads_never_enters_transport,
                               stress_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* thread safety unavailable */

static void thread_stress_not_applicable(void** state)
{
    (void)state;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(thread_stress_not_applicable),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif

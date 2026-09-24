/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/*
 * G-023: Concurrent operations across multiple independent contexts.
 *
 * Separate contexts must be usable concurrently from separate threads
 * without shared-state interference. Each context owns its own transport
 * connection (and, with secure transport enabled, its own TLS session),
 * so N threads driving N contexts must all complete cleanly. This guards
 * against accidental global/static state in the transport, TLS, or
 * pipeline layers.
 *
 * Requires PUBNUB_CFG_THREAD_SAFETY=1 AND PUBNUB_ENABLE_PUBLISH (enforced
 * at the CMake registration site). A watchdog turns any cross-context
 * deadlock into a diagnostic abort instead of a silent hang.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "it_thread.h"
#include "it_watchdog.h"

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#if PUBNUB_ENABLE_SUBSCRIBE
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "it_bus.h"
#endif

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** Watchdog budget for the concurrent-context tests (seconds). */
#define CC_WATCHDOG_S 30U
/** Number of contexts exercised by the four-context test. */
#define CC_FOUR 4U

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    it_test_state_t* s = it_state_create(env);
    if (NULL == s) {
        return -1;
    }
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    /* Disarm unconditionally: an assert failure inside the armed window
     * longjmps past the in-body disarm, leaving the watchdog pending. It
     * would then fire during a later test with a misattributed
     * diagnostic. it_watchdog_disarm() is idempotent. */
    it_watchdog_disarm();
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

/** Argument block for one publishing worker thread. */
typedef struct cc_pub_arg {
    pubnub_context_t* ctx;     /**< Context this worker drives. */
    const char*       channel; /**< Channel to publish to. */
    const char*       message; /**< JSON message literal. */
    pubnub_res_t      result;  /**< Publish result code. */
} cc_pub_arg_t;

static void* cc_publish_thread(void* arg)
{
    cc_pub_arg_t*   a = (cc_pub_arg_t*)arg;
    pubnub_future_t fut;

    fut       = pubnub_publish(a->ctx,
                         &(pubnub_publish_opts_t){
                                   .channel = a->channel,
                                   .message = a->message,
                         });
    a->result = pubnub_await(fut);
    pubnub_future_release(fut);
    return NULL;
}

/*
 * Test 1: two contexts publish concurrently, each on its own thread.
 *
 * Both publishes must succeed — a shared-state collision between the two
 * transport/TLS sessions would surface as a failure or a hang here.
 */
static void concurrent_publish_two_contexts(void** state)
{
    it_test_state_t* s    = *state;
    cc_pub_arg_t     arg1 = {0};
    cc_pub_arg_t     arg2 = {0};
    pn_test_thread_t t1;
    pn_test_thread_t t2;
    int              rc1;
    int              rc2;

    it_state_add_ctx2(s);
    assert_non_null(s->ctx2);
    print_message("channel: %s", s->channel);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    arg1.ctx     = s->ctx;
    arg1.channel = s->channel;
    arg1.message = "\"cc-ctx1\"";
    arg1.result  = PUBNUB_ERR_INVALID_ARGUMENT;

    arg2.ctx     = s->ctx2;
    arg2.channel = s->channel;
    arg2.message = "\"cc-ctx2\"";
    arg2.result  = PUBNUB_ERR_INVALID_ARGUMENT;

    it_watchdog_arm(CC_WATCHDOG_S, "concurrent_publish_two_contexts");

    rc1 = pn_test_thread_create(&t1, cc_publish_thread, &arg1);
    assert_int_equal(0, rc1);
    rc2 = pn_test_thread_create(&t2, cc_publish_thread, &arg2);
    assert_int_equal(0, rc2);

    pn_test_thread_join(t1);
    pn_test_thread_join(t2);

    it_watchdog_disarm();

    if (PUBNUB_OK != arg1.result) {
        print_error("ctx1 publish failed: %s", pubnub_res_str(arg1.result));
    }
    if (PUBNUB_OK != arg2.result) {
        print_error("ctx2 publish failed: %s", pubnub_res_str(arg2.result));
    }
    assert_int_equal(PUBNUB_OK, arg1.result);
    assert_int_equal(PUBNUB_OK, arg2.result);
}

/*
 * Test 2: four contexts publish concurrently, each on its own thread.
 *
 * Scales the concurrency past the two-context baseline. Three extra
 * contexts are created in-body (each with its own keyset context and
 * channel) and destroyed before returning; the primary context is
 * cleaned up by teardown.
 */
static void concurrent_publish_four_contexts(void** state)
{
    it_test_state_t*  s                   = *state;
    it_test_state_t*  extra[CC_FOUR - 1U] = {0};
    cc_pub_arg_t      args[CC_FOUR];
    pn_test_thread_t  threads[CC_FOUR];
    pubnub_context_t* ctxs[CC_FOUR];
    const char*       channels[CC_FOUR];
    unsigned int      i;

    /* Build the context/channel roster: slot 0 is the primary context,
     * slots 1..3 are freshly created contexts. On the happy path the
     * extras are destroyed at the end of the body; an assert failure
     * longjmps past that destroy loop and leaks the extras. That is an
     * accepted host-only failure-path leak — the process is exiting with
     * a test failure, so no reclamation matters. (Register in it_cleanup
     * instead if an ASan/LSan lane is ever added for these tests.) */
    ctxs[0]     = s->ctx;
    channels[0] = s->channel;
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    for (i = 0U; i < CC_FOUR - 1U; ++i) {
        extra[i] = it_state_create(s->env);
        assert_non_null(extra[i]);
        ctxs[i + 1U]     = extra[i]->ctx;
        channels[i + 1U] = extra[i]->channel;
        it_cleanup_add(
            &extra[i]->cleanup, IT_CLEANUP_DELETE_MESSAGES, extra[i]->channel, NULL);
    }

    it_watchdog_arm(CC_WATCHDOG_S, "concurrent_publish_four_contexts");

    for (i = 0U; i < CC_FOUR; ++i) {
        args[i].ctx     = ctxs[i];
        args[i].channel = channels[i];
        args[i].message = "\"cc-four\"";
        args[i].result  = PUBNUB_ERR_INVALID_ARGUMENT;
        assert_int_equal(
            0, pn_test_thread_create(&threads[i], cc_publish_thread, &args[i]));
    }

    for (i = 0U; i < CC_FOUR; ++i) {
        pn_test_thread_join(threads[i]);
    }

    it_watchdog_disarm();

    for (i = 0U; i < CC_FOUR; ++i) {
        if (PUBNUB_OK != args[i].result) {
            print_error(
                "ctx[%u] publish failed: %s", i, pubnub_res_str(args[i].result));
        }
        assert_int_equal(PUBNUB_OK, args[i].result);
    }

    for (i = 0U; i < CC_FOUR - 1U; ++i) {
        it_state_destroy(extra[i]);
    }
}

#if PUBNUB_ENABLE_SUBSCRIBE

static void on_cc_status_cb(const pubnub_subscribe_status_event_t* ev, void* user_data)
{
    it_bus_push_status((it_bus_t*)user_data, ev->status);
}

static void on_cc_message_cb(const pubnub_subscribe_event_t* ev, void* user_data)
{
    (void)ev;
    *(volatile int*)user_data = 1;
}

static int cc_flag_set(void* arg)
{
    return *(volatile int*)arg;
}

/*
 * Test 3: subscribe on one context, publish from another.
 *
 * The subscriber context runs its long-poll on the background thread
 * while the publisher context sends a message. The subscriber must
 * receive it — proving two contexts interoperate over the wire without
 * cross-context state leakage.
 */
static void cross_context_subscribe_publish(void** state)
{
    it_test_state_t*            s               = *state;
    it_bus_t*                   bus             = it_bus_create();
    volatile int                received        = 0;
    pubnub_subscribe_listener_t msg_listener    = {0};
    pubnub_subscribe_listener_t status_listener = {0};
    pubnub_listener_handle_t    mlh;
    pubnub_listener_handle_t    slh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             pub_fut;
    pubnub_res_t                pub_st;
    int                         waited;

    assert_non_null(bus);
    it_state_add_ctx2(s);
    assert_non_null(s->ctx2);
    print_message("channel: %s", s->channel);

    msg_listener.on_message = on_cc_message_cb;
    msg_listener.user_data  = (void*)&received;
    mlh                     = pubnub_add_listener(s->ctx, &msg_listener);

    status_listener.on_status = on_cc_status_cb;
    status_listener.user_data = bus;
    slh                       = pubnub_add_listener(s->ctx, &status_listener);

    it_watchdog_arm(CC_WATCHDOG_S, "cross_context_subscribe_publish");

    entity = pubnub_channel(s->ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pub_fut = pubnub_publish(s->ctx2,
                             &(pubnub_publish_opts_t){
                                 .channel = s->channel,
                                 .message = "\"cc-cross\"",
                             });
    pub_st  = pubnub_await(pub_fut);
    pubnub_future_release(pub_fut);

    waited = pn_test_wait_until(
        cc_flag_set, (void*)&received, IT_SUBSCRIBE_MESSAGE_MAX_MS, 50U);

    it_watchdog_disarm();

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx, slh);
    pubnub_remove_listener(s->ctx, mlh);
    it_bus_destroy(bus);

    if (PUBNUB_OK != pub_st) {
        print_error("cross-context publish failed: %s", pubnub_res_str(pub_st));
    }
    assert_int_equal(PUBNUB_OK, pub_st);
    assert_true(waited);
}

#endif /* PUBNUB_ENABLE_SUBSCRIBE */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            concurrent_publish_two_contexts, setup, teardown),
        cmocka_unit_test_setup_teardown(
            concurrent_publish_four_contexts, setup, teardown),
#if PUBNUB_ENABLE_SUBSCRIBE
        cmocka_unit_test_setup_teardown(
            cross_context_subscribe_publish, setup, teardown),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

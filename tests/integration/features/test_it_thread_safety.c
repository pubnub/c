/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "it_thread.h"

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#if IT_HAS_HISTORY
#include "pubnub/features/history.h"
#endif

#if IT_HAS_SUBSCRIBE
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "it_bus.h"
#endif

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** Maximum time (ms) to wait for async callbacks to complete. */
#define TS_WAIT_MS 10000U
/** Polling interval (ms) for async wait loops. */
#define TS_POLL_MS 50U
/** Number of iterations for the rapid-sequential test. */
#define TS_RAPID_N 20U

/**
 * @brief Shared callback context for thread-safety tests.
 *
 * All async callbacks write their results here. The main thread polls
 * `done` via `pn_test_wait_until`.
 */
typedef struct ts_cb_ctx {
    volatile int      done;
    pubnub_res_t      status;
    pubnub_res_t      status2;
    pubnub_context_t* ctx;
    const char*       channel;
    pubnub_future_t   extra_fut;
} ts_cb_ctx_t;

static int ts_is_done(void* arg)
{
    return ((ts_cb_ctx_t*)arg)->done;
}

/** Generic flag-check predicate for pn_test_wait_until. */
static int ts_flag_set(void* arg)
{
    return *(volatile int*)arg;
}

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
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

static int setup_dual(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    it_test_state_t* s = it_state_create(env);
    if (NULL == s) {
        return -1;
    }
    it_state_add_ctx2(s);
    if (NULL == s->ctx2) {
        it_state_destroy(s);
        return -1;
    }
    *state = s;
    return 0;
}

/*
 * Test 1: publish_from_publish_callback_same_context
 *
 * Verifies that issuing a second publish from within the completion
 * callback of a first publish on the same context does not deadlock
 * and both operations succeed.
 */

static void on_pub2_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    ts_cb_ctx_t* cb = (ts_cb_ctx_t*)user_data;
    cb->status2     = status;
    pubnub_future_release(future);
    cb->done = 1;
}

static void on_pub1_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    ts_cb_ctx_t*    cb = (ts_cb_ctx_t*)user_data;
    pubnub_res_t    reg;
    pubnub_future_t fut2;

    cb->status = status;
    pubnub_future_release(future);

    fut2 = pubnub_publish(cb->ctx,
                          &(pubnub_publish_opts_t){
                              .channel = cb->channel,
                              .message = "\"ts-msg2\"",
                          });

    reg = pubnub_async(fut2, on_pub2_cb, cb);
    if (PUBNUB_OK != reg) {
        cb->status2 = reg;
        pubnub_future_release(fut2);
        cb->done = 1;
    }
}

static void publish_from_publish_callback_same_context(void** state)
{
    it_test_state_t* s  = *state;
    ts_cb_ctx_t      cb = {0};
    pubnub_future_t  fut1;
    pubnub_res_t     reg;
    int              waited;

    print_message("channel: %s", s->channel);

    cb.ctx     = s->ctx;
    cb.channel = s->channel;

    fut1 = pubnub_publish(s->ctx,
                          &(pubnub_publish_opts_t){
                              .channel = s->channel,
                              .message = "\"ts-msg1\"",
                          });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    reg = pubnub_async(fut1, on_pub1_cb, &cb);
    assert_int_equal(PUBNUB_OK, reg);

    waited = pn_test_wait_until(ts_is_done, &cb, TS_WAIT_MS, TS_POLL_MS);
    assert_true(waited);
    assert_int_equal(PUBNUB_OK, cb.status);
    assert_int_equal(PUBNUB_OK, cb.status2);
}

/*
 * Test 2: history_from_publish_callback_same_context
 *
 * Publishes a message synchronously, waits for propagation, then
 * fires a second publish whose callback issues a fetch_messages
 * on the same context. Validates cross-feature re-entry from a
 * callback.
 */

#if IT_HAS_HISTORY

static void on_history_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    ts_cb_ctx_t* cb = (ts_cb_ctx_t*)user_data;
    cb->status2     = status;
    pubnub_future_release(future);
    cb->done = 1;
}

static void on_pub_then_history_cb(pubnub_future_t future,
                                   pubnub_res_t    status,
                                   void*           user_data)
{
    ts_cb_ctx_t*                 cb = (ts_cb_ctx_t*)user_data;
    pubnub_fetch_messages_opts_t hopts;
    pubnub_future_t              hfut;
    pubnub_res_t                 reg;

    cb->status = status;
    pubnub_future_release(future);

    if (PUBNUB_OK != status) {
        cb->status2 = status;
        cb->done    = 1;
        return;
    }

    hopts = (pubnub_fetch_messages_opts_t)PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    hopts.channels = cb->channel;
    hopts.count    = 5U;

    hfut = pubnub_fetch_messages(cb->ctx, &hopts);
    reg  = pubnub_async(hfut, on_history_cb, cb);
    if (PUBNUB_OK != reg) {
        cb->status2 = reg;
        pubnub_future_release(hfut);
        cb->done = 1;
    }
}

static void history_from_publish_callback_same_context(void** state)
{
    it_test_state_t* s  = *state;
    ts_cb_ctx_t      cb = {0};
    pubnub_future_t  seed_fut;
    pubnub_res_t     seed_st;
    pubnub_future_t  trigger_fut;
    pubnub_res_t     reg;
    int              waited;

    print_message("channel: %s", s->channel);

    /* Seed a message so history has something to return. */
    seed_fut = pubnub_publish(s->ctx,
                              &(pubnub_publish_opts_t){
                                  .channel = s->channel,
                                  .message = "\"ts-seed\"",
                              });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    seed_st = pubnub_await(seed_fut);
    assert_int_equal(PUBNUB_OK, seed_st);
    pubnub_future_release(seed_fut);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* Trigger publish whose callback issues fetch_messages. */
    cb.ctx     = s->ctx;
    cb.channel = s->channel;

    trigger_fut = pubnub_publish(s->ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = s->channel,
                                     .message = "\"ts-trigger\"",
                                 });

    reg = pubnub_async(trigger_fut, on_pub_then_history_cb, &cb);
    assert_int_equal(PUBNUB_OK, reg);

    waited = pn_test_wait_until(ts_is_done, &cb, TS_WAIT_MS, TS_POLL_MS);
    assert_true(waited);
    assert_int_equal(PUBNUB_OK, cb.status);
    assert_int_equal(PUBNUB_OK, cb.status2);
}

#endif /* IT_HAS_HISTORY */

/*
 * Test 3: publish_from_subscribe_on_message_listener
 *
 * Subscribes on ctx, publishes a trigger from ctx2. The on_message
 * listener fires on the bg thread and publishes a reply on the
 * subscribing ctx. Validates that the context lock is not held
 * during listener dispatch.
 */

#if IT_HAS_SUBSCRIBE

typedef struct ts_sub_reply_ctx {
    volatile int done;
    volatile int dispatched; /**< Set on first on_trigger_msg_cb invocation. */
    pubnub_res_t reply_status;
    pubnub_context_t* ctx;
    const char*       channel;
} ts_sub_reply_ctx_t;

static void on_reply_done_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    ts_sub_reply_ctx_t* cb = (ts_sub_reply_ctx_t*)user_data;
    cb->reply_status       = status;
    pubnub_future_release(future);
    cb->done = 1;
}

static void on_trigger_msg_cb(const pubnub_subscribe_event_t* ev, void* user_data)
{
    ts_sub_reply_ctx_t* cb = (ts_sub_reply_ctx_t*)user_data;
    pubnub_future_t     fut;
    pubnub_res_t        reg;

    (void)ev;

    /* Guard against duplicate deliveries (same message received twice on
     * subscribe reconnect). Only the first invocation dispatches a reply;
     * subsequent ones would register an async callback pointing at a
     * stack-allocated reply_ctx that may be gone by the time the callback
     * fires. */
    if (cb->dispatched) {
        return;
    }
    cb->dispatched = 1;

    /* Publish reply from within subscribe listener callback. */
    fut = pubnub_publish(cb->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = cb->channel,
                             .message = "\"ts-reply\"",
                         });

    reg = pubnub_async(fut, on_reply_done_cb, cb);
    if (PUBNUB_OK != reg) {
        cb->reply_status = reg;
        pubnub_future_release(fut);
        cb->done = 1;
    }
}

static void on_ts_status_cb(const pubnub_subscribe_status_event_t* ev, void* user_data)
{
    it_bus_push_status((it_bus_t*)user_data, ev->status);
}

static void publish_from_subscribe_on_message_listener(void** state)
{
    it_test_state_t*            s         = *state;
    it_bus_t*                   bus       = it_bus_create();
    ts_sub_reply_ctx_t          reply_ctx = {0};
    pubnub_subscribe_listener_t listener  = {0};
    pubnub_listener_handle_t    lh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             trigger_fut;
    pubnub_res_t                trigger_st;
    int                         waited;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    reply_ctx.ctx     = s->ctx;
    reply_ctx.channel = s->channel;

    listener.on_message = on_trigger_msg_cb;
    listener.user_data  = &reply_ctx;

    lh = pubnub_add_listener(s->ctx, &listener);

    /* Override on_status user_data to the bus for CONNECTED wait. */
    {
        pubnub_subscribe_listener_t status_listener = {0};
        pubnub_listener_handle_t    slh;

        status_listener.on_status = on_ts_status_cb;
        status_listener.user_data = bus;
        slh = pubnub_add_listener(s->ctx, &status_listener);

        entity = pubnub_channel(s->ctx, s->channel);
        sub    = pubnub_subscription_create(entity, NULL);
        pubnub_entity_destroy(entity);
        pubnub_subscription_subscribe(sub);

        assert_int_not_equal(0,
                             it_bus_wait_status(bus,
                                                IT_SUBSCRIBE_CONNECT_MAX_MS,
                                                PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
        pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

        pubnub_remove_listener(s->ctx, slh);
    }

    /* Publish trigger from ctx2; subscribe on ctx receives it. */
    trigger_fut = pubnub_publish(s->ctx2,
                                 &(pubnub_publish_opts_t){
                                     .channel = s->channel,
                                     .message = "\"ts-trigger\"",
                                 });

    trigger_st = pubnub_await(trigger_fut);
    assert_int_equal(PUBNUB_OK, trigger_st);
    pubnub_future_release(trigger_fut);

    /* Wait for the reply publish (fired from on_message cb). */
    waited = pn_test_wait_until(
        ts_flag_set, (void*)&reply_ctx.done, TS_WAIT_MS, TS_POLL_MS);

    /* Capture results before cleanup so assert failures don't leave lh
     * pointing at a dead stack frame. */
    {
        pubnub_res_t reply_status = reply_ctx.reply_status;
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_remove_listener(s->ctx, lh);
        it_bus_destroy(bus);
        assert_true(waited);
        assert_int_equal(PUBNUB_OK, reply_status);
    }
}

/*
 * Test 5: subscribe_while_publishing_same_context
 *
 * Subscribe long-poll active on ctx; a second pthread publishes on
 * the same ctx concurrently. Validates that per-context locking
 * serializes subscribe-poll and publish-submit without deadlock
 * or data corruption.
 */

typedef struct ts_sub_pub_ctx {
    volatile int      pub_done;
    volatile int      msg_received;
    pubnub_res_t      pub_status;
    pubnub_context_t* ctx;
    const char*       channel;
} ts_sub_pub_ctx_t;

static void on_sub_pub_msg_cb(const pubnub_subscribe_event_t* ev, void* user_data)
{
    ts_sub_pub_ctx_t* cb = (ts_sub_pub_ctx_t*)user_data;
    (void)ev;
    cb->msg_received = 1;
}

static void* sub_pub_thread(void* arg)
{
    ts_sub_pub_ctx_t* cb = (ts_sub_pub_ctx_t*)arg;
    pubnub_future_t   fut;

    fut            = pubnub_publish(cb->ctx,
                         &(pubnub_publish_opts_t){
                                        .channel = cb->channel,
                                        .message = "\"ts-sub-pub\"",
                         });
    cb->pub_status = pubnub_await(fut);
    pubnub_future_release(fut);
    cb->pub_done = 1;
    return NULL;
}

static void subscribe_while_publishing_same_context(void** state)
{
    it_test_state_t*            s               = *state;
    it_bus_t*                   bus             = it_bus_create();
    ts_sub_pub_ctx_t            ctx             = {0};
    pubnub_subscribe_listener_t listener        = {0};
    pubnub_subscribe_listener_t status_listener = {0};
    pubnub_listener_handle_t    lh;
    pubnub_listener_handle_t    slh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pn_test_thread_t            pub_thread;
    int                         rc;
    int                         waited;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    ctx.ctx     = s->ctx;
    ctx.channel = s->channel;

    listener.on_message = on_sub_pub_msg_cb;
    listener.user_data  = &ctx;
    lh                  = pubnub_add_listener(s->ctx, &listener);

    status_listener.on_status = on_ts_status_cb;
    status_listener.user_data = bus;
    slh                       = pubnub_add_listener(s->ctx, &status_listener);

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

    /* Spawn a thread that publishes on the SAME context. */
    rc = pn_test_thread_create(&pub_thread, sub_pub_thread, &ctx);
    assert_int_equal(0, rc);

    pn_test_thread_join(pub_thread);

    assert_true(ctx.pub_done);
    if (PUBNUB_OK != ctx.pub_status) {
        print_error("sub+pub thread publish failed: %s",
                    pubnub_res_str(ctx.pub_status));
    }
    assert_int_equal(PUBNUB_OK, ctx.pub_status);

    /* The published message should also arrive via subscribe. */
    waited = pn_test_wait_until(ts_flag_set,
                                (void*)&ctx.msg_received,
                                IT_SUBSCRIBE_MESSAGE_MAX_MS,
                                TS_POLL_MS);
    assert_true(waited);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx, slh);
    pubnub_remove_listener(s->ctx, lh);
    it_bus_destroy(bus);
}

#endif /* IT_HAS_SUBSCRIBE */

/*
 * Test 4: concurrent_publish_two_threads_same_context
 *
 * Spawns two pthreads that each publish-and-await on the same
 * context. Validates that the per-context mutex serializes access
 * without deadlock or corruption.
 */

typedef struct ts_thread_arg {
    pubnub_context_t* ctx;
    const char*       channel;
    const char*       message;
    pubnub_res_t      result;
} ts_thread_arg_t;

static void* publish_thread(void* arg)
{
    ts_thread_arg_t* a = (ts_thread_arg_t*)arg;
    pubnub_future_t  fut;

    fut       = pubnub_publish(a->ctx,
                         &(pubnub_publish_opts_t){
                                   .channel = a->channel,
                                   .message = a->message,
                         });
    a->result = pubnub_await(fut);
    pubnub_future_release(fut);
    return NULL;
}

static void concurrent_publish_two_threads_same_context(void** state)
{
    it_test_state_t* s    = *state;
    ts_thread_arg_t  arg1 = {0};
    ts_thread_arg_t  arg2 = {0};
    pn_test_thread_t t1;
    pn_test_thread_t t2;
    int              rc1;
    int              rc2;

    print_message("channel: %s", s->channel);

    arg1.ctx     = s->ctx;
    arg1.channel = s->channel;
    arg1.message = "\"ts-thread1\"";
    arg1.result  = PUBNUB_ERR_INVALID_ARGUMENT;

    arg2.ctx     = s->ctx;
    arg2.channel = s->channel;
    arg2.message = "\"ts-thread2\"";
    arg2.result  = PUBNUB_ERR_INVALID_ARGUMENT;

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    rc1 = pn_test_thread_create(&t1, publish_thread, &arg1);
    assert_int_equal(0, rc1);
    rc2 = pn_test_thread_create(&t2, publish_thread, &arg2);
    assert_int_equal(0, rc2);

    pn_test_thread_join(t1);
    pn_test_thread_join(t2);

    if (PUBNUB_OK != arg1.result) {
        print_error("thread1 publish failed: %s", pubnub_res_str(arg1.result));
    }
    if (PUBNUB_OK != arg2.result) {
        print_error("thread2 publish failed: %s", pubnub_res_str(arg2.result));
    }
    assert_int_equal(PUBNUB_OK, arg1.result);
    assert_int_equal(PUBNUB_OK, arg2.result);
}

/*
 * Test 6: future_release_from_callback
 *
 * Calls pubnub_future_release on the callback's own future from
 * within the callback. Validates deferred-release safety (ASan will
 * catch use-after-free).
 */

static void on_release_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    ts_cb_ctx_t* cb = (ts_cb_ctx_t*)user_data;
    cb->status      = status;
    pubnub_future_release(future);
    cb->done = 1;
}

static void future_release_from_callback(void** state)
{
    it_test_state_t* s  = *state;
    ts_cb_ctx_t      cb = {0};
    pubnub_future_t  fut;
    pubnub_res_t     reg;
    int              waited;

    print_message("channel: %s", s->channel);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = s->channel,
                             .message = "\"ts-release\"",
                         });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    reg = pubnub_async(fut, on_release_cb, &cb);
    assert_int_equal(PUBNUB_OK, reg);

    waited = pn_test_wait_until(ts_is_done, &cb, TS_WAIT_MS, TS_POLL_MS);
    assert_true(waited);
    assert_int_equal(PUBNUB_OK, cb.status);
}

/*
 * Test 7: cancel_from_callback
 *
 * Starts two publishes. The first publish's callback cancels the
 * second publish's future. The main thread awaits the second future
 * and verifies it is either OK (completed before cancel) or
 * CANCELLED. Validates no deadlock regardless of race outcome.
 */

static void on_cancel_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    ts_cb_ctx_t* cb = (ts_cb_ctx_t*)user_data;
    cb->status      = status;
    pubnub_future_cancel(cb->extra_fut);
    pubnub_future_release(future);
    cb->done = 1;
}

static void cancel_from_callback(void** state)
{
    it_test_state_t* s  = *state;
    ts_cb_ctx_t      cb = {0};
    pubnub_future_t  fut1;
    pubnub_future_t  fut2;
    pubnub_res_t     reg;
    pubnub_res_t     st2;
    int              waited;

    print_message("channel: %s", s->channel);

    fut1 = pubnub_publish(s->ctx,
                          &(pubnub_publish_opts_t){
                              .channel = s->channel,
                              .message = "\"ts-cancel1\"",
                          });
    fut2 = pubnub_publish(s->ctx,
                          &(pubnub_publish_opts_t){
                              .channel = s->channel,
                              .message = "\"ts-cancel2\"",
                          });

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    cb.extra_fut = fut2;

    reg = pubnub_async(fut1, on_cancel_cb, &cb);
    assert_int_equal(PUBNUB_OK, reg);

    st2 = pubnub_await(fut2);
    assert_true(PUBNUB_OK == st2 || PUBNUB_ERR_CANCELLED == st2);
    pubnub_future_release(fut2);

    waited = pn_test_wait_until(ts_is_done, &cb, TS_WAIT_MS, TS_POLL_MS);
    assert_true(waited);
}

/*
 * Test 8: rapid_sequential_operations_same_context
 *
 * Runs 20 publish-await-release cycles back-to-back with no sleep.
 * Validates that rapid sequential re-use of the same context does
 * not corrupt internal state.
 */

static void rapid_sequential_operations_same_context(void** state)
{
    it_test_state_t* s = *state;
    unsigned int     i;

    print_message("channel: %s", s->channel);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    for (i = 0U; i < TS_RAPID_N; ++i) {
        pubnub_future_t fut;
        pubnub_res_t    st;

        fut = pubnub_publish(s->ctx,
                             &(pubnub_publish_opts_t){
                                 .channel = s->channel,
                                 .message = "\"ts-rapid\"",
                             });
        st  = pubnub_await(fut);
        if (PUBNUB_OK != st) {
            pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
            print_error("rapid iteration %u failed: %s (http=%d "
                        "msg=%.*s)",
                        i,
                        pubnub_res_str(st),
                        pubnub_response_status_code(fut),
                        (int)errmsg.len,
                        errmsg.ptr ? errmsg.ptr : "");
        }
        assert_int_equal(PUBNUB_OK, st);
        pubnub_future_release(fut);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            publish_from_publish_callback_same_context, setup, teardown),
#if IT_HAS_HISTORY
        cmocka_unit_test_setup_teardown(
            history_from_publish_callback_same_context, setup, teardown),
#endif
#if IT_HAS_SUBSCRIBE
        cmocka_unit_test_setup_teardown(
            publish_from_subscribe_on_message_listener, setup_dual, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_while_publishing_same_context, setup, teardown),
#endif
        cmocka_unit_test_setup_teardown(
            concurrent_publish_two_threads_same_context, setup, teardown),
        cmocka_unit_test_setup_teardown(future_release_from_callback, setup, teardown),
        cmocka_unit_test_setup_teardown(cancel_from_callback, setup, teardown),
        cmocka_unit_test_setup_teardown(
            rapid_sequential_operations_same_context, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

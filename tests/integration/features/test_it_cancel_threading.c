/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/*
 * G-021: Cross-thread request cancellation.
 *
 * pubnub_future_cancel must be safe to call from a thread other than the
 * one that issued (and may be awaiting) the request. The cancel path and
 * the await path both funnel through the per-context lock, so a
 * concurrent cancel must never deadlock, corrupt the slot, or crash —
 * regardless of which side wins the race.
 *
 * These tests require PUBNUB_CFG_THREAD_SAFETY=1 so the per-context lock
 * is a real mutex. No background I/O thread is started here: pubnub_async
 * is never called, so pubnub_await drives the cooperative processing tick
 * on the calling (main) thread. The secondary thread's
 * pubnub_future_cancel therefore races that in-thread processing through
 * the context and pool locks — exactly the cross-thread contention that
 * THREAD_SAFETY must make safe. Each test is guarded by a watchdog so a
 * deadlock terminates the binary with a diagnostic instead of hanging
 * until the ctest wall-clock timeout.
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

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** Per-test watchdog budget (seconds). A cross-thread cancel that
 *  deadlocks must trip this rather than hang the suite. */
#define CT_WATCHDOG_S 10U
/** Delay before the secondary thread fires the cancel, giving the main
 *  thread time to enter pubnub_await first. */
#define CT_CANCEL_DELAY_MS 20U

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
    /* Disarm unconditionally: if a test body longjmp'd out on an assert
     * failure between arm and disarm, the alarm/watchdog thread is still
     * pending and would otherwise fire during a later test with a
     * misattributed diagnostic. it_watchdog_disarm() is idempotent. */
    it_watchdog_disarm();
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

/** Argument block for the canceller thread. */
typedef struct ct_cancel_arg {
    pubnub_future_t fut;       /**< Future to cancel (shared value copy). */
    pubnub_res_t    cancel_rc; /**< Result of pubnub_future_cancel. */
} ct_cancel_arg_t;

static void* ct_cancel_thread(void* arg)
{
    ct_cancel_arg_t* a = (ct_cancel_arg_t*)arg;

    /* Let the main thread reach pubnub_await before cancelling so the
     * cancel genuinely races an in-flight await. */
    pn_test_sleep_ms(CT_CANCEL_DELAY_MS);
    a->cancel_rc = pubnub_future_cancel(a->fut);
    return NULL;
}

/*
 * Test 1: a secondary thread cancels a request while the main thread is
 * blocked in pubnub_await on the same future.
 *
 * The await must return a terminal code — either PUBNUB_OK (the publish
 * completed before the cancel took effect) or PUBNUB_ERR_CANCELLED (the
 * cancel won). Any other outcome, a hang, or a crash is a defect.
 */
static void cross_thread_cancel_during_await(void** state)
{
    it_test_state_t* s = *state;
    ct_cancel_arg_t  arg;
    pn_test_thread_t canceller;
    pubnub_future_t  fut;
    pubnub_res_t     st;
    int              rc;

    print_message("channel: %s", s->channel);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    it_watchdog_arm(CT_WATCHDOG_S, "cross_thread_cancel_during_await");

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = s->channel,
                             .message = "\"ct-cancel-during-await\"",
                         });

    arg.fut       = fut;
    arg.cancel_rc = PUBNUB_ERR_INVALID_ARGUMENT;

    rc = pn_test_thread_create(&canceller, ct_cancel_thread, &arg);
    assert_int_equal(0, rc);

    st = pubnub_await(fut);

    pn_test_thread_join(canceller);
    it_watchdog_disarm();

    print_message("await result: %s, cancel rc: %s",
                  pubnub_res_str(st),
                  pubnub_res_str(arg.cancel_rc));
    assert_true(PUBNUB_OK == st || PUBNUB_ERR_CANCELLED == st);
    pubnub_future_release(fut);
}

/*
 * Test 2: cancel is issued before the await on the same thread.
 *
 * Cancelling a still-active request then awaiting it must resolve to a
 * terminal code without hanging: PUBNUB_ERR_CANCELLED if the cancel
 * landed first, or PUBNUB_OK if the publish had already completed.
 */
static void cancel_before_await(void** state)
{
    it_test_state_t* s = *state;
    pubnub_future_t  fut;
    pubnub_res_t     cancel_rc;
    pubnub_res_t     st;

    print_message("channel: %s", s->channel);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    it_watchdog_arm(CT_WATCHDOG_S, "cancel_before_await");

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = s->channel,
                             .message = "\"ct-cancel-before-await\"",
                         });

    cancel_rc = pubnub_future_cancel(fut);
    st        = pubnub_await(fut);

    it_watchdog_disarm();

    print_message("cancel rc: %s, await result: %s",
                  pubnub_res_str(cancel_rc),
                  pubnub_res_str(st));
    /* Cancel of a still-active request dispatches (OK); if the publish
     * had already gone terminal, cancel reports IN_PROGRESS (nothing to
     * do). Both are valid. */
    assert_true(PUBNUB_OK == cancel_rc || PUBNUB_IN_PROGRESS == cancel_rc);
    assert_true(PUBNUB_OK == st || PUBNUB_ERR_CANCELLED == st);
    pubnub_future_release(fut);
}

/*
 * Test 3: cancelling an already-completed future is a no-op.
 *
 * After a request reaches a terminal state, pubnub_future_cancel has
 * nothing to cancel and must report that via PUBNUB_IN_PROGRESS (the
 * documented "already terminal" sentinel) rather than pretending a
 * cancel was dispatched.
 */
static void cancel_completed_future_is_noop(void** state)
{
    it_test_state_t* s = *state;
    pubnub_future_t  fut;
    pubnub_res_t     st;
    pubnub_res_t     cancel_rc;

    print_message("channel: %s", s->channel);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    it_watchdog_arm(CT_WATCHDOG_S, "cancel_completed_future_is_noop");

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = s->channel,
                             .message = "\"ct-cancel-completed\"",
                         });

    st = pubnub_await(fut);
    assert_int_equal(PUBNUB_OK, st);

    cancel_rc = pubnub_future_cancel(fut);

    it_watchdog_disarm();

    print_message("post-completion cancel rc: %s", pubnub_res_str(cancel_rc));
    /* BUG if not PUBNUB_IN_PROGRESS: cancelling an already-completed
     * future must report the terminal state, not indicate the future is
     * still running or claim a cancel was dispatched. */
    assert_int_equal(PUBNUB_IN_PROGRESS, cancel_rc);
    pubnub_future_release(fut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            cross_thread_cancel_during_await, setup, teardown),
        cmocka_unit_test_setup_teardown(cancel_before_await, setup, teardown),
        cmocka_unit_test_setup_teardown(
            cancel_completed_future_is_noop, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

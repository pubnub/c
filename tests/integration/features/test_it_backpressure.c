/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/*
 * G-011: Concurrent same-context operations and bounded backpressure.
 *
 * The two-tier request pipeline (MAX_IN_FLIGHT in-flight + a bounded
 * pending queue) must accept multiple simultaneous operations on one
 * context and, once both tiers are saturated, reject further issues with
 * a deterministic PUBNUB_ERR_QUEUE_FULL instead of crashing, corrupting
 * state, or silently dropping work.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

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

/** Burst size — chosen larger than the full profile's 4 in-flight + 8
 *  pending = 12 capacity so at least one issue is forced to backpressure. */
#define BP_BURST_N 16U

/** Cooperative pump step (ms) while waiting for the subscribe handshake on a
 *  context that this thread also drives via pubnub_await(). */
#define BP_PUMP_STEP_MS 10U

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

/*
 * Test 1: two concurrent publishes on the same context both complete.
 *
 * Issue two publishes back-to-back WITHOUT awaiting the first, then
 * await both. Both must resolve to PUBNUB_OK — the second issue must
 * not fail merely because the first is still in flight.
 */
static void two_concurrent_publishes_both_complete(void** state)
{
    it_test_state_t* s = *state;
    pubnub_future_t  fut1;
    pubnub_future_t  fut2;
    pubnub_res_t     st1;
    pubnub_res_t     st2;

    print_message("channel: %s", s->channel);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    fut1 = pubnub_publish(s->ctx,
                          &(pubnub_publish_opts_t){
                              .channel = s->channel,
                              .message = "\"bp-concurrent-1\"",
                          });
    fut2 = pubnub_publish(s->ctx,
                          &(pubnub_publish_opts_t){
                              .channel = s->channel,
                              .message = "\"bp-concurrent-2\"",
                          });

    /* Both issues must have been accepted (in-flight or queued), never
     * rejected — two concurrent operations are within the baseline. */
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut1));
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut2));

    st1 = pubnub_await(fut1);
    st2 = pubnub_await(fut2);

    if (PUBNUB_OK != st1) {
        print_error("publish 1 failed: %s", pubnub_res_str(st1));
    }
    if (PUBNUB_OK != st2) {
        print_error("publish 2 failed: %s", pubnub_res_str(st2));
    }
    assert_int_equal(PUBNUB_OK, st1);
    assert_int_equal(PUBNUB_OK, st2);

    pubnub_future_release(fut1);
    pubnub_future_release(fut2);
}

/*
 * Test 2: a burst larger than pipeline capacity is handled cleanly.
 *
 * Every issued future must resolve to either PUBNUB_OK (accepted and
 * completed) or PUBNUB_ERR_QUEUE_FULL (rejected at the backpressure
 * boundary) — NEVER any other code, and NEVER a crash. After the burst
 * drains, the context must still accept new work.
 */
static void burst_beyond_capacity_tolerant(void** state)
{
    it_test_state_t* s = *state;
    pubnub_future_t  futs[BP_BURST_N];
    unsigned int     i;
    unsigned int     accepted = 0U;
    unsigned int     rejected = 0U;
    pubnub_future_t  probe_fut;
    pubnub_res_t     probe_st;

    print_message("channel: %s", s->channel);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    for (i = 0U; i < BP_BURST_N; ++i) {
        futs[i] = pubnub_publish(s->ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = s->channel,
                                     .message = "\"bp-burst\"",
                                 });
    }

    /* Drain every issued future. A terminal/rejected future returns from
     * pubnub_await immediately; an accepted one is driven to completion. */
    for (i = 0U; i < BP_BURST_N; ++i) {
        pubnub_res_t final_st = pubnub_await(futs[i]);

        if (PUBNUB_OK == final_st) {
            ++accepted;
        } else if (PUBNUB_ERR_QUEUE_FULL == final_st) {
            ++rejected;
        } else {
            print_error("burst[%u] resolved to unexpected code: %s",
                        i,
                        pubnub_res_str(final_st));
        }
        assert_true(PUBNUB_OK == final_st || PUBNUB_ERR_QUEUE_FULL == final_st);
        pubnub_future_release(futs[i]);
    }

    print_message("burst: %u accepted, %u backpressured", accepted, rejected);

    /* At least one publish must have been accepted — otherwise the
     * pipeline rejected the entire burst, which is a real defect. */
    assert_true(accepted > 0U);

    /* The context must remain healthy after the burst drains. */
    probe_fut = pubnub_publish(s->ctx,
                               &(pubnub_publish_opts_t){
                                   .channel = s->channel,
                                   .message = "\"bp-probe\"",
                               });
    probe_st  = pubnub_await(probe_fut);
    if (PUBNUB_OK != probe_st) {
        print_error("post-burst probe failed: %s", pubnub_res_str(probe_st));
    }
    assert_int_equal(PUBNUB_OK, probe_st);
    pubnub_future_release(probe_fut);
}

#if PUBNUB_ENABLE_SUBSCRIBE

static void on_bp_status_cb(const pubnub_subscribe_status_event_t* ev, void* user_data)
{
    it_bus_push_status((it_bus_t*)user_data, ev->status);
}

/*
 * Test 3: publish while a subscribe long-poll is pending on the same
 * context.
 *
 * A subscribe receive request occupies one in-flight slot for its entire
 * long-poll duration. A publish issued while that request is pending must
 * still be accepted and complete — the long-poll must not starve
 * transaction traffic.
 */
static void publish_while_subscribe_pending(void** state)
{
    it_test_state_t*            s               = *state;
    it_bus_t*                   bus             = it_bus_create();
    pubnub_subscribe_listener_t status_listener = {0};
    pubnub_listener_handle_t    slh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             pub_fut;
    pubnub_res_t                pub_st;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    status_listener.on_status = on_bp_status_cb;
    status_listener.user_data = bus;
    slh                       = pubnub_add_listener(s->ctx, &status_listener);

    entity = pubnub_channel(s->ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    /* This test drives BOTH the subscribe long-poll and the publish below
     * on the SAME context, and awaits the publish on ctx. A driver thread
     * pumping ctx would race pubnub_await(), so ctx must be pumped
     * cooperatively from this thread. pubnub_await() pumps ctx after
     * CONNECTED; here we pump it manually until the handshake connects. */
    {
        unsigned int waited_ms = 0U;
        int          connected = 0;

        while (waited_ms < IT_SUBSCRIBE_CONNECT_MAX_MS) {
            (void)pubnub_process(s->ctx);
            if (0
                != it_bus_wait_status(
                    bus, BP_PUMP_STEP_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
                connected = 1;
                break;
            }
            waited_ms += BP_PUMP_STEP_MS;
        }
        assert_int_not_equal(0, connected);
    }
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    /* Publish on the SAME context while the receive long-poll is pending. */
    pub_fut = pubnub_publish(s->ctx,
                             &(pubnub_publish_opts_t){
                                 .channel = s->channel,
                                 .message = "\"bp-while-sub\"",
                             });
    pub_st  = pubnub_await(pub_fut);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx, slh);
    it_bus_destroy(bus);

    if (PUBNUB_OK != pub_st) {
        print_error("publish-while-subscribe failed: %s", pubnub_res_str(pub_st));
    }
    assert_int_equal(PUBNUB_OK, pub_st);
    pubnub_future_release(pub_fut);
}

#endif /* PUBNUB_ENABLE_SUBSCRIBE */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            two_concurrent_publishes_both_complete, setup, teardown),
        cmocka_unit_test_setup_teardown(
            burst_beyond_capacity_tolerant, setup, teardown),
#if PUBNUB_ENABLE_SUBSCRIBE
        cmocka_unit_test_setup_teardown(
            publish_while_subscribe_pending, setup, teardown),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

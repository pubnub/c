/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/*
 * G-001: Subscribe event-engine AB-BA deadlock detection.
 *
 * With PUBNUB_CFG_THREAD_SAFETY=1 the SDK drives the subscribe long-poll
 * on its own background thread, holding the per-context lock while it
 * dispatches status/message events. A caller that unsubscribes from the
 * main thread must acquire that same lock. If the two paths acquire the
 * context lock and the subscribe-manager state in opposite orders, the
 * result is a classic AB-BA deadlock.
 *
 * These tests exercise unsubscribe concurrently with a live background
 * loop and use a watchdog so a deadlock terminates the binary with a
 * diagnostic instead of hanging. Liveness is proven positively: after
 * each unsubscribe the context must still reach a coherent subscribe
 * state again.
 *
 * Requires PUBNUB_CFG_THREAD_SAFETY=1 AND PUBNUB_ENABLE_SUBSCRIBE (both
 * enforced at the CMake registration site).
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "it_watchdog.h"

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"

#include "it_bus.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** Watchdog budget for the single-shot unsubscribe tests (seconds). */
#define ST_WATCHDOG_S 10U
/** Watchdog budget for the rapid churn loop (seconds). */
#define ST_LOOP_WATCHDOG_S 30U
/** Number of subscribe/unsubscribe/resubscribe cycles in the churn loop. */
#define ST_LOOP_N 10U
/** Inter-cycle pause for the rapid-reconnect loop.
 *  `IT_DELAY_RECEIVE_STABILIZE_MS` is enough for handshake teardown but not
 *  for server-side connection-rate throttle recovery on loaded CI runners. */
#define ST_LOOP_INTER_CYCLE_MS 600U

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

static void on_st_status_cb(const pubnub_subscribe_status_event_t* ev, void* user_data)
{
    it_bus_push_status((it_bus_t*)user_data, ev->status);
}

/*
 * Test 1: unsubscribe_all races the live background subscribe loop.
 *
 * Subscribe to a channel, wait for CONNECTED (background loop is now
 * actively polling and dispatching under the context lock), then call
 * pubnub_subscribe_unsubscribe_all from the main thread. The call must
 * return without deadlocking and the loop must wind down to a
 * DISCONNECTED status — proving the lock was actually released and the
 * teardown ran to completion.
 */
static void subscribe_then_unsubscribe_all_concurrent(void** state)
{
    it_test_state_t*            s        = *state;
    it_bus_t*                   bus      = it_bus_create();
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    lh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_res_t                unsub_rc;
    int                         disconnected;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    listener.on_status = on_st_status_cb;
    listener.user_data = bus;
    lh                 = pubnub_add_listener(s->ctx, &listener);

    entity = pubnub_channel(s->ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    it_watchdog_arm(ST_WATCHDOG_S, "subscribe_then_unsubscribe_all_concurrent");

    unsub_rc     = pubnub_subscribe_unsubscribe_all(s->ctx);
    disconnected = it_bus_wait_status(
        bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED);

    it_watchdog_disarm();

    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx, lh);
    it_bus_destroy(bus);

    print_message("unsubscribe_all rc: %s, disconnected: %d",
                  pubnub_res_str(unsub_rc),
                  disconnected);
    assert_int_equal(PUBNUB_OK, unsub_rc);
    assert_int_not_equal(0, disconnected);
}

/*
 * Test 2: single-subscription unsubscribe races the background loop.
 *
 * Same AB-BA exposure as test 1 but through the per-subscription
 * pubnub_subscription_unsubscribe entry point. After unsubscribing the
 * only active subscription the loop must emit DISCONNECTED.
 */
static void subscribe_then_subscription_unsubscribe_concurrent(void** state)
{
    it_test_state_t*            s        = *state;
    it_bus_t*                   bus      = it_bus_create();
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    lh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_res_t                unsub_rc;
    int                         disconnected;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    listener.on_status = on_st_status_cb;
    listener.user_data = bus;
    lh                 = pubnub_add_listener(s->ctx, &listener);

    entity = pubnub_channel(s->ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    it_watchdog_arm(ST_WATCHDOG_S,
                    "subscribe_then_subscription_unsubscribe_concurrent");

    unsub_rc     = pubnub_subscription_unsubscribe(sub);
    disconnected = it_bus_wait_status(
        bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED);

    it_watchdog_disarm();

    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx, lh);
    it_bus_destroy(bus);

    print_message("subscription_unsubscribe rc: %s, disconnected: %d",
                  pubnub_res_str(unsub_rc),
                  disconnected);
    assert_int_equal(PUBNUB_OK, unsub_rc);
    assert_int_not_equal(0, disconnected);
}

/*
 * Test 3: rapid subscribe / unsubscribe / resubscribe churn.
 *
 * Ten back-to-back cycles of create-subscribe-connect-unsubscribe-destroy
 * on the same context, each racing the background loop's lock. A single
 * missed unlock or state-order inversion in any cycle deadlocks and trips
 * the 30-second watchdog; a state-machine corruption shows up as a
 * missing CONNECTED on a later cycle.
 */
static void rapid_subscribe_unsubscribe_resubscribe_loop(void** state)
{
    it_test_state_t*            s        = *state;
    it_bus_t*                   bus      = it_bus_create();
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    lh;
    unsigned int                i;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    listener.on_status = on_st_status_cb;
    listener.user_data = bus;
    lh                 = pubnub_add_listener(s->ctx, &listener);

    it_watchdog_arm(ST_LOOP_WATCHDOG_S,
                    "rapid_subscribe_unsubscribe_resubscribe_loop");

    for (i = 0U; i < ST_LOOP_N; ++i) {
        pubnub_entity_t       entity = pubnub_channel(s->ctx, s->channel);
        pubnub_subscription_t sub    = pubnub_subscription_create(entity, NULL);
        int                   connected;

        pubnub_entity_destroy(entity);
        pubnub_subscription_subscribe(sub);

        connected = it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED);
        if (0 == connected) {
            print_error("cycle %u never reached CONNECTED", i);
        }
        assert_int_not_equal(0, connected);

        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);

        /* Brief pause so the server does not rate-limit rapid reconnects.
         * The TLS connection teardown on unsubscribe + immediate reconnect
         * on the next cycle can hit server-side connection throttling. */
        pn_test_sleep_ms(ST_LOOP_INTER_CYCLE_MS);
    }

    it_watchdog_disarm();

    pubnub_remove_listener(s->ctx, lh);
    it_bus_destroy(bus);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            subscribe_then_unsubscribe_all_concurrent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_then_subscription_unsubscribe_concurrent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            rapid_subscribe_unsubscribe_resubscribe_loop, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

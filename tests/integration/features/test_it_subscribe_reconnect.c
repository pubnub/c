/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/*
 * G-010: Subscribe channel continuity and no-replay across poll cycles.
 *
 * A subscribe stays live across many long-poll cycles, each of which
 * re-issues a receive request carrying the advanced timetoken. Two
 * observable invariants must hold:
 *   - Every subscribed channel keeps delivering across cycles (no channel
 *     is silently dropped when the receive request is renewed).
 *   - A message delivered once at timetoken T is never redelivered on a
 *     later cycle (the advanced timetoken is honoured — no replay).
 *
 * Channel-group subscription continuity is covered when the channel-group
 * feature is compiled in.
 *
 * Requires PUBNUB_ENABLE_SUBSCRIBE AND PUBNUB_ENABLE_PUBLISH (publish is
 * used to generate the messages whose delivery is observed). Registered
 * as a slow test — subscribe long-poll turnaround dominates the runtime.
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
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"

#if PUBNUB_ENABLE_CHANNEL_GROUPS
#include "pubnub/features/channel_groups.h"
#endif

#include "it_bus.h"
#include "it_channel.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** Time to let a subsequent long-poll cycle run while checking that no
 *  already-delivered message is replayed (milliseconds). */
#define SR_QUIESCE_MS 3000U
/** Poll interval for delivery-flag waits (milliseconds). */
#define SR_POLL_MS 50U

static int setup(void** state)
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

static int teardown(void** state)
{
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

/** @return non-zero when @p v equals the NUL-terminated string @p s. */
static int sr_view_eq(pubnub_string_view_t v, const char* s)
{
    size_t n = strlen(s);

    if (NULL == v.ptr) {
        return 0;
    }
    return v.len == n && 0 == memcmp(v.ptr, s, n);
}

static void on_sr_status_cb(const pubnub_subscribe_status_event_t* ev, void* user_data)
{
    it_bus_push_status((it_bus_t*)user_data, ev->status);
}

/** Tracks per-channel delivery for the multi-channel test. */
typedef struct sr_multi_ctx {
    const char*  chan_a;
    const char*  chan_b;
    volatile int got_a;
    volatile int got_b;
} sr_multi_ctx_t;

static void on_sr_multi_msg_cb(const pubnub_subscribe_event_t* ev, void* user_data)
{
    sr_multi_ctx_t* m = (sr_multi_ctx_t*)user_data;

    if (sr_view_eq(ev->channel, m->chan_a)) {
        m->got_a = 1;
    } else if (sr_view_eq(ev->channel, m->chan_b)) {
        m->got_b = 1;
    }
}

static int sr_both_received(void* arg)
{
    sr_multi_ctx_t* m = (sr_multi_ctx_t*)arg;
    return m->got_a && m->got_b;
}

/*
 * Test 1: a multi-channel subscribe keeps delivering on every channel
 * across long-poll cycles.
 *
 * Subscribe to two channels, confirm both deliver, then let another
 * long-poll cycle run and confirm both still deliver. A channel dropped
 * when the receive request is renewed would fail the second round.
 */
static void multi_channel_reconnect_resumes_all(void** state)
{
    it_test_state_t*            s               = *state;
    it_bus_t*                   bus             = it_bus_create();
    sr_multi_ctx_t              m               = {0};
    pubnub_subscribe_listener_t msg_listener    = {0};
    pubnub_subscribe_listener_t status_listener = {0};
    pubnub_listener_handle_t    mlh;
    pubnub_listener_handle_t    slh;
    pubnub_entity_t             ent_a;
    pubnub_entity_t             ent_b;
    pubnub_subscription_t       sub_a;
    pubnub_subscription_t       sub_b;
    pubnub_future_t             fa;
    pubnub_future_t             fb;
    int                         waited;

    assert_non_null(bus);
    m.chan_a = s->channel;
    m.chan_b = s->channel2;
    print_message("channels: %s , %s", m.chan_a, m.chan_b);

    /* Subscribe on ctx2 (pumped by the process driver) and publish on ctx
     * (driven cooperatively by pubnub_await). Awaiting on the driver-pumped
     * context would race the driver's pubnub_process on the same context. */
    msg_listener.on_message = on_sr_multi_msg_cb;
    msg_listener.user_data  = &m;
    mlh                     = pubnub_add_listener(s->ctx2, &msg_listener);

    status_listener.on_status = on_sr_status_cb;
    status_listener.user_data = bus;
    slh                       = pubnub_add_listener(s->ctx2, &status_listener);

    ent_a = pubnub_channel(s->ctx2, m.chan_a);
    sub_a = pubnub_subscription_create(ent_a, NULL);
    pubnub_entity_destroy(ent_a);
    pubnub_subscription_subscribe(sub_a);

    ent_b = pubnub_channel(s->ctx2, m.chan_b);
    sub_b = pubnub_subscription_create(ent_b, NULL);
    pubnub_entity_destroy(ent_b);
    pubnub_subscription_subscribe(sub_b);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, m.chan_a, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, m.chan_b, NULL);

    /* Round 1: both channels must deliver. */
    fa = pubnub_publish(
        s->ctx,
        &(pubnub_publish_opts_t){.channel = m.chan_a, .message = "\"sr-a1\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fa));
    pubnub_future_release(fa);
    fb = pubnub_publish(
        s->ctx,
        &(pubnub_publish_opts_t){.channel = m.chan_b, .message = "\"sr-b1\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fb));
    pubnub_future_release(fb);

    waited = pn_test_wait_until(
        sr_both_received, &m, IT_SUBSCRIBE_MESSAGE_MAX_MS, SR_POLL_MS);
    assert_true(waited);

    /* Round 2: after another long-poll cycle both channels must still
     * be live. */
    m.got_a = 0;
    m.got_b = 0;
    fa      = pubnub_publish(
        s->ctx,
        &(pubnub_publish_opts_t){.channel = m.chan_a, .message = "\"sr-a2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fa));
    pubnub_future_release(fa);
    fb = pubnub_publish(
        s->ctx,
        &(pubnub_publish_opts_t){.channel = m.chan_b, .message = "\"sr-b2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fb));
    pubnub_future_release(fb);

    waited = pn_test_wait_until(
        sr_both_received, &m, IT_SUBSCRIBE_MESSAGE_MAX_MS, SR_POLL_MS);
    assert_true(waited);

    pubnub_subscription_unsubscribe(sub_a);
    pubnub_subscription_unsubscribe(sub_b);
    pubnub_subscription_destroy(sub_a);
    pubnub_subscription_destroy(sub_b);
    pubnub_remove_listener(s->ctx2, slh);
    pubnub_remove_listener(s->ctx2, mlh);
    it_bus_destroy(bus);
}

/** Counts total messages delivered on the subscribed channel. */
typedef struct sr_count_ctx {
    volatile int count;
} sr_count_ctx_t;

static void on_sr_count_msg_cb(const pubnub_subscribe_event_t* ev, void* user_data)
{
    (void)ev;
    ++((sr_count_ctx_t*)user_data)->count;
}

static int sr_count_at_least_1(void* arg)
{
    return ((sr_count_ctx_t*)arg)->count >= 1;
}

static int sr_count_at_least_2(void* arg)
{
    return ((sr_count_ctx_t*)arg)->count >= 2;
}

/*
 * Test 2: a delivered message is not replayed on subsequent poll cycles.
 *
 * Publish one message and receive it, then idle through another long-poll
 * cycle: the delivery count must stay at 1 (no spontaneous replay).
 * Publishing a second message must raise the count to exactly 2 — if the
 * receive request had renewed with a stale timetoken, the first message
 * would be redelivered and the count would overshoot.
 */
static void reconnect_no_replay(void** state)
{
    it_test_state_t*            s               = *state;
    it_bus_t*                   bus             = it_bus_create();
    sr_count_ctx_t              c               = {0};
    pubnub_subscribe_listener_t msg_listener    = {0};
    pubnub_subscribe_listener_t status_listener = {0};
    pubnub_listener_handle_t    mlh;
    pubnub_listener_handle_t    slh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    int                         count_after_first;

    assert_non_null(bus);
    print_message("channel: %s", s->channel);

    /* Subscribe on ctx2 (pumped by the process driver) and publish on ctx
     * (driven cooperatively by pubnub_await). Awaiting on the driver-pumped
     * context would race the driver's pubnub_process on the same context. */
    msg_listener.on_message = on_sr_count_msg_cb;
    msg_listener.user_data  = &c;
    mlh                     = pubnub_add_listener(s->ctx2, &msg_listener);

    status_listener.on_status = on_sr_status_cb;
    status_listener.user_data = bus;
    slh                       = pubnub_add_listener(s->ctx2, &status_listener);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"sr-first\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    assert_true(pn_test_wait_until(
        sr_count_at_least_1, &c, IT_SUBSCRIBE_MESSAGE_MAX_MS, SR_POLL_MS));
    count_after_first = c.count;
    assert_int_equal(1, count_after_first);

    /* Idle across another long-poll cycle — no message should replay. */
    pn_test_sleep_ms(SR_QUIESCE_MS);
    assert_int_equal(1, c.count);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"sr-second\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    assert_true(pn_test_wait_until(
        sr_count_at_least_2, &c, IT_SUBSCRIBE_MESSAGE_MAX_MS, SR_POLL_MS));

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, slh);
    pubnub_remove_listener(s->ctx2, mlh);
    it_bus_destroy(bus);

    /* Exactly two deliveries — the first message must not have replayed
     * when the second arrived. */
    assert_int_equal(2, c.count);
}

#if PUBNUB_ENABLE_CHANNEL_GROUPS

static void on_sr_group_msg_cb(const pubnub_subscribe_event_t* ev, void* user_data)
{
    (void)ev;
    *(volatile int*)user_data = 1;
}

static int sr_flag_set(void* arg)
{
    return *(volatile int*)arg;
}

/*
 * Test 3: a channel-group subscription delivers messages published to a
 * member channel.
 *
 * Adds a channel to a fresh group, subscribes to the group, and verifies
 * a message published to the member channel arrives — the group
 * membership must survive the subscribe long-poll cycle.
 */
static void channel_group_reconnect(void** state)
{
    it_test_state_t*                s        = *state;
    it_bus_t*                       bus      = it_bus_create();
    volatile int                    received = 0;
    const char*                     group    = it_unique_name("sr-cg");
    const char*                     member;
    pubnub_channel_group_add_opts_t add_opts;
    pubnub_future_t                 add_fut;
    pubnub_res_t                    add_st;
    pubnub_subscribe_listener_t     msg_listener    = {0};
    pubnub_subscribe_listener_t     status_listener = {0};
    pubnub_listener_handle_t        mlh;
    pubnub_listener_handle_t        slh;
    pubnub_entity_t                 entity;
    pubnub_subscription_t           sub;
    pubnub_future_t                 pub_fut;
    pubnub_res_t                    pub_st;
    int                             waited;

    assert_non_null(bus);
    member = s->channel;
    print_message("group: %s, member: %s", group, member);

    add_opts = (pubnub_channel_group_add_opts_t)PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    add_opts.channel_group = group;
    add_opts.channels      = member;
    add_fut = pubnub_channel_group_add_channels(s->ctx, &add_opts);
    add_st  = pubnub_await(add_fut);
    pubnub_future_release(add_fut);
    assert_int_equal(PUBNUB_OK, add_st);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_REMOVE_CHANNEL_GROUP, group, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, member, NULL);

    pn_test_sleep_ms(IT_DELAY_CHANNEL_GROUP_MS);

    /* Subscribe on ctx2 (pumped by the process driver) and publish on ctx
     * (driven cooperatively by pubnub_await). The channel group is created
     * above via ctx but is keyset-scoped, so ctx2 (same subscribe key) can
     * subscribe to it. Awaiting on the driver-pumped context would race the
     * driver's pubnub_process on the same context. */
    msg_listener.on_message = on_sr_group_msg_cb;
    msg_listener.user_data  = (void*)&received;
    mlh                     = pubnub_add_listener(s->ctx2, &msg_listener);

    status_listener.on_status = on_sr_status_cb;
    status_listener.user_data = bus;
    slh                       = pubnub_add_listener(s->ctx2, &status_listener);

    entity = pubnub_channel_group(s->ctx2, group);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    pub_fut = pubnub_publish(
        s->ctx, &(pubnub_publish_opts_t){.channel = member, .message = "\"sr-cg\""});
    pub_st = pubnub_await(pub_fut);
    pubnub_future_release(pub_fut);
    assert_int_equal(PUBNUB_OK, pub_st);

    waited = pn_test_wait_until(
        sr_flag_set, (void*)&received, IT_SUBSCRIBE_MESSAGE_MAX_MS, SR_POLL_MS);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, slh);
    pubnub_remove_listener(s->ctx2, mlh);
    it_bus_destroy(bus);

    assert_true(waited);
}

#endif /* PUBNUB_ENABLE_CHANNEL_GROUPS */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            multi_channel_reconnect_resumes_all, setup, teardown),
        cmocka_unit_test_setup_teardown(reconnect_no_replay, setup, teardown),
#if PUBNUB_ENABLE_CHANNEL_GROUPS
        cmocka_unit_test_setup_teardown(channel_group_reconnect, setup, teardown),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

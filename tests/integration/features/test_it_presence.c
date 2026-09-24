/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/channel_groups.h"
#include "pubnub/features/presence.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"
#include "pubnub/json.h"

#include "core/pn_format.h"

#include "it_bus.h"
#include "it_channel.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/**
 * @brief Presence-enabled subscriber context.
 *
 * Creates a context with presence_timeout=30 so the subscribe URL
 * includes the heartbeat parameter. Without it the PubNub server does
 * not register the UUID for presence tracking and here_now returns 0.
 */
static pubnub_context_t* create_presence_sub_ctx(it_test_state_t* s,
                                                 const char*      user_id)
{
    pubnub_config_t   cfg = pubnub_config_defaults();
    pubnub_context_t* ctx;

    cfg.subscribe_key              = s->env->subscribe_key;
    cfg.publish_key                = s->env->publish_key;
    cfg.user_id                    = user_id;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.presence_timeout           = 30;
    ctx                            = pubnub_create(&cfg);
    if (NULL != ctx) {
        it_state_pump_ctx(s, ctx);
    }
    return ctx;
}

typedef struct {
    pubnub_context_t* ctx;
    const char*       channel;
    uint32_t          min_occupancy;
} here_now_poll_args_t;

typedef struct {
    pubnub_context_t* ctx;
    const char*       uuid;
    const char*       channel1;
    const char*       channel2;
} where_now_poll_args_t;

typedef struct {
    pubnub_context_t* ctx;
    const char*       channel;
} here_now_state_args_t;

static void on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    it_bus_push_status((it_bus_t*)ud, ev->status);
}

static int check_here_now_occupancy(void* arg)
{
    here_now_poll_args_t*    a    = (here_now_poll_args_t*)arg;
    pubnub_here_now_opts_t   opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t          fut;
    pubnub_here_now_result_t res;

    opts.channels = a->channel;
    fut           = pubnub_here_now(a->ctx, &opts);
    if (PUBNUB_OK != pubnub_await(fut)) {
        pubnub_future_release(fut);
        return 0;
    }
    res = pubnub_here_now_result(fut);
    pubnub_future_release(fut);
    return (int)(res.total_occupancy >= a->min_occupancy);
}

static int check_where_now_channels(void* arg)
{
    where_now_poll_args_t*    a    = (where_now_poll_args_t*)arg;
    pubnub_where_now_opts_t   opts = PUBNUB_WHERE_NOW_OPTS_INIT;
    pubnub_future_t           fut;
    pubnub_where_now_result_t res;
    int                       found1 = 0;
    int                       found2 = 0;
    size_t                    i;

    opts.uuid = a->uuid;
    fut       = pubnub_where_now(a->ctx, &opts);
    if (PUBNUB_OK != pubnub_await(fut)) {
        pubnub_future_release(fut);
        return 0;
    }
    res = pubnub_where_now_result(fut);
    for (i = 0; i < (size_t)res.channel_count; ++i) {
        pubnub_string_view_t ch = pubnub_where_now_result_channel_at(fut, i);
        if (ch.len == strlen(a->channel1)
            && 0 == memcmp(ch.ptr, a->channel1, ch.len)) {
            found1 = 1;
        }
        if (ch.len == strlen(a->channel2)
            && 0 == memcmp(ch.ptr, a->channel2, ch.len)) {
            found2 = 1;
        }
    }
    pubnub_future_release(fut);
    return found1 && found2;
}

static int check_here_now_has_state(void* arg)
{
    here_now_state_args_t*           a    = (here_now_state_args_t*)arg;
    pubnub_here_now_opts_t           opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t                  fut;
    pubnub_here_now_result_t         res;
    pubnub_here_now_channel_result_t ch_res;
    int                              ok = 0;
    size_t                           j;

    opts.channels      = a->channel;
    opts.include_state = 1;
    fut                = pubnub_here_now(a->ctx, &opts);
    if (PUBNUB_OK != pubnub_await(fut)) {
        pubnub_future_release(fut);
        return 0;
    }
    res = pubnub_here_now_result(fut);
    if (0 < res.channel_count) {
        ch_res = pubnub_here_now_result_channel_at(fut, 0);
        for (j = 0; j < (size_t)ch_res.occupant_count; ++j) {
            pubnub_here_now_occupant_result_t occ =
                pubnub_here_now_result_occupant_at(fut, 0, j);
            if (0 < occ.state.len) {
                ok = 1;
                break;
            }
        }
    }
    pubnub_future_release(fut);
    return ok;
}

static int setup(void** state)
{
    const it_env_t*  env = it_env_load();
    it_test_state_t* s;

    SKIP_IF_NO_KEYS(env);
    s = it_state_create(env);
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

static void here_now_reflects_subscribed_client(void** state)
{
    it_test_state_t*  s           = *state;
    it_bus_t*         bus         = it_bus_create();
    pubnub_context_t* sub_ctx     = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    here_now_poll_args_t        args;

    print_message("channel: %s", s->channel);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    /* Poll here_now via s->ctx (REST-only); sub_ctx is the subscriber */
    args.ctx           = s->ctx;
    args.channel       = s->channel;
    args.min_occupancy = 1;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 1");
        goto cleanup;
    }

cleanup:
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void here_now_empty_channel_returns_zero(void** state)
{
    it_test_state_t*         s    = *state;
    pubnub_here_now_opts_t   opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t          fut;
    pubnub_here_now_result_t res;

    print_message("channel2: %s", s->channel2);

    opts.channels = s->channel2;
    fut           = pubnub_here_now(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_here_now_result(fut);
    assert_int_equal(0, (int)res.total_occupancy);
    pubnub_future_release(fut);
}

static void where_now_returns_subscribed_channels(void** state)
{
    it_test_state_t*  s           = *state;
    it_bus_t*         bus         = it_bus_create();
    pubnub_context_t* sub_ctx     = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             e1;
    pubnub_entity_t             e2;
    pubnub_subscription_t       sub1;
    pubnub_subscription_t       sub2;
    pubnub_subscription_set_t   ss;
    where_now_poll_args_t       args;

    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    ss   = pubnub_subscription_set_create(sub_ctx);
    e1   = pubnub_channel(sub_ctx, s->channel);
    sub1 = pubnub_subscription_create(e1, NULL);
    pubnub_entity_destroy(e1);
    e2   = pubnub_channel(sub_ctx, s->channel2);
    sub2 = pubnub_subscription_create(e2, NULL);
    pubnub_entity_destroy(e2);
    pubnub_subscription_set_add_subscription(ss, sub1);
    pubnub_subscription_set_add_subscription(ss, sub2);
    pubnub_subscription_set_subscribe(ss);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    /* Query via s->ctx; the subscriber's uuid is s->user_id */
    args.ctx      = s->ctx;
    args.uuid     = s->user_id;
    args.channel1 = s->channel;
    args.channel2 = s->channel2;
    if (!pn_test_wait_until(check_where_now_channels,
                            &args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for where_now channels");
        goto cleanup;
    }

cleanup:
    pubnub_subscription_set_unsubscribe(ss);
    pubnub_subscription_set_destroy(ss);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_destroy(sub2);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void set_state_get_state_round_trip(void** state)
{
    it_test_state_t*  s       = *state;
    it_bus_t*         bus     = it_bus_create();
    pubnub_context_t* sub_ctx = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t       l = {0};
    pubnub_listener_handle_t          h;
    pubnub_entity_t                   entity;
    pubnub_subscription_t             sub;
    pubnub_set_state_opts_t           ss_opts = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_get_state_opts_t           gs_opts = PUBNUB_GET_STATE_OPTS_INIT;
    pubnub_future_t                   fut;
    pubnub_get_state_result_t         res;
    pubnub_get_state_channel_result_t entry;
    pubnub_serialization_provider_t*  serial;
    const pubnub_json_value_t*        mood_v;
    size_t                            mlen = 0;
    const char*                       mstr;

    print_message("channel: %s  user: %s", s->channel, s->user_id);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    ss_opts.channels = s->channel;
    ss_opts.state    = "{\"mood\":\"testing\"}";
    fut              = pubnub_set_state(s->ctx, &ss_opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    fut = PUBNUB_FUTURE_INVALID;
    for (int _attempt = 0; _attempt < 5; _attempt++) {
        pn_test_sleep_ms(500);
        gs_opts.channels = s->channel;
        gs_opts.uuid     = s->user_id;
        fut              = pubnub_get_state(s->ctx, &gs_opts);
        assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
        res   = pubnub_get_state_result(fut);
        entry = pubnub_get_state_result_channel_at(fut, 0);
        if (NULL != entry.state) {
            break;
        }
        pubnub_future_release(fut);
        fut = PUBNUB_FUTURE_INVALID;
    }

    assert_int_not_equal(0, (int)res.channel_count);
    assert_non_null(entry.state);

    serial = pubnub_serialization(s->ctx);
    assert_non_null(serial);
    assert_non_null(serial->object_get);
    mood_v = serial->object_get(entry.state, "mood", 4);
    assert_non_null(mood_v);
    assert_non_null(serial->value_as_string);
    mstr = serial->value_as_string(mood_v, &mlen);
    assert_non_null(mstr);
    assert_int_equal(7, (int)mlen);
    assert_memory_equal("testing", mstr, 7);

    pubnub_future_release(fut);
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void here_now_multiple_occupants(void** state)
{
    it_test_state_t*            s    = *state;
    it_bus_t*                   bus1 = it_bus_create();
    it_bus_t*                   bus2 = it_bus_create();
    pubnub_context_t*           ctx_a;
    pubnub_context_t*           ctx_b;
    pubnub_subscribe_listener_t l1 = {0};
    pubnub_subscribe_listener_t l2 = {0};
    pubnub_listener_handle_t    h1;
    pubnub_listener_handle_t    h2;
    pubnub_entity_t             entity1;
    pubnub_entity_t             entity2;
    pubnub_subscription_t       sub1;
    pubnub_subscription_t       sub2;
    here_now_poll_args_t        args;

    print_message("channel: %s", s->channel);

    ctx_a = create_presence_sub_ctx(s, IT_UUID("pres-a"));
    ctx_b = create_presence_sub_ctx(s, IT_UUID("pres-b"));
    if (NULL == ctx_a || NULL == ctx_b) {
        if (NULL != ctx_a) {
            it_state_unpump_ctx(s, ctx_a);
            pubnub_destroy(ctx_a);
        }
        if (NULL != ctx_b) {
            it_state_unpump_ctx(s, ctx_b);
            pubnub_destroy(ctx_b);
        }
        it_bus_destroy(bus1);
        it_bus_destroy(bus2);
        skip();
    }

    l1.on_status = on_status_cb;
    l1.user_data = bus1;
    h1           = pubnub_add_listener(ctx_a, &l1);

    entity1 = pubnub_channel(ctx_a, s->channel);
    sub1    = pubnub_subscription_create(entity1, NULL);
    pubnub_entity_destroy(entity1);
    pubnub_subscription_subscribe(sub1);

    l2.on_status = on_status_cb;
    l2.user_data = bus2;
    h2           = pubnub_add_listener(ctx_b, &l2);

    entity2 = pubnub_channel(ctx_b, s->channel);
    sub2    = pubnub_subscription_create(entity2, NULL);
    pubnub_entity_destroy(entity2);
    pubnub_subscription_subscribe(sub2);

    if (!it_bus_wait_status(
            bus1, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on ctx_a");
        goto cleanup;
    }
    if (!it_bus_wait_status(
            bus2, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on ctx_b");
        goto cleanup;
    }

    args.ctx           = s->ctx;
    args.channel       = s->channel;
    args.min_occupancy = 2;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 2");
        goto cleanup;
    }

cleanup:
    pubnub_subscription_unsubscribe(sub1);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_unsubscribe(sub2);
    pubnub_subscription_destroy(sub2);
    pubnub_remove_listener(ctx_a, h1);
    pubnub_remove_listener(ctx_b, h2);
    it_state_unpump_ctx(s, ctx_a);
    pubnub_destroy(ctx_a);
    it_state_unpump_ctx(s, ctx_b);
    pubnub_destroy(ctx_b);
    it_bus_destroy(bus1);
    it_bus_destroy(bus2);
}

static void here_now_with_limit_honors_limit(void** state)
{
    it_test_state_t*                 s    = *state;
    it_bus_t*                        bus1 = it_bus_create();
    it_bus_t*                        bus2 = it_bus_create();
    it_bus_t*                        bus3 = it_bus_create();
    pubnub_context_t*                ctx_a;
    pubnub_context_t*                ctx_b;
    pubnub_context_t*                ctx_c;
    pubnub_subscribe_listener_t      l1 = {0};
    pubnub_subscribe_listener_t      l2 = {0};
    pubnub_subscribe_listener_t      l3 = {0};
    pubnub_listener_handle_t         h1;
    pubnub_listener_handle_t         h2;
    pubnub_listener_handle_t         h3;
    pubnub_entity_t                  entity1;
    pubnub_entity_t                  entity2;
    pubnub_entity_t                  entity3;
    pubnub_subscription_t            sub1;
    pubnub_subscription_t            sub2;
    pubnub_subscription_t            sub3;
    here_now_poll_args_t             poll_args;
    pubnub_here_now_opts_t           opts;
    pubnub_future_t                  fut;
    pubnub_here_now_result_t         res;
    pubnub_here_now_channel_result_t ch;

    print_message("channel: %s", s->channel);

    ctx_a = create_presence_sub_ctx(s, IT_UUID("lim-a"));
    ctx_b = create_presence_sub_ctx(s, IT_UUID("lim-b"));
    ctx_c = create_presence_sub_ctx(s, IT_UUID("lim-c"));
    if (NULL == ctx_a || NULL == ctx_b || NULL == ctx_c) {
        if (NULL != ctx_a) {
            it_state_unpump_ctx(s, ctx_a);
            pubnub_destroy(ctx_a);
        }
        if (NULL != ctx_b) {
            it_state_unpump_ctx(s, ctx_b);
            pubnub_destroy(ctx_b);
        }
        if (NULL != ctx_c) {
            it_state_unpump_ctx(s, ctx_c);
            pubnub_destroy(ctx_c);
        }
        it_bus_destroy(bus1);
        it_bus_destroy(bus2);
        it_bus_destroy(bus3);
        skip();
    }

    l1.on_status = on_status_cb;
    l1.user_data = bus1;
    h1           = pubnub_add_listener(ctx_a, &l1);
    entity1      = pubnub_channel(ctx_a, s->channel);
    sub1         = pubnub_subscription_create(entity1, NULL);
    pubnub_entity_destroy(entity1);
    pubnub_subscription_subscribe(sub1);

    l2.on_status = on_status_cb;
    l2.user_data = bus2;
    h2           = pubnub_add_listener(ctx_b, &l2);
    entity2      = pubnub_channel(ctx_b, s->channel);
    sub2         = pubnub_subscription_create(entity2, NULL);
    pubnub_entity_destroy(entity2);
    pubnub_subscription_subscribe(sub2);

    l3.on_status = on_status_cb;
    l3.user_data = bus3;
    h3           = pubnub_add_listener(ctx_c, &l3);
    entity3      = pubnub_channel(ctx_c, s->channel);
    sub3         = pubnub_subscription_create(entity3, NULL);
    pubnub_entity_destroy(entity3);
    pubnub_subscription_subscribe(sub3);

    if (!it_bus_wait_status(
            bus1, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on ctx_a");
        goto cleanup;
    }
    if (!it_bus_wait_status(
            bus2, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on ctx_b");
        goto cleanup;
    }
    if (!it_bus_wait_status(
            bus3, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on ctx_c");
        goto cleanup;
    }

    /* Wait until all 3 are visible to here_now. */
    poll_args.ctx           = s->ctx;
    poll_args.channel       = s->channel;
    poll_args.min_occupancy = 3;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &poll_args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 3");
        goto cleanup;
    }

    /* Server returns full occupancy but only limit=2 UUID entries. */
    opts          = (pubnub_here_now_opts_t)PUBNUB_HERE_NOW_OPTS_INIT;
    opts.channels = s->channel;
    opts.limit    = 2;
    fut           = pubnub_here_now(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));

    res = pubnub_here_now_result(fut);
    assert_int_not_equal(0, (int)res.channel_count);
    ch = pubnub_here_now_result_channel_at(fut, 0);

    assert_true(3 <= ch.occupancy);
    assert_int_equal(2, (int)ch.occupant_count);

    pubnub_future_release(fut);

cleanup:
    pubnub_subscription_unsubscribe(sub1);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_unsubscribe(sub2);
    pubnub_subscription_destroy(sub2);
    pubnub_subscription_unsubscribe(sub3);
    pubnub_subscription_destroy(sub3);
    pubnub_remove_listener(ctx_a, h1);
    pubnub_remove_listener(ctx_b, h2);
    pubnub_remove_listener(ctx_c, h3);
    it_state_unpump_ctx(s, ctx_a);
    pubnub_destroy(ctx_a);
    it_state_unpump_ctx(s, ctx_b);
    pubnub_destroy(ctx_b);
    it_state_unpump_ctx(s, ctx_c);
    pubnub_destroy(ctx_c);
    it_bus_destroy(bus1);
    it_bus_destroy(bus2);
    it_bus_destroy(bus3);
}

static void here_now_multiple_channels_returns_both(void** state)
{
    it_test_state_t*  s           = *state;
    it_bus_t*         bus         = it_bus_create();
    pubnub_context_t* sub_ctx     = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    here_now_poll_args_t        poll_args;
    pubnub_here_now_opts_t      opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t             fut;
    pubnub_here_now_result_t    res;
    char                        chan_both[192];
    int                         found_ch1 = 0;
    size_t                      i;

    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    /* Poll single-channel here_now via s->ctx until sub_ctx appears */
    poll_args.ctx           = s->ctx;
    poll_args.channel       = s->channel;
    poll_args.min_occupancy = 1;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &poll_args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 1");
        goto cleanup;
    }

    /* Multi-channel here_now query */
    pn_snprintf(chan_both, sizeof(chan_both), "%s,%s", s->channel, s->channel2);
    opts.channels = chan_both;
    fut           = pubnub_here_now(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));

    res = pubnub_here_now_result(fut);
    for (i = 0; i < (size_t)res.channel_count; ++i) {
        pubnub_here_now_channel_result_t ch =
            pubnub_here_now_result_channel_at(fut, i);
        if (ch.name.len == strlen(s->channel)
            && 0 == memcmp(ch.name.ptr, s->channel, ch.name.len)) {
            found_ch1 = 1;
            assert_int_not_equal(0, (int)ch.occupancy);
        }
        /* channel2 must not appear with non-zero occupancy */
        if (ch.name.len == strlen(s->channel2)
            && 0 == memcmp(ch.name.ptr, s->channel2, ch.name.len)) {
            assert_int_equal(0, (int)ch.occupancy);
        }
    }
    assert_int_not_equal(0, found_ch1);
    pubnub_future_release(fut);

cleanup:
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void here_now_with_state_includes_state_fields(void** state)
{
    it_test_state_t*  s           = *state;
    it_bus_t*         bus         = it_bus_create();
    pubnub_context_t* sub_ctx     = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_set_state_opts_t     ss_opts = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_future_t             fut;
    here_now_state_args_t       state_args;

    print_message("channel: %s", s->channel);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    /* Temporarily stop bg-thread pumping of sub_ctx to avoid racing
     * pubnub_await (which also calls pubnub_process on the context). */
    it_state_unpump_ctx(s, sub_ctx);

    ss_opts.channels = s->channel;
    ss_opts.state    = "{\"score\":99}";
    fut              = pubnub_set_state(sub_ctx, &ss_opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    /* Re-register for bg pumping (subscribe long-poll needs it). */
    it_state_pump_ctx(s, sub_ctx);

    /* Poll here_now (with state) via s->ctx until an occupant has state */
    state_args.ctx     = s->ctx;
    state_args.channel = s->channel;
    if (!pn_test_wait_until(check_here_now_has_state,
                            &state_args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupant state");
        goto cleanup;
    }

cleanup:
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void here_now_without_uuids_returns_count_only(void** state)
{
    it_test_state_t*  s                = *state;
    it_bus_t*         bus              = it_bus_create();
    pubnub_context_t* sub_ctx          = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t      l = {0};
    pubnub_listener_handle_t         h;
    pubnub_entity_t                  entity;
    pubnub_subscription_t            sub;
    here_now_poll_args_t             poll_args;
    pubnub_here_now_opts_t           opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t                  fut;
    pubnub_here_now_result_t         res;
    pubnub_here_now_channel_result_t ch_res;

    print_message("channel: %s", s->channel);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    poll_args.ctx           = s->ctx;
    poll_args.channel       = s->channel;
    poll_args.min_occupancy = 1;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &poll_args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 1");
        goto cleanup;
    }

    /* Query without UUIDs via s->ctx */
    opts.channels      = s->channel;
    opts.include_uuids = 0;
    fut                = pubnub_here_now(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));

    res = pubnub_here_now_result(fut);
    assert_int_not_equal(0, (int)res.total_occupancy);

    if (0 < res.channel_count) {
        ch_res = pubnub_here_now_result_channel_at(fut, 0);
        assert_int_not_equal(0, (int)ch_res.occupancy);
        assert_int_equal(0, (int)ch_res.occupant_count);
    }
    pubnub_future_release(fut);

cleanup:
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void here_now_unsubscribed_channel_returns_zero(void** state)
{
    it_test_state_t*  s           = *state;
    it_bus_t*         bus         = it_bus_create();
    pubnub_context_t* sub_ctx     = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    here_now_poll_args_t        poll_args;
    pubnub_here_now_opts_t      opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t             fut;
    pubnub_here_now_result_t    res;

    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    /* Confirm sub_ctx appears on channel1 before querying channel2 */
    poll_args.ctx           = s->ctx;
    poll_args.channel       = s->channel;
    poll_args.min_occupancy = 1;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &poll_args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 1 on channel");
        goto cleanup;
    }

    opts.channels = s->channel2;
    fut           = pubnub_here_now(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_here_now_result(fut);
    assert_int_equal(0, (int)res.total_occupancy);
    pubnub_future_release(fut);

cleanup:
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void set_state_get_state_multi_channel_round_trips(void** state)
{
    it_test_state_t*  s                = *state;
    it_bus_t*         bus              = it_bus_create();
    pubnub_context_t* sub_ctx          = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t      l = {0};
    pubnub_listener_handle_t         h;
    pubnub_entity_t                  e1;
    pubnub_entity_t                  e2;
    pubnub_subscription_t            sub1;
    pubnub_subscription_t            sub2;
    pubnub_subscription_set_t        ss;
    pubnub_set_state_opts_t          ss_opts = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_get_state_opts_t          gs_opts = PUBNUB_GET_STATE_OPTS_INIT;
    pubnub_future_t                  fut;
    pubnub_get_state_result_t        res;
    pubnub_serialization_provider_t* serial;
    char                             chan_both[192];
    size_t                           i;

    print_message("ch1: %s  ch2: %s  user: %s", s->channel, s->channel2, s->user_id);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    pn_snprintf(chan_both, sizeof(chan_both), "%s,%s", s->channel, s->channel2);

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    ss   = pubnub_subscription_set_create(sub_ctx);
    e1   = pubnub_channel(sub_ctx, s->channel);
    sub1 = pubnub_subscription_create(e1, NULL);
    pubnub_entity_destroy(e1);
    e2   = pubnub_channel(sub_ctx, s->channel2);
    sub2 = pubnub_subscription_create(e2, NULL);
    pubnub_entity_destroy(e2);
    pubnub_subscription_set_add_subscription(ss, sub1);
    pubnub_subscription_set_add_subscription(ss, sub2);
    pubnub_subscription_set_subscribe(ss);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    ss_opts.channels = chan_both;
    ss_opts.state    = "{\"score\":77}";
    fut              = pubnub_set_state(s->ctx, &ss_opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    fut = PUBNUB_FUTURE_INVALID;
    for (int _attempt = 0; _attempt < 5; _attempt++) {
        pn_test_sleep_ms(500);
        gs_opts.channels = chan_both;
        gs_opts.uuid     = s->user_id;
        fut              = pubnub_get_state(s->ctx, &gs_opts);
        assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
        res = pubnub_get_state_result(fut);
        if (2 <= (int)res.channel_count) {
            break;
        }
        pubnub_future_release(fut);
        fut = PUBNUB_FUTURE_INVALID;
    }

    assert_true(2 <= (int)res.channel_count);

    serial = pubnub_serialization(s->ctx);
    assert_non_null(serial);
    assert_non_null(serial->object_get);
    assert_non_null(serial->value_as_int);

    for (i = 0; i < (size_t)res.channel_count; ++i) {
        pubnub_get_state_channel_result_t entry =
            pubnub_get_state_result_channel_at(fut, i);
        const pubnub_json_value_t* score_v;
        int                        score = 0;

        assert_non_null(entry.state);
        score_v = serial->object_get(entry.state, "score", 5);
        assert_non_null(score_v);
        assert_int_equal(PUBNUB_OK, (int)serial->value_as_int(score_v, &score));
        assert_int_equal(77, score);
    }

    pubnub_future_release(fut);
    pubnub_subscription_set_unsubscribe(ss);
    pubnub_subscription_set_destroy(ss);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_destroy(sub2);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void get_state_multi_channel_returns_both_channels(void** state)
{
    it_test_state_t*  s                = *state;
    it_bus_t*         bus              = it_bus_create();
    pubnub_context_t* sub_ctx          = create_presence_sub_ctx(s, s->user_id);
    pubnub_subscribe_listener_t      l = {0};
    pubnub_listener_handle_t         h;
    pubnub_entity_t                  e1;
    pubnub_entity_t                  e2;
    pubnub_subscription_t            sub1;
    pubnub_subscription_t            sub2;
    pubnub_subscription_set_t        ss;
    pubnub_set_state_opts_t          ss_opts = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_get_state_opts_t          gs_opts = PUBNUB_GET_STATE_OPTS_INIT;
    pubnub_future_t                  fut;
    pubnub_get_state_result_t        res;
    pubnub_serialization_provider_t* serial;
    char                             chan_both[192];
    size_t                           i;

    print_message("ch1: %s  ch2: %s  user: %s", s->channel, s->channel2, s->user_id);

    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    pn_snprintf(chan_both, sizeof(chan_both), "%s,%s", s->channel, s->channel2);

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    ss   = pubnub_subscription_set_create(sub_ctx);
    e1   = pubnub_channel(sub_ctx, s->channel);
    sub1 = pubnub_subscription_create(e1, NULL);
    pubnub_entity_destroy(e1);
    e2   = pubnub_channel(sub_ctx, s->channel2);
    sub2 = pubnub_subscription_create(e2, NULL);
    pubnub_entity_destroy(e2);
    pubnub_subscription_set_add_subscription(ss, sub1);
    pubnub_subscription_set_add_subscription(ss, sub2);
    pubnub_subscription_set_subscribe(ss);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    ss_opts.channels = s->channel;
    ss_opts.state    = "{\"tag\":\"test\"}";
    fut              = pubnub_set_state(s->ctx, &ss_opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ss_opts          = (pubnub_set_state_opts_t)PUBNUB_SET_STATE_OPTS_INIT;
    ss_opts.channels = s->channel2;
    ss_opts.state    = "{\"tag\":\"test\"}";
    fut              = pubnub_set_state(s->ctx, &ss_opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    fut = PUBNUB_FUTURE_INVALID;
    for (int _attempt = 0; _attempt < 5; _attempt++) {
        pn_test_sleep_ms(500);
        gs_opts.channels = chan_both;
        gs_opts.uuid     = s->user_id;
        fut              = pubnub_get_state(s->ctx, &gs_opts);
        assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
        res = pubnub_get_state_result(fut);
        if (2 <= (int)res.channel_count) {
            break;
        }
        pubnub_future_release(fut);
        fut = PUBNUB_FUTURE_INVALID;
    }

    assert_true(2 <= (int)res.channel_count);

    serial = pubnub_serialization(s->ctx);
    assert_non_null(serial);
    assert_non_null(serial->object_get);

    for (i = 0; i < (size_t)res.channel_count; ++i) {
        pubnub_get_state_channel_result_t entry =
            pubnub_get_state_result_channel_at(fut, i);
        const pubnub_json_value_t* tag_v;

        assert_non_null(entry.state);
        tag_v = serial->object_get(entry.state, "tag", 3);
        assert_non_null(tag_v);
    }

    pubnub_future_release(fut);
    pubnub_subscription_set_unsubscribe(ss);
    pubnub_subscription_set_destroy(ss);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_destroy(sub2);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

static void here_now_with_channel_groups_returns_group_occupancy(void** state)
{
    it_test_state_t*                s   = *state;
    it_bus_t*                       bus = it_bus_create();
    pubnub_context_t*               sub_ctx;
    pubnub_subscribe_listener_t     l = {0};
    pubnub_listener_handle_t        h;
    pubnub_entity_t                 entity;
    pubnub_subscription_t           sub;
    pubnub_channel_group_add_opts_t ao = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    here_now_poll_args_t            poll_args;
    pubnub_here_now_opts_t          opts = PUBNUB_HERE_NOW_OPTS_INIT;
    pubnub_future_t                 fut;
    pubnub_here_now_result_t        res;
    char                            cg[80];

    pn_snprintf(cg, sizeof(cg), "%s", IT_GROUP("hncg"));
    it_cleanup_add(&s->cleanup, IT_CLEANUP_REMOVE_CHANNEL_GROUP, cg, NULL);

    print_message("channel: %s  group: %s", s->channel, cg);

    sub_ctx = create_presence_sub_ctx(s, s->user_id);
    if (NULL == sub_ctx) {
        it_bus_destroy(bus);
        skip();
    }

    ao.channel_group = cg;
    ao.channels      = s->channel;
    fut              = pubnub_channel_group_add_channels(s->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(sub_ctx, &l);

    entity = pubnub_channel(sub_ctx, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    if (!it_bus_wait_status(
            bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED)) {
        fail_msg("timed out waiting for CONNECTED on s->channel");
        goto cleanup;
    }

    poll_args.ctx           = s->ctx;
    poll_args.channel       = s->channel;
    poll_args.min_occupancy = 1;
    if (!pn_test_wait_until(check_here_now_occupancy,
                            &poll_args,
                            IT_PRESENCE_WAIT_MAX_MS,
                            IT_PRESENCE_WAIT_POLL_MS)) {
        fail_msg("timed out waiting for here_now occupancy >= 1");
        goto cleanup;
    }

    opts.channel_groups = cg;
    fut                 = pubnub_here_now(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));

    res = pubnub_here_now_result(fut);
    assert_true(1 <= (int)res.total_occupancy);
    pubnub_future_release(fut);

cleanup:
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(sub_ctx, h);
    it_state_unpump_ctx(s, sub_ctx);
    pubnub_destroy(sub_ctx);
    it_bus_destroy(bus);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            here_now_reflects_subscribed_client, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_empty_channel_returns_zero, setup, teardown),
        cmocka_unit_test_setup_teardown(
            where_now_returns_subscribed_channels, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_state_get_state_round_trip, setup, teardown),
        cmocka_unit_test_setup_teardown(here_now_multiple_occupants, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_with_limit_honors_limit, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_multiple_channels_returns_both, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_with_state_includes_state_fields, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_without_uuids_returns_count_only, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_unsubscribed_channel_returns_zero, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_state_get_state_multi_channel_round_trips, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_state_multi_channel_returns_both_channels, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_with_channel_groups_returns_group_occupancy, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

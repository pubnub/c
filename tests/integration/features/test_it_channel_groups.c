/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/channel_groups.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"

#include "it_bus.h"
#include "it_channel.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** @brief Per-test state for channel-groups integration tests. */
typedef struct {
    /** Base state with contexts, channels, and cleanup queue. */
    it_test_state_t* base;
    /** Unique channel group name for this test run. */
    char group[80];
} cg_test_state_t;

static int channel_in_list(pubnub_future_t fut, uint32_t count, const char* name)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < (size_t)count; ++i) {
        pubnub_string_view_t v =
            pubnub_channel_group_list_result_channel_at(fut, i);
        if (v.len == name_len && 0 == memcmp(v.ptr, name, v.len)) {
            return 1;
        }
    }
    return 0;
}

static void on_message_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    it_bus_push_message((it_bus_t*)ud, ev);
}

static void on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    it_bus_push_status((it_bus_t*)ud, ev->status);
}

static int setup(void** state)
{
    const it_env_t*  env = it_env_load();
    cg_test_state_t* s;

    SKIP_IF_NO_KEYS(env);
    s = calloc(1, sizeof(*s));
    if (NULL == s) {
        return -1;
    }
    s->base = it_state_create(env);
    if (NULL == s->base) {
        free(s);
        return -1;
    }
    snprintf(s->group, sizeof(s->group), "%s", IT_GROUP("grp"));
    it_cleanup_add(&s->base->cleanup, IT_CLEANUP_REMOVE_CHANNEL_GROUP, s->group, NULL);
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    cg_test_state_t* s = *state;
    it_state_destroy(s->base);
    free(s);
    return 0;
}

static void add_channels_returns_ok(void** state)
{
    cg_test_state_t*                s    = *state;
    pubnub_channel_group_add_opts_t opts = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    pubnub_future_t                 fut;

    print_message("group: %s  channel: %s", s->group, s->base->channel);

    opts.channel_group = s->group;
    opts.channels      = s->base->channel;
    fut                = pubnub_channel_group_add_channels(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void list_channels_returns_added_channels(void** state)
{
    cg_test_state_t*                   s  = *state;
    pubnub_channel_group_add_opts_t    ao = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    pubnub_channel_group_list_opts_t   lo = PUBNUB_CHANNEL_GROUP_LIST_OPTS_INIT;
    pubnub_channel_group_list_result_t res;
    pubnub_future_t                    fut;
    char                               both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("group: %s  channels: %s", s->group, both);

    ao.channel_group = s->group;
    ao.channels      = both;
    fut              = pubnub_channel_group_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_CHANNEL_GROUP_MS);

    lo.channel_group = s->group;
    fut              = pubnub_channel_group_list_channels(s->base->ctx, &lo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_channel_group_list_result(fut);
    assert_int_not_equal(0, (int)res.count);
    assert_int_not_equal(0, channel_in_list(fut, res.count, s->base->channel));
    assert_int_not_equal(0, channel_in_list(fut, res.count, s->base->channel2));
    pubnub_future_release(fut);
}

static void remove_channels_returns_ok(void** state)
{
    cg_test_state_t*                s  = *state;
    pubnub_channel_group_add_opts_t ao = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    pubnub_channel_group_remove_opts_t ro = PUBNUB_CHANNEL_GROUP_REMOVE_OPTS_INIT;
    pubnub_future_t fut;
    char            both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("group: %s  remove: %s", s->group, s->base->channel);

    ao.channel_group = s->group;
    ao.channels      = both;
    fut              = pubnub_channel_group_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ro.channel_group = s->group;
    ro.channels      = s->base->channel;
    fut              = pubnub_channel_group_remove_channels(s->base->ctx, &ro);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void list_after_remove_reflects_removal(void** state)
{
    cg_test_state_t*                s  = *state;
    pubnub_channel_group_add_opts_t ao = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    pubnub_channel_group_remove_opts_t ro = PUBNUB_CHANNEL_GROUP_REMOVE_OPTS_INIT;
    pubnub_channel_group_list_opts_t   lo = PUBNUB_CHANNEL_GROUP_LIST_OPTS_INIT;
    pubnub_channel_group_list_result_t res;
    pubnub_future_t                    fut;
    char                               both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("group: %s  remove: %s", s->group, s->base->channel);

    ao.channel_group = s->group;
    ao.channels      = both;
    fut              = pubnub_channel_group_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ro.channel_group = s->group;
    ro.channels      = s->base->channel;
    fut              = pubnub_channel_group_remove_channels(s->base->ctx, &ro);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_CHANNEL_GROUP_MS);

    lo.channel_group = s->group;
    fut              = pubnub_channel_group_list_channels(s->base->ctx, &lo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_channel_group_list_result(fut);
    assert_int_equal(0, channel_in_list(fut, res.count, s->base->channel));
    assert_int_not_equal(0, channel_in_list(fut, res.count, s->base->channel2));
    pubnub_future_release(fut);
}

static void remove_group_deletes_it_entirely(void** state)
{
    cg_test_state_t*                s  = *state;
    pubnub_channel_group_add_opts_t ao = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    pubnub_channel_group_remove_group_opts_t rgo =
        PUBNUB_CHANNEL_GROUP_REMOVE_GROUP_OPTS_INIT;
    pubnub_future_t fut;

    print_message("group: %s  channel: %s", s->group, s->base->channel);

    ao.channel_group = s->group;
    ao.channels      = s->base->channel;
    fut              = pubnub_channel_group_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    rgo.channel_group = s->group;
    fut               = pubnub_channel_group_remove(s->base->ctx, &rgo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void subscribe_to_channel_group_delivers_messages(void** state)
{
    cg_test_state_t*                s   = *state;
    pubnub_channel_group_add_opts_t ao  = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    it_bus_t*                       bus = NULL;
    pubnub_subscribe_listener_t     l   = {0};
    pubnub_listener_handle_t        h;
    pubnub_entity_t                 entity;
    pubnub_subscription_t           sub;
    pubnub_future_t                 fut;
    pubnub_subscribe_event_t        ev = {0};

    print_message("group: %s  channel: %s", s->group, s->base->channel);

    ao.channel_group = s->group;
    ao.channels      = s->base->channel;
    fut              = pubnub_channel_group_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_CHANNEL_GROUP_MS);

    it_state_add_ctx2(s->base);
    bus = it_bus_create();
    if (NULL == s->base->ctx2) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->base->ctx2, &l);

    entity = pubnub_channel_group(s->base->ctx2, s->group);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    fut = pubnub_publish(s->base->ctx,
                         &(pubnub_publish_opts_t){.channel = s->base->channel,
                                                  .message = "\"cg-test\""});
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->base->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->base->ctx2, h);
    it_bus_destroy(bus);
}

static void unsubscribe_from_channel_group_stops_delivery(void** state)
{
    cg_test_state_t*                s   = *state;
    pubnub_channel_group_add_opts_t ao  = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    it_bus_t*                       bus = NULL;
    pubnub_subscribe_listener_t     l   = {0};
    pubnub_listener_handle_t        h;
    pubnub_entity_t                 entity;
    pubnub_subscription_t           sub;
    pubnub_future_t                 fut;
    pubnub_subscribe_event_t        ev = {0};

    print_message("group: %s  channel: %s", s->group, s->base->channel);

    ao.channel_group = s->group;
    ao.channels      = s->base->channel;
    fut              = pubnub_channel_group_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_CHANNEL_GROUP_MS);

    it_state_add_ctx2(s->base);
    bus = it_bus_create();
    if (NULL == s->base->ctx2) {
        it_bus_destroy(bus);
        skip();
    }

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->base->ctx2, &l);

    entity = pubnub_channel_group(s->base->ctx2, s->group);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    /* Allow the subscribe loop to re-initiate without the channel group. */
    pn_test_sleep_ms(1000);

    fut =
        pubnub_publish(s->base->ctx,
                       &(pubnub_publish_opts_t){.channel = s->base->channel,
                                                .message = "\"after-unsub\""});
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->base->channel, NULL);

    assert_int_equal(0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));

    pubnub_remove_listener(s->base->ctx2, h);
    it_bus_destroy(bus);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(add_channels_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            list_channels_returns_added_channels, setup, teardown),
        cmocka_unit_test_setup_teardown(remove_channels_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            list_after_remove_reflects_removal, setup, teardown),
        cmocka_unit_test_setup_teardown(
            remove_group_deletes_it_entirely, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_to_channel_group_delivers_messages, setup, teardown),
        cmocka_unit_test_setup_teardown(
            unsubscribe_from_channel_group_stops_delivery, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

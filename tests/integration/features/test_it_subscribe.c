/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/error.h"
#include "pubnub/features/app_context.h"
#include "pubnub/features/files.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/features/presence.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/signal.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/response.h"

#include "it_bus.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

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

typedef struct {
    it_bus_t*         bus;
    pubnub_context_t* ctx;
    char              last_str[512];
    int               last_n;
} sub_full_listener_data_t;

static void on_message_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    it_bus_push_message((it_bus_t*)ud, ev);
}

static void on_presence_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    it_bus_push_message((it_bus_t*)ud, ev);
}

static void on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    it_bus_push_status((it_bus_t*)ud, ev->status);
}

/**
 * @brief Listener data for presence-event tests.
 *
 * The presence callback parses ev->payload inline while it is still valid
 * (the JSON tree is freed after the callback returns). Flags are set here
 * so the main thread can poll without touching the dangling payload pointer.
 */
typedef struct {
    /** Bus used for status events (CONNECTED / DISCONNECTED). */
    it_bus_t* bus;
    /** Context whose serialization provider is used to parse presence events. */
    pubnub_context_t* ctx;
    /** Set to 1 when any JOIN event with non-null payload arrives. */
    volatile int got_join;
    /** Set to 1 when a LEAVE event arrives. */
    volatile int got_leave;
    /** Set to 1 when a STATE_CHANGE event arrives. */
    volatile int got_state_change;
    /** Set to 1 when a TIMEOUT event arrives instead of a LEAVE event. */
    volatile int got_timeout;
    /** Only act on events from this UUID (NULL = accept all). */
    const char* expected_uuid;
} pres_listener_data_t;

static void pres_on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    pres_listener_data_t* d = (pres_listener_data_t*)ud;
    it_bus_push_status(d->bus, ev->status);
}

/** Presence callback that parses the event inline while ev->payload is valid. */
static void pres_on_presence_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    pres_listener_data_t*             d    = (pres_listener_data_t*)ud;
    pubnub_subscribe_presence_event_t pres = {0};

    if (NULL == ev->payload) {
        return;
    }
    if (PUBNUB_OK != pubnub_subscribe_event_presence(d->ctx, ev, &pres)) {
        return;
    }

    /* Only act on presence events from the expected actor UUID. Prevents the
     * observer's own self-JOIN (delivered by PubNub on initial subscribe) from
     * triggering the got_join flag before the actor has joined. */
    if (NULL != d->expected_uuid
        && (pres.uuid.len != strlen(d->expected_uuid)
            || 0 != memcmp(pres.uuid.ptr, d->expected_uuid, pres.uuid.len))) {
        return;
    }

    switch (pres.action) {
    case PUBNUB_PRESENCE_JOIN: d->got_join = 1; break;
    case PUBNUB_PRESENCE_LEAVE: d->got_leave = 1; break;
    case PUBNUB_PRESENCE_TIMEOUT: d->got_timeout = 1; break;
    case PUBNUB_PRESENCE_STATE_CHANGE: d->got_state_change = 1; break;
    default: break;
    }
}

static int check_flag(void* arg)
{
    return *(volatile int*)arg;
}

static void on_status_full_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    sub_full_listener_data_t* d = (sub_full_listener_data_t*)ud;
    it_bus_push_status(d->bus, ev->status);
}

static void on_message_full_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    sub_full_listener_data_t*        d      = (sub_full_listener_data_t*)ud;
    pubnub_subscribe_message_event_t msg    = {0};
    pubnub_serialization_provider_t* serial = NULL;

    if (PUBNUB_OK == pubnub_subscribe_event_message(d->ctx, ev, &msg)
        && NULL != msg.message) {
        serial = pubnub_serialization(d->ctx);
        if (NULL != serial) {
            if (NULL != serial->value_as_string) {
                size_t      len = 0U;
                const char* str = serial->value_as_string(msg.message, &len);
                if (NULL != str) {
                    size_t n = len < (sizeof(d->last_str) - 1U)
                                 ? len
                                 : (sizeof(d->last_str) - 1U);
                    memcpy(d->last_str, str, n);
                    d->last_str[n] = '\0';
                }
            }
            if (NULL != serial->object_get && NULL != serial->value_as_int) {
                const pubnub_json_value_t* n_node =
                    serial->object_get(msg.message, "n", 1U);
                if (NULL != n_node) {
                    (void)serial->value_as_int(n_node, &d->last_n);
                }
            }
        }
    }
    it_bus_push_message(d->bus, ev);
}

static void subscribe_receives_published_string_message(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    sub_full_listener_data_t    ld  = {0};
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    ld.bus       = bus;
    ld.ctx       = s->ctx2;
    l.on_status  = on_status_full_cb;
    l.on_message = on_message_full_cb;
    l.user_data  = &ld;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    fut =
        pubnub_publish(s->ctx,
                       &(pubnub_publish_opts_t){.channel = s->channel,
                                                .message = "\"hello from c\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);
    assert_string_equal("hello from c", ld.last_str);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_json_message_payload_intact(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    sub_full_listener_data_t    ld  = {0};
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    ld.bus       = bus;
    ld.ctx       = s->ctx2;
    l.on_status  = on_status_full_cb;
    l.on_message = on_message_full_cb;
    l.user_data  = &ld;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "{\"n\":42}"});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);
    assert_int_equal(42, ld.last_n);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_message_on_second_channel(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             e1;
    pubnub_entity_t             e2;
    pubnub_subscription_t       sub1;
    pubnub_subscription_t       sub2;
    pubnub_subscription_set_t   ss;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);
    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    ss   = pubnub_subscription_set_create(s->ctx2);
    e1   = pubnub_channel(s->ctx2, s->channel);
    sub1 = pubnub_subscription_create(e1, NULL);
    pubnub_entity_destroy(e1);
    e2   = pubnub_channel(s->ctx2, s->channel2);
    sub2 = pubnub_subscription_create(e2, NULL);
    pubnub_entity_destroy(e2);
    pubnub_subscription_set_add_subscription(ss, sub1);
    pubnub_subscription_set_add_subscription(ss, sub2);
    pubnub_subscription_set_subscribe(ss);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel2,
                                                  .message = "\"on-ch2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel2, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel2), (int)ev.channel.len);
    assert_memory_equal(s->channel2, ev.channel.ptr, ev.channel.len);

    pubnub_subscription_set_unsubscribe(ss);
    /* Set is non-owning: destroy the set first, members remain valid. */
    pubnub_subscription_set_destroy(ss);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_destroy(sub2);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_presence_join_event(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_opts_t  opts = {0};
    pubnub_subscription_t       sub;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    /* ctx2 subscribes with presence and detects its own join event.
     * PubNub delivers the self-join on the presence channel during
     * the first receive cycle after CONNECTED. */
    l.on_status   = on_status_cb;
    l.on_presence = on_presence_cb;
    l.user_data   = bus;
    h             = pubnub_add_listener(s->ctx2, &l);

    opts.with_presence = 1;
    entity             = pubnub_channel(s->ctx2, s->channel);
    sub                = pubnub_subscription_create(entity, &opts);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    assert_int_not_equal(0, it_bus_wait_message(bus, IT_PRESENCE_WAIT_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_PRESENCE, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_connected_status_fires_on_connect(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_set_delivers_messages_on_all_channels(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             e1;
    pubnub_entity_t             e2;
    pubnub_subscription_t       sub1;
    pubnub_subscription_t       sub2;
    pubnub_subscription_set_t   ss;
    pubnub_future_t             f1;
    pubnub_future_t             f2;
    pubnub_subscribe_event_t    ev1 = {0};
    pubnub_subscribe_event_t    ev2 = {0};

    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);
    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    ss   = pubnub_subscription_set_create(s->ctx2);
    e1   = pubnub_channel(s->ctx2, s->channel);
    sub1 = pubnub_subscription_create(e1, NULL);
    pubnub_entity_destroy(e1);
    e2   = pubnub_channel(s->ctx2, s->channel2);
    sub2 = pubnub_subscription_create(e2, NULL);
    pubnub_entity_destroy(e2);
    pubnub_subscription_set_add_subscription(ss, sub1);
    pubnub_subscription_set_add_subscription(ss, sub2);
    pubnub_subscription_set_subscribe(ss);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    f1 = pubnub_publish(s->ctx,
                        &(pubnub_publish_opts_t){.channel = s->channel,
                                                 .message = "\"msg-ch1\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(f1));
    pubnub_future_release(f1);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    f2 = pubnub_publish(s->ctx,
                        &(pubnub_publish_opts_t){.channel = s->channel2,
                                                 .message = "\"msg-ch2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(f2));
    pubnub_future_release(f2);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel2, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev1));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev1.type);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev2));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev2.type);

    pubnub_subscription_set_unsubscribe(ss);
    /* Set is non-owning: destroy the set first, members remain valid. */
    pubnub_subscription_set_destroy(ss);
    pubnub_subscription_destroy(sub1);
    pubnub_subscription_destroy(sub2);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_unsubscribe_resubscribe_delivers_message(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    pubnub_subscription_unsubscribe(sub);

    pubnub_subscription_subscribe(sub);
    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    fut =
        pubnub_publish(s->ctx,
                       &(pubnub_publish_opts_t){.channel = s->channel,
                                                .message = "\"resubscribed\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_wildcard_channel_receives_subchannel_message(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};
    char                        wildcard[96];
    char                        subchan[96];
    int                         got;

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    snprintf(wildcard, sizeof(wildcard), "%s.*", s->channel);
    snprintf(subchan, sizeof(subchan), "%s.sub", s->channel);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, wildcard);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    /* Skip if wildcard subscription fails to connect. */
    got = it_bus_wait_status(
        bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_CONNECTED);
    if (0 == got) {
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_remove_listener(s->ctx2, h);
        it_bus_destroy(bus);
        skip();
    }
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = subchan,
                                                  .message = "\"wildcard\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, subchan, NULL);

    got = it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev);
    if (0 == got) {
        /* Wildcard routing not active on this keyset — skip silently. */
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_remove_listener(s->ctx2, h);
        it_bus_destroy(bus);
        skip();
    }
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_custom_message_type_delivered_to_listener(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_publish_opts_t       opts;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    opts                     = (pubnub_publish_opts_t){0};
    opts.channel             = s->channel;
    opts.message             = "\"typed\"";
    opts.custom_message_type = "sub-type";
    fut                      = pubnub_publish(s->ctx, &opts);
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen("sub-type"), (int)ev.custom_message_type.len);
    assert_memory_equal(
        "sub-type", ev.custom_message_type.ptr, ev.custom_message_type.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_signal_event(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.on_signal  = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    fut = pubnub_signal(
        s->ctx,
        &(pubnub_signal_opts_t){.channel = s->channel, .message = "\"sig\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_SIGNAL, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);

    /* Accessor returns OK when the type matches. */
    pubnub_subscribe_signal_event_t sig = {0};
    assert_int_equal(PUBNUB_OK,
                     (int)pubnub_subscribe_event_signal(s->ctx2, &ev, &sig));
    assert_int_equal((int)strlen(s->channel), (int)sig.channel.len);
    assert_memory_equal(s->channel, sig.channel.ptr, sig.channel.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_message_action_event(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev         = {0};
    char                        msg_tt[18] = {0};

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    /* Publish a message to get a timetoken for the reaction. */
    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"anchor\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    {
        pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        size_t             n  = tt.len < 17U ? tt.len : 17U;
        memcpy(msg_tt, tt.ptr, n);
        msg_tt[n] = '\0';
    }
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    /* Subscribe ctx2, wait for CONNECTED. */
    l.on_status         = on_status_cb;
    l.on_message        = on_message_cb;
    l.on_message_action = on_message_cb;
    l.user_data         = bus;
    h                   = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Add a reaction to the published message. */
    {
        pubnub_add_message_action_opts_t ma_opts =
            PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
        ma_opts.channel           = s->channel;
        ma_opts.message_timetoken = msg_tt;
        ma_opts.type              = "reaction";
        ma_opts.value             = "thumbs_up";

        fut = pubnub_add_message_action(s->ctx, &ma_opts);
        assert_int_equal(PUBNUB_OK, pubnub_await(fut));
        pubnub_future_release(fut);
    }

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE_ACTION, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);

    /* Accessor returns OK when the type matches. */
    pubnub_subscribe_message_action_event_t ma = {0};
    assert_int_equal(
        PUBNUB_OK, (int)pubnub_subscribe_event_message_action(s->ctx2, &ev, &ma));
    assert_int_equal((int)strlen(s->channel), (int)ma.channel.len);
    assert_memory_equal(s->channel, ma.channel.ptr, ma.channel.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_file_notification_event(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    static const uint8_t s_payload[] = "subscribe file test";

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    /* Subscribe ctx2, wait for CONNECTED. */
    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.on_file    = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Upload a small file from ctx. */
    {
        pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
        opts.channel                 = s->channel;
        opts.file_name               = "sub_test.txt";
        opts.data                    = s_payload;
        opts.data_len                = sizeof(s_payload) - 1U;

        fut = pubnub_send_file(s->ctx, &opts);
        assert_int_equal(PUBNUB_OK, pubnub_await(fut));
        pubnub_future_release(fut);
    }
    it_cleanup_add(&s->cleanup, IT_CLEANUP_LIST_DELETE_FILES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_FILE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);

    /* Accessor returns OK when the type matches. */
    pubnub_subscribe_file_event_t file_ev = {0};
    assert_int_equal(PUBNUB_OK,
                     (int)pubnub_subscribe_event_file(s->ctx2, &ev, &file_ev));
    assert_int_equal((int)strlen(s->channel), (int)file_ev.channel.len);
    assert_memory_equal(s->channel, file_ev.channel.ptr, file_ev.channel.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_app_context_event(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    print_message("user_id channel: %s", s->user_id);
    it_state_add_ctx2(s);

    /* Subscribe ctx2 to ctx's user_id channel (App Context events
     * for UUID metadata are delivered on that channel). */
    l.on_status      = on_status_cb;
    l.on_message     = on_message_cb;
    l.on_app_context = on_message_cb;
    l.user_data      = bus;
    h                = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->user_id);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Set UUID metadata from ctx (uuid=NULL uses context user_id). */
    {
        pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
        opts.name = "IT Test User";

        fut = pubnub_set_uuid_metadata(s->ctx, &opts);
        assert_int_equal(PUBNUB_OK, pubnub_await(fut));
        pubnub_future_release(fut);
    }
    it_cleanup_add(&s->cleanup, IT_CLEANUP_REMOVE_UUID_METADATA, s->user_id, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_APP_CONTEXT, (int)ev.type);

    /* Accessor returns OK when the type matches. */
    pubnub_subscribe_app_context_event_t obj = {0};
    assert_int_equal(PUBNUB_OK,
                     (int)pubnub_subscribe_event_app_context(s->ctx2, &ev, &obj));

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_reconnect_resumes_from_prior_timetoken(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};
    char                        saved_tt[20];
    size_t                      saved_tt_len;

    print_message("channel: %s", s->channel);
    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Publish an anchor message and receive it to obtain a cursor. */
    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"anchor\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    /* Save the anchor's publish timetoken as the restore cursor. */
    assert_int_not_equal(0, (int)ev.timetoken.len);
    saved_tt_len = ev.timetoken.len < (sizeof(saved_tt) - 1)
                     ? ev.timetoken.len
                     : sizeof(saved_tt) - 1;
    memcpy(saved_tt, ev.timetoken.ptr, saved_tt_len);
    saved_tt[saved_tt_len] = '\0';

    /* Disconnect ctx2; subscriptions remain registered. */
    pubnub_subscribe_disconnect(s->ctx2);

    /* Publish two messages while ctx2 is disconnected. */
    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"gap-1\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"gap-2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    /* Restore the cursor, then reconnect.  From a stopped state,
     * restore stores the cursor but does not restart the connection;
     * reconnect is required to drive the state machine to HANDSHAKING
     * and then to RECEIVING with the restored timetoken. */
    assert_int_equal(
        PUBNUB_OK,
        pubnub_subscribe_restore(
            s->ctx2, (pubnub_timetoken_t){.ptr = saved_tt, .len = saved_tt_len}));
    pubnub_subscribe_reconnect(s->ctx2);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_presence_leave_event(void** state)
{
    it_test_state_t*            s       = *state;
    it_bus_t*                   obs_bus = it_bus_create();
    it_bus_t*                   act_bus = it_bus_create();
    pres_listener_data_t        obs_d   = {obs_bus, NULL, 0, 0, 0};
    pubnub_subscribe_listener_t obs_l   = {0};
    pubnub_subscribe_listener_t act_l   = {0};
    pubnub_listener_handle_t    obs_h;
    pubnub_listener_handle_t    act_h;
    pubnub_entity_t             entity;
    pubnub_subscription_opts_t  opts = {0};
    pubnub_subscription_t       obs_sub;
    pubnub_subscription_t       act_sub;

    it_state_add_ctx2(s);

    /* ctx = observer: subscribes with presence, parses events inline.
     * Enable pump_ctx so the driver polls ctx in non-thread-safety builds. */
    obs_d.ctx           = s->ctx;
    obs_d.expected_uuid = s->user_id2;
#if !PUBNUB_CFG_THREAD_SAFETY
    s->pump_ctx = 1;
#endif
    obs_l.on_status   = pres_on_status_cb;
    obs_l.on_presence = pres_on_presence_cb;
    obs_l.user_data   = &obs_d;
    obs_h             = pubnub_add_listener(s->ctx, &obs_l);

    opts.with_presence = 1;
    entity             = pubnub_channel(s->ctx, s->channel);
    obs_sub            = pubnub_subscription_create(entity, &opts);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(obs_sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(obs_bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    /* ctx2 = actor: subscribes WITH presence so PubNub tracks it immediately. */
    act_l.on_status = on_status_cb;
    act_l.user_data = act_bus;
    act_h           = pubnub_add_listener(s->ctx2, &act_l);

    opts.with_presence = 1;
    entity             = pubnub_channel(s->ctx2, s->channel);
    act_sub            = pubnub_subscription_create(entity, &opts);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(act_sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(act_bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    /* Wait for observer to receive ctx2's JOIN (confirms PubNub presence registered). */
    assert_int_not_equal(0,
                         pn_test_wait_until(check_flag,
                                            (void*)&obs_d.got_join,
                                            IT_PRESENCE_WAIT_MAX_MS,
                                            IT_PRESENCE_WAIT_POLL_MS));

    /* Actor unsubscribes — generates LEAVE visible to observer. */
    obs_d.got_leave   = 0;
    obs_d.got_timeout = 0;
    pubnub_subscription_unsubscribe(act_sub);

    assert_int_not_equal(0,
                         pn_test_wait_until(check_flag,
                                            (void*)&obs_d.got_leave,
                                            IT_PRESENCE_WAIT_MAX_MS,
                                            IT_PRESENCE_WAIT_POLL_MS));

#if !PUBNUB_CFG_THREAD_SAFETY
    s->pump_ctx = 0;
#endif
    pubnub_subscription_unsubscribe(obs_sub);
    pubnub_subscription_destroy(obs_sub);
    pubnub_subscription_destroy(act_sub);
    pubnub_remove_listener(s->ctx, obs_h);
    pubnub_remove_listener(s->ctx2, act_h);
    it_bus_destroy(obs_bus);
    it_bus_destroy(act_bus);
}

static void subscribe_receives_presence_state_change_event(void** state)
{
    it_test_state_t*            s       = *state;
    it_bus_t*                   obs_bus = it_bus_create();
    it_bus_t*                   act_bus = it_bus_create();
    pres_listener_data_t        obs_d   = {obs_bus, NULL, 0, 0, 0};
    pubnub_subscribe_listener_t obs_l   = {0};
    pubnub_subscribe_listener_t act_l   = {0};
    pubnub_listener_handle_t    obs_h;
    pubnub_listener_handle_t    act_h;
    pubnub_entity_t             entity;
    pubnub_subscription_opts_t  opts = {0};
    pubnub_subscription_t       obs_sub;
    pubnub_subscription_t       act_sub;
    pubnub_set_state_opts_t     ss_opts = PUBNUB_SET_STATE_OPTS_INIT;
    pubnub_future_t             ss_fut;

    it_state_add_ctx2(s);

    /* ctx2 = observer: subscribes with presence, parses events inline. */
    obs_d.ctx           = s->ctx2;
    obs_d.expected_uuid = s->user_id;
    obs_l.on_status     = pres_on_status_cb;
    obs_l.on_presence   = pres_on_presence_cb;
    obs_l.user_data     = &obs_d;
    obs_h               = pubnub_add_listener(s->ctx2, &obs_l);

    opts.with_presence = 1;
    entity             = pubnub_channel(s->ctx2, s->channel);
    obs_sub            = pubnub_subscription_create(entity, &opts);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(obs_sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(obs_bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    /* ctx = actor: subscribes WITH presence so PubNub tracks it immediately.
     * Enable pump_ctx so the driver polls ctx in non-thread-safety builds. */
#if !PUBNUB_CFG_THREAD_SAFETY
    s->pump_ctx = 1;
#endif
    act_l.on_status = on_status_cb;
    act_l.user_data = act_bus;
    act_h           = pubnub_add_listener(s->ctx, &act_l);

    opts.with_presence = 1;
    entity             = pubnub_channel(s->ctx, s->channel);
    act_sub            = pubnub_subscription_create(entity, &opts);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(act_sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(act_bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    /* Wait for observer to receive ctx's JOIN (confirms presence registered). */
    assert_int_not_equal(0,
                         pn_test_wait_until(check_flag,
                                            (void*)&obs_d.got_join,
                                            IT_PRESENCE_WAIT_MAX_MS,
                                            IT_PRESENCE_WAIT_POLL_MS));

    /* Actor sets state — generates STATE_CHANGE on observer.
     *
     * Stop the bg pump for ctx first so we can safely call pubnub_await
     * on T0 without a data race (THREAD_SAFETY=0 builds have no locks).
     * The observer (ctx2) keeps pumping on the driver thread. */
#if !PUBNUB_CFG_THREAD_SAFETY
    s->pump_ctx = 0;
#endif
    ss_opts.channels = s->channel;
    ss_opts.state    = "{\"mood\":\"test\"}";
    ss_fut           = pubnub_set_state(s->ctx, &ss_opts);
    assert_int_equal(PUBNUB_OK, pubnub_await(ss_fut));
    pubnub_future_release(ss_fut);

    assert_int_not_equal(0,
                         pn_test_wait_until(check_flag,
                                            (void*)&obs_d.got_state_change,
                                            IT_PRESENCE_WAIT_MAX_MS,
                                            IT_PRESENCE_WAIT_POLL_MS));
    pubnub_subscription_unsubscribe(obs_sub);
    pubnub_subscription_unsubscribe(act_sub);
    pubnub_subscription_destroy(obs_sub);
    pubnub_subscription_destroy(act_sub);
    pubnub_remove_listener(s->ctx2, obs_h);
    pubnub_remove_listener(s->ctx, act_h);
    it_bus_destroy(obs_bus);
    it_bus_destroy(act_bus);
}

static void subscribe_reconnect_after_disconnect_delivers_messages(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_subscribe_event_t    ev = {0};

    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Publish 2 messages while subscribed, verify both delivered. */
    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"pre-1\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"pre-2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    /* Disconnect and reconnect — simulates network disruption. */
    pubnub_subscribe_disconnect(s->ctx2);
    pn_test_sleep_ms(1000);

    pubnub_subscribe_reconnect(s->ctx2);
    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Publish 2 more messages after reconnect, verify delivery. */
    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"post-1\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){.channel = s->channel,
                                                  .message = "\"post-2\""});
    assert_int_equal(PUBNUB_OK, pubnub_await(fut));
    pubnub_future_release(fut);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

static void subscribe_receives_status_disconnected_on_disconnect(void** state)
{
    it_test_state_t*            s   = *state;
    it_bus_t*                   bus = it_bus_create();
    pubnub_subscribe_listener_t l   = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;

    it_state_add_ctx2(s);

    l.on_status  = on_status_cb;
    l.on_message = on_message_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(s->ctx2, &l);

    entity = pubnub_channel(s->ctx2, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    /* Explicit disconnect should fire a DISCONNECTED status. */
    pubnub_subscribe_disconnect(s->ctx2);

    /* Wait for DISCONNECTED status event. */
    int got_disconnected = it_bus_wait_status(
        bus, IT_SUBSCRIBE_CONNECT_MAX_MS, PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED);
    assert_int_not_equal(0, got_disconnected);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx2, h);
    it_bus_destroy(bus);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            subscribe_receives_published_string_message, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_json_message_payload_intact, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_message_on_second_channel, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_presence_join_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_presence_leave_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_presence_state_change_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_connected_status_fires_on_connect, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_set_delivers_messages_on_all_channels, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_unsubscribe_resubscribe_delivers_message, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_wildcard_channel_receives_subchannel_message, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_custom_message_type_delivered_to_listener, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_reconnect_resumes_from_prior_timetoken, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_signal_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_message_action_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_file_notification_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_app_context_event, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_reconnect_after_disconnect_delivers_messages, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscribe_receives_status_disconnected_on_disconnect, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

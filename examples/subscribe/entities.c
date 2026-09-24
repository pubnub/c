/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/subscribe/entities.c
 * @brief Entities, subscriptions, subscription sets, and the three
 *        listener registration levels.
 *
 * Three snippets live here:
 *
 *   subscribeEntities -- pubnub_channel / pubnub_channel_group /
 *       pubnub_channel_metadata / pubnub_user_metadata, and turning an
 *       entity into a subscription.
 *   subscribeSubscriptionSet -- grouping subscriptions so they activate
 *       and deactivate atomically.
 *   subscribeListeners -- context-global, per-subscription, and per-set
 *       registration, and which of them see status events.
 *
 * See callback.c for a single-channel program that publishes and
 * observes its own echo.
 *
 * Build: cmake --build build/full --target example_subscribe_entities
 * Run:   ./build/full/examples/subscribe/example_subscribe_entities
 */

#include "pubnub/pubnub.h"

#include <stdio.h>

#define POLL_ITERATIONS 200000

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    (void)user_data;
    printf("STATUS: %d (%s)\n", (int)event->status, pubnub_res_str(event->reason));
}

static void on_any_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    printf("GLOBAL MSG on %.*s\n", (int)event->channel.len, event->channel.ptr);
}

static void on_alerts_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)user_data;
    printf("ALERTS MSG on %.*s\n", (int)event->channel.len, event->channel.ptr);
}

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-subscribe-entities";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    // snippet.subscribeEntities

    /* 1. An entity names something subscribable. Four kinds exist, and
     * pubnub_entity_type() reports which one a handle is. */
    pubnub_entity_t alerts   = pubnub_channel(ctx, "alerts");
    pubnub_entity_t group    = pubnub_channel_group(ctx, "regional-sensors");
    pubnub_entity_t ch_meta  = pubnub_channel_metadata(ctx, "alerts");
    pubnub_entity_t usr_meta = pubnub_user_metadata(ctx, "user-alice");

    if (NULL == alerts || NULL == group || NULL == ch_meta || NULL == usr_meta) {
        printf("Failed to create an entity\n");
        pubnub_destroy(ctx);
        return 1;
    }
    printf("%s is entity type %d\n",
           pubnub_entity_name(alerts),
           (int)pubnub_entity_type(alerts));

    /* 2. A subscription is the activatable object. with_presence adds the
     * matching -pnpres channel, and is ignored for metadata entities. */
    const pubnub_subscription_opts_t sub_opts = {.with_presence = 1};

    pubnub_subscription_t alerts_sub =
        pubnub_subscription_create(alerts, &sub_opts);
    pubnub_subscription_t group_sub = pubnub_subscription_create(group, NULL);
    pubnub_subscription_t meta_sub  = pubnub_subscription_create(ch_meta, NULL);
    pubnub_subscription_t user_sub = pubnub_subscription_create(usr_meta, NULL);

    /* 3. The entity is only needed to build the subscription, so destroy
     * the handles now. */
    pubnub_entity_destroy(alerts);
    pubnub_entity_destroy(group);
    pubnub_entity_destroy(ch_meta);
    pubnub_entity_destroy(usr_meta);

    if (NULL == alerts_sub || NULL == group_sub || NULL == meta_sub
        || NULL == user_sub) {
        printf("Failed to create a subscription\n");
        pubnub_destroy(ctx);
        return 1;
    }

    // snippet.end

    // snippet.subscribeListeners

    /* 4. A context-global listener sees events from every active
     * subscription, and it is the only level that receives status
     * events. */
    pubnub_subscribe_listener_t global = {0};
    global.on_status                   = on_status;
    global.on_message                  = on_any_message;

    pubnub_listener_handle_t global_lh = pubnub_add_listener(ctx, &global);
    if (PUBNUB_LISTENER_HANDLE_INVALID == global_lh) {
        printf("Listener registry full\n");
        pubnub_destroy(ctx);
        return 1;
    }

    /* 5. A per-subscription listener sees data events from that
     * subscription only. on_status would never fire here, so leave it
     * NULL. All three levels draw from one pool of
     * PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS slots. */
    pubnub_subscribe_listener_t alerts_only = {0};
    alerts_only.on_message                  = on_alerts_message;

    pubnub_listener_handle_t alerts_lh =
        pubnub_subscription_add_listener(alerts_sub, &alerts_only);

    // snippet.end

    // snippet.subscribeSubscriptionSet

    /* 6. A set activates and deactivates its members together. Adding a
     * subscription to an already-subscribed set activates it at once,
     * and adding the same one twice is a no-op. */
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    if (PUBNUB_SUBSCRIPTION_SET_INVALID == set) {
        printf("Failed to create the subscription set\n");
        pubnub_remove_listener(ctx, global_lh);
        pubnub_destroy(ctx);
        return 1;
    }

    pubnub_subscription_set_add_subscription(set, group_sub);
    pubnub_subscription_set_add_subscription(set, meta_sub);
    pubnub_subscription_set_add_subscription(set, user_sub);

    /* 7. A per-set listener sees data events from every member. */
    pubnub_subscribe_listener_t set_listener = {0};
    set_listener.on_message                  = on_any_message;
    pubnub_listener_handle_t set_lh =
        pubnub_subscription_set_add_listener(set, &set_listener);

    /* 8. One call activates the whole set. A subscription can be in a set
     * and subscribed individually at the same time: presence leave is
     * only sent once the last reference goes inactive. */
    pubnub_res_t rc = pubnub_subscription_set_subscribe(set);
    if (PUBNUB_OK != rc) {
        printf("set subscribe failed: %s\n", pubnub_res_str(rc));
    }

    // snippet.end

    pubnub_subscription_subscribe(alerts_sub);

    for (long i = 0; i < POLL_ITERATIONS; ++i) {
        pubnub_process(ctx);
    }

    /* 9. Tear down in reverse: listeners, then subscriptions, then the
     * set, then the context. */
    pubnub_subscription_set_unsubscribe(set);
    pubnub_subscription_set_remove_listener(set, set_lh);
    pubnub_subscription_set_remove_subscription(set, user_sub);
    pubnub_subscription_set_destroy(set);

    pubnub_subscription_unsubscribe(alerts_sub);
    pubnub_subscription_remove_listener(alerts_sub, alerts_lh);
    pubnub_remove_listener(ctx, global_lh);

    pubnub_subscription_destroy(user_sub);
    pubnub_subscription_destroy(meta_sub);
    pubnub_subscription_destroy(group_sub);
    pubnub_subscription_destroy(alerts_sub);

    pubnub_destroy(ctx);
    return 0;
}

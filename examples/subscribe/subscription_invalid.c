/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/subscribe/subscription_invalid.c
 * @brief Check the result of pubnub_subscription_create.
 *
 * pubnub_subscription_create returns PUBNUB_SUBSCRIPTION_INVALID
 * instead of a handle when it cannot create the subscription, for
 * example when the subscription table is full. Always compare the
 * result before using it.
 *
 * Build: cmake --build build/full --target example_subscribe_subscription_invalid
 * Run:   ./build/full/examples/subscribe/example_subscribe_subscription_invalid
 */

// snippet.subscribeCheckSubscriptionInvalid

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-subscription-invalid";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Create an entity and a subscription from it. */
    pubnub_entity_t alerts = pubnub_channel(ctx, "alerts");
    if (NULL == alerts) {
        printf("Failed to create the entity\n");
        pubnub_destroy(ctx);
        return 1;
    }

    pubnub_subscription_t sub = pubnub_subscription_create(alerts, NULL);

    /* The entity is only needed to build the subscription. */
    pubnub_entity_destroy(alerts);

    /* 3. Compare the result with PUBNUB_SUBSCRIPTION_INVALID. A full
     * subscription table is the usual cause. Retrying cannot succeed
     * until a subscription is destroyed, or the SDK is rebuilt with a
     * larger PUBNUB_CFG_MAX_SUBSCRIPTIONS. */
    if (PUBNUB_SUBSCRIPTION_INVALID == sub) {
        printf("Failed to create the subscription\n");
        pubnub_destroy(ctx);
        return 1;
    }

    printf("Subscription created\n");

    /* 4. Cleanup. */
    pubnub_subscription_destroy(sub);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end

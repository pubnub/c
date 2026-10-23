/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/subscribe/subscription_set_limit.c
 * @brief Handle PUBNUB_ERR_LIMIT_REACHED when filling a subscription set.
 *
 * A subscription set holds at most PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET
 * members. Adding one more returns PUBNUB_ERR_LIMIT_REACHED, and
 * retrying cannot succeed until the SDK is rebuilt with a larger value.
 *
 * Build: cmake --build build/full --target example_subscribe_subscription_set_limit
 * Run:   ./build/full/examples/subscribe/example_subscribe_subscription_set_limit
 */

// snippet.subscribeSetLimitReached

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-subscription-set-limit";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Create a set and a subscription to add to it. */
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    if (PUBNUB_SUBSCRIPTION_SET_INVALID == set) {
        printf("Failed to create the subscription set\n");
        pubnub_destroy(ctx);
        return 1;
    }

    pubnub_entity_t       alerts = pubnub_channel(ctx, "alerts");
    pubnub_subscription_t sub    = pubnub_subscription_create(alerts, NULL);
    pubnub_entity_destroy(alerts);

    if (PUBNUB_SUBSCRIPTION_INVALID == sub) {
        printf("Failed to create the subscription\n");
        pubnub_subscription_set_destroy(set);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 3. Add the subscription and handle the limit. */
    const pubnub_res_t rc = pubnub_subscription_set_add_subscription(set, sub);
    if (PUBNUB_ERR_LIMIT_REACHED == rc) {
        printf("The set is full. Rebuild the SDK with a larger "
               "PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET, or use another set.\n");
    } else if (PUBNUB_OK != rc) {
        printf("Add to the set failed: %s\n", pubnub_res_str(rc));
    } else {
        printf("Subscription added to the set\n");
    }

    /* 4. Cleanup. The set releases its members, then the handle owned
     * by this program. */
    pubnub_subscription_set_destroy(set);
    pubnub_subscription_destroy(sub);
    pubnub_destroy(ctx);
    return (PUBNUB_OK == rc) ? 0 : 1;
}

// snippet.end

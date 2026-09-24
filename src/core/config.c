/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "core_internal.h"
#include "pubnub/config.h"

#include <string.h>

#define PN_RETRY_MIN_DELAY_MS 2000
#define PN_RETRY_MAX_ATTEMPTS 10
#define PN_TIMEOUT_MIN_MS     1000

/** Validate retry configuration fields. No-op when retry is disabled. */
static pubnub_res_t pn_retry_validate(const pubnub_config_t* config)
{
#if PUBNUB_ENABLE_RETRY
    if (config->retry_configuration.policy == PUBNUB_RETRY_NONE) {
        return PUBNUB_OK;
    }

    if (config->retry_configuration.delay_ms > 0
        && config->retry_configuration.delay_ms < PN_RETRY_MIN_DELAY_MS) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (config->retry_configuration.maximum_retry > PN_RETRY_MAX_ATTEMPTS) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (config->retry_configuration.policy == PUBNUB_RETRY_EXPONENTIAL
        && config->retry_configuration.maximum_delay_ms > 0
        && config->retry_configuration.delay_ms > 0
        && config->retry_configuration.maximum_delay_ms
               < config->retry_configuration.delay_ms) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    return PUBNUB_OK;
#else
    (void)config;
    return PUBNUB_OK;
#endif
}

pubnub_res_t pn_config_validate(const pubnub_config_t* config)
{
    if (!config) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (!config->subscribe_key || config->subscribe_key[0] == '\0') {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (!config->user_id || config->user_id[0] == '\0') {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (config->transaction_timeout_ms > 0
        && config->transaction_timeout_ms < PN_TIMEOUT_MIN_MS) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (config->non_transaction_timeout_ms > 0
        && config->non_transaction_timeout_ms < PN_TIMEOUT_MIN_MS) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    return pn_retry_validate(config);
}

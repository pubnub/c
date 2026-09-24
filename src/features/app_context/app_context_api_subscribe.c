/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/features/app_context.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_api_subscribe.c requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "app_context_internal.h"
#include "core/core_internal.h"

#include <stddef.h>
#include <string.h>

#if PUBNUB_ENABLE_SUBSCRIBE

#include "pubnub/features/subscribe_types.h"

pubnub_res_t pubnub_subscribe_app_context_uuid_metadata(
    pubnub_context_t*                                ctx,
    const struct pubnub_subscribe_app_context_event* event,
    pubnub_uuid_metadata_t*                          out)
{
    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (NULL == event->data) {
        return PUBNUB_OK;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    return pn_uuid_metadata_parse(serial, event->data, out);
}

pubnub_res_t pubnub_subscribe_app_context_channel_metadata(
    pubnub_context_t*                                ctx,
    const struct pubnub_subscribe_app_context_event* event,
    pubnub_channel_metadata_t*                       out)
{
    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (NULL == event->data) {
        return PUBNUB_OK;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    return pn_channel_metadata_parse(serial, event->data, out);
}

pubnub_res_t pubnub_subscribe_app_context_membership(
    pubnub_context_t*                                ctx,
    const struct pubnub_subscribe_app_context_event* event,
    pubnub_membership_t*                             out)
{
    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (NULL == event->data) {
        return PUBNUB_OK;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    return pn_membership_parse(serial, event->data, out);
}

#endif /* PUBNUB_ENABLE_SUBSCRIBE */

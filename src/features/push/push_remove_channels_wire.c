/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "push_internal.h"

#if !PUBNUB_ENABLE_PUSH_NOTIFICATIONS
#error "push_remove_channels_wire.c requires PUBNUB_ENABLE_PUSH_NOTIFICATIONS=ON"
#endif

#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

/**
 * @brief Add channels parameter for remove-channels operation.
 *
 * @param request HTTP request to populate.
 * @param encoded_channels Comma-separated, URL-encoded channel list.
 * @return PUBNUB_OK on success, or error code.
 */
pubnub_res_t pn_push_remove_channels_param(pubnub_http_request_t* request,
                                           const char* encoded_channels)
{
    if (NULL == request || NULL == encoded_channels) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    const pubnub_string_view_t val = {encoded_channels, strlen(encoded_channels)};
    return pn_request_add_query_param_view(request, "remove", val);
}

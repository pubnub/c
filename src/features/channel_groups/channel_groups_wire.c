/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "channel_groups_internal.h"

#if !PUBNUB_ENABLE_CHANNEL_GROUPS
#error "channel_groups_wire.c requires PUBNUB_ENABLE_CHANNEL_GROUPS=ON"
#endif

#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/pubnub_compat.h"

#include "core/protocol_common/pn_response_probe.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 7,
                     "Channel Groups requires at least 7 path segments");

pubnub_res_t pn_channel_groups_build_path(pubnub_http_request_t* request,
                                          const char*            subscribe_key,
                                          const char*            channel_group,
                                          int                    remove_group)
{
    if (NULL == request || NULL == subscribe_key || NULL == channel_group) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_string_view_t group_view;
    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_request_scratch_encode(
        request, channel_group, &group_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Path layout:
     *   /v1/channel-registration/sub-key/{sub}/channel-group/{group}
     * With remove_group:
     *   /v1/channel-registration/sub-key/{sub}/channel-group/{group}/remove
     */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] =
        (pubnub_string_view_t){"channel-registration", 20};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel-group", 13};
    request->path_segments[n++] = group_view;
    if (remove_group) {
        request->path_segments[n++] = (pubnub_string_view_t){"remove", 6};
    }
    request->path_segment_count = n;

    return PUBNUB_OK;
}

pubnub_res_t pn_channel_groups_response_validator(const uint8_t* body,
                                                  size_t         body_len,
                                                  int            http_status)
{
    return pn_probe_object_error_flag(body, body_len, http_status, 150);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_wire_internal.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_wire.c requires PUBNUB_ENABLE_PRESENCE=ON - this translation " \
    "unit has no meaning without the presence feature."
#endif

#include "core/pn_format.h"
#include "pubnub/pubnub_compat.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 7,
                     "Presence heartbeat/leave require 7 path segments");
PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_HTTP_SCRATCH_SIZE >= 128,
    "Presence middleware query params require >= 128B scratch");

/**
 * @brief Build the common path prefix for presence requests.
 *
 * Path: /v2/presence/sub-key/{sub_key}/channel/{channels}
 *
 * Writes 6 path segments, leaving room for the caller to append the
 * final action segment ("heartbeat" or "leave"). Channels are expected
 * pre-encoded by the caller (no scratch-encode step needed).
 *
 * @param request  Request to populate.
 * @param inputs   Wire inputs (subscribe_key, channels — pre-encoded).
 * @param out_n    Output segment count on success.
 * @return PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t pn_presence_build_path_prefix(pubnub_http_request_t* request,
                                                  const pn_presence_wire_inputs_t* inputs,
                                                  unsigned int* out_n)
{
    unsigned int         n = 0;
    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"presence", 8};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};
    request->path_segments[n++] =
        (pubnub_string_view_t){inputs->channels, strlen(inputs->channels)};
    *out_n = n;

    return PUBNUB_OK;
}

pubnub_res_t pn_presence_build_heartbeat(pubnub_http_request_t* request,
                                         const pn_presence_wire_inputs_t* inputs)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channels) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* heartbeat_sec=0 is not a valid timeout — callers must only dispatch
     * heartbeats when presence_timeout is configured. */
    if (0 == inputs->heartbeat_sec) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    unsigned int n  = 0;
    pubnub_res_t rc = pn_presence_build_path_prefix(request, inputs, &n);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = (pubnub_string_view_t){"heartbeat", 9};
    request->path_segment_count = n;

    /* heartbeat={timeout_sec} — always present. */
    char hb_buf[12];
    (void)pn_snprintf(
        hb_buf, sizeof(hb_buf), "%u", (unsigned int)inputs->heartbeat_sec);
    rc = pn_request_add_query_param(request, "heartbeat", hb_buf, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* channel-group — pre-encoded, assigned as a borrowed view. */
    if (NULL != inputs->channel_groups && '\0' != inputs->channel_groups[0]) {
        rc = pn_request_add_query_param_view(
            request,
            "channel-group",
            (pubnub_string_view_t){inputs->channel_groups,
                                   strlen(inputs->channel_groups)});
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_presence_build_leave(pubnub_http_request_t*           request,
                                     const pn_presence_wire_inputs_t* inputs)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channels) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    unsigned int n  = 0;
    pubnub_res_t rc = pn_presence_build_path_prefix(request, inputs, &n);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = (pubnub_string_view_t){"leave", 5};
    request->path_segment_count = n;

    /* channel-group — pre-encoded, assigned as a borrowed view. */
    if (NULL != inputs->channel_groups && '\0' != inputs->channel_groups[0]) {
        rc = pn_request_add_query_param_view(
            request,
            "channel-group",
            (pubnub_string_view_t){inputs->channel_groups,
                                   strlen(inputs->channel_groups)});
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

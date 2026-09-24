/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "push_internal.h"

#if !PUBNUB_ENABLE_PUSH_NOTIFICATIONS
#error "push_add_channels_wire.c requires PUBNUB_ENABLE_PUSH_NOTIFICATIONS=ON"
#endif

#include "pubnub/pubnub_compat.h"
#include "core/runtime/middleware/middleware_internal.h"

#include "core/protocol_common/pn_response_probe.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 7,
                     "push notifications require at least 7 path segments");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS >= 8,
                     "push notifications require at least 8 query params");

/**
 * @brief Build path segments for a push operation.
 *
 * Constructs path for either APNS2 or FCM gateway, with optional /remove
 * suffix for device removal.
 *
 * @param request HTTP request to populate.
 * @param in Path inputs (gateway, keys, device token, remove flag).
 * @return PUBNUB_OK on success, or error code.
 */
pubnub_res_t pn_push_build_path(pubnub_http_request_t*       request,
                                const pn_push_path_inputs_t* in)
{
    if (NULL == request || NULL == in || NULL == in->subscribe_key
        || NULL == in->device) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_string_view_t sub_key_view;
    pubnub_string_view_t device_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    unsigned int n = 0;
    if (PUBNUB_PUSH_APNS2 == in->gateway) {
        request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    } else {
        request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    }
    request->path_segments[n++] = (pubnub_string_view_t){"push", 4};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_key_view;

    if (PUBNUB_PUSH_APNS2 == in->gateway) {
        request->path_segments[n++] = (pubnub_string_view_t){"devices-apns2", 13};
    } else {
        request->path_segments[n++] = (pubnub_string_view_t){"devices", 7};
    }
    /* Device tokens are hex (APNs) or base64url (FCM) — already URL-safe,
     * so copy verbatim into scratch. The copy makes the request
     * self-contained instead of borrowing the caller's device pointer,
     * which may not outlive a queued request. */
    rc = pn_request_scratch_encode(request, in->device, &device_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = device_view;

    if (in->append_remove) {
        request->path_segments[n++] = (pubnub_string_view_t){"remove", 6};
    }
    request->path_segment_count = n;

    return PUBNUB_OK;
}

/**
 * @brief Add gateway-specific query parameters.
 *
 * Adds type, environment, and topic params based on gateway.
 *
 * @param request HTTP request to populate.
 * @param gateway APNS2 or FCM.
 * @param environment Production or development (APNS2 only).
 * @param topic Bundle ID (APNS2 only, optional).
 * @return PUBNUB_OK on success, or error code.
 */
pubnub_res_t pn_push_add_gateway_params(pubnub_http_request_t*    request,
                                        pubnub_push_gateway_t     gateway,
                                        pubnub_push_environment_t environment,
                                        const char*               topic)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    const char*  type_str = (PUBNUB_PUSH_APNS2 == gateway) ? "apns2" : "fcm";
    pubnub_res_t rc =
        pn_request_add_query_param(request, "type", type_str, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    if (PUBNUB_PUSH_APNS2 == gateway) {
        const char* env_str = (PUBNUB_PUSH_ENV_PRODUCTION == environment)
                                ? "production"
                                : "development";
        rc                  = pn_request_add_query_param(
            request, "environment", env_str, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }

        if (NULL != topic) {
            rc = pn_request_add_query_param(request, "topic", topic, PN_ENCODE_FULL);
            if (PUBNUB_OK != rc) {
                return rc;
            }
        }
    }

    return PUBNUB_OK;
}

/**
 * @brief Add channels parameter for add-channels operation.
 *
 * @param request HTTP request to populate.
 * @param encoded_channels Comma-separated, URL-encoded channel list.
 * @return PUBNUB_OK on success, or error code.
 */
pubnub_res_t pn_push_add_channels_param(pubnub_http_request_t* request,
                                        const char*            encoded_channels)
{
    if (NULL == request || NULL == encoded_channels) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    const pubnub_string_view_t val = {encoded_channels, strlen(encoded_channels)};
    return pn_request_add_query_param_view(request, "add", val);
}

pubnub_res_t pn_push_mutation_response_validator(const uint8_t* body,
                                                 size_t         body_len,
                                                 int            http_status)
{
    return pn_probe_array_status(body, body_len, http_status, 20);
}

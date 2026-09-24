/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "signal_internal.h"

#if !PUBNUB_ENABLE_SIGNAL
#error "signal_wire.c requires PUBNUB_ENABLE_SIGNAL=ON - this translation unit has no meaning without the signal feature. Check the CMake feature gating in src/features/CMakeLists.txt; the file must not appear in the build when the flag is off."
#endif

#include "pubnub/pubnub_compat.h"

#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 7,
                     "Signal requires at least 7 path segments");

#include "core/protocol_common/pn_response_probe.h"

pubnub_res_t pn_signal_build_path(pubnub_http_request_t*         request,
                                  pubnub_allocator_provider_t*   allocator,
                                  const pn_signal_path_inputs_t* in,
                                  pn_signal_url_encoded_t*       out)
{
    if (NULL == request || NULL == allocator || NULL == in || NULL == out
        || NULL == in->publish_key || NULL == in->subscribe_key
        || NULL == in->channel || NULL == in->serialized) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel = NULL;
    out->message = NULL;

    /* Scratch-encode keys so the request is self-contained. */
    pubnub_string_view_t pub_key_view;
    pubnub_string_view_t sub_key_view;
    pubnub_string_view_t channel_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, in->publish_key, &pub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Channel: short NUL-terminated name → encode into scratch. */
    rc = pn_request_scratch_encode(
        request, in->channel, &channel_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Message: serialized payload (may be large) → heap-allocate. */
    char* encoded_message = pn_url_encode_alloc_n(
        in->serialized, in->serialized_len, allocator, PN_ENCODE_FULL);
    if (NULL == encoded_message) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Path layout: /signal/{pub}/{sub}/0/{channel}/0/{payload} */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"signal", 6};
    request->path_segments[n++] = pub_key_view;
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    request->path_segments[n++] = channel_view;
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    request->path_segments[n++] =
        (pubnub_string_view_t){encoded_message, strlen(encoded_message)};
    request->path_segment_count = n;

    out->message = encoded_message;
    return PUBNUB_OK;
}

pubnub_res_t pn_signal_add_query_params(pubnub_http_request_t* request,
                                        const char* custom_message_type)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL != custom_message_type) {
        pubnub_res_t rc = pn_request_add_query_param(
            request, "custom_message_type", custom_message_type, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_signal_response_validator(const uint8_t* body,
                                          size_t         body_len,
                                          int            http_status)
{
    return pn_probe_array_status(body, body_len, http_status, 20);
}

pubnub_res_t pn_signal_parse_response(pubnub_serialization_provider_t* serial,
                                      const pubnub_json_value_t*       tree,
                                      pn_signal_parsed_t*              out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->timetoken = (pubnub_timetoken_t){NULL, 0};

    return pn_parse_publish_array_response(serial, tree, &out->timetoken);
}

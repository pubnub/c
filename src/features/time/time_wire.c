/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "time_internal.h"

#if !PUBNUB_ENABLE_TIME
#error "time_wire.c requires PUBNUB_ENABLE_TIME=ON - this translation unit has no meaning without the time feature. Check the CMake feature gating in src/features/CMakeLists.txt; the file must not appear in the build when the flag is off."
#endif

#include "pubnub/pubnub_compat.h"

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 2,
                     "Time requires at least 2 path segments");

pubnub_res_t pn_time_build_path(pubnub_http_request_t* request)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    request->path_segments[0]   = (pubnub_string_view_t){"time", 4};
    request->path_segments[1]   = (pubnub_string_view_t){"0", 1};
    request->path_segment_count = 2;

    return PUBNUB_OK;
}

pubnub_res_t pn_time_response_validator(const uint8_t* body,
                                        size_t         body_len,
                                        int            http_status)
{
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    pubnub_timetoken_t dummy = {0};
    return pn_time_parse_response(body, body_len, &dummy);
}

pubnub_res_t pn_time_parse_response(const uint8_t*      body,
                                    size_t              body_len,
                                    pubnub_timetoken_t* out_token)
{
    if (NULL == out_token) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    *out_token = (pubnub_timetoken_t){NULL, 0};

    if (NULL == body || 0 == body_len) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    size_t i = 0;
    while (i < body_len && '[' != body[i]) {
        i++;
    }
    if (i >= body_len) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    i++; /* skip '[' */

    while (i < body_len
           && (' ' == body[i] || '\t' == body[i] || '\r' == body[i]
               || '\n' == body[i])) {
        i++;
    }

    if (i >= body_len || body[i] < '0' || body[i] > '9') {
        return PUBNUB_ERR_SERIALIZATION;
    }

    size_t digit_start = i;
    while (i < body_len && body[i] >= '0' && body[i] <= '9') {
        i++;
    }

    out_token->ptr = (const char*)(body + digit_start);
    out_token->len = i - digit_start;

    return PUBNUB_OK;
}

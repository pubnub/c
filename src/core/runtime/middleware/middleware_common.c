/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "middleware_internal.h"

#include "core/protocol_common/pn_url_encode.h"

#include <string.h>

pubnub_res_t pn_request_set_host(pubnub_http_request_t* request, const char* host)
{
    size_t len;
    size_t need;
    size_t cap;
    char*  dst;

    if (NULL == request || NULL == host) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    len  = strlen(host);
    need = len + 1; /* include NUL terminator */
    cap  = PUBNUB_CFG_HTTP_SCRATCH_SIZE - request->scratch_used;

    if (need > cap) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    dst = &request->scratch[request->scratch_used];
    memcpy(dst, host, need); /* copies len bytes + NUL */
    request->scratch_used += (unsigned int)need;
    request->host = dst;

    return PUBNUB_OK;
}

pubnub_res_t pn_request_scratch_encode(pubnub_http_request_t* request,
                                       const char*            raw,
                                       pubnub_string_view_t*  out,
                                       int                    encode)
{
    if (NULL == raw) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_request_scratch_encode_n(
        request, (const uint8_t*)raw, strlen(raw), out, encode);
}

pubnub_res_t pn_request_scratch_encode_n(pubnub_http_request_t* request,
                                         const uint8_t*         raw,
                                         size_t                 len,
                                         pubnub_string_view_t*  out,
                                         int                    encode)
{
    if (NULL == request || NULL == out || (NULL == raw && len > 0)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    const unsigned int saved_used = request->scratch_used;
    char*              dst        = &request->scratch[request->scratch_used];
    size_t cap = PUBNUB_CFG_HTTP_SCRATCH_SIZE - request->scratch_used;

    if (PN_ENCODE_NONE == encode) {
        if (len > cap) {
            return PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(dst, raw, len); // NOLINT(bugprone-not-null-terminated-result)
        request->scratch_used += (unsigned int)len;
        out->ptr = dst;
        out->len = len;
    } else {
        if (0 == cap) {
            return PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        pubnub_res_t rc = pn_url_encode_n((const char*)raw, len, dst, cap, encode);
        if (PUBNUB_OK != rc) {
            request->scratch_used = saved_used;
            return rc;
        }
        size_t encoded_len = strlen(dst);
        request->scratch_used += (unsigned int)encoded_len;
        out->ptr = dst;
        out->len = encoded_len;
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_request_add_query_param(pubnub_http_request_t* request,
                                        const char*            key,
                                        const char*            value,
                                        int                    encode)
{
    if (NULL == request || NULL == key || NULL == value) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (request->query_param_count >= PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    const unsigned int saved_used = request->scratch_used;

    pubnub_string_view_t key_view;
    pubnub_res_t         rc =
        pn_request_scratch_encode(request, key, &key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        request->scratch_used = saved_used;
        return rc;
    }

    pubnub_string_view_t value_view;
    rc = pn_request_scratch_encode(request, value, &value_view, encode);
    if (PUBNUB_OK != rc) {
        request->scratch_used = saved_used;
        return rc;
    }

    pubnub_kv_t* param = &request->query_params[request->query_param_count++];
    param->key         = key_view;
    param->value       = value_view;

    return PUBNUB_OK;
}

pubnub_res_t pn_request_add_query_param_view(pubnub_http_request_t* request,
                                             const char*            key,
                                             pubnub_string_view_t   value)
{
    if (NULL == request || NULL == key || NULL == value.ptr) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (request->query_param_count >= PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    const unsigned int saved_used = request->scratch_used;

    pubnub_string_view_t key_view;
    pubnub_res_t         rc =
        pn_request_scratch_encode(request, key, &key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        request->scratch_used = saved_used;
        return rc;
    }

    pubnub_kv_t* param = &request->query_params[request->query_param_count++];
    param->key         = key_view;
    param->value       = value;

    return PUBNUB_OK;
}

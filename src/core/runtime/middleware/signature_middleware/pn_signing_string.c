/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_signing_string.c
 * @brief PAMv3 canonical signing-string builder.
 */

#include "pn_signing_string.h"

#include <string.h>

/** Line-feed byte that joins the five canonical sections. */
#define PN_SIGNING_LINE_FEED '\n'

/**
 * @brief Whether @p request targets the /publish endpoint family.
 *
 * In segment form, the first path segment starts with "publish"
 * (matches `path.startsWith('/publish')` in the JS SDK).
 */
static int request_is_publish(const pubnub_http_request_t* request)
{
    if (request->path_segment_count == 0) {
        return 0;
    }
    const pubnub_string_view_t* first = &request->path_segments[0];
    return first->len >= 7 && memcmp(first->ptr, "publish", 7) == 0;
}

/**
 * @brief PAM-compatible signing method for @p request.
 *
 * The PAM service has a long-standing bug on /publish: it does not
 * canonicalize the POST body, so a client that signs the body gets
 * a signature mismatch against what PAM itself computes. The JS
 * SDK works around this by rewriting the method to GET for any
 * /publish request before signing - we do the same here. Every
 * other endpoint is signed with the real method.
 *
 * Note: this affects only the signing-string. The request is still
 * dispatched over the wire with its original method/body; only the
 * canonical string fed into HMAC is normalized.
 */
static pubnub_http_method_t signing_method(const pubnub_http_request_t* request)
{
    if (request_is_publish(request)) {
        return PUBNUB_HTTP_GET;
    }
    return request->method;
}

const char* pn_signing_method_verb(pubnub_http_method_t method)
{
    switch (method) {
    case PUBNUB_HTTP_GET: return "GET";
    case PUBNUB_HTTP_POST: return "POST";
    case PUBNUB_HTTP_PATCH: return "PATCH";
    case PUBNUB_HTTP_DELETE: return "DELETE";
    }

    return "UNKNOWN";
}

/**
 * @brief Compute bytes needed for the PATH section (including the
 *        leading `/` and any inter-segment separators).
 *
 * An empty segment list still produces a single `/` byte to match
 * the legacy convention that even a root-request has a path prefix.
 */
static size_t path_bytes_len(const pubnub_http_request_t* request)
{
    if (request->path_segment_count == 0) {
        return 1; /* single '/' */
    }

    size_t total = 0;
    for (unsigned int i = 0; i < request->path_segment_count; i++) {
        total += 1; /* leading '/' before every segment */
        total += request->path_segments[i].len;
    }

    return total;
}

/**
 * @brief Compute bytes needed for the QUERY section (key=value
 *        pairs joined by `&`, no leading `?`).
 */
static size_t query_bytes_len(const pubnub_http_request_t* request)
{
    if (request->query_param_count == 0) {
        return 0;
    }

    size_t total = 0;
    for (unsigned int i = 0; i < request->query_param_count; i++) {
        if (i > 0) {
            total += 1; /* '&' separator */
        }
        total += request->query_params[i].key.len;
        total += 1; /* '=' */
        total += request->query_params[i].value.len;
    }

    return total;
}

/** @brief Whether @p method contributes a body to the signing string. */
static int method_has_body(pubnub_http_method_t method)
{
    return method == PUBNUB_HTTP_POST || method == PUBNUB_HTTP_PATCH;
}

/**
 * @brief Compute bytes contributed by the BODY section.
 *
 * Only POST/PATCH include body bytes. The signing_method()
 * normalization ensures /publish (forced to GET) never reaches here
 * with a body-bearing method.
 */
static size_t body_bytes_len(const pubnub_http_request_t* request,
                             pubnub_http_method_t         method)
{
    if (!method_has_body(method)) {
        return 0;
    }
    if (request->body == NULL) {
        return 0;
    }
    return request->body_len;
}

size_t pn_signing_string_len(const pubnub_http_request_t* request,
                             const char*                  publish_key)
{
    if (publish_key == NULL || request == NULL) {
        return 0;
    }

    pubnub_http_method_t method = signing_method(request);

    const char* verb = pn_signing_method_verb(method);

    size_t total = strlen(verb);
    total += 1; /* line feed */
    total += strlen(publish_key);
    total += 1; /* line feed */
    total += path_bytes_len(request);
    total += 1; /* line feed */
    total += query_bytes_len(request);
    total += 1; /* line feed */
    total += body_bytes_len(request, method);

    return total;
}

/* Per-section writers advance from @p output and return the byte
 * count. The caller is responsible for having sized the buffer via
 * pn_signing_string_len(); writers do not validate capacity. */

static size_t write_method(uint8_t* output, pubnub_http_method_t method)
{
    const char* verb = pn_signing_method_verb(method);
    size_t      len  = strlen(verb);

    memcpy(output, verb, len); // NOLINT(bugprone-not-null-terminated-result)
    output[len] = PN_SIGNING_LINE_FEED;

    return len + 1;
}

static size_t write_publish_key(uint8_t* output, const char* publish_key)
{
    size_t len = strlen(publish_key);

    memcpy(output, publish_key, len); // NOLINT(bugprone-not-null-terminated-result)
    output[len] = PN_SIGNING_LINE_FEED;

    return len + 1;
}

static size_t write_path(uint8_t* output, const pubnub_http_request_t* request)
{
    size_t pos = 0;

    if (request->path_segment_count == 0) {
        output[pos++] = '/';
    } else {
        for (unsigned int i = 0; i < request->path_segment_count; i++) {
            const pubnub_string_view_t* seg = &request->path_segments[i];

            output[pos++] = '/';
            if (seg->len > 0) {
                memcpy(output + pos, seg->ptr, seg->len);
                pos += seg->len;
            }
        }
    }
    output[pos++] = PN_SIGNING_LINE_FEED;

    return pos;
}

static size_t write_query(uint8_t* output, const pubnub_http_request_t* request)
{
    size_t pos = 0;

    for (unsigned int i = 0; i < request->query_param_count; i++) {
        const pubnub_kv_t* param = &request->query_params[i];

        if (i > 0) {
            output[pos++] = '&';
        }
        if (param->key.len > 0) {
            memcpy(output + pos, param->key.ptr, param->key.len);
            pos += param->key.len;
        }
        output[pos++] = '=';
        if (param->value.len > 0) {
            memcpy(output + pos, param->value.ptr, param->value.len);
            pos += param->value.len;
        }
    }
    output[pos++] = PN_SIGNING_LINE_FEED;

    return pos;
}

static size_t write_body(uint8_t*                     output,
                         const pubnub_http_request_t* request,
                         pubnub_http_method_t         method)
{
    if (!method_has_body(method) || request->body == NULL || request->body_len == 0) {
        return 0;
    }
    memcpy(output, request->body, request->body_len);
    return request->body_len;
}

pubnub_res_t pn_signing_string_build(const pubnub_http_request_t* request,
                                     const char*                  publish_key,
                                     uint8_t*                     output,
                                     size_t                       out_cap,
                                     size_t*                      out_len)
{
    if (publish_key == NULL || request == NULL || output == NULL || out_len == NULL) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_http_method_t method = signing_method(request);

    const size_t need = pn_signing_string_len(request, publish_key);
    if (need == 0) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (need > out_cap) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0;
    pos += write_method(output + pos, method);
    pos += write_publish_key(output + pos, publish_key);
    pos += write_path(output + pos, request);
    pos += write_query(output + pos, request);
    pos += write_body(output + pos, request, method);

    *out_len = pos;

    return PUBNUB_OK;
}

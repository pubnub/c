/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "publish_internal.h"

#if !PUBNUB_ENABLE_PUBLISH
#error "publish_wire.c requires PUBNUB_ENABLE_PUBLISH=ON - this translation unit has no meaning without the publish feature. Check the CMake feature gating in src/features/CMakeLists.txt; the file must not appear in the build when the flag is off."
#endif

#include "core/pn_format.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

#include "core/protocol_common/pn_response_probe.h"

pubnub_res_t pn_publish_serialize_json_value(pubnub_serialization_provider_t* serialization,
                                             const pubnub_json_value_t* value,
                                             uint8_t*                   buf,
                                             const size_t               buf_cap,
                                             size_t*                    out_len)
{
    if (NULL == serialization || NULL == serialization->serialize
        || NULL == value || NULL == buf || 0 == buf_cap || NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return serialization->serialize(serialization, value, buf, buf_cap, out_len);
}

pubnub_res_t pn_publish_build_path(pubnub_http_request_t*          request,
                                   pubnub_allocator_provider_t*    allocator,
                                   const pn_publish_path_inputs_t* in,
                                   pn_publish_url_encoded_t*       out)
{
    if (NULL == request || NULL == allocator || NULL == in || NULL == out
        || NULL == in->publish_key || NULL == in->subscribe_key || NULL == in->channel
        || (in->include_message && NULL == in->serialized)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Zero-initialize out so every error path leaves a consistent
     * "nothing to free" state. */
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

    /* Encode channel into scratch - channel names are short text
     * strings that fit comfortably in the request scratch buffer. */
    rc = pn_request_scratch_encode(
        request, in->channel, &channel_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Message encoding only happens for GET-style publish - POST
     * places the raw message in the body, no URL encoding.
     * Messages can be large (serialized JSON), so use an
     * allocator-owned buffer via pn_url_encode_alloc_n. */
    char* encoded_message = NULL;
    if (in->include_message) {
        encoded_message = pn_url_encode_alloc_n(
            in->serialized, in->serialized_len, allocator, PN_ENCODE_FULL);
        if (NULL == encoded_message) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    }

    /* Path layout per REST spec:
     *   GET:  /publish/{pub}/{sub}/0/{channel}/0/{payload}
     *   POST: /publish/{pub}/{sub}/0/{channel}/0
     *
     * Keys and literal "0" tokens come from context / ASCII; they
     * need no encoding.  `callback` is fixed at "0" because the
     * SDK never requests a JSONP wrapper. */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"publish", 7};
    request->path_segments[n++] = pub_key_view;
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    request->path_segments[n++] = channel_view;
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    if (in->include_message) {
        request->path_segments[n++] =
            (pubnub_string_view_t){encoded_message, strlen(encoded_message)};
    }
    request->path_segment_count = n;

    out->channel = NULL; /* Channel now lives in scratch, not allocated. */
    out->message = encoded_message; /* NULL when include_message was false */
    return PUBNUB_OK;
}

pubnub_res_t pn_publish_add_query_params(pubnub_http_request_t* request,
                                         int                    opts_meta,
                                         const char*            meta_text,
                                         size_t                 meta_len,
                                         pubnub_publish_store_t store,
                                         unsigned int           ttl,
                                         const char* custom_message_type)
{
    if (NULL == request) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (PUBNUB_PUBLISH_STORE_YES == store) {
        pubnub_res_t rc =
            pn_request_add_query_param(request, "store", "1", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    } else if (PUBNUB_PUBLISH_STORE_NO == store) {
        pubnub_res_t rc =
            pn_request_add_query_param(request, "store", "0", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    /* Send `ttl` when the caller set one, except when store == NO:
     * a non-persisted message has no TTL to apply, so the parameter
     * would be wire noise. For YES and ACCOUNT_DEFAULT we send it
     * and let the server decide - ACCOUNT_DEFAULT resolves to the
     * keyset's storage default, which the client does not know in
     * advance. */
    if (ttl > 0 && PUBNUB_PUBLISH_STORE_NO != store) {
        /* Decimal representation of unsigned int fits in 16 chars
         * on every target.  pn_snprintf for safety in case the int
         * width grows in the future. */
        char ttl_buf[16];
        (void)pn_snprintf(ttl_buf, sizeof(ttl_buf), "%u", ttl);
        pubnub_res_t rc =
            pn_request_add_query_param(request, "ttl", ttl_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (opts_meta && NULL != meta_text) {
        pubnub_res_t rc;
        if (meta_len > 0) {
            /* Length-counted meta: honor the caller's explicit length
             * rather than treating meta_text as NUL-terminated. Encode
             * the exact byte range into scratch and attach by view. */
            const unsigned int   saved_used = request->scratch_used;
            pubnub_string_view_t meta_view;
            rc = pn_request_scratch_encode_n(request,
                                             (const uint8_t*)meta_text,
                                             meta_len,
                                             &meta_view,
                                             PN_ENCODE_FULL);
            if (PUBNUB_OK != rc) {
                return rc;
            }
            rc = pn_request_add_query_param_view(request, "meta", meta_view);
            if (PUBNUB_OK != rc) {
                request->scratch_used = saved_used;
                return rc;
            }
        } else {
            rc = pn_request_add_query_param(
                request, "meta", meta_text, PN_ENCODE_FULL);
            if (PUBNUB_OK != rc) {
                return rc;
            }
        }
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

/**
 * @brief Validator vs parser split
 *
 * The publish feature carries two response-side helpers with
 * deliberately different cost profiles:
 *
 *   - @ref pn_publish_response_validator runs a bounded ~3-byte
 *     bytewise scan to decide whether an HTTP-200 body is
 *     `[1, ...]` (success) vs `[0, ...]` (logical failure). It
 *     runs on every response, so it stays bytewise - no JSON
 *     parser invocation, no allocator interaction, no provider
 *     dispatch. The cost is constant regardless of body size.
 *
 *   - @ref pn_publish_parse_response walks the *parsed* tree to
 *     extract the timetoken view. It runs lazily, only when a
 *     getter (e.g. @ref pubnub_publish_result_timetoken) demands
 *     the timetoken. Going through the serialization vtable here
 *     keeps the parser code path uniform across backends and
 *     eliminates the duplicate hand-rolled JSON tokenizer the
 *     SDK used to carry alongside the cJSON / jsmn providers.
 *
 * The two helpers do not share a code path because pessimising
 * the validator's hot path with a full parse would charge every
 * successful publish for the cost of failure-path diagnostics.
 */

pubnub_res_t pn_publish_response_validator(const uint8_t* body,
                                           size_t         body_len,
                                           int            http_status)
{
    return pn_probe_array_status(body, body_len, http_status, 20);
}

pubnub_res_t pn_publish_parse_response(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       tree,
                                       pn_publish_parsed_t*             out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->timetoken = (pubnub_timetoken_t){NULL, 0};

    return pn_parse_publish_array_response(serial, tree, &out->timetoken);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "history_internal.h"

#if !PUBNUB_ENABLE_HISTORY
#error "history_wire.c requires PUBNUB_ENABLE_HISTORY=ON"
#endif

#include "core/pn_format.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

/** Max bytes examined when probing the history response prefix. */
#define PN_HISTORY_RESPONSE_PROBE_LIMIT 50

/**
 * @brief Validate that a timetoken is 1-19 decimal digits.
 *
 * Timetokens are copied verbatim into the request query string, so a
 * value carrying anything other than decimal digits would inject
 * unexpected characters into the URL. A valid PubNub timetoken is a
 * decimal integer that fits in 64 bits (at most 19 digits).
 *
 * @param tt NUL-terminated candidate timetoken.
 * @return PUBNUB_OK when valid, PUBNUB_ERR_INVALID_ARGUMENT otherwise.
 */
static pubnub_res_t pn_validate_timetoken(const char* tt)
{
    size_t len;

    if (NULL == tt || '\0' == tt[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    for (len = 0; '\0' != tt[len]; ++len) {
        if (len >= 19 || tt[len] < '0' || tt[len] > '9') {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
    }

    return PUBNUB_OK;
}

/**
 * @brief Validate a comma-separated list of timetokens.
 *
 * Used for the message-counts @c channelsTimetoken parameter, which
 * carries one timetoken per channel. Each comma-separated segment must
 * be 1-19 decimal digits; empty segments (leading, trailing, or
 * consecutive commas) are rejected so that no non-digit byte can reach
 * the query string.
 *
 * @param list NUL-terminated candidate list.
 * @return PUBNUB_OK when valid, PUBNUB_ERR_INVALID_ARGUMENT otherwise.
 */
static pubnub_res_t pn_validate_timetoken_list(const char* list)
{
    size_t i;
    size_t seg_len = 0;

    if (NULL == list || '\0' == list[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; '\0' != list[i]; ++i) {
        if (',' == list[i]) {
            if (0 == seg_len) {
                return PUBNUB_ERR_INVALID_ARGUMENT;
            }
            seg_len = 0;
            continue;
        }
        if (list[i] < '0' || list[i] > '9' || seg_len >= 19) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        ++seg_len;
    }

    /* A trailing comma leaves an empty final segment. */
    if (0 == seg_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_build_fetch_path(pubnub_http_request_t* request,
                                         const char*            subscribe_key,
                                         pubnub_string_view_t encoded_channels,
                                         int                  with_actions)
{
    pubnub_string_view_t sub_view;
    pubnub_res_t         rc;
    unsigned int         n = 0;

    if (NULL == request || NULL == subscribe_key || NULL == encoded_channels.ptr
        || 0 == encoded_channels.len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    rc = pn_request_scratch_encode(request, subscribe_key, &sub_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    if (with_actions) {
        request->path_segments[n++] = (pubnub_string_view_t){"v3", 2};
        request->path_segments[n++] =
            (pubnub_string_view_t){"history-with-actions", 20};
    } else {
        request->path_segments[n++] = (pubnub_string_view_t){"v3", 2};
        request->path_segments[n++] = (pubnub_string_view_t){"history", 7};
    }
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};
    request->path_segments[n++] = encoded_channels;
    request->path_segment_count = n;

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_build_delete_path(pubnub_http_request_t* request,
                                          const char*            subscribe_key,
                                          pubnub_string_view_t encoded_channel)
{
    pubnub_string_view_t sub_view;
    pubnub_res_t         rc;
    unsigned int         n = 0;

    if (NULL == request || NULL == subscribe_key || NULL == encoded_channel.ptr
        || 0 == encoded_channel.len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    rc = pn_request_scratch_encode(request, subscribe_key, &sub_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = (pubnub_string_view_t){"v3", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"history", 7};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channel", 7};
    request->path_segments[n++] = encoded_channel;
    request->path_segment_count = n;

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_build_counts_path(pubnub_http_request_t* request,
                                          const char*            subscribe_key,
                                          pubnub_string_view_t encoded_channels)
{
    pubnub_string_view_t sub_view;
    pubnub_res_t         rc;
    unsigned int         n = 0;

    if (NULL == request || NULL == subscribe_key || NULL == encoded_channels.ptr
        || 0 == encoded_channels.len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    rc = pn_request_scratch_encode(request, subscribe_key, &sub_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    request->path_segments[n++] = (pubnub_string_view_t){"v3", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"history", 7};
    request->path_segments[n++] = (pubnub_string_view_t){"sub-key", 7};
    request->path_segments[n++] = sub_view;
    request->path_segments[n++] = (pubnub_string_view_t){"message-counts", 14};
    request->path_segments[n++] = encoded_channels;
    request->path_segment_count = n;

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_add_fetch_query_params(pubnub_http_request_t* request,
                                               const pubnub_fetch_messages_opts_t* opts)
{
    if (NULL == request || NULL == opts) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (0 != opts->count) {
        char         count_buf[8];
        pubnub_res_t rc;
        (void)pn_snprintf(count_buf, sizeof(count_buf), "%u", (unsigned)opts->count);
        rc = pn_request_add_query_param(request, "max", count_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != opts->start) {
        pubnub_res_t rc;
        if (PUBNUB_OK != pn_validate_timetoken(opts->start)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(request, "start", opts->start, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != opts->end) {
        pubnub_res_t rc;
        if (PUBNUB_OK != pn_validate_timetoken(opts->end)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(request, "end", opts->end, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (0 != opts->reverse) {
        pubnub_res_t rc =
            pn_request_add_query_param(request, "reverse", "true", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (0 != opts->include_meta) {
        pubnub_res_t rc = pn_request_add_query_param(
            request, "include_meta", "true", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (0 != opts->include_uuid) {
        pubnub_res_t rc = pn_request_add_query_param(
            request, "include_uuid", "true", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (0 != opts->include_message_type) {
        pubnub_res_t rc = pn_request_add_query_param(
            request, "include_message_type", "true", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (0 != opts->include_custom_message_type) {
        pubnub_res_t rc = pn_request_add_query_param(
            request, "include_custom_message_type", "true", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    {
        pubnub_res_t rc = pn_request_add_query_param(
            request, "string_message_token", "true", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_add_delete_query_params(pubnub_http_request_t* request,
                                                const pubnub_delete_messages_opts_t* opts)
{
    if (NULL == request || NULL == opts) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL != opts->start) {
        pubnub_res_t rc;
        if (PUBNUB_OK != pn_validate_timetoken(opts->start)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(request, "start", opts->start, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != opts->end) {
        pubnub_res_t rc;
        if (PUBNUB_OK != pn_validate_timetoken(opts->end)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(request, "end", opts->end, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_add_counts_query_params(pubnub_http_request_t* request,
                                                const pubnub_message_counts_opts_t* opts)
{
    if (NULL == request || NULL == opts) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL != opts->timetoken) {
        pubnub_res_t rc;
        if (PUBNUB_OK != pn_validate_timetoken(opts->timetoken)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(
            request, "timetoken", opts->timetoken, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != opts->channels_timetokens) {
        pubnub_res_t rc;
        if (PUBNUB_OK != pn_validate_timetoken_list(opts->channels_timetokens)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        rc = pn_request_add_query_param(
            request, "channelsTimetoken", opts->channels_timetokens, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_response_validator(const uint8_t* body,
                                           size_t         body_len,
                                           int            http_status)
{
    size_t limit = body_len;
    size_t i;

    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    /* Scan for "status": in the first N bytes. If the value is
     * >= 400, treat as logical failure. */
    if (limit > PN_HISTORY_RESPONSE_PROBE_LIMIT) {
        limit = PN_HISTORY_RESPONSE_PROBE_LIMIT;
    }

    for (i = 0; i + 9 < limit; ++i) {
        if ('"' == body[i] && 's' == body[i + 1] && 't' == body[i + 2]
            && 'a' == body[i + 3] && 't' == body[i + 4] && 'u' == body[i + 5]
            && 's' == body[i + 6] && '"' == body[i + 7]) {
            /* Found "status" — skip ": and whitespace to find digit. */
            size_t j = i + 8;
            while (j < body_len
                   && (':' == body[j] || ' ' == body[j] || '\t' == body[j])) {
                ++j;
            }
            if (j < body_len && body[j] >= '4' && body[j] <= '5') {
                return PUBNUB_ERR_SERVER;
            }
            return PUBNUB_OK;
        }
    }

    return PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_delete_response_validator(const uint8_t* body,
                                                  size_t         body_len,
                                                  int            http_status)
{
    (void)body;
    (void)body_len;
    return (http_status >= 400) ? PUBNUB_ERR_SERVER : PUBNUB_OK;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void pn_history_feature_state_cleanup(void*                        state,
                                      pubnub_allocator_provider_t* allocator)
{
    pn_history_state_t* s;

    if (NULL == state || NULL == allocator) {
        return;
    }

    s = (pn_history_state_t*)state;

    if (NULL != s->parsed && NULL != allocator->free) {
        if (PN_HISTORY_OP_FETCH == s->operation) {
            pn_history_fetch_parsed_t* fp = (pn_history_fetch_parsed_t*)s->parsed;
            if (PUBNUB_ENABLE_CRYPTO && NULL != fp->serial
                && NULL != fp->serial->value_destroy) {
                if (NULL != fp->decrypted_msg_tree) {
                    fp->serial->value_destroy(fp->serial, fp->decrypted_msg_tree);
                    fp->decrypted_msg_tree = NULL;
                }
                if (NULL != fp->decrypted_file_tree) {
                    fp->serial->value_destroy(fp->serial, fp->decrypted_file_tree);
                    fp->decrypted_file_tree = NULL;
                }
            }
            if (NULL != fp->channel_entries) {
                PN_FREE(allocator, fp->channel_entries);
            }
        } else if (PN_HISTORY_OP_COUNTS == s->operation) {
            pn_history_counts_parsed_t* cp = (pn_history_counts_parsed_t*)s->parsed;
            if (NULL != cp->channel_entries) {
                PN_FREE(allocator, cp->channel_entries);
            }
        }
        PN_FREE(allocator, s->parsed);
        s->parsed = NULL;
    }

    if (NULL != s->encoded_channels && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_channels);
        s->encoded_channels = NULL;
    }

    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}

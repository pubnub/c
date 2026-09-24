/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_response_probe.h"

#include <string.h>

pubnub_res_t pn_probe_array_status(const uint8_t* body,
                                   size_t         body_len,
                                   int            http_status,
                                   size_t         probe_limit)
{
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    if (NULL == body || 0 == body_len) {
        return PUBNUB_OK;
    }

    /* Bounded scan: skip whitespace, expect '[', skip whitespace,
     * read the status digit. */
    size_t i = 0;
    while (i < body_len && i < probe_limit) {
        const uint8_t c = body[i];
        if (' ' == c || '\t' == c || '\r' == c || '\n' == c) {
            i++;
            continue;
        }
        break;
    }

    if (i >= body_len || '[' != body[i]) {
        return PUBNUB_OK; /* Unknown format - let lazy parser decide. */
    }
    i++;

    while (i < body_len && i < probe_limit) {
        const uint8_t c = body[i];
        if (' ' == c || '\t' == c || '\r' == c || '\n' == c) {
            i++;
            continue;
        }
        break;
    }

    if (i >= body_len) {
        return PUBNUB_OK;
    }

    if ('1' == body[i]) {
        return PUBNUB_OK;
    }
    if ('0' == body[i]) {
        return PUBNUB_ERR_SERVER;
    }

    /* Unexpected digit or character - don't reject. */
    return PUBNUB_OK;
}

pubnub_res_t pn_probe_object_error_flag(const uint8_t* body,
                                        size_t         body_len,
                                        int            http_status,
                                        size_t         probe_limit)
{
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    if (NULL == body || 0 == body_len) {
        return PUBNUB_OK;
    }

    /* Bounded byte-scan for the pattern:  "error" : true
     * within the first probe_limit bytes. */
    const size_t limit = (body_len < probe_limit) ? body_len : probe_limit;

    /* Phase 1: find the substring "error" (with quotes). */
    const char   needle[]   = "\"error\"";
    const size_t needle_len = 7;
    size_t       found_pos  = 0;
    int          found      = 0;

    for (size_t i = 0; i + needle_len <= limit; ++i) {
        if (0 == memcmp(body + i, needle, needle_len)) {
            found_pos = i + needle_len;
            found     = 1;
            break;
        }
    }

    if (!found) {
        return PUBNUB_OK;
    }

    /* Phase 2: skip whitespace, expect ':', skip whitespace, read value. */
    size_t pos = found_pos;
    while (pos < limit
           && (' ' == body[pos] || '\t' == body[pos] || '\r' == body[pos]
               || '\n' == body[pos])) {
        pos++;
    }

    if (pos >= limit || ':' != body[pos]) {
        return PUBNUB_OK;
    }
    pos++;

    while (pos < limit
           && (' ' == body[pos] || '\t' == body[pos] || '\r' == body[pos]
               || '\n' == body[pos])) {
        pos++;
    }

    if (pos >= limit) {
        return PUBNUB_OK;
    }

    /* Check for "true" (4 bytes) or "false" (5 bytes). */
    if (pos + 4 <= limit && 0 == memcmp(body + pos, "true", 4)) {
        return PUBNUB_ERR_SERVER;
    }
    if (pos + 5 <= limit && 0 == memcmp(body + pos, "false", 5)) {
        return PUBNUB_OK;
    }

    /* Unrecognized value - let lazy parser decide. */
    return PUBNUB_OK;
}

pubnub_res_t pn_parse_publish_array_response(pubnub_serialization_provider_t* serial,
                                             const pubnub_json_value_t* tree,
                                             pubnub_timetoken_t* out_token)
{
    if (NULL == out_token) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out_token->ptr = NULL;
    out_token->len = 0;

    if (NULL == serial || NULL == tree || NULL == serial->value_type
        || NULL == serial->array_size || NULL == serial->array_get
        || NULL == serial->value_as_string || NULL == serial->value_as_int) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_ARRAY != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    const size_t n = serial->array_size(tree);
    if (n < 2) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* status_node = serial->array_get(tree, 0);
    if (NULL == status_node || PUBNUB_JSON_INT != serial->value_type(status_node)) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    int status = 0;
    if (PUBNUB_OK != serial->value_as_int(status_node, &status)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* msg_node = serial->array_get(tree, 1);
    if (NULL == msg_node || PUBNUB_JSON_STRING != serial->value_type(msg_node)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Optional timetoken in slot 2. The PAM `Forbidden` shape
     * (`[0,"Forbidden"]`) and other 2-element error shapes leave
     * timetoken empty per the documented contract. */
    if (n < 3) {
        return PUBNUB_OK;
    }
    const pubnub_json_value_t* tt_node = serial->array_get(tree, 2);
    if (NULL == tt_node || PUBNUB_JSON_STRING != serial->value_type(tt_node)) {
        return PUBNUB_OK;
    }
    size_t      tt_len = 0;
    const char* tt_ptr = serial->value_as_string(tt_node, &tt_len);
    if (NULL == tt_ptr) {
        return PUBNUB_OK;
    }
    out_token->ptr = tt_ptr;
    out_token->len = tt_len;
    return PUBNUB_OK;
}

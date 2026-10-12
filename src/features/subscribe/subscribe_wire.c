/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "subscribe_wire_internal.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_wire.c requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "core/pn_format.h"
#include "pubnub/pubnub_compat.h"
#include "core/runtime/middleware/middleware_internal.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 5,
                     "Subscribe requires at least 5 path segments");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_SCRATCH_SIZE >= 128,
                     "Middleware query params require >= 128B scratch");

/** Outcome of parsing one element of the "m" array. */
typedef enum pn_parse_msg_result {
    /** Element parsed; the event is populated. */
    PN_PARSE_MSG_OK = 0,
    /** No usable channel; the caller drops the whole batch. */
    PN_PARSE_MSG_REJECT,
    /** Unknown or undecodable event type; only this element is skipped. */
    PN_PARSE_MSG_SKIP
} pn_parse_msg_result_t;

/**
 * @brief Populate shared path segments and query parameters for both
 *        handshake and receive requests.
 *
 * Path: /v2/subscribe/{sub_key}/{channels}/0
 * Query: tt, tr (if non-zero), filter-expr, channel-group, heartbeat
 *
 * The channels string in inputs is already percent-encoded by the
 * caller (dispatch state owns the encoded buffer). Channel-groups,
 * if present, are also pre-encoded.
 */
static pubnub_res_t pn_subscribe_build_common(pubnub_http_request_t* request,
                                              const pn_subscribe_wire_inputs_t* inputs,
                                              const char* timetoken,
                                              uint32_t    region)
{
    /* Path segments: v2 / subscribe / sub_key / channels / 0 */
    unsigned int         n = 0;
    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, inputs->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    request->path_segments[n++] = (pubnub_string_view_t){"v2", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"subscribe", 9};
    request->path_segments[n++] = sub_key_view;
    /* Channels are pre-encoded — assign directly as a view. */
    request->path_segments[n++] =
        (pubnub_string_view_t){inputs->channels, strlen(inputs->channels)};
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    request->path_segment_count = n;

    request->method     = PUBNUB_HTTP_GET;
    request->secure     = PUBNUB_ENABLE_SECURE_TRANSPORT;
    request->timeout_ms = inputs->timeout_ms;

    /* tt — always present. */
    rc = pn_request_add_query_param(request, "tt", timetoken, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* tr — omit when zero. */
    if (0 != region) {
        char region_buf[12];
        (void)pn_snprintf(region_buf, sizeof(region_buf), "%u", (unsigned int)region);
        rc = pn_request_add_query_param(request, "tr", region_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    /* filter-expr — omit when NULL or empty. */
    if (NULL != inputs->filter_expr && '\0' != inputs->filter_expr[0]) {
        rc = pn_request_add_query_param(
            request, "filter-expr", inputs->filter_expr, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
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

    /* heartbeat — omit when zero. */
    if (0 != inputs->heartbeat_sec) {
        char hb_buf[12];
        (void)pn_snprintf(
            hb_buf, sizeof(hb_buf), "%u", (unsigned int)inputs->heartbeat_sec);
        rc = pn_request_add_query_param(request, "heartbeat", hb_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_subscribe_build_handshake(pubnub_http_request_t* request,
                                          const pn_subscribe_wire_inputs_t* inputs)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channels) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    return pn_subscribe_build_common(request, inputs, "0", 0);
}

pubnub_res_t pn_subscribe_build_receive(pubnub_http_request_t* request,
                                        const pn_subscribe_wire_inputs_t* inputs,
                                        const pn_subscribe_cursor_t* cursor)
{
    if (NULL == request || NULL == inputs || NULL == inputs->subscribe_key
        || NULL == inputs->channels || NULL == cursor) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (0 == cursor->timetoken_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    return pn_subscribe_build_common(
        request, inputs, cursor->timetoken, cursor->region);
}

/**
 * @brief Extract a cursor (timetoken + region) from a JSON object
 *        node with shape `{"t": "<digits>", "r": <int>}`.
 *
 * @param serial  Serialization provider.
 * @param cursor_obj  JSON object node to read.
 * @param out     Cursor struct to populate.
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERIALIZATION if the
 *         cursor object is malformed.
 */
static pubnub_res_t parse_cursor_object(pubnub_serialization_provider_t* serial,
                                        const pubnub_json_value_t* cursor_obj,
                                        pn_subscribe_cursor_t*     out)
{
    const pubnub_json_value_t* tt_node;
    const pubnub_json_value_t* r_node;
    const char*                tt_ptr;
    size_t                     tt_len = 0;

    if (NULL == cursor_obj || NULL == serial->object_get
        || NULL == serial->value_as_string || NULL == serial->value_as_int) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* "t" field — timetoken string. */
    tt_node = serial->object_get(cursor_obj, "t", 1);
    if (NULL == tt_node) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    tt_ptr = serial->value_as_string(tt_node, &tt_len);
    if (NULL == tt_ptr || 0 == tt_len || tt_len >= sizeof(out->timetoken)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Reject non-digits: the timetoken is spliced verbatim into the tt=
     * query param, so only numeric values may advance. */
    {
        size_t i;
        for (i = 0; i < tt_len; ++i) {
            if (tt_ptr[i] < '0' || tt_ptr[i] > '9') {
                return PUBNUB_ERR_SERIALIZATION;
            }
        }
    }

    memcpy(out->timetoken, tt_ptr, tt_len);
    out->timetoken[tt_len] = '\0';
    out->timetoken_len     = (uint8_t)tt_len;

    /* "r" field — region integer (optional, default 0). */
    r_node = serial->object_get(cursor_obj, "r", 1);
    if (NULL != r_node) {
        int region_val = 0;
        if (PUBNUB_OK == serial->value_as_int(r_node, &region_val)) {
            out->region = (uint32_t)region_val;
        }
    }

    return PUBNUB_OK;
}

/**
 * @brief Decode the "e" event-type node, logging unknown values at debug.
 *
 * A non-integer node is logged as a fixed literal (server bytes are never
 * echoed); an integer outside the known range is logged numerically.
 *
 * @param serial   Serialization provider.
 * @param log      Logger provider; may be NULL.
 * @param e_node   The "e" JSON node (non-NULL).
 * @param out_type Decoded type; written only when the function returns 1.
 * @retval 1 Known event type decoded.
 * @retval 0 Unknown event type; the element should be skipped.
 */
static int decode_event_type(pubnub_serialization_provider_t* serial,
                             pubnub_logger_provider_t*        log,
                             const pubnub_json_value_t*       e_node,
                             pubnub_subscribe_message_type_t* out_type)
{
    int int_val = 0;

    (void)log;

    if (PUBNUB_OK != serial->value_as_int(e_node, &int_val)) {
        PUBNUB_LOG(log,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "Unknown event type (%s) has been received",
                   "non-numeric");
        return 0;
    }
    if (int_val < PUBNUB_SUBSCRIBE_MESSAGE || int_val > PUBNUB_SUBSCRIBE_FILE) {
        PUBNUB_LOG(log,
                   PUBNUB_LOG_LEVEL_DEBUG,
                   "Unknown event type (%d) has been received",
                   int_val);
        return 0;
    }
    *out_type = (pubnub_subscribe_message_type_t)int_val;
    return 1;
}

/**
 * @brief Parse one message element from the "m" array.
 *
 * A missing/non-string/empty "c" channel cannot be routed, so the element
 * is rejected and the caller drops the whole batch. A present "e" that is
 * non-numeric or outside the known event types skips just this element.
 * A known "e" decides the type; without "e" a -pnpres channel suffix
 * selects presence, otherwise the type stays message.
 *
 * @param serial Serialization provider.
 * @param log    Logger provider used for the unknown-type debug line; may
 *               be NULL.
 * @param elem   JSON object for one message.
 * @param event  Output event; may be partially written on SKIP, so the
 *               caller must re-zero it before reuse.
 * @return PN_PARSE_MSG_OK, PN_PARSE_MSG_REJECT or PN_PARSE_MSG_SKIP.
 */
static pn_parse_msg_result_t parse_single_message(pubnub_serialization_provider_t* serial,
                                                  pubnub_logger_provider_t* log,
                                                  const pubnub_json_value_t* elem,
                                                  pubnub_subscribe_event_t* event)
{
    const pubnub_json_value_t* e_node;
    const pubnub_json_value_t* f_node;
    const pubnub_json_value_t* c_node;
    const pubnub_json_value_t* b_node;
    const pubnub_json_value_t* i_node;
    const pubnub_json_value_t* cmt_node;
    const pubnub_json_value_t* p_node;
    const pubnub_json_value_t* tt_node;
    const char*                str_ptr;
    size_t                     str_len;
    int                        int_val;

    /* "c" — channel (required); reject when missing, non-string, or empty. */
    c_node = serial->object_get(elem, "c", 1);
    if (NULL == c_node) {
        return PN_PARSE_MSG_REJECT;
    }
    str_len = 0;
    str_ptr = serial->value_as_string(c_node, &str_len);
    if (NULL == str_ptr || 0 == str_len) {
        return PN_PARSE_MSG_REJECT;
    }
    event->channel = (pubnub_string_view_t){str_ptr, str_len};

    /* "f" — flags. */
    f_node = serial->object_get(elem, "f", 1);
    if (NULL != f_node) {
        int_val = 0;
        if (PUBNUB_OK == serial->value_as_int(f_node, &int_val)) {
            event->flags = (uint32_t)int_val;
        }
    }

    /* "b" — subscription match (wildcard or channel-group name), kept
     * verbatim including any -pnpres suffix. */
    b_node = serial->object_get(elem, "b", 1);
    if (NULL != b_node) {
        str_len = 0;
        str_ptr = serial->value_as_string(b_node, &str_len);
        if (NULL != str_ptr) {
            event->subscription = (pubnub_string_view_t){str_ptr, str_len};
        }
    }
    /* Fall back to the raw channel (before -pnpres narrowing) when "b" is
     * absent or empty. */
    if (0 == event->subscription.len) {
        event->subscription = event->channel;
    }

    /* "e" — event type; when present it is decisive. */
    e_node = serial->object_get(elem, "e", 1);
    if (NULL != e_node) {
        if (!decode_event_type(serial, log, e_node, &event->type)) {
            return PN_PARSE_MSG_SKIP;
        }
    } else if (pn_pnpres_has_suffix(event->channel.ptr, event->channel.len)) {
        /* No "e": the suffix implies presence; narrow the view to the base
         * channel (shrink length, keep pointer). */
        event->type = PUBNUB_SUBSCRIBE_PRESENCE;
        event->channel.len -= PN_PNPRES_SUFFIX_LEN;
    }

    /* "i" — publisher UUID. */
    i_node = serial->object_get(elem, "i", 1);
    if (NULL != i_node) {
        str_len = 0;
        str_ptr = serial->value_as_string(i_node, &str_len);
        if (NULL != str_ptr) {
            event->publisher = (pubnub_string_view_t){str_ptr, str_len};
        }
    }

    /* "cmt" — custom message type. */
    cmt_node = serial->object_get(elem, "cmt", 3);
    if (NULL != cmt_node) {
        str_len = 0;
        str_ptr = serial->value_as_string(cmt_node, &str_len);
        if (NULL != str_ptr) {
            event->custom_message_type = (pubnub_string_view_t){str_ptr, str_len};
        }
    }

    /* "d" — payload node. Stored unconditionally for accessor use. */
    event->payload = serial->object_get(elem, "d", 1);

    /* "u" — user metadata node. */
    event->user_metadata = serial->object_get(elem, "u", 1);

    /* "p" — publish timetoken. */
    p_node = serial->object_get(elem, "p", 1);
    if (NULL != p_node) {
        tt_node = serial->object_get(p_node, "t", 1);
        if (NULL != tt_node) {
            str_len = 0;
            str_ptr = serial->value_as_string(tt_node, &str_len);
            if (NULL != str_ptr) {
                event->timetoken = (pubnub_string_view_t){str_ptr, str_len};
            }
        }
    }

    return PN_PARSE_MSG_OK;
}

/**
 * @brief Parse the "m" array into @p out->messages.
 *
 * A rejected element drops the whole batch (message_count = 0, malformed
 * = 1); a skipped element is omitted without affecting the others.
 *
 * @param serial Serialization provider.
 * @param log    Logger provider; may be NULL.
 * @param m_arr  JSON array node ("m").
 * @param out    Parsed response; messages, message_count, truncated and
 *               malformed are updated.
 */
static void parse_message_array(pubnub_serialization_provider_t* serial,
                                pubnub_logger_provider_t*        log,
                                const pubnub_json_value_t*       m_arr,
                                pn_subscribe_parsed_response_t*  out)
{
    pubnub_json_array_iter_t iter;
    pubnub_json_value_t*     elem = NULL;
    size_t                   count;
    size_t                   i = 0;

    count = serial->array_size(m_arr);
    if (count > PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE) {
        count          = PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE;
        out->truncated = 1;
    }

    if (!serial->array_iter_init(m_arr, &iter)) {
        return;
    }
    while (i < count && serial->array_iter_next(&iter, &elem)) {
        pn_parse_msg_result_t pr;
        i++;
        /* A non-object/NULL element or one without a usable channel drops
         * the whole batch; only the cursor survives so the next request
         * steps over it. */
        if (NULL == elem || PUBNUB_JSON_OBJECT != serial->value_type(elem)) {
            pr = PN_PARSE_MSG_REJECT;
        } else {
            /* Re-zero the target slot so fields written by a skipped
             * element cannot leak into the next one. */
            pubnub_subscribe_event_t* slot = &out->messages[out->message_count];
            memset(slot, 0, sizeof(*slot));
            pr = parse_single_message(serial, log, elem, slot);
        }
        if (PN_PARSE_MSG_REJECT == pr) {
            out->message_count = 0;
            out->malformed     = 1;
            break;
        }
        if (PN_PARSE_MSG_SKIP == pr) {
            continue;
        }
        out->message_count++;
    }
}

pubnub_res_t pn_subscribe_parse_response(pubnub_serialization_provider_t* serial,
                                         pubnub_logger_provider_t* log,
                                         const uint8_t*            body,
                                         size_t                    body_len,
                                         pn_subscribe_parsed_response_t* out)
{
    pubnub_json_value_t*       root;
    const pubnub_json_value_t* t_obj;
    const pubnub_json_value_t* m_arr;
    pubnub_res_t               rc;

    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));

    if (NULL == serial || NULL == serial->parse || NULL == serial->value_destroy
        || NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->array_iter_init || NULL == serial->array_iter_next
        || NULL == serial->array_size) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    if (NULL == body || 0 == body_len) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    root = serial->parse(serial, body, body_len);
    if (NULL == root) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Envelope must be an object. */
    if (PUBNUB_JSON_OBJECT != serial->value_type(root)) {
        serial->value_destroy(serial, root);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* "t" — cursor object with shape {"t":"<tt>", "r":<region>}. */
    t_obj = serial->object_get(root, "t", 1);
    if (NULL == t_obj) {
        serial->value_destroy(serial, root);
        return PUBNUB_ERR_SERIALIZATION;
    }

    rc = parse_cursor_object(serial, t_obj, &out->cursor);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, root);
        return rc;
    }

    /* "m" — messages array. A valid response may have no "m" array (empty
     * batch); the tree is still stored for cursor extraction. */
    m_arr = serial->object_get(root, "m", 1);
    if (NULL != m_arr && PUBNUB_JSON_ARRAY == serial->value_type(m_arr)) {
        parse_message_array(serial, log, m_arr, out);
    }

    out->_tree = root;
    return PUBNUB_OK;
}

pubnub_res_t pn_subscribe_response_validator(const uint8_t* body,
                                             size_t         body_len,
                                             int            http_status)
{
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    /* Minimal structural check: a valid subscribe V2 envelope is a
     * JSON object starting with '{'. We require at least 7 bytes for
     * the minimal `{"t":{}}` shape. */
    if (NULL == body || body_len < 7) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Skip leading whitespace (bounded to 16 bytes). */
    size_t i = 0;
    while (i < body_len && i < 16) {
        const uint8_t c = body[i];
        if (' ' == c || '\t' == c || '\r' == c || '\n' == c) {
            i++;
            continue;
        }
        break;
    }

    if (i >= body_len || '{' != body[i]) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    return PUBNUB_OK;
}

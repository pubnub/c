/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/features/subscribe.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_event_accessors.c requires PUBNUB_ENABLE_SUBSCRIBE=ON -- " \
    "this translation unit has no meaning without the subscribe feature."
#endif

#include "subscribe_manager_internal.h"

#include "core/core_internal.h"
#include "core/pn_lock.h"

#include "pubnub/error.h"
#include "pubnub/providers/serialization.h"

#include <stdint.h>
#include <string.h>

pubnub_subscribe_connection_state_t pubnub_subscribe_state(const pubnub_context_t* ctx)
{
    const pn_subscribe_manager_t*       mgr;
    pubnub_subscribe_connection_state_t state;

    if (NULL == ctx) {
        return PUBNUB_SUBSCRIBE_IDLE;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);
    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIBE_IDLE;
    }
    state = mgr->connection_state;
    pn_ctx_unlock(platform, lock);

    return state;
}

pubnub_res_t pubnub_subscribe_event_message(pubnub_context_t* ctx,
                                            const pubnub_subscribe_event_t* event,
                                            pubnub_subscribe_message_event_t* out)
{
    (void)ctx;

    if (NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (PUBNUB_SUBSCRIBE_MESSAGE != event->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel             = event->channel;
    out->subscription        = event->subscription;
    out->publisher           = event->publisher;
    out->timetoken           = event->timetoken;
    out->custom_message_type = event->custom_message_type;
    out->message             = event->payload;
    out->user_metadata       = event->user_metadata;
    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscribe_event_signal(pubnub_context_t* ctx,
                                           const pubnub_subscribe_event_t* event,
                                           pubnub_subscribe_signal_event_t* out)
{
    (void)ctx;

    if (NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (PUBNUB_SUBSCRIBE_SIGNAL != event->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel             = event->channel;
    out->subscription        = event->subscription;
    out->publisher           = event->publisher;
    out->timetoken           = event->timetoken;
    out->custom_message_type = event->custom_message_type;
    out->message             = event->payload;
    out->user_metadata       = event->user_metadata;
    return PUBNUB_OK;
}

/**
 * @brief Helper: extract a string view from a JSON object by key.
 *
 * Returns an empty view if the key is absent or not a string.
 */
static pubnub_string_view_t get_str_field(pubnub_serialization_provider_t* serial,
                                          const pubnub_json_value_t* obj,
                                          const char*                key,
                                          size_t                     key_len)
{
    pubnub_string_view_t sv = {NULL, 0};

    if (NULL == serial || NULL == obj || NULL == serial->object_get
        || NULL == serial->value_as_string) {
        return sv;
    }

    const pubnub_json_value_t* node = serial->object_get(obj, key, key_len);
    if (NULL == node) {
        return sv;
    }

    size_t      len = 0;
    const char* ptr = serial->value_as_string(node, &len);
    if (NULL != ptr) {
        sv.ptr = ptr;
        sv.len = len;
    }
    return sv;
}

/**
 * @brief Helper: extract an int64 from a JSON object field.
 */
static int get_int_field(pubnub_serialization_provider_t* serial,
                         const pubnub_json_value_t*       obj,
                         const char*                      key,
                         size_t                           key_len)
{
    int val = 0;

    if (NULL == serial || NULL == obj || NULL == serial->object_get
        || NULL == serial->value_as_int) {
        return 0;
    }

    const pubnub_json_value_t* node = serial->object_get(obj, key, key_len);
    if (NULL == node) {
        return 0;
    }

    if (PUBNUB_OK != serial->value_as_int(node, &val)) {
        return 0;
    }
    return val;
}

/**
 * @brief Match a presence action string to the action enum.
 */
static pubnub_presence_action_t match_presence_action(pubnub_string_view_t sv)
{
    if (NULL == sv.ptr || 0 == sv.len) {
        return PUBNUB_PRESENCE_JOIN;
    }
    if (4 == sv.len && 0 == memcmp(sv.ptr, "join", 4)) {
        return PUBNUB_PRESENCE_JOIN;
    }
    if (5 == sv.len && 0 == memcmp(sv.ptr, "leave", 5)) {
        return PUBNUB_PRESENCE_LEAVE;
    }
    if (7 == sv.len && 0 == memcmp(sv.ptr, "timeout", 7)) {
        return PUBNUB_PRESENCE_TIMEOUT;
    }
    if (12 == sv.len && 0 == memcmp(sv.ptr, "state-change", 12)) {
        return PUBNUB_PRESENCE_STATE_CHANGE;
    }
    if (8 == sv.len && 0 == memcmp(sv.ptr, "interval", 8)) {
        return PUBNUB_PRESENCE_INTERVAL;
    }
    return PUBNUB_PRESENCE_JOIN;
}

pubnub_res_t pubnub_subscribe_event_presence(pubnub_context_t* ctx,
                                             const pubnub_subscribe_event_t* event,
                                             pubnub_subscribe_presence_event_t* out)
{
    pubnub_serialization_provider_t* serial;

    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (PUBNUB_SUBSCRIBE_PRESENCE != event->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel      = event->channel;
    out->subscription = event->subscription;
    out->timetoken    = event->timetoken;

    serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* tree = event->payload;
    if (NULL == tree) {
        return PUBNUB_OK;
    }

    pubnub_string_view_t action_sv = get_str_field(serial, tree, "action", 6);
    out->action                    = match_presence_action(action_sv);
    out->uuid                      = get_str_field(serial, tree, "uuid", 4);
    out->occupancy = (uint32_t)get_int_field(serial, tree, "occupancy", 9);

    /* State: expose the "data" sub-object as a JSON node pointer. */
    if (NULL != serial->object_get && NULL != serial->value_type) {
        const pubnub_json_value_t* data_node = serial->object_get(tree, "data", 4);
        if (NULL != data_node
            && PUBNUB_JSON_OBJECT == serial->value_type(data_node)) {
            out->state = data_node;
        }
    }

    /* Interval event: extract here_now_refresh boolean. */
    if (NULL != serial->object_get) {
        const pubnub_json_value_t* hnr_node =
            serial->object_get(tree, "here_now_refresh", 16);
        if (NULL != hnr_node && NULL != serial->value_as_bool) {
            int hnr_val = 0;
            if (PUBNUB_OK == serial->value_as_bool(hnr_node, &hnr_val)) {
                out->here_now_refresh = (uint8_t)hnr_val;
            }
        }
    }

    /* Interval event: extract join/leave/timeout arrays. */
    if (NULL != serial->object_get && NULL != serial->value_type) {
        const pubnub_json_value_t* join_node = serial->object_get(tree, "join", 4);
        if (NULL != join_node && PUBNUB_JSON_ARRAY == serial->value_type(join_node)) {
            out->joined = join_node;
        }

        const pubnub_json_value_t* leave_node =
            serial->object_get(tree, "leave", 5);
        if (NULL != leave_node
            && PUBNUB_JSON_ARRAY == serial->value_type(leave_node)) {
            out->left = leave_node;
        }

        const pubnub_json_value_t* timeout_node =
            serial->object_get(tree, "timeout", 7);
        if (NULL != timeout_node
            && PUBNUB_JSON_ARRAY == serial->value_type(timeout_node)) {
            out->timed_out = timeout_node;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t
pubnub_subscribe_event_message_action(pubnub_context_t*               ctx,
                                      const pubnub_subscribe_event_t* event,
                                      pubnub_subscribe_message_action_event_t* out)
{
    pubnub_serialization_provider_t* serial;

    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (PUBNUB_SUBSCRIBE_MESSAGE_ACTION != event->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel      = event->channel;
    out->subscription = event->subscription;
    out->publisher    = event->publisher;

    serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* tree = event->payload;
    if (NULL == tree) {
        return PUBNUB_OK;
    }

    /* Determine event type from "event" field ("added" or "removed"). */
    pubnub_string_view_t event_sv = get_str_field(serial, tree, "event", 5);
    if (7 == event_sv.len && NULL != event_sv.ptr
        && 0 == memcmp(event_sv.ptr, "removed", 7)) {
        out->event = PUBNUB_MESSAGE_ACTION_REMOVED;
    } else {
        out->event = PUBNUB_MESSAGE_ACTION_ADDED;
    }

    /* Extract "data" sub-object. */
    const pubnub_json_value_t* data_node = NULL;
    if (NULL != serial->object_get) {
        data_node = serial->object_get(tree, "data", 4);
    }
    if (NULL != data_node) {
        out->message_timetoken =
            get_str_field(serial, data_node, "messageTimetoken", 16);
        out->action_timetoken =
            get_str_field(serial, data_node, "actionTimetoken", 15);
        out->type  = get_str_field(serial, data_node, "type", 4);
        out->value = get_str_field(serial, data_node, "value", 5);
    }

    return PUBNUB_OK;
}

pubnub_res_t
pubnub_subscribe_event_app_context(pubnub_context_t*                     ctx,
                                   const pubnub_subscribe_event_t*       event,
                                   pubnub_subscribe_app_context_event_t* out)
{
    pubnub_serialization_provider_t* serial;

    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (PUBNUB_SUBSCRIBE_APP_CONTEXT != event->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel      = event->channel;
    out->subscription = event->subscription;

    serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* tree = event->payload;
    if (NULL == tree) {
        return PUBNUB_OK;
    }

    /* "event": "set" | "delete" */
    pubnub_string_view_t event_sv = get_str_field(serial, tree, "event", 5);
    if (6 == event_sv.len && NULL != event_sv.ptr
        && 0 == memcmp(event_sv.ptr, "delete", 6)) {
        out->event = PUBNUB_APP_CONTEXT_REMOVED;
    } else {
        out->event = PUBNUB_APP_CONTEXT_SET;
    }

    /* Decode object type string to enum. */
    pubnub_string_view_t type_sv = get_str_field(serial, tree, "type", 4);
    if (NULL != type_sv.ptr) {
        if (4 == type_sv.len && 0 == memcmp(type_sv.ptr, "uuid", 4)) {
            out->object_type = PUBNUB_APP_CONTEXT_OBJECT_UUID;
        } else if (7 == type_sv.len && 0 == memcmp(type_sv.ptr, "channel", 7)) {
            out->object_type = PUBNUB_APP_CONTEXT_OBJECT_CHANNEL;
        } else if (10 == type_sv.len && 0 == memcmp(type_sv.ptr, "membership", 10)) {
            out->object_type = PUBNUB_APP_CONTEXT_OBJECT_MEMBERSHIP;
        }
    }

    /* "data" field as a parsed JSON node pointer. */
    if (NULL != serial->object_get) {
        out->data = serial->object_get(tree, "data", 4);
    }

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscribe_event_file(pubnub_context_t*               ctx,
                                         const pubnub_subscribe_event_t* event,
                                         pubnub_subscribe_file_event_t*  out)
{
    pubnub_serialization_provider_t* serial;

    if (NULL == ctx || NULL == event || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (PUBNUB_SUBSCRIBE_FILE != event->type) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    out->channel      = event->channel;
    out->subscription = event->subscription;
    out->publisher    = event->publisher;
    out->timetoken    = event->timetoken;

    serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* tree = event->payload;
    if (NULL == tree) {
        return PUBNUB_OK;
    }

    /* Message: expose as a JSON node pointer. */
    if (NULL != serial->object_get) {
        out->message = serial->object_get(tree, "message", 7);
    }

    /* File info lives in a "file" sub-object. */
    const pubnub_json_value_t* file_node = NULL;
    if (NULL != serial->object_get) {
        file_node = serial->object_get(tree, "file", 4);
    }
    if (NULL != file_node) {
        out->file_id   = get_str_field(serial, file_node, "id", 2);
        out->file_name = get_str_field(serial, file_node, "name", 4);
    }

    return PUBNUB_OK;
}

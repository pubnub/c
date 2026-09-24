/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "message_actions_internal.h"

#if !PUBNUB_ENABLE_MESSAGE_ACTIONS
#error "message_actions_api.c requires PUBNUB_ENABLE_MESSAGE_ACTIONS=ON"
#endif

#include "core/core_internal.h"
#include "pubnub/client.h"
#include "pubnub/future.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief Maximum type string length enforced by the server. */
#define PN_MESSAGE_ACTIONS_TYPE_MAX_LEN 15

/** @brief Locate per-request message actions state in a ready slot. */
static pn_message_actions_state_t* ma_state_for(pn_request_t* slot)
{
    void* state =
        pn_request_feature_state_for(slot, PUBNUB_FEATURE_MESSAGE_ACTIONS);
    if (NULL == state) {
        return NULL;
    }
    return (pn_message_actions_state_t*)state;
}

/**
 * @brief Lazy-parse the add response; cache in feature state.
 */
static const pn_message_actions_action_parsed_t* get_add_parse(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }

    pn_message_actions_state_t* ms = ma_state_for(slot);
    if (NULL == ms || PN_MESSAGE_ACTIONS_OP_ADD != ms->op) {
        return NULL;
    }
    if (NULL != ms->parsed.add) {
        return ms->parsed.add;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    pubnub_json_value_t* tree = pn_request_get_parsed_body(slot, serial);
    if (NULL == tree) {
        return NULL;
    }

    pubnub_allocator_provider_t* allocator = pn_context_allocator(future.ctx);
    if (NULL == allocator) {
        return NULL;
    }

    pn_message_actions_action_parsed_t* cached =
        (pn_message_actions_action_parsed_t*)PN_ALLOC(
            allocator, sizeof(pn_message_actions_action_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_message_actions_parse_add(serial, tree, allocator, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    ms->parsed.add = cached;
    return cached;
}

/**
 * @brief Lazy-parse the get response; cache in feature state.
 */
static const pn_message_actions_get_parsed_t* get_get_parse(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }

    pn_message_actions_state_t* ms = ma_state_for(slot);
    if (NULL == ms || PN_MESSAGE_ACTIONS_OP_GET != ms->op) {
        return NULL;
    }
    if (NULL != ms->parsed.get) {
        return ms->parsed.get;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    pubnub_json_value_t* tree = pn_request_get_parsed_body(slot, serial);
    if (NULL == tree) {
        return NULL;
    }

    pubnub_allocator_provider_t* allocator = pn_context_allocator(future.ctx);
    if (NULL == allocator) {
        return NULL;
    }

    pn_message_actions_get_parsed_t* cached =
        (pn_message_actions_get_parsed_t*)PN_ALLOC(
            allocator, sizeof(pn_message_actions_get_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_message_actions_parse_get(serial, tree, allocator, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    ms->parsed.get = cached;
    return cached;
}

/**
 * @brief Build and serialize JSON body for add message action.
 *
 * Constructs {"type":"<type>","value":"<value>"} and serializes into buffer.
 */
static pubnub_res_t build_add_body(const char*                      type,
                                   const char*                      value,
                                   pubnub_serialization_provider_t* serial,
                                   pubnub_allocator_provider_t*     allocator,
                                   pubnub_buffer_t*                 out_buf,
                                   size_t*                          out_len)
{
    pubnub_json_value_t* obj = serial->value_create_object(serial);
    if (NULL == obj) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    pubnub_json_value_t* type_val =
        serial->value_create_string(serial, type, strlen(type));
    if (NULL == type_val) {
        serial->value_destroy(serial, obj);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    pubnub_res_t rc = serial->object_set(serial, obj, "type", 4, type_val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, type_val);
        serial->value_destroy(serial, obj);
        return rc;
    }

    pubnub_json_value_t* value_val =
        serial->value_create_string(serial, value, strlen(value));
    if (NULL == value_val) {
        serial->value_destroy(serial, obj);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    rc = serial->object_set(serial, obj, "value", 5, value_val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, value_val);
        serial->value_destroy(serial, obj);
        return rc;
    }

    pubnub_buffer_t body_buf = allocator->buf_acquire(allocator, PUBNUB_BUF_OBJ);
    if (NULL == body_buf.data || 0 == body_buf.cap) {
        serial->value_destroy(serial, obj);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    size_t body_len = 0;
    rc = serial->serialize(serial, obj, body_buf.data, body_buf.cap, &body_len);
    serial->value_destroy(serial, obj);
    if (PUBNUB_OK != rc) {
        allocator->buf_release(allocator, &body_buf);
        return rc;
    }

    *out_buf = body_buf;
    *out_len = body_len;
    return PUBNUB_OK;
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_add_message_action(pubnub_context_t* ctx,
                                          const pubnub_add_message_action_opts_t* opts)
{
    pn_feature_prep_t                prep;
    pn_message_actions_state_t*      state;
    pubnub_serialization_provider_t* serial;
    pubnub_buffer_t                  body_buf;
    size_t                           body_len = 0;
    pubnub_res_t                     rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->message_timetoken || '\0' == opts->message_timetoken[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->type || '\0' == opts->type[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (strlen(opts->type) > PN_MESSAGE_ACTIONS_TYPE_MAX_LEN) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->value || '\0' == opts->value[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_MESSAGE_ACTIONS,
                            sizeof(pn_message_actions_state_t),
                            pn_message_actions_state_cleanup,
                            pn_message_actions_response_validator,
                            PUBNUB_HTTP_POST,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state     = (pn_message_actions_state_t*)prep.state;
    state->op = PN_MESSAGE_ACTIONS_OP_ADD;

    serial = pn_context_serialization(ctx);
    if (NULL == serial || NULL == serial->value_create_object
        || NULL == serial->value_create_string || NULL == serial->object_set
        || NULL == serial->serialize || NULL == serial->value_destroy) {
        rc = PUBNUB_ERR_PROVIDER_MISSING;
        goto cleanup;
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* ma_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(ma_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(ma_head_, opts->message_timetoken, message_timetoken)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "add_message_action params", ma_head_);
    }
#endif

    rc = build_add_body(
        opts->type, opts->value, serial, prep.allocator, &body_buf, &body_len);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    body_buf.len          = body_len;
    state->owned_body_buf = body_buf;

    prep.entry->http_request.body     = body_buf.data;
    prep.entry->http_request.body_len = body_len;

    rc = pn_request_add_content_type_json(&prep.entry->http_request);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    {
        const pn_message_actions_add_wire_inputs_t wire_inputs = {
            .subscribe_key     = prep.cfg->subscribe_key,
            .channel           = opts->channel,
            .message_timetoken = opts->message_timetoken,
            .type              = opts->type,
            .value             = opts->value,
            .timeout_ms        = opts->timeout_ms,
        };

        rc = pn_message_actions_build_add(&prep.entry->http_request, &wire_inputs);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t pubnub_get_message_actions(pubnub_context_t* ctx,
                                           const pubnub_get_message_actions_opts_t* opts)
{
    pn_feature_prep_t           prep;
    pn_message_actions_state_t* state;
    pubnub_res_t                rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_MESSAGE_ACTIONS,
                            sizeof(pn_message_actions_state_t),
                            pn_message_actions_state_cleanup,
                            pn_message_actions_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state     = (pn_message_actions_state_t*)prep.state;
    state->op = PN_MESSAGE_ACTIONS_OP_GET;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* ma_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(ma_head_, opts->channel, channel)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "get_message_actions params", ma_head_);
    }
#endif

    {
        const pn_message_actions_get_wire_inputs_t wire_inputs = {
            .subscribe_key = prep.cfg->subscribe_key,
            .channel       = opts->channel,
            .start         = opts->start,
            .end           = opts->end,
            .limit         = opts->limit,
            .timeout_ms    = opts->timeout_ms,
        };

        rc = pn_message_actions_build_get(&prep.entry->http_request, &wire_inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_future_t
pubnub_remove_message_action(pubnub_context_t*                          ctx,
                             const pubnub_remove_message_action_opts_t* opts)
{
    pn_feature_prep_t           prep;
    pn_message_actions_state_t* state;
    pubnub_res_t                rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->message_timetoken || '\0' == opts->message_timetoken[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->action_timetoken || '\0' == opts->action_timetoken[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_MESSAGE_ACTIONS,
                            sizeof(pn_message_actions_state_t),
                            pn_message_actions_state_cleanup,
                            pn_message_actions_response_validator,
                            PUBNUB_HTTP_DELETE,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state     = (pn_message_actions_state_t*)prep.state;
    state->op = PN_MESSAGE_ACTIONS_OP_REMOVE;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* ma_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(ma_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(ma_head_, opts->message_timetoken, message_timetoken)
        PUBNUB_LOG_MAP_SET_STRING(ma_head_, opts->action_timetoken, action_timetoken)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "remove_message_action params", ma_head_);
    }
#endif

    {
        const pn_message_actions_remove_wire_inputs_t wire_inputs = {
            .subscribe_key     = prep.cfg->subscribe_key,
            .channel           = opts->channel,
            .message_timetoken = opts->message_timetoken,
            .action_timetoken  = opts->action_timetoken,
            .timeout_ms        = opts->timeout_ms,
        };

        rc = pn_message_actions_build_remove(&prep.entry->http_request,
                                             &wire_inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_add_message_action_result_t
pubnub_add_message_action_result(const pubnub_future_t future)
{
    pubnub_add_message_action_result_t result;
    memset(&result, 0, sizeof(result));

    const pn_message_actions_action_parsed_t* cached = get_add_parse(future);
    if (NULL == cached) {
        return result;
    }

    result.action.type              = cached->type;
    result.action.value             = cached->value;
    result.action.uuid              = cached->uuid;
    result.action.action_timetoken  = cached->action_timetoken;
    result.action.message_timetoken = cached->message_timetoken;
    return result;
}

pubnub_get_message_actions_result_t
pubnub_get_message_actions_result(const pubnub_future_t future)
{
    pubnub_get_message_actions_result_t result;
    memset(&result, 0, sizeof(result));

    const pn_message_actions_get_parsed_t* cached = get_get_parse(future);
    if (NULL == cached) {
        return result;
    }

    result.count      = (uint32_t)cached->count;
    result.has_more   = cached->has_more;
    result.more_start = cached->more_start;
    result.more_end   = cached->more_end;
    result.more_limit = cached->more_limit;
    return result;
}

pubnub_message_action_t
pubnub_get_message_actions_result_action_at(const pubnub_future_t future,
                                            const size_t          index)
{
    pubnub_message_action_t result;
    memset(&result, 0, sizeof(result));

    const pn_message_actions_get_parsed_t* cached = get_get_parse(future);
    if (NULL == cached || index >= cached->count) {
        return result;
    }

    const pn_message_actions_action_parsed_t* a = &cached->actions[index];
    result.type                                 = a->type;
    result.value                                = a->value;
    result.uuid                                 = a->uuid;
    result.action_timetoken                     = a->action_timetoken;
    result.message_timetoken                    = a->message_timetoken;
    return result;
}

void pn_message_actions_state_cleanup(void*                        state,
                                      pubnub_allocator_provider_t* allocator)
{
    if (NULL == state || NULL == allocator) {
        return;
    }

    pn_message_actions_state_t* s = (pn_message_actions_state_t*)state;

    /* Release body buffer if one was acquired (add op). */
    if (0 != s->owned_body_buf.cap && NULL != allocator->buf_release) {
        allocator->buf_release(allocator, &s->owned_body_buf);
    }

    switch (s->op) {
    case PN_MESSAGE_ACTIONS_OP_ADD:
        if (NULL != s->parsed.add && NULL != allocator->free) {
            PN_FREE(allocator, s->parsed.add);
        }
        break;
    case PN_MESSAGE_ACTIONS_OP_GET:
        if (NULL != s->parsed.get) {
            if (NULL != s->parsed.get->actions && NULL != allocator->free) {
                PN_FREE(allocator, s->parsed.get->actions);
            }
            if (NULL != allocator->free) {
                PN_FREE(allocator, s->parsed.get);
            }
        }
        break;
    case PN_MESSAGE_ACTIONS_OP_REMOVE:
        /* Remove has no parsed state. */
        break;
    }

    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}

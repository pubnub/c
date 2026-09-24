/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "presence_api_internal.h"
#include "presence_api.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_api.c requires PUBNUB_ENABLE_PRESENCE=ON - this translation unit has no meaning without the presence feature. Check the CMake feature gating in src/features/CMakeLists.txt; the file must not appear in the build when the flag is off."
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_buf_serialize.h"
#include "core/protocol_common/pn_url_encode.h"
#include "presence_effects.h"
#include "presence_manager.h"
#include "pubnub/client.h"
#include "pubnub/future.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief Locate the presence feature state inside a ready slot. */
static pn_presence_api_state_t* presence_state_for(pn_request_t* slot)
{
    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_PRESENCE);
    if (NULL == state) {
        return NULL;
    }
    return (pn_presence_api_state_t*)state;
}

/**
 * @brief Lazy-parse the here-now response body once; cache in feature state.
 */
static const pn_presence_here_now_parsed_t* get_here_now_parse(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }

    pn_presence_api_state_t* ps = presence_state_for(slot);
    if (NULL == ps || PN_PRESENCE_OP_HERE_NOW != ps->op) {
        return NULL;
    }
    if (NULL != ps->parsed.here_now) {
        return ps->parsed.here_now;
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

    pn_presence_here_now_parsed_t* cached = (pn_presence_here_now_parsed_t*)PN_ALLOC(
        allocator, sizeof(pn_presence_here_now_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_presence_parse_here_now(serial, tree, allocator, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    ps->parsed.here_now = cached;
    return cached;
}

/**
 * @brief Lazy-parse the where-now response body once; cache in feature state.
 */
static const pn_presence_where_now_parsed_t* get_where_now_parse(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }

    pn_presence_api_state_t* ps = presence_state_for(slot);
    if (NULL == ps || PN_PRESENCE_OP_WHERE_NOW != ps->op) {
        return NULL;
    }
    if (NULL != ps->parsed.where_now) {
        return ps->parsed.where_now;
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

    pn_presence_where_now_parsed_t* cached =
        (pn_presence_where_now_parsed_t*)PN_ALLOC(
            allocator, sizeof(pn_presence_where_now_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_presence_parse_where_now(serial, tree, allocator, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    ps->parsed.where_now = cached;
    return cached;
}

/**
 * @brief Lazy-parse a state response (set-state or get-state); cache result.
 */
static const pn_presence_state_parsed_t* get_state_parse(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }

    pn_presence_api_state_t* ps = presence_state_for(slot);
    if (NULL == ps) {
        return NULL;
    }
    if (PN_PRESENCE_OP_SET_STATE != ps->op && PN_PRESENCE_OP_GET_STATE != ps->op) {
        return NULL;
    }
    if (NULL != ps->parsed.state) {
        return ps->parsed.state;
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

    pn_presence_state_parsed_t* cached = (pn_presence_state_parsed_t*)PN_ALLOC(
        allocator, sizeof(pn_presence_state_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_presence_parse_state(
        serial, tree, allocator, cached, ps->single_channel);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    /* Single-channel responses lack the channel key in the envelope;
     * inject the channel name from dispatch-time state. */
    if (ps->single_channel && cached->entry_count > 0 && NULL != ps->channel_name) {
        cached->entries[0].channel =
            (pubnub_string_view_t){ps->channel_name, ps->channel_name_len};
    }

    ps->parsed.state = cached;
    return cached;
}

/**
 * @brief Lazy-allocate the presence manager for a context.
 *
 * If the manager is not yet created, allocates it and registers it
 * in the feature registry with the cleanup and tick callbacks.
 * Returns the manager on success, NULL on allocation failure.
 */
static pn_presence_manager_t* pn_ensure_presence_manager(pubnub_context_t* ctx)
{
    pn_presence_manager_t* mgr = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    if (NULL != mgr) {
        return mgr;
    }

    const pubnub_config_t* config = pn_context_config(ctx);
    if (NULL == config || NULL == config->allocator) {
        return NULL;
    }

    mgr = pn_presence_manager_create(ctx, config->allocator);
    if (NULL == mgr) {
        return NULL;
    }

    pn_context_set_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE, mgr, pn_presence_manager_cleanup);
    pn_context_set_feature_tick(
        ctx, PUBNUB_FEATURE_PRESENCE, pn_presence_feature_tick);

    return mgr;
}

void pn_presence_api_joined(pubnub_context_t* ctx,
                            const char*       channels,
                            const char*       groups)
{
    if (NULL == ctx) {
        return;
    }

    pn_presence_manager_t* mgr = pn_ensure_presence_manager(ctx);
    if (NULL == mgr) {
        return;
    }

    pn_presence_joined(mgr, channels, groups);
}

void pn_presence_api_left(pubnub_context_t* ctx,
                          const char*       remaining_channels,
                          const char*       remaining_groups,
                          const char*       removed_channels,
                          const char*       removed_groups,
                          uint8_t           subscriptions_empty)
{
    if (NULL == ctx) {
        return;
    }

    pn_presence_manager_t* mgr = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    if (NULL == mgr) {
        return;
    }

    if (subscriptions_empty) {
        pn_presence_left_all(mgr);
    } else {
        pn_presence_left(mgr,
                         remaining_channels,
                         remaining_groups,
                         removed_channels,
                         removed_groups,
                         subscriptions_empty);
    }
}

void pn_presence_api_left_all(pubnub_context_t* ctx)
{
    if (NULL == ctx) {
        return;
    }

    pn_presence_manager_t* mgr = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    if (NULL == mgr) {
        return;
    }

    pn_presence_left_all(mgr);
}

void pn_presence_api_disconnect(pubnub_context_t* ctx)
{
    if (NULL == ctx) {
        return;
    }

    pn_presence_manager_t* mgr = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    if (NULL == mgr) {
        return;
    }

    pn_presence_disconnect(mgr);
}

void pn_presence_api_reconnect(pubnub_context_t* ctx)
{
    if (NULL == ctx) {
        return;
    }

    pn_presence_manager_t* mgr = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    if (NULL == mgr) {
        return;
    }

    pn_presence_reconnect(mgr);
}

pubnub_future_t pubnub_here_now(pubnub_context_t*             ctx,
                                const pubnub_here_now_opts_t* opts)
{
    pn_feature_prep_t        prep;
    pn_presence_api_state_t* state;
    pubnub_res_t             rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if ((NULL == opts->channels || '\0' == opts->channels[0])
        && (NULL == opts->channel_groups || '\0' == opts->channel_groups[0])) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PRESENCE,
                            sizeof(pn_presence_api_state_t),
                            pn_presence_api_state_cleanup,
                            pn_presence_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state     = (pn_presence_api_state_t*)prep.state;
    state->op = PN_PRESENCE_OP_HERE_NOW;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* pres_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, opts->channels, channels)
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, opts->channel_groups, channel_groups)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "here_now params", pres_head_);
    }
#endif

    {
        const pn_presence_here_now_wire_inputs_t wire_inputs = {
            .subscribe_key  = prep.cfg->subscribe_key,
            .channels       = opts->channels,
            .channel_groups = opts->channel_groups,
            .include_uuids  = opts->include_uuids,
            .include_state  = opts->include_state,
            .limit          = opts->limit,
            .offset         = opts->offset,
            .timeout_ms     = opts->timeout_ms,
        };

        rc = pn_presence_build_here_now(&prep.entry->http_request, &wire_inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_future_t pubnub_where_now(pubnub_context_t*              ctx,
                                 const pubnub_where_now_opts_t* opts)
{
    pn_feature_prep_t        prep;
    pn_presence_api_state_t* state;
    const char*              uuid;
    pubnub_res_t             rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PRESENCE,
                            sizeof(pn_presence_api_state_t),
                            pn_presence_api_state_cleanup,
                            pn_presence_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state     = (pn_presence_api_state_t*)prep.state;
    state->op = PN_PRESENCE_OP_WHERE_NOW;

    /* pn_feature_prepare guarantees user_id is non-NULL. */
    uuid = (NULL != opts->uuid) ? opts->uuid : pn_context_user_id(ctx);

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* pres_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, uuid, user_id)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "where_now params", pres_head_);
    }
#endif

    {
        const pn_presence_where_now_wire_inputs_t wire_inputs = {
            .subscribe_key = prep.cfg->subscribe_key,
            .uuid          = uuid,
            .timeout_ms    = opts->timeout_ms,
        };

        rc = pn_presence_build_where_now(&prep.entry->http_request, &wire_inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_set_state(pubnub_context_t*              ctx,
                                 const pubnub_set_state_opts_t* opts)
{
    pn_feature_prep_t                prep;
    pn_presence_api_state_t*         state;
    const char*                      user_id;
    int                              has_channels;
    int                              has_groups;
    const char*                      state_str;
    size_t                           state_len     = 0;
    pubnub_buffer_t                  state_buf     = {0};
    char*                            encoded_state = NULL;
    pubnub_serialization_provider_t* serial;
    pubnub_res_t                     rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* Exactly one of state or state_value must be set. */
    if ((NULL == opts->state && NULL == opts->state_value)
        || (NULL != opts->state && NULL != opts->state_value)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* At least one target is required. */
    has_channels = (NULL != opts->channels && '\0' != opts->channels[0]);
    has_groups = (NULL != opts->channel_groups && '\0' != opts->channel_groups[0]);
    if (!has_channels && !has_groups) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PRESENCE,
                            sizeof(pn_presence_api_state_t),
                            pn_presence_api_state_cleanup,
                            pn_presence_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state                 = (pn_presence_api_state_t*)prep.state;
    state->op             = PN_PRESENCE_OP_SET_STATE;
    state->single_channel = 1;

    /* pn_feature_prepare guarantees user_id is non-NULL. */
    user_id = pn_context_user_id(ctx);

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* pres_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, opts->channels, channels)
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, opts->channel_groups, channel_groups)
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, user_id, user_id)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "set_state params", pres_head_);
    }
#endif

    /* Resolve state to a JSON string. For state_value, serialize via
     * buf_acquire (short-lived per-request memory). State can be large
     * (up to 32KB per PubNub docs). */
    state_str = opts->state;

    if (NULL != opts->state_value) {
        serial = pn_context_serialization(ctx);
        if (NULL == serial || NULL == serial->serialize) {
            rc = PUBNUB_ERR_PROVIDER_MISSING;
            goto cleanup;
        }
        state_buf = prep.allocator->buf_acquire(prep.allocator, PUBNUB_BUF_OBJ);
        if (NULL == state_buf.data || 0 == state_buf.cap) {
            rc = PUBNUB_ERR_OUT_OF_MEMORY;
            goto cleanup;
        }
        rc = pn_buf_serialize_grow(
            prep.allocator, serial, opts->state_value, &state_buf);
        if (PUBNUB_OK != rc) {
            prep.allocator->buf_release(prep.allocator, &state_buf);
            state_buf.data = NULL;
            goto cleanup;
        }
        state_str = (const char*)state_buf.data;
        state_len = state_buf.len;
    } else {
        state_len = (0 == opts->state_len) ? strlen(opts->state) : opts->state_len;
    }

    /* Percent-encode the state value via heap allocation (state can be
     * large — scratch buffer is insufficient for real-world payloads). */
    encoded_state = pn_url_encode_alloc_n(
        (const uint8_t*)state_str, state_len, prep.allocator, PN_ENCODE_FULL);

    if (NULL != state_buf.data) {
        prep.allocator->buf_release(prep.allocator, &state_buf);
        state_buf.data = NULL;
    }

    if (NULL == encoded_state) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    state->encoded_state = encoded_state;

    if (has_channels) {
        size_t ch_len  = strlen(opts->channels);
        char*  ch_copy = (char*)PN_ALLOC(prep.allocator, ch_len + 1, 0);
        if (NULL != ch_copy) {
            memcpy(ch_copy, opts->channels, ch_len + 1);
            state->channel_name     = ch_copy;
            state->channel_name_len = ch_len;
        }
    }

    {
        const pn_presence_set_state_wire_inputs_t wire_inputs = {
            .subscribe_key  = prep.cfg->subscribe_key,
            .channels       = has_channels ? opts->channels : ",",
            .channel_groups = opts->channel_groups,
            .uuid           = user_id,
            .state          = encoded_state,
            .state_len      = strlen(encoded_state),
            .timeout_ms     = opts->timeout_ms,
        };

        rc = pn_presence_build_set_state(&prep.entry->http_request, &wire_inputs);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    if (NULL != state_buf.data) {
        prep.allocator->buf_release(prep.allocator, &state_buf);
    }
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t pubnub_get_state(pubnub_context_t*              ctx,
                                 const pubnub_get_state_opts_t* opts)
{
    pn_feature_prep_t        prep;
    pn_presence_api_state_t* state;
    const char*              uuid;
    int                      has_channels;
    int                      has_groups;
    uint8_t                  single_channel;
    pubnub_res_t             rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* At least one target is required. */
    has_channels = (NULL != opts->channels && '\0' != opts->channels[0]);
    has_groups = (NULL != opts->channel_groups && '\0' != opts->channel_groups[0]);
    if (!has_channels && !has_groups) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PRESENCE,
                            sizeof(pn_presence_api_state_t),
                            pn_presence_api_state_cleanup,
                            pn_presence_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state     = (pn_presence_api_state_t*)prep.state;
    state->op = PN_PRESENCE_OP_GET_STATE;

    /* pn_feature_prepare guarantees user_id is non-NULL. */
    uuid = (NULL != opts->uuid) ? opts->uuid : pn_context_user_id(ctx);

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* pres_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, opts->channels, channels)
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, opts->channel_groups, channel_groups)
        PUBNUB_LOG_MAP_SET_STRING(pres_head_, uuid, user_id)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "get_state params", pres_head_);
    }
#endif

    /* Single-channel detection: exactly one channel name with no comma,
     * and no channel groups specified. */
    single_channel =
        (has_channels && NULL == strchr(opts->channels, ',') && !has_groups) ? 1
                                                                             : 0;
    state->single_channel = single_channel;

    if (single_channel) {
        const size_t ch_len  = strlen(opts->channels);
        char*        ch_copy = (char*)PN_ALLOC(prep.allocator, ch_len + 1, 0);
        if (NULL != ch_copy) {
            memcpy(ch_copy, opts->channels, ch_len + 1);
            state->channel_name     = ch_copy;
            state->channel_name_len = ch_len;
        }
    }

    {
        const pn_presence_get_state_wire_inputs_t wire_inputs = {
            .subscribe_key  = prep.cfg->subscribe_key,
            .channels       = has_channels ? opts->channels : ",",
            .channel_groups = opts->channel_groups,
            .uuid           = uuid,
            .timeout_ms     = opts->timeout_ms,
        };

        rc = pn_presence_build_get_state(&prep.entry->http_request, &wire_inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_here_now_result_t pubnub_here_now_result(const pubnub_future_t future)
{
    pubnub_here_now_result_t             result = {0};
    const pn_presence_here_now_parsed_t* p      = get_here_now_parse(future);
    if (NULL == p) {
        return result;
    }
    result.total_occupancy = p->total_occupancy;
    result.total_channels  = p->total_channels;
    result.channel_count   = (uint32_t)p->channel_count;
    return result;
}

pubnub_here_now_channel_result_t
pubnub_here_now_result_channel_at(const pubnub_future_t future, const size_t index)
{
    pubnub_here_now_channel_result_t     result = {0};
    const pn_presence_here_now_parsed_t* p      = get_here_now_parse(future);
    if (NULL == p || index >= p->channel_count) {
        return result;
    }
    result.name           = p->channels[index].name;
    result.occupancy      = p->channels[index].occupancy;
    result.occupant_count = (uint32_t)p->channels[index].occupant_count;
    return result;
}

pubnub_here_now_occupant_result_t
pubnub_here_now_result_occupant_at(const pubnub_future_t future,
                                   const size_t          ch_index,
                                   const size_t          occ_index)
{
    pubnub_here_now_occupant_result_t    result = {0};
    const pn_presence_here_now_parsed_t* p      = get_here_now_parse(future);
    if (NULL == p || ch_index >= p->channel_count) {
        return result;
    }
    const pn_presence_here_now_channel_t* ch = &p->channels[ch_index];
    if (occ_index >= ch->occupant_count || NULL == ch->occupants) {
        return result;
    }
    result.uuid  = ch->occupants[occ_index].uuid;
    result.state = ch->occupants[occ_index].state;
    return result;
}

pubnub_where_now_result_t pubnub_where_now_result(const pubnub_future_t future)
{
    pubnub_where_now_result_t             result = {0};
    const pn_presence_where_now_parsed_t* p      = get_where_now_parse(future);
    if (NULL == p) {
        return result;
    }
    result.channel_count = (uint32_t)p->channel_count;
    return result;
}

pubnub_string_view_t pubnub_where_now_result_channel_at(const pubnub_future_t future,
                                                        const size_t index)
{
    const pn_presence_where_now_parsed_t* p = get_where_now_parse(future);
    if (NULL == p || index >= p->channel_count) {
        return (pubnub_string_view_t){NULL, 0};
    }
    return p->channels[index];
}

pubnub_set_state_result_t pubnub_set_state_result(const pubnub_future_t future)
{
    pubnub_set_state_result_t         result = {0};
    const pn_presence_state_parsed_t* p      = get_state_parse(future);
    if (NULL == p || 0 == p->entry_count) {
        return result;
    }
    result.state = p->entries[0].state;
    return result;
}

pubnub_get_state_result_t pubnub_get_state_result(const pubnub_future_t future)
{
    pubnub_get_state_result_t         result = {0};
    const pn_presence_state_parsed_t* p      = get_state_parse(future);
    if (NULL == p) {
        return result;
    }
    result.channel_count = (uint32_t)p->entry_count;
    return result;
}

pubnub_get_state_channel_result_t
pubnub_get_state_result_channel_at(const pubnub_future_t future, const size_t index)
{
    pubnub_get_state_channel_result_t result = {0};
    const pn_presence_state_parsed_t* p      = get_state_parse(future);
    if (NULL == p || index >= p->entry_count) {
        return result;
    }
    result.channel = p->entries[index].channel;
    result.state   = p->entries[index].state;
    return result;
}

static void cleanup_here_now(pn_presence_here_now_parsed_t* hn,
                             pubnub_allocator_provider_t*   alloc)
{
    if (NULL == hn) {
        return;
    }
    if (NULL != hn->channels && NULL != alloc->free) {
        size_t i;
        for (i = 0; i < hn->channel_count; ++i) {
            size_t j;
            if (NULL == hn->channels[i].occupants) {
                continue;
            }
            for (j = 0; j < hn->channels[i].occupant_count; ++j) {
                if (NULL != hn->channels[i].occupants[j].state.ptr) {
                    PN_FREE(alloc, (void*)hn->channels[i].occupants[j].state.ptr);
                }
            }
            PN_FREE(alloc, hn->channels[i].occupants);
        }
        PN_FREE(alloc, hn->channels);
    }
    if (NULL != alloc->free) {
        PN_FREE(alloc, hn);
    }
}

static void cleanup_state_parsed(pn_presence_state_parsed_t*  sp,
                                 pubnub_allocator_provider_t* alloc)
{
    if (NULL == sp) {
        return;
    }
    if (NULL != sp->entries && NULL != alloc->free) {
        /* State pointers are borrowed from the parsed tree — no free
         * needed. Only the entries array itself is allocator-owned. */
        PN_FREE(alloc, sp->entries);
    }
    if (NULL != alloc->free) {
        PN_FREE(alloc, sp);
    }
}

void pn_presence_api_state_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    if (NULL == state || NULL == alloc) {
        return;
    }

    pn_presence_api_state_t* s = (pn_presence_api_state_t*)state;

    switch (s->op) {
    case PN_PRESENCE_OP_HERE_NOW:
        cleanup_here_now(s->parsed.here_now, alloc);
        break;

    case PN_PRESENCE_OP_WHERE_NOW:
        if (NULL != s->parsed.where_now) {
            pn_presence_where_now_parsed_t* wn = s->parsed.where_now;
            if (NULL != wn->channels && NULL != alloc->free) {
                PN_FREE(alloc, wn->channels);
            }
            if (NULL != alloc->free) {
                PN_FREE(alloc, wn);
            }
        }
        break;

    case PN_PRESENCE_OP_SET_STATE: /* FALLTHROUGH */
    case PN_PRESENCE_OP_GET_STATE:
        if (NULL != s->channel_name && NULL != alloc->free) {
            PN_FREE(alloc, (void*)s->channel_name);
        }
        if (NULL != s->encoded_state && NULL != alloc->free) {
            PN_FREE(alloc, s->encoded_state);
        }
        cleanup_state_parsed(s->parsed.state, alloc);
        break;
    }

    if (NULL != alloc->free) {
        PN_FREE(alloc, s);
    }
}

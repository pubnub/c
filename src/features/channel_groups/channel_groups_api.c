/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "channel_groups_internal.h"

#if !PUBNUB_ENABLE_CHANNEL_GROUPS
#error "channel_groups_api.c requires PUBNUB_ENABLE_CHANNEL_GROUPS=ON"
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/client.h"
#include "pubnub/future.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief Adapter: match pn_parse_response_fn_t for channel groups. */
static pubnub_res_t channel_groups_parse_adapter(pubnub_serialization_provider_t* serial,
                                                 pubnub_json_value_t* tree,
                                                 void*                out)
{
    return pn_channel_groups_parse_list_response(
        serial, tree, (pn_channel_groups_parsed_t*)out);
}

/**
 * @brief Lazy-parse the slot's response body once and cache the
 *        list-channels decomposition.
 */
static const pn_channel_groups_parsed_t*
get_cached_parse(pn_request_t*                slot,
                 const pubnub_future_t        future,
                 pn_channel_groups_parsed_t** parsed_slot)
{
    pubnub_json_value_t*        tree = NULL;
    pn_channel_groups_parsed_t* mutable_result =
        (pn_channel_groups_parsed_t*)pn_resolve_cached_parse(
            slot,
            future,
            (void**)parsed_slot,
            sizeof(pn_channel_groups_parsed_t),
            1,
            channel_groups_parse_adapter,
            &tree);

    if (NULL != mutable_result && NULL != tree) {
        mutable_result->tree = tree;
    }
    return mutable_result;
}

/**
 * @brief Locate the cached-parse slot for a channel-groups future.
 */
static pn_channel_groups_parsed_t** parsed_slot_for(pn_request_t* slot)
{
    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_CHANNEL_GROUPS);
    if (NULL == state) {
        return NULL;
    }

    pn_channel_groups_state_t* s = (pn_channel_groups_state_t*)state;
    return &s->parsed;
}

/**
 * @brief Common dispatch path for add/remove/list/remove-group operations.
 *
 * Validates common prerequisites, allocates feature state, builds the
 * HTTP request path and dispatches via @ref pn_dispatch_or_enqueue.
 *
 * @param ctx           Client context (may be NULL for validation).
 * @param channel_group Required group name.
 * @param channels      Comma-separated channel string (NULL for list/remove-group).
 * @param param_key     "add" or "remove" (NULL for list/remove-group).
 * @param remove_group  Non-zero to append "/remove" path segment.
 * @param timeout_ms    Per-request timeout override (0 = context default).
 * @return Future handle.
 */
/* NOLINTNEXTLINE(readability-function-size) */
static pubnub_future_t channel_groups_dispatch(pubnub_context_t* ctx,
                                               const char*       channel_group,
                                               const char*       channels,
                                               const char*       param_key,
                                               int               remove_group,
                                               uint32_t          timeout_ms)
{
    pn_feature_prep_t          prep;
    pn_channel_groups_state_t* state;
    pubnub_res_t               rc;

    if (NULL == channel_group || '\0' == channel_group[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* add/remove operations require a non-empty channel string. */
    if (NULL != param_key && (NULL == channels || '\0' == channels[0])) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_CHANNEL_GROUPS,
                            sizeof(pn_channel_groups_state_t),
                            pn_channel_groups_feature_state_cleanup,
                            pn_channel_groups_response_validator,
                            PUBNUB_HTTP_GET,
                            timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_channel_groups_state_t*)prep.state;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* cg_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(cg_head_, channel_group, channel_group)
        PUBNUB_LOG_MAP_SET_STRING(cg_head_, channels, channels)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "channel_groups params", cg_head_);
    }
#endif

    /* Build path segments (group name encoded into scratch buffer). */
    rc = pn_channel_groups_build_path(&prep.entry->http_request,
                                      prep.cfg->subscribe_key,
                                      channel_group,
                                      remove_group);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    /* Append channel list query param if applicable. Pre-encode via
     * dynamic allocation to avoid scratch buffer overflow with large
     * channel lists. */
    if (NULL != param_key) {
        char* encoded = pn_url_encode_alloc_n((const uint8_t*)channels,
                                              strlen(channels),
                                              prep.allocator,
                                              PN_ENCODE_KEEP_COMMAS);
        if (NULL == encoded) {
            rc = PUBNUB_ERR_OUT_OF_MEMORY;
            goto cleanup;
        }
        state->encoded_channels = encoded;
        rc                      = pn_request_add_query_param_view(
            &prep.entry->http_request,
            param_key,
            (pubnub_string_view_t){encoded, strlen(encoded)});
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

pubnub_future_t
pubnub_channel_group_add_channels(pubnub_context_t*                      ctx,
                                  const pubnub_channel_group_add_opts_t* opts)
{
    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    return channel_groups_dispatch(
        ctx, opts->channel_group, opts->channels, "add", 0, opts->timeout_ms);
}

pubnub_future_t pubnub_channel_group_remove_channels(
    pubnub_context_t*                         ctx,
    const pubnub_channel_group_remove_opts_t* opts)
{
    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    return channel_groups_dispatch(
        ctx, opts->channel_group, opts->channels, "remove", 0, opts->timeout_ms);
}

pubnub_future_t
pubnub_channel_group_list_channels(pubnub_context_t*                       ctx,
                                   const pubnub_channel_group_list_opts_t* opts)
{
    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    return channel_groups_dispatch(
        ctx, opts->channel_group, NULL, NULL, 0, opts->timeout_ms);
}

pubnub_future_t
pubnub_channel_group_remove(pubnub_context_t* ctx,
                            const pubnub_channel_group_remove_group_opts_t* opts)
{
    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    return channel_groups_dispatch(
        ctx, opts->channel_group, NULL, NULL, 1, opts->timeout_ms);
}

pubnub_channel_group_list_result_t
pubnub_channel_group_list_result(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return (pubnub_channel_group_list_result_t){0};
    }
    pn_channel_groups_parsed_t** ps = parsed_slot_for(slot);
    if (NULL == ps) {
        return (pubnub_channel_group_list_result_t){0};
    }
    const pn_channel_groups_parsed_t* cached = get_cached_parse(slot, future, ps);
    if (NULL == cached) {
        return (pubnub_channel_group_list_result_t){0};
    }
    return (pubnub_channel_group_list_result_t){.count = cached->count};
}

pubnub_string_view_t
pubnub_channel_group_list_result_channel_at(const pubnub_future_t future, size_t index)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return (pubnub_string_view_t){NULL, 0};
    }
    pn_channel_groups_parsed_t** ps = parsed_slot_for(slot);
    if (NULL == ps) {
        return (pubnub_string_view_t){NULL, 0};
    }
    const pn_channel_groups_parsed_t* cached = get_cached_parse(slot, future, ps);
    pn_channel_groups_parsed_t* mut = (pn_channel_groups_parsed_t*)cached;
    if (NULL == cached || NULL == cached->channels_array) {
        return (pubnub_string_view_t){NULL, 0};
    }
    if (index >= cached->count) {
        return (pubnub_string_view_t){NULL, 0};
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    if (NULL == serial || NULL == serial->array_get
        || NULL == serial->value_as_string) {
        return (pubnub_string_view_t){NULL, 0};
    }

    const pubnub_json_value_t* ch_node =
        pn_json_array_cursor_get(serial,
                                 cached->channels_array,
                                 index,
                                 &mut->iter_cache,
                                 &mut->iter_pos,
                                 &mut->iter_valid);
    if (NULL == ch_node) {
        return (pubnub_string_view_t){NULL, 0};
    }

    size_t      len = 0;
    const char* ptr = serial->value_as_string(ch_node, &len);
    if (NULL == ptr) {
        return (pubnub_string_view_t){NULL, 0};
    }
    return (pubnub_string_view_t){ptr, len};
}

void pn_channel_groups_feature_state_cleanup(void* state,
                                             pubnub_allocator_provider_t* allocator)
{
    if (NULL == state || NULL == allocator) {
        return;
    }

    pn_channel_groups_state_t* s = (pn_channel_groups_state_t*)state;

    if (NULL != s->encoded_channels && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_channels);
        s->encoded_channels = NULL;
    }

    if (NULL != s->parsed) {
        /* The tree is owned by the request slot's parsed_body cache;
         * we do NOT destroy it here. Only free the parsed wrapper. */
        if (NULL != allocator->free) {
            PN_FREE(allocator, s->parsed);
        }
        s->parsed = NULL;
    }

    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}

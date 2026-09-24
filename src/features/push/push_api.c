/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "push_internal.h"

#if !PUBNUB_ENABLE_PUSH_NOTIFICATIONS
#error "push_api.c requires PUBNUB_ENABLE_PUSH_NOTIFICATIONS=ON"
#endif

#include "core/core_internal.h"
#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"
#include "core/protocol_common/pn_url_encode.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Locate the cached-parse slot for a push list-channels future.
 */
static pn_push_list_parsed_t** parsed_slot_for(pn_request_t* slot)
{
    void* state =
        pn_request_feature_state_for(slot, PUBNUB_FEATURE_PUSH_NOTIFICATIONS);
    if (NULL == state) {
        return NULL;
    }
    pn_push_state_t* s = (pn_push_state_t*)state;
    return &s->parsed;
}

/** @brief Adapter: match pn_parse_response_fn_t signature for push. */
static pubnub_res_t push_parse_adapter(pubnub_serialization_provider_t* serial,
                                       pubnub_json_value_t*             tree,
                                       void*                            out)
{
    return pn_push_list_parse_response(serial, tree, (pn_push_list_parsed_t*)out);
}

/**
 * @brief Lazy-parse the list-channels response and cache.
 */
static const pn_push_list_parsed_t* get_cached_parse(pn_request_t* slot,
                                                     const pubnub_future_t future,
                                                     pn_push_list_parsed_t** parsed_slot)
{
    return (const pn_push_list_parsed_t*)pn_resolve_cached_parse(
        slot,
        future,
        (void**)parsed_slot,
        sizeof(pn_push_list_parsed_t),
        1,
        push_parse_adapter,
        NULL);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_push_add_channels(pubnub_context_t* ctx,
                                         const pubnub_push_add_channels_opts_t* opts)
{
    pn_feature_prep_t     prep;
    pn_push_state_t*      state;
    char*                 encoded;
    pn_push_path_inputs_t path_in;
    pubnub_res_t          rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->device || '\0' == opts->device[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channels || '\0' == opts->channels[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (PUBNUB_PUSH_APNS2 == opts->gateway && NULL == opts->topic) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PUSH_NOTIFICATIONS,
                            sizeof(pn_push_state_t),
                            pn_push_feature_state_cleanup,
                            pn_push_mutation_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_push_state_t*)prep.state;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* push_log = NULL;
        PUBNUB_LOG_MAP_SET_STRING(push_log, opts->device, device_id)
        PUBNUB_LOG_MAP_SET_NUMBER(push_log, (int64_t)opts->gateway, push_type)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "push_add_channels params", push_log);
    }
#endif

    encoded = pn_url_encode_alloc_n((const uint8_t*)opts->channels,
                                    strlen(opts->channels),
                                    prep.allocator,
                                    PN_ENCODE_KEEP_COMMAS);
    if (NULL == encoded) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    state->encoded_channels = encoded;

    path_in.subscribe_key = prep.cfg->subscribe_key;
    path_in.device        = opts->device;
    path_in.gateway       = opts->gateway;
    path_in.append_remove = 0;

    rc = pn_push_build_path(&prep.entry->http_request, &path_in);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_push_add_gateway_params(
        &prep.entry->http_request, opts->gateway, opts->environment, opts->topic);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_push_add_channels_param(&prep.entry->http_request, encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_push_remove_channels(pubnub_context_t* ctx,
                                            const pubnub_push_remove_channels_opts_t* opts)
{
    pn_feature_prep_t prep;
    pn_push_state_t*  state;
    char*             encoded;

    pn_push_path_inputs_t path_in;
    pubnub_res_t          rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->device || '\0' == opts->device[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channels || '\0' == opts->channels[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (PUBNUB_PUSH_APNS2 == opts->gateway && NULL == opts->topic) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PUSH_NOTIFICATIONS,
                            sizeof(pn_push_state_t),
                            pn_push_feature_state_cleanup,
                            pn_push_mutation_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_push_state_t*)prep.state;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* push_log = NULL;
        PUBNUB_LOG_MAP_SET_STRING(push_log, opts->device, device_id)
        PUBNUB_LOG_MAP_SET_NUMBER(push_log, (int64_t)opts->gateway, push_type)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "push_remove_channels params", push_log);
    }
#endif

    encoded = pn_url_encode_alloc_n((const uint8_t*)opts->channels,
                                    strlen(opts->channels),
                                    prep.allocator,
                                    PN_ENCODE_KEEP_COMMAS);
    if (NULL == encoded) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    state->encoded_channels = encoded;

    path_in.subscribe_key = prep.cfg->subscribe_key;
    path_in.device        = opts->device;
    path_in.gateway       = opts->gateway;
    path_in.append_remove = 0;

    rc = pn_push_build_path(&prep.entry->http_request, &path_in);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_push_add_gateway_params(
        &prep.entry->http_request, opts->gateway, opts->environment, opts->topic);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_push_remove_channels_param(&prep.entry->http_request, encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_push_list_channels(pubnub_context_t* ctx,
                                          const pubnub_push_list_channels_opts_t* opts)
{
    pn_feature_prep_t     prep;
    pn_push_path_inputs_t path_in;
    pubnub_res_t          rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->device || '\0' == opts->device[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (PUBNUB_PUSH_APNS2 == opts->gateway && NULL == opts->topic) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PUSH_NOTIFICATIONS,
                            sizeof(pn_push_state_t),
                            pn_push_feature_state_cleanup,
                            pn_push_list_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* push_log = NULL;
        PUBNUB_LOG_MAP_SET_STRING(push_log, opts->device, device_id)
        PUBNUB_LOG_MAP_SET_NUMBER(push_log, (int64_t)opts->gateway, push_type)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "push_list_channels params", push_log);
    }
#endif

    path_in.subscribe_key = prep.cfg->subscribe_key;
    path_in.device        = opts->device;
    path_in.gateway       = opts->gateway;
    path_in.append_remove = 0;

    rc = pn_push_build_path(&prep.entry->http_request, &path_in);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_push_add_gateway_params(
        &prep.entry->http_request, opts->gateway, opts->environment, opts->topic);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_push_add_list_params(&prep.entry->http_request, opts->start, opts->count);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_push_remove_device(pubnub_context_t* ctx,
                                          const pubnub_push_remove_device_opts_t* opts)
{
    pn_feature_prep_t     prep;
    pn_push_path_inputs_t path_in;
    pubnub_res_t          rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->device || '\0' == opts->device[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (PUBNUB_PUSH_APNS2 == opts->gateway && NULL == opts->topic) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PUSH_NOTIFICATIONS,
                            sizeof(pn_push_state_t),
                            pn_push_feature_state_cleanup,
                            pn_push_mutation_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* push_log = NULL;
        PUBNUB_LOG_MAP_SET_STRING(push_log, opts->device, device_id)
        PUBNUB_LOG_MAP_SET_NUMBER(push_log, (int64_t)opts->gateway, push_type)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "push_remove_device params", push_log);
    }
#endif

    path_in.subscribe_key = prep.cfg->subscribe_key;
    path_in.device        = opts->device;
    path_in.gateway       = opts->gateway;
    path_in.append_remove = 1;

    rc = pn_push_build_path(&prep.entry->http_request, &path_in);
    if (PUBNUB_OK != rc) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    rc = pn_push_add_gateway_params(
        &prep.entry->http_request, opts->gateway, opts->environment, opts->topic);
    if (PUBNUB_OK != rc) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_push_list_channels_result_t
pubnub_push_list_channels_result(const pubnub_future_t future)
{
    pubnub_push_list_channels_result_t result = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }
    pn_push_list_parsed_t** ps = parsed_slot_for(slot);
    if (NULL == ps) {
        return result;
    }
    const pn_push_list_parsed_t* cached = get_cached_parse(slot, future, ps);
    if (NULL == cached) {
        return result;
    }

    result.channel_count = cached->channel_count;
    return result;
}

pubnub_string_view_t
pubnub_push_list_channels_result_channel_at(const pubnub_future_t future,
                                            const size_t          index)
{
    const pubnub_string_view_t empty = {NULL, 0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return empty;
    }
    pn_push_list_parsed_t** ps = parsed_slot_for(slot);
    if (NULL == ps) {
        return empty;
    }
    const pn_push_list_parsed_t* cached = get_cached_parse(slot, future, ps);
    pn_push_list_parsed_t*       mut    = (pn_push_list_parsed_t*)cached;
    if (NULL == cached || NULL == cached->tree) {
        return empty;
    }

    if (index >= cached->channel_count) {
        return empty;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    if (NULL == serial || NULL == serial->array_get
        || NULL == serial->value_as_string) {
        return empty;
    }

    const pubnub_json_value_t* elem = pn_json_array_cursor_get(
        serial, cached->tree, index, &mut->iter_cache, &mut->iter_pos, &mut->iter_valid);
    if (NULL == elem) {
        return empty;
    }

    size_t      len = 0;
    const char* ptr = serial->value_as_string(elem, &len);
    if (NULL == ptr) {
        return empty;
    }

    return (pubnub_string_view_t){ptr, len};
}

void pn_push_feature_state_cleanup(void* state, pubnub_allocator_provider_t* allocator)
{
    if (NULL == state || NULL == allocator) {
        return;
    }

    pn_push_state_t* s = (pn_push_state_t*)state;

    if (NULL != s->parsed) {
        if (NULL != allocator->free) {
            PN_FREE(allocator, s->parsed);
        }
        s->parsed = NULL;
    }

    if (NULL != s->encoded_channels && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_channels);
    }
    s->encoded_channels = NULL;

    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}

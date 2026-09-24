/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/features/app_context.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_api_channel.c requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "app_context_internal.h"
#include "core/core_internal.h"
#include "pubnub/client.h"
#include "pubnub/future.h"

#include <stddef.h>
#include <stdint.h>

pubnub_future_t
pubnub_get_all_channel_metadata(pubnub_context_t* ctx,
                                const pubnub_get_all_channel_metadata_opts_t* opts)
{
    pubnub_get_all_channel_metadata_opts_t defaults =
        PUBNUB_GET_ALL_CHANNEL_METADATA_OPTS_INIT;
    pn_feature_prep_t prep;
    pubnub_res_t      rc;

    if (NULL == opts) {
        opts = &defaults;
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_APP_CONTEXT,
                            sizeof(pn_app_context_state_t),
                            pn_app_context_feature_state_cleanup,
                            pn_app_context_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }

    rc = pn_channel_metadata_build_path_get_all(&prep.entry->http_request,
                                                prep.cfg->subscribe_key);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_app_context_add_list_params(&prep.entry->http_request,
                                        opts->include,
                                        opts->limit,
                                        opts->start,
                                        opts->end,
                                        opts->filter,
                                        opts->sort);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t pubnub_get_channel_metadata(pubnub_context_t* ctx,
                                            const pubnub_get_channel_metadata_opts_t* opts)
{
    pn_feature_prep_t       prep;
    pn_app_context_state_t* state;
    char*                   encoded = NULL;
    pubnub_res_t            rc;

    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_APP_CONTEXT,
                            sizeof(pn_app_context_state_t),
                            pn_app_context_feature_state_cleanup,
                            pn_app_context_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_app_context_state_t*)prep.state;

    rc = pn_channel_metadata_build_path_single(&prep.entry->http_request,
                                               prep.allocator,
                                               prep.cfg->subscribe_key,
                                               opts->channel,
                                               &encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    state->encoded_path_segment = encoded;

    rc = pn_app_context_add_include_param(&prep.entry->http_request, opts->include);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t pubnub_set_channel_metadata(pubnub_context_t* ctx,
                                            const pubnub_set_channel_metadata_opts_t* opts)
{
    pn_feature_prep_t                prep;
    pn_app_context_state_t*          state;
    pubnub_serialization_provider_t* serial   = NULL;
    pubnub_buffer_t                  body_buf = {0};
    char*                            encoded  = NULL;
    pubnub_res_t                     rc;

    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if (NULL != opts->custom && NULL != opts->custom_value) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_APP_CONTEXT,
                            sizeof(pn_app_context_state_t),
                            pn_app_context_feature_state_cleanup,
                            pn_app_context_response_validator,
                            PUBNUB_HTTP_PATCH,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_app_context_state_t*)prep.state;

    serial = pn_context_serialization(ctx);
    if (NULL == serial || NULL == serial->serialize) {
        rc = PUBNUB_ERR_PROVIDER_MISSING;
        goto cleanup;
    }

    body_buf = prep.allocator->buf_acquire(prep.allocator, PUBNUB_BUF_OBJ);
    if (NULL == body_buf.data || 0 == body_buf.cap) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    state->owned_body_buf = body_buf;

    rc = pn_channel_metadata_build_body(
        serial, prep.allocator, opts, &state->owned_body_buf);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    prep.entry->http_request.body     = state->owned_body_buf.data;
    prep.entry->http_request.body_len = state->owned_body_buf.len;

    rc = pn_channel_metadata_build_path_single(&prep.entry->http_request,
                                               prep.allocator,
                                               prep.cfg->subscribe_key,
                                               opts->channel,
                                               &encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    state->encoded_path_segment = encoded;

    rc = pn_request_add_content_type_json(&prep.entry->http_request);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_app_context_add_if_match(&prep.entry->http_request, opts->if_match);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_app_context_add_include_param(&prep.entry->http_request, opts->include);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t
pubnub_remove_channel_metadata(pubnub_context_t* ctx,
                               const pubnub_remove_channel_metadata_opts_t* opts)
{
    pn_feature_prep_t       prep;
    pn_app_context_state_t* state;
    char*                   encoded = NULL;
    pubnub_res_t            rc;

    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_APP_CONTEXT,
                            sizeof(pn_app_context_state_t),
                            pn_app_context_feature_state_cleanup,
                            pn_app_context_response_validator,
                            PUBNUB_HTTP_DELETE,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_app_context_state_t*)prep.state;

    rc = pn_channel_metadata_build_path_single(&prep.entry->http_request,
                                               prep.allocator,
                                               prep.cfg->subscribe_key,
                                               opts->channel,
                                               &encoded);
    if (PUBNUB_OK != rc) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }
    state->encoded_path_segment = encoded;

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_app_context_page_t pubnub_get_all_channel_metadata_result(const pubnub_future_t future)
{
    pubnub_app_context_page_t      page = {0};
    pn_request_t*                  slot = NULL;
    const pn_app_context_parsed_t* parsed =
        pn_app_context_resolve_parsed(future, &slot);
    if (NULL == parsed) {
        return page;
    }

    pn_app_context_parse_page(parsed->serial, parsed->tree, &page);
    return page;
}

pubnub_channel_metadata_t
pubnub_get_all_channel_metadata_result_channel_at(const pubnub_future_t future,
                                                  const size_t          index)
{
    pubnub_channel_metadata_t      result   = {0};
    pn_request_t*                  slot     = NULL;
    pubnub_json_value_t*           data_arr = NULL;
    pubnub_json_value_t*           item     = NULL;
    const pn_app_context_parsed_t* parsed =
        pn_app_context_resolve_parsed(future, &slot);
    pn_app_context_parsed_t* cache = (pn_app_context_parsed_t*)parsed;
    if (NULL == parsed) {
        return result;
    }

    data_arr = pn_app_context_get_data_array(parsed->serial, parsed->tree);
    if (NULL == data_arr) {
        return result;
    }

    item = pn_json_array_cursor_get(parsed->serial,
                                    data_arr,
                                    index,
                                    &cache->iter_cache,
                                    &cache->iter_pos,
                                    &cache->iter_valid);
    if (NULL == item) {
        return result;
    }

    pn_channel_metadata_parse(parsed->serial, item, &result);
    return result;
}

pubnub_channel_metadata_t pubnub_get_channel_metadata_result(const pubnub_future_t future)
{
    pubnub_channel_metadata_t      result = {0};
    pn_request_t*                  slot   = NULL;
    pubnub_json_value_t*           data   = NULL;
    const pn_app_context_parsed_t* parsed =
        pn_app_context_resolve_parsed(future, &slot);
    if (NULL == parsed) {
        return result;
    }

    data = pn_app_context_get_data_object(parsed->serial, parsed->tree);
    if (NULL == data) {
        return result;
    }

    pn_channel_metadata_parse(parsed->serial, data, &result);
    return result;
}

pubnub_channel_metadata_t pubnub_set_channel_metadata_result(const pubnub_future_t future)
{
    pubnub_channel_metadata_t      result = {0};
    pn_request_t*                  slot   = NULL;
    pubnub_json_value_t*           data   = NULL;
    const pn_app_context_parsed_t* parsed =
        pn_app_context_resolve_parsed(future, &slot);
    if (NULL == parsed) {
        return result;
    }

    data = pn_app_context_get_data_object(parsed->serial, parsed->tree);
    if (NULL == data) {
        return result;
    }

    pn_channel_metadata_parse(parsed->serial, data, &result);
    return result;
}

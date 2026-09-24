/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/features/app_context.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_api_membership.c requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "app_context_internal.h"
#include "core/core_internal.h"
#include "pubnub/client.h"
#include "pubnub/future.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

pubnub_future_t pubnub_get_memberships(pubnub_context_t* ctx,
                                       const pubnub_get_memberships_opts_t* opts)
{
    pubnub_get_memberships_opts_t defaults = PUBNUB_GET_MEMBERSHIPS_OPTS_INIT;
    pn_feature_prep_t             prep;
    pn_app_context_state_t*       state;
    const char*                   uuid    = NULL;
    char*                         encoded = NULL;
    pubnub_res_t                  rc;

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
    state = (pn_app_context_state_t*)prep.state;

    uuid = opts->uuid;
    if (NULL == uuid) {
        uuid = pn_context_user_id(ctx);
    }
    if (NULL == uuid) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_INVALID_ARGUMENT,
                           pubnub_res_str(PUBNUB_ERR_INVALID_ARGUMENT),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_memberships_build_path(&prep.entry->http_request,
                                   prep.allocator,
                                   prep.cfg->subscribe_key,
                                   uuid,
                                   &encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    state->encoded_path_segment = encoded;

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

pubnub_future_t pubnub_set_memberships(pubnub_context_t* ctx,
                                       const pubnub_set_memberships_opts_t* opts)
{
    pn_feature_prep_t                prep;
    pn_app_context_state_t*          state;
    pubnub_serialization_provider_t* serial   = NULL;
    const char*                      uuid     = NULL;
    pubnub_buffer_t                  body_buf = {0};
    char*                            encoded  = NULL;
    pubnub_res_t                     rc;
    size_t                           i;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if (0 == opts->set_count && 0 == opts->remove_count) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    for (i = 0; i < opts->set_count; ++i) {
        if (NULL != opts->set[i].custom && NULL != opts->set[i].custom_value) {
            return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
        }
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

    uuid = opts->uuid;
    if (NULL == uuid) {
        uuid = pn_context_user_id(ctx);
    }
    if (NULL == uuid) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_INVALID_ARGUMENT,
                           pubnub_res_str(PUBNUB_ERR_INVALID_ARGUMENT),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

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

    rc = pn_memberships_build_body(serial,
                                   prep.allocator,
                                   opts->set,
                                   opts->set_count,
                                   opts->remove,
                                   opts->remove_count,
                                   &state->owned_body_buf);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    prep.entry->http_request.body     = state->owned_body_buf.data;
    prep.entry->http_request.body_len = state->owned_body_buf.len;

    rc = pn_memberships_build_path(&prep.entry->http_request,
                                   prep.allocator,
                                   prep.cfg->subscribe_key,
                                   uuid,
                                   &encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    state->encoded_path_segment = encoded;

    rc = pn_request_add_content_type_json(&prep.entry->http_request);
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

pubnub_app_context_page_t pubnub_get_memberships_result(const pubnub_future_t future)
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

pubnub_membership_t
pubnub_get_memberships_result_membership_at(const pubnub_future_t future,
                                            const size_t          index)
{
    pubnub_membership_t            result   = {0};
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

    pn_membership_parse(parsed->serial, item, &result);
    return result;
}

pubnub_app_context_page_t pubnub_set_memberships_result(const pubnub_future_t future)
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

pubnub_membership_t
pubnub_set_memberships_result_membership_at(const pubnub_future_t future,
                                            const size_t          index)
{
    pubnub_membership_t            result   = {0};
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

    pn_membership_parse(parsed->serial, item, &result);
    return result;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/features/app_context.h"

#if !PUBNUB_ENABLE_APP_CONTEXT
#error "app_context_api_common.c requires PUBNUB_ENABLE_APP_CONTEXT=ON"
#endif

#include "app_context_internal.h"
#include "core/core_internal.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <string.h>

PUBNUB_STATIC_ASSERT(sizeof(pubnub_member_t) <= 256,
                     "pubnub_member_t exceeds embedded stack budget");

pn_app_context_state_t* pn_app_context_state_alloc(pubnub_allocator_provider_t* allocator)
{
    pn_app_context_state_t* s =
        (pn_app_context_state_t*)PN_ALLOC(allocator, sizeof(*s), 0);
    if (NULL != s) {
        memset(s, 0, sizeof(*s));
    }
    return s;
}

const pn_app_context_parsed_t*
pn_app_context_get_cached_parse(pn_request_t*           slot,
                                const pubnub_future_t   future,
                                pn_app_context_state_t* state)
{
    pubnub_serialization_provider_t* serial    = NULL;
    pubnub_json_value_t*             tree      = NULL;
    pubnub_allocator_provider_t*     allocator = NULL;
    pn_app_context_parsed_t*         cached    = NULL;

    if (NULL == state) {
        return NULL;
    }
    if (NULL != state->parsed) {
        return state->parsed;
    }

    serial = pn_context_serialization(future.ctx);
    tree   = pn_request_get_parsed_body(slot, serial);
    if (NULL == tree) {
        return NULL;
    }

    allocator = pn_context_allocator(future.ctx);
    if (NULL == allocator) {
        return NULL;
    }

    cached = (pn_app_context_parsed_t*)PN_ALLOC(
        allocator, sizeof(pn_app_context_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }

    memset(cached, 0, sizeof(*cached));
    cached->tree   = tree;
    cached->serial = serial;

    state->parsed = cached;
    return cached;
}

pubnub_res_t pn_app_context_add_list_params(pubnub_http_request_t* request,
                                            uint32_t               include,
                                            uint32_t               limit,
                                            const char*            start,
                                            const char*            end,
                                            const char*            filter,
                                            const char*            sort)
{
    pubnub_res_t rc = pn_app_context_add_include_param(request, include);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_app_context_add_pagination_params(request, limit, start, end);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_app_context_add_filter_param(request, filter);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_app_context_add_sort_param(request, sort);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    return pn_app_context_add_count_param(request, include);
}

pn_app_context_state_t* pn_app_context_state_for_future(pn_request_t* slot)
{
    void* raw = pn_request_feature_state_for(slot, PUBNUB_FEATURE_APP_CONTEXT);
    return (pn_app_context_state_t*)raw;
}

const pn_app_context_parsed_t*
pn_app_context_resolve_parsed(const pubnub_future_t future, pn_request_t** out_slot)
{
    pn_app_context_state_t* state = NULL;

    *out_slot = pn_ready_slot_for_future(future);
    if (NULL == *out_slot) {
        return NULL;
    }

    state = pn_app_context_state_for_future(*out_slot);
    if (NULL == state) {
        return NULL;
    }

    return pn_app_context_get_cached_parse(*out_slot, future, state);
}

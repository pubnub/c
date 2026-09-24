/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "access_internal.h"

#if !PUBNUB_ENABLE_PAM
#error "access_api.c requires PUBNUB_ENABLE_PAM=ON - this translation unit " \
    "has no meaning without the PAM feature. Check the CMake feature "      \
    "gating in src/features/CMakeLists.txt."
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_buf_serialize.h"
#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <string.h>

/**
 * @brief Return non-zero when at least one resource or pattern count
 *        in the grant options is positive.
 */
static int has_any_permission(const pubnub_grant_token_opts_t* opts)
{
    return (0 != opts->channel_count || 0 != opts->group_count
            || 0 != opts->uuid_count || 0 != opts->channel_pattern_count
            || 0 != opts->group_pattern_count || 0 != opts->uuid_pattern_count);
}

/**
 * @brief Lazy-parse the slot's grant response and cache result.
 *
 * @param slot   Request slot holding the raw HTTP response.
 * @param future Future handle for context provider resolution.
 * @param state  Per-request PAM state with cached parse slot.
 * @return Parsed result, or NULL on failure.
 */
static const pn_access_grant_parsed_t*
get_cached_grant_parse(pn_request_t*         slot,
                       const pubnub_future_t future,
                       pn_access_state_t*    state)
{
    if (NULL != state->parsed) {
        return state->parsed;
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

    pn_access_grant_parsed_t* cached = (pn_access_grant_parsed_t*)PN_ALLOC(
        allocator, sizeof(pn_access_grant_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }

    pubnub_res_t rc = pn_access_grant_parse_response(serial, tree, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    state->parsed = cached;
    return cached;
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_grant_token(pubnub_context_t*                ctx,
                                   const pubnub_grant_token_opts_t* opts)
{
    pn_feature_prep_t                prep;
    pn_access_state_t*               state;
    pubnub_serialization_provider_t* serial;
    pubnub_buffer_t                  body_buf = {0};
    size_t                           body_len = 0;
    pubnub_res_t                     rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if (0 == opts->ttl || opts->ttl > 43200) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if (!has_any_permission(opts)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PAM,
                            sizeof(pn_access_state_t),
                            pn_access_feature_state_cleanup,
                            pn_access_grant_response_validator,
                            PUBNUB_HTTP_POST,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_access_state_t*)prep.state;

    if (NULL == prep.cfg->publish_key || NULL == prep.cfg->secret_key) {
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

    PUBNUB_LOG_TEXT(
        pn_context_logger(ctx), PUBNUB_LOG_LEVEL_DEBUG, "Grant token dispatched");

    body_buf = prep.allocator->buf_acquire(prep.allocator, PUBNUB_BUF_OBJ);
    if (NULL == body_buf.data || 0 == body_buf.cap) {
        rc = PUBNUB_ERR_QUEUE_FULL;
        goto cleanup;
    }
    state->owned_body_buf = body_buf;

    rc = pn_access_grant_build_body(
        serial, opts, body_buf.data, body_buf.cap, &body_len);
    {
        int attempts = 0;
        while (attempts < 16 && PUBNUB_ERR_BUFFER_TOO_SMALL == rc
               && 0 == pn_buf_ensure_cap(prep.allocator, &body_buf, body_buf.cap * 2)) {
            state->owned_body_buf = body_buf;
            rc                    = pn_access_grant_build_body(
                serial, opts, body_buf.data, body_buf.cap, &body_len);
            ++attempts;
        }
    }
    state->owned_body_buf = body_buf;
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    prep.entry->http_request.body     = state->owned_body_buf.data;
    prep.entry->http_request.body_len = body_len;

    rc = pn_request_add_content_type_json(&prep.entry->http_request);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_access_grant_build_path(&prep.entry->http_request,
                                    prep.cfg->subscribe_key);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t pubnub_revoke_token(pubnub_context_t*                 ctx,
                                    const pubnub_revoke_token_opts_t* opts)
{
    pn_feature_prep_t  prep;
    pn_access_state_t* state;
    pubnub_res_t       rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if (NULL == opts->token || '\0' == opts->token[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PAM,
                            sizeof(pn_access_state_t),
                            pn_access_feature_state_cleanup,
                            NULL,
                            PUBNUB_HTTP_DELETE,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_access_state_t*)prep.state;

    if (NULL == prep.cfg->secret_key) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_INVALID_ARGUMENT,
                           pubnub_res_str(PUBNUB_ERR_INVALID_ARGUMENT),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                    PUBNUB_LOG_LEVEL_DEBUG,
                    "Revoke token dispatched");

    /* Build path: /v3/pam/{subscribe_key}/grant/{encoded_token} */
    rc = pn_access_revoke_build_path(&prep.entry->http_request,
                                     prep.allocator,
                                     prep.cfg->subscribe_key,
                                     opts->token,
                                     &state->encoded_token);
    if (PUBNUB_OK != rc) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_grant_token_result_t pubnub_grant_token_result(const pubnub_future_t future)
{
    const pubnub_grant_token_result_t empty = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return empty;
    }

    void* raw_state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_PAM);
    if (NULL == raw_state) {
        return empty;
    }

    pn_access_state_t* state = (pn_access_state_t*)raw_state;

    const pn_access_grant_parsed_t* cached =
        get_cached_grant_parse(slot, future, state);
    if (NULL == cached) {
        return empty;
    }

    return (pubnub_grant_token_result_t){.token = cached->token};
}

void pn_access_feature_state_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    if (NULL == state || NULL == alloc) {
        return;
    }

    pn_access_state_t* s = (pn_access_state_t*)state;

    if (NULL != s->parsed && NULL != alloc->free) {
        PN_FREE(alloc, s->parsed);
        s->parsed = NULL;
    }

    if (NULL != s->encoded_token && NULL != alloc->free) {
        PN_FREE(alloc, s->encoded_token);
        s->encoded_token = NULL;
    }

    if (NULL != s->owned_body_buf.data && NULL != alloc->buf_release) {
        alloc->buf_release(alloc, &s->owned_body_buf);
    }

    if (NULL != alloc->free) {
        PN_FREE(alloc, s);
    }
}

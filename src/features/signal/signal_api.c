/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "signal_internal.h"

#if !PUBNUB_ENABLE_SIGNAL
#error "signal_api.c requires PUBNUB_ENABLE_SIGNAL=ON - this translation unit has no meaning without the signal feature. Check the CMake feature gating in src/features/CMakeLists.txt; the file must not appear in the build when the flag is off."
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_buf_serialize.h"
#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief Adapter: match pn_parse_response_fn_t signature for signal. */
static pubnub_res_t signal_parse_adapter(pubnub_serialization_provider_t* serial,
                                         pubnub_json_value_t* tree,
                                         void*                out)
{
    return pn_signal_parse_response(serial, tree, (pn_signal_parsed_t*)out);
}

/**
 * @brief Lazy-parse the slot's response body once and cache the
 *        feature-specific decomposition inside the slot's
 *        feature_state.
 */
static const pn_signal_parsed_t* get_cached_parse(pn_request_t*         slot,
                                                  const pubnub_future_t future,
                                                  pn_signal_parsed_t** parsed_slot)
{
    return (const pn_signal_parsed_t*)pn_resolve_cached_parse(
        slot,
        future,
        (void**)parsed_slot,
        sizeof(pn_signal_parsed_t),
        0,
        signal_parse_adapter,
        NULL);
}

/**
 * @brief Locate the cached-parse slot for a signal-feature future.
 *
 * @return Pointer to the cached-parse slot, or NULL when the slot
 *         has no recognised signal feature_state.
 */
static pn_signal_parsed_t** parsed_slot_for(pn_request_t* slot)
{
    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_SIGNAL);
    if (NULL == state) {
        return NULL;
    }

    pn_signal_state_t* s = (pn_signal_state_t*)state;
    return &s->parsed;
}

/**
 * @brief Resolve allocator and serialization provider dependencies
 *        required for value-tree signal paths.
 *
 * @param ctx         Client context.
 * @param opts        Signal options (only checked for value-tree fields).
 * @param[out] allocator  Resolved allocator.
 * @param[out] serializer Resolved serialization provider.
 * @return PUBNUB_OK when all required providers are available.
 */
static pubnub_res_t
resolve_serialization_dependencies(pubnub_context_t*                 ctx,
                                   const pubnub_signal_opts_t*       opts,
                                   pubnub_allocator_provider_t**     allocator,
                                   pubnub_serialization_provider_t** serializer)
{
    pubnub_res_t rc = PUBNUB_OK;

    *allocator  = pn_context_allocator(ctx);
    *serializer = pn_context_serialization(ctx);

    if (NULL == *allocator || NULL == (*allocator)->buf_acquire
        || NULL == (*allocator)->buf_release) {
        rc = NULL == *allocator ? PUBNUB_ERR_NOT_INITIALIZED
                                : PUBNUB_ERR_PROVIDER_MISSING;
    }

    if (NULL != opts->message_value) {
        if (NULL == *serializer || NULL == (*serializer)->serialize) {
            rc = NULL == *serializer ? PUBNUB_ERR_NOT_INITIALIZED
                                     : PUBNUB_ERR_PROVIDER_MISSING;
        }
    }

    return rc;
}

/**
 * @brief Build the pending entry and dispatch (or enqueue) the signal request.
 *
 * @param ctx       Client context (validated non-NULL).
 * @param opts      Signal options (borrowed).
 * @param cfg       Client config (borrowed, validated).
 * @param allocator Pipeline allocator (borrowed).
 * @param message   Resolved message bytes (borrowed).
 * @param message_len Length of @p message in bytes.
 * @param body_buf  Owned buffer from value-tree serialization (may be zero).
 * @return Future representing the dispatched or enqueued request.
 */
static pubnub_future_t signal_build_and_dispatch(pubnub_context_t* ctx,
                                                 const pubnub_signal_opts_t* opts,
                                                 const pubnub_config_t* cfg,
                                                 pubnub_allocator_provider_t* allocator,
                                                 const char*     message,
                                                 size_t          message_len,
                                                 pubnub_buffer_t body_buf)
{
    pn_feature_prep_t       prep;
    pn_signal_state_t*      state;
    pn_signal_url_encoded_t url_encoded = {0};
    pn_signal_path_inputs_t path_inputs;
    pubnub_res_t            rc;

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_SIGNAL,
                            sizeof(pn_signal_state_t),
                            pn_signal_feature_state_cleanup,
                            pn_signal_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        if (0 != body_buf.cap) {
            allocator->buf_release(allocator, &body_buf);
        }
        return pn_failed_future(rc);
    }
    state = (pn_signal_state_t*)prep.state;

    path_inputs.publish_key    = cfg->publish_key;
    path_inputs.subscribe_key  = cfg->subscribe_key;
    path_inputs.channel        = opts->channel;
    path_inputs.serialized     = (const uint8_t*)message;
    path_inputs.serialized_len = message_len;

    rc = pn_signal_build_path(
        &prep.entry->http_request, allocator, &path_inputs, &url_encoded);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }
    state->encoded_channel = url_encoded.channel;
    state->encoded_message = url_encoded.message;

    rc = pn_signal_add_query_params(&prep.entry->http_request,
                                    opts->custom_message_type);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    /* Signal is always GET: the message is URL-encoded in the path.
     * The OBJ buffer (from value-tree serialization) is no longer
     * needed after path building. Release it to free pool capacity. */
    if (0 != body_buf.cap) {
        allocator->buf_release(allocator, &body_buf);
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    if (0 != body_buf.cap) {
        allocator->buf_release(allocator, &body_buf);
    }
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_future_t pubnub_signal(pubnub_context_t* ctx, const pubnub_signal_opts_t* opts)
{
    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if ((NULL == opts->message && NULL == opts->message_value)
        || (NULL != opts->message && NULL != opts->message_value)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    const pubnub_config_t* cfg = NULL;
    if (PUBNUB_OK != pn_validate_ctx(ctx, &cfg)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == cfg->publish_key) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    pubnub_allocator_provider_t* allocator = pn_context_allocator(ctx);
    if (NULL == allocator) {
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_NOT_INITIALIZED,
                           pubnub_res_str(PUBNUB_ERR_NOT_INITIALIZED),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_NOT_INITIALIZED);
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* sig_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(sig_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(
            sig_head_, opts->custom_message_type, custom_message_type)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "signal params", sig_head_);
    }
#endif

    pubnub_serialization_provider_t* serial = NULL;
    pubnub_allocator_provider_t*     alloc  = NULL;

    const pubnub_res_t resolve =
        resolve_serialization_dependencies(ctx, opts, &alloc, &serial);
    if (PUBNUB_OK != resolve) {
        PN_LOG_ERROR_ENTRY(ctx, (int)resolve, pubnub_res_str(resolve), NULL);
        return pn_failed_future(resolve);
    }

    /* Resolve message bytes. */
    const char*     message     = opts->message;
    size_t          message_len = 0;
    pubnub_buffer_t body_buf    = {0};

    if (NULL != opts->message_value && NULL != alloc && NULL != serial) {
        body_buf = alloc->buf_acquire(alloc, PUBNUB_BUF_OBJ);
        if (NULL == body_buf.data || 0 == body_buf.cap) {
            PN_LOG_ERROR_ENTRY(ctx,
                               (int)PUBNUB_ERR_QUEUE_FULL,
                               pubnub_res_str(PUBNUB_ERR_QUEUE_FULL),
                               NULL);
            return pn_failed_future(PUBNUB_ERR_QUEUE_FULL);
        }

        const pubnub_res_t rc =
            pn_buf_serialize_grow(alloc, serial, opts->message_value, &body_buf);
        if (PUBNUB_OK != rc) {
            alloc->buf_release(alloc, &body_buf);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
        message     = (const char*)body_buf.data;
        message_len = body_buf.len;
    } else {
        message_len = (0 == opts->message_len) ? strlen(opts->message)
                                               : opts->message_len;
    }

    return signal_build_and_dispatch(
        ctx, opts, cfg, allocator, message, message_len, body_buf);
}

pubnub_timetoken_t pubnub_signal_result_timetoken(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return (pubnub_timetoken_t){NULL, 0};
    }
    pn_signal_parsed_t** ps = parsed_slot_for(slot);
    if (NULL == ps) {
        return (pubnub_timetoken_t){NULL, 0};
    }
    const pn_signal_parsed_t* cached = get_cached_parse(slot, future, ps);
    if (NULL == cached) {
        return (pubnub_timetoken_t){NULL, 0};
    }
    return cached->timetoken;
}

void pn_signal_feature_state_cleanup(void*                        state,
                                     pubnub_allocator_provider_t* allocator)
{
    if (NULL == state || NULL == allocator) {
        return;
    }

    pn_signal_state_t* s = (pn_signal_state_t*)state;

    if (NULL != s->parsed) {
        if (NULL != allocator->free) {
            PN_FREE(allocator, s->parsed);
        }
        s->parsed = NULL;
    }

    if (NULL != s->encoded_channel && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_channel);
    }
    if (NULL != s->encoded_message && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_message);
    }
    s->encoded_channel = NULL;
    s->encoded_message = NULL;

    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}

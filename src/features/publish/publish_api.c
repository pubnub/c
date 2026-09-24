/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "publish_internal.h"

#if !PUBNUB_ENABLE_PUBLISH
#error "publish_api.c requires PUBNUB_ENABLE_PUBLISH=ON - this translation unit has no meaning without the publish feature. Check the CMake feature gating in src/features/CMakeLists.txt; the file must not appear in the build when the flag is off."
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_buf_serialize.h"
#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if PUBNUB_ENABLE_CRYPTO
/* Forward declaration — avoids cross-feature include coupling.
 * The definition lives in src/features/crypto/crypto_api.c. */
pubnub_res_t pn_crypto_module_encrypt_to_base64(pubnub_crypto_module_t* module,
                                                const uint8_t*          input,
                                                size_t  input_len,
                                                char**  out_base64,
                                                size_t* out_len,
                                                pubnub_allocator_provider_t* alloc);
#endif

/**
 * @brief Resolved publish inputs passed from the validation stage
 *        to the dispatch stage.
 */
typedef struct pn_publish_resolved {
    const char*     message;
    size_t          message_len;
    const char*     meta;
    size_t          meta_len;
    pubnub_buffer_t body_buf;
    /** Allocator-owned encrypted payload; NULL when crypto inactive. */
    char* encrypted_payload;
} pn_publish_resolved_t;

/**
 * @brief Lazy-parse the slot's response body once and cache the
 *        feature-specific decomposition inside the slot's
 *        feature_state.
 *
 * The acquire-load on @c parsed_cached provides the fast path; the
 * release-store after writing @c state->parsed guarantees pointer
 * visibility to concurrent readers on the same completed future.
 *
 * @param slot   Request slot that holds the raw HTTP response.
 * @param future Future handle used to resolve context providers.
 * @param state  Per-request publish state (non-NULL).
 * @return Pointer to the cached parsed result, or NULL if parsing
 *         fails or the response is not available.
 */
static const pn_publish_parsed_t* get_cached_parse(pn_request_t*         slot,
                                                   const pubnub_future_t future,
                                                   pn_publish_state_t*   state)
{
    if (NULL == state) {
        return NULL;
    }

    /* Acquire-load: if the flag is set, the pointer write that preceded
     * the release-store is visible here. */
    if (PUBNUB_ATOMIC_LOAD_U8(&state->parsed_cached)) {
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

    pn_publish_parsed_t* cached =
        (pn_publish_parsed_t*)PN_ALLOC(allocator, sizeof(pn_publish_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }

    pubnub_res_t rc = pn_publish_parse_response(serial, tree, cached);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, cached);
        return NULL;
    }

    state->parsed = cached;
    PUBNUB_ATOMIC_STORE_U8(&state->parsed_cached, 1);
    return cached;
}

/**
 * @brief Resolve allocator and serialization provider dependencies
 *        required for value-tree publish paths.
 *
 * @param ctx    Client context.
 * @param opts   Publish options (only checked for value-tree fields).
 * @param[out] allocator  Resolved allocator.
 * @param[out] serializer Resolved serialization provider.
 * @return PUBNUB_OK when all required providers are available.
 */
static pubnub_res_t
resolve_serialization_dependencies(pubnub_context_t*                 ctx,
                                   const pubnub_publish_opts_t*      opts,
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

    if (NULL != opts->message_value || NULL != opts->meta_value) {
        if (NULL == *serializer || NULL == (*serializer)->serialize) {
            rc = NULL == *serializer ? PUBNUB_ERR_NOT_INITIALIZED
                                     : PUBNUB_ERR_PROVIDER_MISSING;
        }
    }

    return rc;
}

/**
 * @brief Acquire (or reuse) a POST body buffer and set the Content-Type header.
 *
 * When the value-tree path already produced an owned buffer, reuses it.
 * Otherwise acquires a fresh OBJ buffer, copies the resolved message
 * bytes, and stores the buffer in @p state for lifetime management.
 *
 * @param entry     Pending entry whose http_request is populated.
 * @param state     Per-request publish state (receives owned_body_buf).
 * @param allocator Allocator for buffer acquisition.
 * @param resolved  Resolved message data.
 * @return PUBNUB_OK on success, PUBNUB_ERR_BUFFER_TOO_SMALL when the
 *         acquired buffer cannot hold the message.
 */
static pubnub_res_t publish_prepare_post_body(pn_pending_entry_t* entry,
                                              pn_publish_state_t* state,
                                              pubnub_allocator_provider_t* allocator,
                                              const pn_publish_resolved_t* resolved)
{
    if (0 != state->owned_body_buf.cap) {
        entry->http_request.body = state->owned_body_buf.data;
    } else {
        pubnub_buffer_t post_buf =
            allocator->buf_acquire(allocator, PUBNUB_BUF_OBJ);
        if (NULL == post_buf.data) {
            return PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        if (post_buf.cap < resolved->message_len) {
            if (0 != pn_buf_ensure_cap(allocator, &post_buf, resolved->message_len)) {
                allocator->buf_release(allocator, &post_buf);
                return PUBNUB_ERR_BUFFER_TOO_SMALL;
            }
        }
        memcpy(post_buf.data, resolved->message, resolved->message_len);
        post_buf.len             = resolved->message_len;
        state->owned_body_buf    = post_buf;
        entry->http_request.body = state->owned_body_buf.data;
    }
    entry->http_request.body_len = resolved->message_len;

    return pn_request_add_content_type_json(&entry->http_request);
}

/**
 * @brief Populate path, body, and query params on a pending entry.
 *
 * Builds path segments, prepares POST body when applicable, appends
 * query parameters, and releases the OBJ buffer for GET requests.
 *
 * @param entry     Initialized pending entry to populate.
 * @param state     Per-request publish state (receives encoded strings).
 * @param allocator Allocator for encoding (borrowed).
 * @param opts      Publish options (borrowed).
 * @param cfg       Context configuration (borrowed).
 * @param resolved  Resolved message/meta inputs (body_buf may be
 *                  released for GET requests).
 * @return PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t publish_populate_request(pn_pending_entry_t* entry,
                                             pn_publish_state_t* state,
                                             pubnub_allocator_provider_t* allocator,
                                             const pubnub_publish_opts_t* opts,
                                             const pubnub_config_t*       cfg,
                                             pn_publish_resolved_t* resolved)
{
    pn_publish_url_encoded_t url_encoded = {0};
    pubnub_res_t             rc;

    const pn_publish_path_inputs_t path_inputs = {
        .publish_key     = cfg->publish_key,
        .subscribe_key   = cfg->subscribe_key,
        .channel         = opts->channel,
        .serialized      = (const uint8_t*)resolved->message,
        .serialized_len  = resolved->message_len,
        .include_message = (PUBNUB_PUBLISH_METHOD_POST != opts->method),
    };

    rc = pn_publish_build_path(
        &entry->http_request, allocator, &path_inputs, &url_encoded);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    state->encoded_channel = url_encoded.channel;
    state->encoded_message = url_encoded.message;

    if (PUBNUB_PUBLISH_METHOD_POST == opts->method) {
        rc = publish_prepare_post_body(entry, state, allocator, resolved);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    rc = pn_publish_add_query_params(&entry->http_request,
                                     NULL != resolved->meta,
                                     resolved->meta,
                                     resolved->meta_len,
                                     opts->store,
                                     opts->ttl,
                                     opts->custom_message_type);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* For GET: release the OBJ buffer before enqueue to free pool
     * capacity. For POST: owned_body_buf is the body source and must
     * survive until request completion (cleanup frees it). */
    if (0 != resolved->body_buf.cap && PUBNUB_PUBLISH_METHOD_POST != opts->method) {
        state->owned_body_buf = (pubnub_buffer_t){0};
        allocator->buf_release(allocator, &resolved->body_buf);
    }

    return PUBNUB_OK;
}

/**
 * @brief Build the pending entry and dispatch (or enqueue) the
 *        publish request.
 *
 * @param ctx       Client context (validated non-NULL).
 * @param opts      Publish options (borrowed).
 * @param cfg       Client config (borrowed, validated).
 * @param allocator Pipeline allocator (borrowed).
 * @param resolved  Resolved message/meta/buffer inputs.
 * @return Future representing the dispatched or enqueued request.
 */
static pubnub_future_t publish_build_and_dispatch(pubnub_context_t* ctx,
                                                  const pubnub_publish_opts_t* opts,
                                                  const pubnub_config_t* cfg,
                                                  pubnub_allocator_provider_t* allocator,
                                                  pn_publish_resolved_t resolved)
{
    pn_feature_prep_t    prep;
    pn_publish_state_t*  state;
    pubnub_http_method_t method;
    pubnub_res_t         rc;

    method = (PUBNUB_PUBLISH_METHOD_POST == opts->method) ? PUBNUB_HTTP_POST
                                                          : PUBNUB_HTTP_GET;
    rc     = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_PUBLISH,
                            sizeof(pn_publish_state_t),
                            pn_publish_feature_state_cleanup,
                            pn_publish_response_validator,
                            method,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        if (0 != resolved.body_buf.cap) {
            allocator->buf_release(allocator, &resolved.body_buf);
        }
        if (NULL != resolved.encrypted_payload) {
            PN_FREE(allocator, resolved.encrypted_payload);
        }
        return pn_failed_future(rc);
    }
    state = (pn_publish_state_t*)prep.state;

    state->encrypted_payload = resolved.encrypted_payload;
    if (0 != resolved.body_buf.cap) {
        state->owned_body_buf = resolved.body_buf;
    }

    /* Positive-match tri-state collapse: only DEFAULT (follow the
     * compile-time toggle) and YES enable compression, so a future enum
     * value cannot silently opt in. GET has no body to compress. */
    prep.entry->http_request.compress_body =
        PUBNUB_ENABLE_REQUEST_COMPRESSION
        && PUBNUB_PUBLISH_METHOD_POST == opts->method
        && (PUBNUB_PUBLISH_COMPRESS_DEFAULT == opts->compress
            || PUBNUB_PUBLISH_COMPRESS_YES == opts->compress);

    rc = publish_populate_request(prep.entry, state, allocator, opts, cfg, &resolved);
    if (PUBNUB_OK != rc) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_publish(pubnub_context_t*            ctx,
                               const pubnub_publish_opts_t* opts)
{
    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if ((NULL == opts->message && NULL == opts->message_value)
        || (NULL != opts->message && NULL != opts->message_value)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    if (NULL != opts->meta && NULL != opts->meta_value) {
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
        pubnub_log_value_t* pub_head_ = NULL;
        /* Security: omit message body at DEBUG. */
        PUBNUB_LOG_MAP_SET_STRING(pub_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_NUMBER(pub_head_, (int64_t)opts->store, store)
        if (0 != opts->ttl) {
            PUBNUB_LOG_MAP_SET_NUMBER(pub_head_, (int64_t)opts->ttl, ttl)
        }
        PUBNUB_LOG_MAP_SET_STRING(
            pub_head_, opts->custom_message_type, custom_message_type)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "publish params", pub_head_);
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

    /* Encrypt message payload when a crypto module is configured. */
    char* encrypted_payload = NULL;
#if PUBNUB_ENABLE_CRYPTO
    if (NULL != pn_context_crypto_module(ctx)) {
        pubnub_crypto_module_t* crypto_mod  = pn_context_crypto_module(ctx);
        char*                   enc_b64     = NULL;
        size_t                  enc_b64_len = 0;
        pubnub_res_t            enc_rc =
            pn_crypto_module_encrypt_to_base64(crypto_mod,
                                               (const uint8_t*)message,
                                               message_len,
                                               &enc_b64,
                                               &enc_b64_len,
                                               allocator);
        if (PUBNUB_OK != enc_rc) {
            if (0 != body_buf.cap && NULL != alloc) {
                alloc->buf_release(alloc, &body_buf);
            }
            PN_LOG_ERROR_ENTRY(ctx, (int)enc_rc, pubnub_res_str(enc_rc), NULL);
            return pn_failed_future(enc_rc);
        }

        /* Wrap in JSON quotes — publish path expects a JSON literal. */
        encrypted_payload = (char*)PN_ALLOC(allocator, enc_b64_len + 3, 1);
        if (NULL == encrypted_payload) {
            PN_FREE(allocator, enc_b64);
            if (0 != body_buf.cap && NULL != alloc) {
                alloc->buf_release(alloc, &body_buf);
            }
            PN_LOG_ERROR_ENTRY(ctx,
                               (int)PUBNUB_ERR_OUT_OF_MEMORY,
                               pubnub_res_str(PUBNUB_ERR_OUT_OF_MEMORY),
                               NULL);
            return pn_failed_future(PUBNUB_ERR_OUT_OF_MEMORY);
        }
        encrypted_payload[0] = '"';
        memcpy(encrypted_payload + 1, enc_b64, enc_b64_len);
        encrypted_payload[enc_b64_len + 1] = '"';
        encrypted_payload[enc_b64_len + 2] = '\0';
        PN_FREE(allocator, enc_b64);

        /* Release the serialization buffer — encrypted replaces it. */
        if (0 != body_buf.cap && NULL != alloc) {
            alloc->buf_release(alloc, &body_buf);
            body_buf = (pubnub_buffer_t){0};
        }

        message     = encrypted_payload;
        message_len = enc_b64_len + 2;
    }
#endif

    /* Resolve meta. Stack buffer sized by PUBNUB_CFG_PUBLISH_META_BUF_SIZE
     * (4096 on hosted, 256 on embedded). Independent of transport scratch. */
    char        meta_buf[PUBNUB_CFG_PUBLISH_META_BUF_SIZE];
    const char* meta     = opts->meta;
    size_t      meta_len = 0;

    if (NULL != opts->meta_value) {
        const pubnub_res_t rc = pn_publish_serialize_json_value(
            serial, opts->meta_value, (uint8_t*)meta_buf, sizeof(meta_buf) - 1, &meta_len);
        if (PUBNUB_OK != rc) {
            if (0 != body_buf.cap && NULL != alloc) {
                alloc->buf_release(alloc, &body_buf);
            }
            if (NULL != encrypted_payload) {
                PN_FREE(allocator, encrypted_payload);
            }
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
        meta_buf[meta_len] = '\0';
        meta               = meta_buf;
    } else if (NULL != opts->meta) {
        meta_len = (0 == opts->meta_len) ? strlen(opts->meta) : opts->meta_len;
    }

    const pn_publish_resolved_t resolved = {
        .message           = message,
        .message_len       = message_len,
        .meta              = meta,
        .meta_len          = meta_len,
        .body_buf          = body_buf,
        .encrypted_payload = encrypted_payload,
    };

    return publish_build_and_dispatch(ctx, opts, cfg, allocator, resolved);
}

pubnub_timetoken_t pubnub_publish_result_timetoken(const pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return (pubnub_timetoken_t){NULL, 0};
    }
    void* state_raw = pn_request_feature_state_for(slot, PUBNUB_FEATURE_PUBLISH);
    if (NULL == state_raw) {
        return (pubnub_timetoken_t){NULL, 0};
    }
    pn_publish_state_t*        state  = (pn_publish_state_t*)state_raw;
    const pn_publish_parsed_t* cached = get_cached_parse(slot, future, state);
    if (NULL == cached) {
        return (pubnub_timetoken_t){NULL, 0};
    }
    return cached->timetoken;
}

void pn_publish_feature_state_cleanup(void*                        state,
                                      pubnub_allocator_provider_t* allocator)
{
    if (NULL == state || NULL == allocator) {
        return;
    }

    pn_publish_state_t* s = (pn_publish_state_t*)state;

    if (NULL != s->parsed) {
        if (NULL != allocator->free) {
            PN_FREE(allocator, s->parsed);
        }
        s->parsed = NULL;
    }

    if (NULL != s->encrypted_payload && NULL != allocator->free) {
        PN_FREE(allocator, s->encrypted_payload);
    }
    s->encrypted_payload = NULL;

    if (NULL != s->encoded_channel && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_channel);
    }
    if (NULL != s->encoded_message && NULL != allocator->free) {
        PN_FREE(allocator, s->encoded_message);
    }
    s->encoded_channel = NULL;
    s->encoded_message = NULL;

    if (NULL != s->owned_body_buf.data && NULL != allocator->buf_release) {
        allocator->buf_release(allocator, &s->owned_body_buf);
    }

    if (NULL != allocator->free) {
        PN_FREE(allocator, s);
    }
}

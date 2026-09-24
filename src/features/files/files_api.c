/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "files_internal.h"

#if !PUBNUB_ENABLE_FILES
#error "files_api.c requires PUBNUB_ENABLE_FILES=ON"
#endif

#include "core/core_internal.h"
#include "core/pn_format.h"
#include "core/pn_string.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/pipeline_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

#if PUBNUB_ENABLE_CRYPTO
/* Defined in src/features/crypto/crypto_api.c when crypto is enabled. */
pubnub_res_t pn_crypto_module_decrypt(pubnub_crypto_module_t*      module,
                                      const uint8_t*               input,
                                      size_t                       input_len,
                                      uint8_t**                    output,
                                      size_t*                      output_len,
                                      pubnub_allocator_provider_t* alloc);
#else
static inline pubnub_res_t pn_crypto_module_decrypt(pubnub_crypto_module_t* module,
                                                    const uint8_t* input,
                                                    size_t         input_len,
                                                    uint8_t**      output,
                                                    size_t*        output_len,
                                                    pubnub_allocator_provider_t* alloc)
{
    (void)module;
    (void)input;
    (void)input_len;
    if (NULL != output) {
        *output = NULL;
    }
    if (NULL != output_len) {
        *output_len = 0;
    }
    (void)alloc;
    return PUBNUB_ERR_NOT_SUPPORTED;
}
#endif

/**
 * @brief Copy opts string fields into allocator-owned state.
 *
 * @return PUBNUB_OK on success; on failure the state is still valid
 *         for cleanup (partial copies are harmless — cleanup frees
 *         everything non-NULL).
 */
static pubnub_res_t send_file_copy_opts(pn_file_send_state_t*          state,
                                        const pubnub_send_file_opts_t* opts,
                                        pubnub_allocator_provider_t* allocator)
{
    state->channel = pn_strdup(opts->channel, allocator);
    if (NULL == state->channel) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    state->data     = opts->data;
    state->data_len = opts->data_len;

    state->store = opts->store;
    state->ttl   = opts->ttl;

    state->upload_timeout_ms = (0 != opts->upload_timeout_ms)
                                 ? opts->upload_timeout_ms
                                 : PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS;
    state->timeout_ms        = opts->timeout_ms;

    if (NULL != opts->message) {
        state->message = pn_strdup(opts->message, allocator);
        if (NULL == state->message) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    }
    if (NULL != opts->meta) {
        state->meta = pn_strdup(opts->meta, allocator);
        if (NULL == state->meta) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    }
    if (NULL != opts->custom_message_type) {
        state->custom_message_type =
            pn_strdup(opts->custom_message_type, allocator);
        if (NULL == state->custom_message_type) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    }
    if (NULL != opts->content_type) {
        state->content_type = pn_strdup(opts->content_type, allocator);
        if (NULL == state->content_type) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
    }

    return PUBNUB_OK;
}

/**
 * @brief Load file data from disk and derive the basename when file_name
 *        is not explicitly provided.
 *
 * @param[in]  opts       User-provided send options.
 * @param[in]  platform   Platform provider (must have file_load).
 * @param[in]  allocator  Allocator for the loaded buffer.
 * @param[out] out_data   Receives pointer to loaded bytes (caller-owned).
 * @param[out] out_len    Receives byte count.
 * @param[out] out_name   Receives derived basename (points into opts->file_path).
 *
 * @return PUBNUB_OK on success, PUBNUB_ERR_NOT_SUPPORTED if platform
 *         lacks file_load, or a transport/allocation error on load failure.
 */
static pubnub_res_t send_file_load_from_path(const pubnub_send_file_opts_t* opts,
                                             pubnub_platform_provider_t* platform,
                                             pubnub_allocator_provider_t* allocator,
                                             uint8_t**    out_data,
                                             size_t*      out_len,
                                             const char** out_name)
{
    *out_data = NULL;
    *out_len  = 0;
    *out_name = NULL;

    if (NULL == opts->file_path || NULL != opts->data) {
        return PUBNUB_OK;
    }

    if (NULL == platform || NULL == platform->file_load) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }

    pubnub_res_t rc = platform->file_load(
        platform, opts->file_path, allocator, out_data, out_len);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    if (NULL == opts->file_name) {
        const char* p    = opts->file_path;
        const char* base = p;
        while ('\0' != *p) {
            if ('/' == *p || '\\' == *p) {
                base = p + 1;
            }
            ++p;
        }
        *out_name = ('\0' != *base) ? base : opts->file_path;
    }

    return PUBNUB_OK;
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_send_file(pubnub_context_t*              ctx,
                                 const pubnub_send_file_opts_t* opts)
{
    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]
        || (NULL == opts->file_name && NULL == opts->file_path)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (0 != opts->data_len && NULL == opts->data && NULL == opts->file_path) {
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

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    if (NULL == platform) {
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_NOT_INITIALIZED,
                           pubnub_res_str(PUBNUB_ERR_NOT_INITIALIZED),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_NOT_INITIALIZED);
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* file_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_name, file_name)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "send_file params", file_head_);
    }
#endif

    pubnub_serialization_provider_t* serial = pn_context_serialization(ctx);
    if (NULL == serial || NULL == serial->serialize || NULL == serial->parse) {
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_NOT_INITIALIZED,
                           pubnub_res_str(PUBNUB_ERR_NOT_INITIALIZED),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_NOT_INITIALIZED);
    }

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    if (NULL == pipeline || NULL == pipeline->chain_head) {
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_NOT_INITIALIZED,
                           pubnub_res_str(PUBNUB_ERR_NOT_INITIALIZED),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_NOT_INITIALIZED);
    }
    pubnub_transport_provider_t* transport = pipeline->chain_head;

    uint8_t*    loaded_data     = NULL;
    size_t      loaded_data_len = 0;
    const char* derived_name    = NULL;

    pubnub_res_t load_rc = send_file_load_from_path(
        opts, platform, allocator, &loaded_data, &loaded_data_len, &derived_name);
    if (PUBNUB_OK != load_rc) {
        PN_LOG_ERROR_ENTRY(ctx, (int)load_rc, pubnub_res_str(load_rc), NULL);
        return pn_failed_future(load_rc);
    }

    pubnub_send_file_opts_t eff_opts = *opts;
    if (NULL != loaded_data) {
        eff_opts.data     = loaded_data;
        eff_opts.data_len = loaded_data_len;
    }
    if (NULL != derived_name) {
        eff_opts.file_name = derived_name;
    }

    if (NULL == eff_opts.file_name || '\0' == eff_opts.file_name[0]) {
        if (NULL != loaded_data) {
            PN_FREE(allocator, loaded_data);
        }
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_INVALID_ARGUMENT,
                           pubnub_res_str(PUBNUB_ERR_INVALID_ARGUMENT),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* Allocate send state. */
    pn_file_send_state_t* state =
        (pn_file_send_state_t*)PN_ALLOC(allocator, sizeof(*state), sizeof(void*));
    if (NULL == state) {
        if (NULL != loaded_data) {
            PN_FREE(allocator, loaded_data);
        }
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_OUT_OF_MEMORY,
                           pubnub_res_str(PUBNUB_ERR_OUT_OF_MEMORY),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_OUT_OF_MEMORY);
    }
    memset(state, 0, sizeof(*state));

    state->phase            = PN_FILE_SEND_GENERATE_URL;
    state->allocator        = allocator;
    state->ctx              = ctx;
    state->transport        = transport;
    state->pipeline         = pipeline;
    state->platform         = platform;
    state->serialization    = serial;
    state->loaded_file_data = loaded_data;

    pubnub_res_t rc = send_file_copy_opts(state, &eff_opts, allocator);
    if (PUBNUB_OK != rc) {
        pn_file_send_state_cleanup(state, allocator);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    /* Build the generate-upload-url request. */
    pn_pending_entry_t* entry = pn_prep_acquire(ctx);
    if (NULL == entry) {
        pn_file_send_state_cleanup(state, allocator);
        return pn_failed_future(PUBNUB_ERR_QUEUE_FULL);
    }

    rc = pn_pending_entry_init(entry,
                               (uint8_t)PUBNUB_FEATURE_FILES,
                               state,
                               pn_file_send_state_cleanup,
                               NULL,
                               PUBNUB_HTTP_POST,
                               cfg,
                               eff_opts.timeout_ms);
    if (PUBNUB_OK != rc) {
        pn_prep_release(ctx, entry);
        pn_file_send_state_cleanup(state, allocator);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    {
        const pn_file_generate_url_inputs_t inputs = {
            .subscribe_key = cfg->subscribe_key,
            .channel       = eff_opts.channel,
            .file_name     = eff_opts.file_name,
        };

        rc = pn_file_build_generate_url_request(
            &entry->http_request, serial, allocator, &inputs);
    }
    if (PUBNUB_OK != rc) {
        pn_prep_release(ctx, entry);
        pn_file_send_state_cleanup(state, allocator);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }
    /* Track the JSON body so it survives until the slot is reset for the
     * S3 upload step. Cleanup frees it if the state machine aborts
     * before the reset occurs. The cast discards const — the buffer
     * is owned by the allocator and is mutable. */
    state->generate_url_body = (uint8_t*)entry->http_request.body;

    entry->on_complete = pn_file_send_on_generate_complete;
    entry->user_data   = state;

    return pn_dispatch_or_enqueue(ctx, entry);
}

pubnub_future_t pubnub_list_files(pubnub_context_t*               ctx,
                                  const pubnub_list_files_opts_t* opts)
{
    pn_feature_prep_t     prep;
    pn_file_list_state_t* state;
    pubnub_res_t          rc;

    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_FILES,
                            sizeof(pn_file_list_state_t),
                            pn_file_list_state_cleanup,
                            pn_file_list_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state                = (pn_file_list_state_t*)prep.state;
    state->allocator     = prep.allocator;
    state->serialization = pn_context_serialization(ctx);

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* file_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->channel, channel)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "list_files params", file_head_);
    }
#endif

    {
        const pn_file_list_inputs_t inputs = {
            .subscribe_key = prep.cfg->subscribe_key,
            .channel       = opts->channel,
            .limit         = opts->limit,
            .next          = opts->next,
        };

        rc = pn_file_build_list_request(&prep.entry->http_request, &inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

pubnub_future_t pubnub_delete_file(pubnub_context_t*                ctx,
                                   const pubnub_delete_file_opts_t* opts)
{
    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]
        || NULL == opts->file_id || '\0' == opts->file_id[0]
        || NULL == opts->file_name || '\0' == opts->file_name[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    const pubnub_config_t* cfg = NULL;
    if (PUBNUB_OK != pn_validate_ctx(ctx, &cfg)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* file_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_id, file_id)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_name, file_name)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "delete_file params", file_head_);
    }
#endif

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    if (NULL == pipeline) {
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_NOT_INITIALIZED,
                           pubnub_res_str(PUBNUB_ERR_NOT_INITIALIZED),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_NOT_INITIALIZED);
    }

    pn_pending_entry_t* entry = pn_prep_acquire(ctx);
    if (NULL == entry) {
        return pn_failed_future(PUBNUB_ERR_QUEUE_FULL);
    }

    {
        pubnub_res_t rc = pn_pending_entry_init(entry,
                                                (uint8_t)PUBNUB_FEATURE_FILES,
                                                NULL,
                                                NULL,
                                                NULL,
                                                PUBNUB_HTTP_DELETE,
                                                cfg,
                                                opts->timeout_ms);
        if (PUBNUB_OK != rc) {
            pn_prep_release(ctx, entry);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    {
        const pn_file_delete_inputs_t inputs = {
            .subscribe_key = cfg->subscribe_key,
            .channel       = opts->channel,
            .file_id       = opts->file_id,
            .file_name     = opts->file_name,
        };
        pubnub_res_t rc =
            pn_file_build_delete_request(&entry->http_request, &inputs);
        if (PUBNUB_OK != rc) {
            pn_prep_release(ctx, entry);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, entry);
}

pubnub_future_t pubnub_download_file(pubnub_context_t*                  ctx,
                                     const pubnub_download_file_opts_t* opts)
{
    pn_feature_prep_t         prep;
    pn_file_download_state_t* state;
    pubnub_res_t              rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]
        || NULL == opts->file_id || '\0' == opts->file_id[0]
        || NULL == opts->file_name || '\0' == opts->file_name[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_FILES,
                            sizeof(pn_file_download_state_t),
                            pn_file_download_state_cleanup,
                            pn_file_download_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state            = (pn_file_download_state_t*)prep.state;
    state->allocator = prep.allocator;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* file_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_id, file_id)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_name, file_name)
        PN_LOG_OBJECT(ctx, PUBNUB_LOG_LEVEL_DEBUG, "download_file params", file_head_);
    }
#endif

    {
        const pn_file_download_inputs_t inputs = {
            .subscribe_key = prep.cfg->subscribe_key,
            .channel       = opts->channel,
            .file_id       = opts->file_id,
            .file_name     = opts->file_name,
        };

        rc = pn_file_build_download_request(&prep.entry->http_request, &inputs);
        if (PUBNUB_OK != rc) {
            pn_feature_prep_release(ctx, &prep);
            PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
            return pn_failed_future(rc);
        }
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

/* NOLINTNEXTLINE(readability-function-size) */
pubnub_future_t pubnub_publish_file_message(pubnub_context_t* ctx,
                                            const pubnub_publish_file_message_opts_t* opts)
{
    pn_feature_prep_t                prep;
    pn_file_publish_state_t*         state;
    pubnub_serialization_provider_t* serial;
    pubnub_crypto_module_t*          crypto_mod = NULL;
    pn_file_publish_encoded_t        encoded    = {0};
    pubnub_res_t                     rc;

    if (NULL == opts) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]
        || NULL == opts->file_id || '\0' == opts->file_id[0]
        || NULL == opts->file_name || '\0' == opts->file_name[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_FILES,
                            sizeof(pn_file_publish_state_t),
                            pn_file_publish_state_cleanup,
                            pn_file_publish_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_file_publish_state_t*)prep.state;

    if (NULL == prep.cfg->publish_key) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx,
                           (int)PUBNUB_ERR_INVALID_ARGUMENT,
                           pubnub_res_str(PUBNUB_ERR_INVALID_ARGUMENT),
                           NULL);
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    serial = pn_context_serialization(ctx);
    if (NULL == serial) {
        rc = PUBNUB_ERR_NOT_INITIALIZED;
        goto cleanup;
    }
    state->allocator     = prep.allocator;
    state->serialization = serial;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* file_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_id, file_id)
        PUBNUB_LOG_MAP_SET_STRING(file_head_, opts->file_name, file_name)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "publish_file_message params", file_head_);
    }
#endif

    if (PUBNUB_ENABLE_CRYPTO) {
        crypto_mod = pn_context_crypto_module(ctx);
    }

    {
        const pn_file_publish_inputs_t inputs = {
            .publish_key         = prep.cfg->publish_key,
            .subscribe_key       = prep.cfg->subscribe_key,
            .channel             = opts->channel,
            .file_id             = opts->file_id,
            .file_name           = opts->file_name,
            .message             = opts->message,
            .meta                = opts->meta,
            .custom_message_type = opts->custom_message_type,
            .store               = opts->store,
            .ttl                 = opts->ttl,
        };

        rc = pn_file_build_publish_request(&prep.entry->http_request,
                                           prep.allocator,
                                           serial,
                                           &inputs,
                                           crypto_mod,
                                           &encoded);
        if (PUBNUB_OK != rc) {
            goto cleanup;
        }
    }
    state->encoded_channel = encoded.channel;
    state->encoded_message = encoded.message;

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_res_t pubnub_get_file_url(pubnub_context_t*                 ctx,
                                 const pubnub_get_file_url_opts_t* opts,
                                 char*                             buf,
                                 size_t                            buf_size,
                                 size_t*                           out_len)
{
    if (NULL == opts || NULL == buf) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == opts->channel || '\0' == opts->channel[0]
        || NULL == opts->file_id || '\0' == opts->file_id[0]
        || NULL == opts->file_name || '\0' == opts->file_name[0]) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    const pubnub_config_t* cfg = NULL;
    if (PUBNUB_OK != pn_validate_ctx(ctx, &cfg)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == cfg->origin) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_allocator_provider_t* alloc = pn_context_allocator(ctx);
    if (NULL == alloc) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    /* Percent-encode path components via allocator to avoid large stack buffers. */
    char* enc_channel = pn_url_encode_alloc_n(
        (const uint8_t*)opts->channel, strlen(opts->channel), alloc, PN_ENCODE_FULL);
    char* enc_file_id = pn_url_encode_alloc_n(
        (const uint8_t*)opts->file_id, strlen(opts->file_id), alloc, PN_ENCODE_FULL);
    char* enc_file_name = pn_url_encode_alloc_n((const uint8_t*)opts->file_name,
                                                strlen(opts->file_name),
                                                alloc,
                                                PN_ENCODE_FULL);

    if (NULL == enc_channel || NULL == enc_file_id || NULL == enc_file_name) {
        pn_strfree(enc_channel, alloc);
        pn_strfree(enc_file_id, alloc);
        pn_strfree(enc_file_name, alloc);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Format: https://{origin}/v1/files/{sub_key}/channels/{channel}/
     *         files/{id}/{name} */
    const char* scheme = PUBNUB_ENABLE_SECURE_TRANSPORT ? "https" : "http";

    int needed = pn_snprintf(buf,
                             buf_size,
                             "%s://%s/v1/files/%s/channels/%s/files/%s/%s",
                             scheme,
                             cfg->origin,
                             cfg->subscribe_key,
                             enc_channel,
                             enc_file_id,
                             enc_file_name);

    pn_strfree(enc_channel, alloc);
    pn_strfree(enc_file_id, alloc);
    pn_strfree(enc_file_name, alloc);

    if (needed < 0) {
        return PUBNUB_ERR_INTERNAL;
    }

    if (NULL != out_len) {
        *out_len = (size_t)needed;
    }

    if ((size_t)needed >= buf_size) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    return PUBNUB_OK;
}

pubnub_send_file_result_t pubnub_send_file_result(pubnub_future_t future)
{
    pubnub_send_file_result_t result = {
        .id        = {NULL, 0},
        .name      = {NULL, 0},
        .timetoken = {NULL, 0},
    };

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_FILES);
    if (NULL == state) {
        return result;
    }

    const pn_file_send_state_t* send = (const pn_file_send_state_t*)state;
    if (PN_FILE_SEND_DONE != send->phase
        && PN_FILE_SEND_PUBLISH_FAILED != send->phase) {
        return result;
    }

    if (NULL != send->file_id) {
        result.id.ptr = send->file_id;
        result.id.len = strlen(send->file_id);
    }
    if (NULL != send->file_name) {
        result.name.ptr = send->file_name;
        result.name.len = strlen(send->file_name);
    }
    if (PN_FILE_SEND_DONE == send->phase) {
        result.timetoken = send->timetoken;
    }

    return result;
}

pubnub_list_files_result_t pubnub_list_files_result(pubnub_future_t future)
{
    pubnub_list_files_result_t result = {
        .count = 0, .next = {NULL, 0}
    };

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_FILES);
    if (NULL == state) {
        return result;
    }

    pn_file_list_state_t* list_state = (pn_file_list_state_t*)state;

    /* Lazy parse on first accessor call. */
    if (NULL == list_state->parsed && NULL != list_state->serialization) {
        pubnub_json_value_t* tree =
            pn_request_get_parsed_body(slot, list_state->serialization);
        list_state->parsed = tree;
    }

    if (NULL == list_state->parsed || NULL == list_state->serialization) {
        return result;
    }

    pubnub_serialization_provider_t* serial = list_state->serialization;

    /* Extract "data" array for count. */
    pubnub_json_value_t* data_arr =
        serial->object_get(list_state->parsed, "data", 4);
    if (NULL != data_arr) {
        result.count = (uint32_t)serial->array_size(data_arr);
    }

    /* Extract "next" pagination token. */
    pubnub_json_value_t* next_val =
        serial->object_get(list_state->parsed, "next", 4);
    if (NULL != next_val) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(next_val, &len);
        if (NULL != ptr && len > 0) {
            result.next.ptr = ptr;
            result.next.len = len;
        }
    }

    return result;
}

pubnub_file_info_t pubnub_list_files_result_file_at(pubnub_future_t future,
                                                    size_t          index)
{
    pubnub_file_info_t info = {
        .id      = {NULL, 0},
        .name    = {NULL, 0},
        .size    = 0,
        .created = {NULL, 0},
    };

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return info;
    }

    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_FILES);
    if (NULL == state) {
        return info;
    }

    pn_file_list_state_t* list_state = (pn_file_list_state_t*)state;

    /* Ensure parsed tree is available. */
    if (NULL == list_state->parsed && NULL != list_state->serialization) {
        pubnub_json_value_t* tree =
            pn_request_get_parsed_body(slot, list_state->serialization);
        list_state->parsed = tree;
    }

    if (NULL == list_state->parsed || NULL == list_state->serialization) {
        return info;
    }

    pubnub_serialization_provider_t* serial = list_state->serialization;

    pubnub_json_value_t* data_arr =
        serial->object_get(list_state->parsed, "data", 4);
    if (NULL == data_arr) {
        return info;
    }

    pubnub_json_value_t* item = pn_json_array_cursor_get(serial,
                                                         data_arr,
                                                         index,
                                                         &list_state->iter_cache,
                                                         &list_state->iter_pos,
                                                         &list_state->iter_valid);
    if (NULL == item) {
        return info;
    }

    /* Extract fields from the file object. */
    pubnub_json_value_t* id_val = serial->object_get(item, "id", 2);
    if (NULL != id_val) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(id_val, &len);
        if (NULL != ptr) {
            info.id.ptr = ptr;
            info.id.len = len;
        }
    }

    pubnub_json_value_t* name_val = serial->object_get(item, "name", 4);
    if (NULL != name_val) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(name_val, &len);
        if (NULL != ptr) {
            info.name.ptr = ptr;
            info.name.len = len;
        }
    }

    pubnub_json_value_t* size_val = serial->object_get(item, "size", 4);
    if (NULL != size_val && NULL != serial->value_as_int) {
        int sz = 0;
        if (PUBNUB_OK == serial->value_as_int(size_val, &sz) && sz >= 0) {
            info.size = (uint32_t)sz;
        }
    }

    pubnub_json_value_t* created_val = serial->object_get(item, "created", 7);
    if (NULL != created_val) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(created_val, &len);
        if (NULL != ptr) {
            info.created.ptr = ptr;
            info.created.len = len;
        }
    }

    return info;
}

pubnub_download_file_result_t pubnub_download_file_result(pubnub_future_t future)
{
    pubnub_download_file_result_t result = {
        .data = NULL, .data_len = 0, .decrypted = 0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_FILES);

    /* If crypto was active, the download state has decrypted data. */
    if (NULL != state) {
        pn_file_download_state_t* dl = (pn_file_download_state_t*)state;
        if (NULL != dl->decrypted) {
            result.data      = dl->decrypted;
            result.data_len  = dl->decrypted_len;
            result.decrypted = 1;
            return result;
        }

        /* Lazy decrypt on first access when crypto module is configured. */
        if (PUBNUB_ENABLE_CRYPTO && NULL != slot->http_response.body
            && slot->http_response.body_len > 0) {
            pubnub_crypto_module_t* crypto_mod =
                pn_context_crypto_module(future.ctx);
            if (NULL != crypto_mod && NULL != dl->allocator) {
                pubnub_res_t dec_rc =
                    pn_crypto_module_decrypt(crypto_mod,
                                             slot->http_response.body,
                                             slot->http_response.body_len,
                                             &dl->decrypted,
                                             &dl->decrypted_len,
                                             dl->allocator);
                if (PUBNUB_OK == dec_rc && NULL != dl->decrypted) {
                    result.data      = dl->decrypted;
                    result.data_len  = dl->decrypted_len;
                    result.decrypted = 1;
                    return result;
                }
            }
        }
    }

    /* No crypto or decryption failed — return raw HTTP response body. */
    result.data     = slot->http_response.body;
    result.data_len = slot->http_response.body_len;

    return result;
}

pubnub_publish_file_message_result_t
pubnub_publish_file_message_result(pubnub_future_t future)
{
    pubnub_publish_file_message_result_t result = {
        .timetoken = {NULL, 0}
    };

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_FILES);
    if (NULL == state) {
        return result;
    }

    pn_file_publish_state_t* pub_state = (pn_file_publish_state_t*)state;

    /* Lazy parse on first call. */
    if (NULL == pub_state->parsed_tree && NULL != pub_state->serialization) {
        pubnub_json_value_t* tree =
            pn_request_get_parsed_body(slot, pub_state->serialization);
        if (NULL != tree) {
            pubnub_timetoken_t tt = {NULL, 0};
            pubnub_res_t       rc =
                pn_file_parse_publish_response(pub_state->serialization, tree, &tt);
            if (PUBNUB_OK == rc) {
                pub_state->parsed_tree = tree;
                pub_state->timetoken   = tt;
            }
        }
    }

    result.timetoken = pub_state->timetoken;
    return result;
}

void pn_file_list_state_cleanup(void*                        state_ptr,
                                pubnub_allocator_provider_t* allocator)
{
    if (NULL == state_ptr) {
        return;
    }

    pn_file_list_state_t* state = (pn_file_list_state_t*)state_ptr;

    /* The parsed tree is owned by the request slot's parsed_body cache
     * (via pn_request_get_parsed_body). It is destroyed when the slot
     * resets; we do NOT destroy it here to avoid double-free. We only
     * clear our reference. */
    state->parsed = NULL;

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, state);
    }
}

void pn_file_download_state_cleanup(void*                        state_ptr,
                                    pubnub_allocator_provider_t* allocator)
{
    if (NULL == state_ptr) {
        return;
    }

    pn_file_download_state_t* state = (pn_file_download_state_t*)state_ptr;

    if (NULL != state->decrypted && NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, state->decrypted);
        state->decrypted = NULL;
    }

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, state);
    }
}

void pn_file_publish_state_cleanup(void*                        state_ptr,
                                   pubnub_allocator_provider_t* allocator)
{
    if (NULL == state_ptr) {
        return;
    }

    pn_file_publish_state_t* state = (pn_file_publish_state_t*)state_ptr;

    if (NULL != state->encoded_channel && NULL != allocator
        && NULL != allocator->free) {
        PN_FREE(allocator, state->encoded_channel);
    }
    if (NULL != state->encoded_message && NULL != allocator
        && NULL != allocator->free) {
        PN_FREE(allocator, state->encoded_message);
    }

    /* parsed_tree is from pn_request_get_parsed_body — slot owns it. */
    state->parsed_tree = NULL;

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, state);
    }
}

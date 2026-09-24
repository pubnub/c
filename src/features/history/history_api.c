/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "history_internal.h"

#if !PUBNUB_ENABLE_HISTORY
#error "history_api.c requires PUBNUB_ENABLE_HISTORY=ON"
#endif

#include "core/core_internal.h"
#include "core/protocol_common/pn_url_encode.h"
#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"
#include "core/runtime/request_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if PUBNUB_ENABLE_CRYPTO
/* Forward declaration — avoids cross-feature include coupling.
 * The definition lives in src/features/crypto/crypto_api.c. */
pubnub_res_t pn_crypto_module_decrypt_from_base64(pubnub_crypto_module_t* module,
                                                  const char* base64,
                                                  size_t      base64_len,
                                                  uint8_t**   output,
                                                  size_t*     output_len,
                                                  pubnub_allocator_provider_t* alloc);
#endif

/**
 * @brief Return non-zero if @p channels contains a comma.
 */
static int has_comma(const char* channels)
{
    for (const char* p = channels; '\0' != *p; ++p) {
        if (',' == *p) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Get the cached fetch parse for a history slot.
 *
 * Triggers lazy parsing on first call.
 */
static const pn_history_fetch_parsed_t*
get_fetch_parse(pn_request_t*               slot,
                const pubnub_future_t       future,
                pn_history_state_t*         state,
                pn_history_fetch_parsed_t** parsed_slot)
{
    if (NULL != *parsed_slot) {
        return *parsed_slot;
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

    pn_history_fetch_parsed_t* cached = (pn_history_fetch_parsed_t*)PN_ALLOC(
        allocator, sizeof(pn_history_fetch_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, allocator, cached);
    if (PUBNUB_OK != rc) {
        if (NULL != cached->channel_entries) {
            PN_FREE(allocator, cached->channel_entries);
        }
        PN_FREE(allocator, cached);
        return NULL;
    }

    *parsed_slot  = cached;
    state->parsed = cached;
    return cached;
}

/**
 * @brief Get the cached counts parse for a history slot.
 *
 * Triggers lazy parsing on first call.
 */
static const pn_history_counts_parsed_t*
get_counts_parse(pn_request_t*                slot,
                 const pubnub_future_t        future,
                 pn_history_state_t*          state,
                 pn_history_counts_parsed_t** parsed_slot)
{
    if (NULL != *parsed_slot) {
        return *parsed_slot;
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

    pn_history_counts_parsed_t* cached = (pn_history_counts_parsed_t*)PN_ALLOC(
        allocator, sizeof(pn_history_counts_parsed_t), 0);
    if (NULL == cached) {
        return NULL;
    }
    memset(cached, 0, sizeof(*cached));

    pubnub_res_t rc = pn_history_parse_counts(serial, tree, allocator, cached);
    if (PUBNUB_OK != rc) {
        if (NULL != cached->channel_entries) {
            PN_FREE(allocator, cached->channel_entries);
        }
        PN_FREE(allocator, cached);
        return NULL;
    }

    *parsed_slot  = cached;
    state->parsed = cached;
    return cached;
}

/**
 * @brief Resolve history state from a ready slot.
 */
static pn_history_state_t* history_state_for(pn_request_t* slot)
{
    void* state = pn_request_feature_state_for(slot, PUBNUB_FEATURE_HISTORY);
    if (NULL == state) {
        return NULL;
    }
    return (pn_history_state_t*)state;
}

#if PUBNUB_ENABLE_CRYPTO
/**
 * @brief Attempt transparent decryption of an encrypted message payload.
 *
 * @param serial          Serialization provider.
 * @param result          Message result with encrypted payload node.
 * @param crypto          Crypto module.
 * @param fp              Fetch parsed state for caching decrypted tree.
 * @param channel_index   Channel index (for cache key).
 * @param message_index   Message index (for cache key).
 * @return Decrypted JSON tree, or NULL on failure (pass-through original).
 */
static pubnub_json_value_t*
decrypt_message_payload(pubnub_serialization_provider_t*       serial,
                        const pubnub_history_message_result_t* result,
                        pubnub_crypto_module_t*                crypto,
                        pn_history_fetch_parsed_t*             fp,
                        size_t                                 channel_index,
                        size_t                                 message_index)
{
    if (NULL == crypto || NULL == fp->allocator || NULL == fp->serial
        || NULL == fp->serial->parse) {
        return NULL;
    }

    /* Cache hit — same indices already decrypted. */
    if (channel_index == fp->cached_channel_idx && message_index == fp->cached_message_idx
        && NULL != fp->decrypted_msg_tree) {
        return fp->decrypted_msg_tree;
    }

    /* Cache miss — destroy old tree and decrypt fresh. */
    if (NULL != fp->decrypted_msg_tree) {
        fp->serial->value_destroy(fp->serial, fp->decrypted_msg_tree);
        fp->decrypted_msg_tree = NULL;
        fp->cached_channel_idx = SIZE_MAX;
        fp->cached_message_idx = SIZE_MAX;
    }

    size_t cipher_len = 0;
    const char* cipher_ptr = serial->value_as_string(result->message, &cipher_len);
    if (NULL == cipher_ptr || cipher_len <= 2) {
        return NULL;
    }

    uint8_t*     decrypted = NULL;
    size_t       dec_len   = 0;
    pubnub_res_t dec_rc    = pn_crypto_module_decrypt_from_base64(
        crypto, cipher_ptr, cipher_len, &decrypted, &dec_len, fp->allocator);

    if (PUBNUB_OK != dec_rc || NULL == decrypted || 0 == dec_len) {
        return NULL;
    }

    pubnub_json_value_t* tree = fp->serial->parse(fp->serial, decrypted, dec_len);
    PN_FREE(fp->allocator, decrypted);

    if (NULL != tree) {
        fp->decrypted_msg_tree = tree;
        fp->cached_channel_idx = channel_index;
        fp->cached_message_idx = message_index;
    }

    return tree;
}
#endif

/**
 * @brief Extract a message result from a specific position in the
 *        fetch-messages parsed cache.
 */
static pubnub_history_message_result_t
extract_message(pubnub_serialization_provider_t*        serial,
                const pn_history_fetch_channel_entry_t* ch_entry,
                size_t                                  message_index)
{
    pubnub_history_message_result_t   result;
    pn_history_fetch_channel_entry_t* mut =
        (pn_history_fetch_channel_entry_t*)ch_entry;
    memset(&result, 0, sizeof(result));
    result.event_type = PUBNUB_EVENT_TYPE_UNKNOWN;

    if (NULL == ch_entry->messages_array || NULL == serial
        || NULL == serial->array_get || NULL == serial->value_type
        || NULL == serial->object_get || NULL == serial->value_as_string) {
        return result;
    }

    const pubnub_json_value_t* msg_node =
        pn_json_array_cursor_get(serial,
                                 ch_entry->messages_array,
                                 message_index,
                                 &mut->iter_cache,
                                 &mut->iter_pos,
                                 &mut->iter_valid);
    if (NULL == msg_node || PUBNUB_JSON_OBJECT != serial->value_type(msg_node)) {
        return result;
    }

    /* Message payload: expose the parsed node directly. Callers use
     * serialization vtable accessors (value_as_string, object_get,
     * etc.) to read the value regardless of JSON type. */
    result.message = serial->object_get(msg_node, "message", 7);

    /* "timetoken" */
    const pubnub_json_value_t* tt_field =
        serial->object_get(msg_node, "timetoken", 9);
    if (NULL != tt_field && PUBNUB_JSON_STRING == serial->value_type(tt_field)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(tt_field, &len);
        if (NULL != ptr) {
            result.timetoken.ptr = ptr;
            result.timetoken.len = len;
        }
    }

    /* "uuid" */
    const pubnub_json_value_t* uuid_field = serial->object_get(msg_node, "uuid", 4);
    if (NULL != uuid_field && PUBNUB_JSON_STRING == serial->value_type(uuid_field)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(uuid_field, &len);
        if (NULL != ptr) {
            result.uuid.ptr = ptr;
            result.uuid.len = len;
        }
    }

    /* Meta: expose the parsed node directly. */
    result.meta = serial->object_get(msg_node, "meta", 4);

    /* "message_type" — PubNub returns null for regular messages. */
    const pubnub_json_value_t* mt_field =
        serial->object_get(msg_node, "message_type", 12);
    if (NULL != mt_field) {
        if (NULL != serial->value_as_int
            && PUBNUB_JSON_INT == serial->value_type(mt_field)) {
            int mt_val = 0;
            if (PUBNUB_OK == serial->value_as_int(mt_field, &mt_val)) {
                result.event_type = (pubnub_event_type_t)mt_val;
            }
        } else if (PUBNUB_JSON_NULL == serial->value_type(mt_field)) {
            result.event_type = PUBNUB_EVENT_TYPE_MESSAGE;
        }
    }

    /* "custom_message_type" */
    const pubnub_json_value_t* cmt_field =
        serial->object_get(msg_node, "custom_message_type", 19);
    if (NULL != cmt_field && PUBNUB_JSON_STRING == serial->value_type(cmt_field)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(cmt_field, &len);
        if (NULL != ptr) {
            result.custom_message_type.ptr = ptr;
            result.custom_message_type.len = len;
        }
    }

    return result;
}

// NOLINTNEXTLINE(misc-use-internal-linkage, readability-function-size)
pubnub_future_t pubnub_fetch_messages(pubnub_context_t*                   ctx,
                                      const pubnub_fetch_messages_opts_t* opts)
{
    pn_feature_prep_t    prep;
    pn_history_state_t*  state;
    char*                encoded;
    pubnub_string_view_t channels_view;
    pubnub_res_t         rc;

    if (NULL == opts || NULL == opts->channels || '\0' == opts->channels[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* With-actions requires single channel. */
    if (0 != opts->include_message_actions && has_comma(opts->channels)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_HISTORY,
                            sizeof(pn_history_state_t),
                            pn_history_feature_state_cleanup,
                            pn_history_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_history_state_t*)prep.state;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* hist_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(hist_head_, opts->channels, channels)
        PUBNUB_LOG_MAP_SET_NUMBER(hist_head_, (int64_t)opts->count, max_per_channel)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "fetch_messages params", hist_head_);
    }
#endif

    /* Encode channels for path. */
    encoded = pn_url_encode_alloc_n((const uint8_t*)opts->channels,
                                    strlen(opts->channels),
                                    prep.allocator,
                                    PN_ENCODE_KEEP_COMMAS);
    if (NULL == encoded) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    state->encoded_channels = encoded;
    state->operation        = (uint8_t)PN_HISTORY_OP_FETCH;

    /* Build path. */
    channels_view.ptr = encoded;
    channels_view.len = strlen(encoded);
    rc                = pn_history_build_fetch_path(&prep.entry->http_request,
                                     prep.cfg->subscribe_key,
                                     channels_view,
                                     0 != opts->include_message_actions);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    /* Build query params. */
    rc = pn_history_add_fetch_query_params(&prep.entry->http_request, opts);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

// NOLINTNEXTLINE(misc-use-internal-linkage, readability-function-size)
pubnub_future_t pubnub_delete_messages(pubnub_context_t* ctx,
                                       const pubnub_delete_messages_opts_t* opts)
{
    pn_feature_prep_t    prep;
    pn_history_state_t*  state;
    char*                encoded;
    pubnub_string_view_t channel_view;
    pubnub_res_t         rc;

    if (NULL == opts || NULL == opts->channel || '\0' == opts->channel[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_HISTORY,
                            sizeof(pn_history_state_t),
                            pn_history_feature_state_cleanup,
                            pn_history_delete_response_validator,
                            PUBNUB_HTTP_DELETE,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_history_state_t*)prep.state;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* hist_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(hist_head_, opts->channel, channel)
        PUBNUB_LOG_MAP_SET_STRING(hist_head_, opts->start, start)
        PUBNUB_LOG_MAP_SET_STRING(hist_head_, opts->end, end)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "delete_messages params", hist_head_);
    }
#endif

    /* Encode single channel. */
    encoded = pn_url_encode_alloc_n((const uint8_t*)opts->channel,
                                    strlen(opts->channel),
                                    prep.allocator,
                                    PN_ENCODE_KEEP_COMMAS);
    if (NULL == encoded) {
        rc = PUBNUB_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    state->encoded_channels = encoded;
    state->operation        = (uint8_t)PN_HISTORY_OP_DELETE;

    channel_view.ptr = encoded;
    channel_view.len = strlen(encoded);
    rc               = pn_history_build_delete_path(
        &prep.entry->http_request, prep.cfg->subscribe_key, channel_view);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_history_add_delete_query_params(&prep.entry->http_request, opts);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

// NOLINTNEXTLINE(misc-use-internal-linkage, readability-function-size)
pubnub_future_t pubnub_message_counts(pubnub_context_t*                   ctx,
                                      const pubnub_message_counts_opts_t* opts)
{
    pn_feature_prep_t    prep;
    pn_history_state_t*  state;
    char*                encoded;
    pubnub_string_view_t channels_view;
    pubnub_res_t         rc;

    if (NULL == opts || NULL == opts->channels || '\0' == opts->channels[0]) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    /* Exactly one of timetoken / channels_timetokens. */
    if ((NULL == opts->timetoken && NULL == opts->channels_timetokens)
        || (NULL != opts->timetoken && NULL != opts->channels_timetokens)) {
        return pn_failed_future(PUBNUB_ERR_INVALID_ARGUMENT);
    }

    rc = pn_feature_prepare(ctx,
                            (uint8_t)PUBNUB_FEATURE_HISTORY,
                            sizeof(pn_history_state_t),
                            pn_history_feature_state_cleanup,
                            pn_history_response_validator,
                            PUBNUB_HTTP_GET,
                            opts->timeout_ms,
                            &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }
    state = (pn_history_state_t*)prep.state;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (pn_log_would_emit(ctx, PUBNUB_LOG_LEVEL_DEBUG)) {
        pubnub_log_value_t* hist_head_ = NULL;
        PUBNUB_LOG_MAP_SET_STRING(hist_head_, opts->channels, channels)
        PUBNUB_LOG_MAP_SET_STRING(hist_head_, opts->timetoken, timetoken)
        PN_LOG_OBJECT(
            ctx, PUBNUB_LOG_LEVEL_DEBUG, "message_counts params", hist_head_);
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
    state->operation        = (uint8_t)PN_HISTORY_OP_COUNTS;

    channels_view.ptr = encoded;
    channels_view.len = strlen(encoded);
    rc                = pn_history_build_counts_path(
        &prep.entry->http_request, prep.cfg->subscribe_key, channels_view);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    rc = pn_history_add_counts_query_params(&prep.entry->http_request, opts);
    if (PUBNUB_OK != rc) {
        goto cleanup;
    }

    return pn_dispatch_or_enqueue(ctx, prep.entry);

cleanup:
    pn_feature_prep_release(ctx, &prep);
    PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
    return pn_failed_future(rc);
}

pubnub_fetch_messages_result_t
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_fetch_messages_result(const pubnub_future_t future)
{
    pubnub_fetch_messages_result_t result = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_FETCH != state->operation) {
        return result;
    }

    pn_history_fetch_parsed_t** parsed_slot =
        (pn_history_fetch_parsed_t**)&state->parsed;
    const pn_history_fetch_parsed_t* cached =
        get_fetch_parse(slot, future, state, parsed_slot);
    if (NULL == cached) {
        return result;
    }

    result.channel_count = cached->channel_count;
    result.next          = cached->next_cursor;
    return result;
}

pubnub_fetch_messages_channel_result_t
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_fetch_messages_result_channel_at(const pubnub_future_t future,
                                        const size_t          index)
{
    pubnub_fetch_messages_channel_result_t result = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_FETCH != state->operation) {
        return result;
    }

    pn_history_fetch_parsed_t** parsed_slot =
        (pn_history_fetch_parsed_t**)&state->parsed;
    const pn_history_fetch_parsed_t* cached =
        get_fetch_parse(slot, future, state, parsed_slot);
    if (NULL == cached || index >= cached->channel_count) {
        return result;
    }

    result.name          = cached->channel_entries[index].name;
    result.message_count = cached->channel_entries[index].message_count;
    return result;
}

#if PUBNUB_ENABLE_CRYPTO
/** @brief True when the message payload is a base64 string that should be decrypted. */
static int should_decrypt_message(const pubnub_serialization_provider_t* serial,
                                  const pubnub_history_message_result_t* result)
{
    if (NULL == serial) {
        return 0;
    }
    if (PUBNUB_EVENT_TYPE_MESSAGE != result->event_type
        && PUBNUB_EVENT_TYPE_UNKNOWN != result->event_type
        && PUBNUB_EVENT_TYPE_FILE != result->event_type) {
        return 0;
    }
    return NULL != result->message && NULL != serial->value_type
        && PUBNUB_JSON_STRING == serial->value_type(result->message);
}
#endif

pubnub_history_message_result_t
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_fetch_messages_result_message_at(const pubnub_future_t future,
                                        const size_t          channel_index,
                                        const size_t          message_index)
{
    pubnub_history_message_result_t result;
    memset(&result, 0, sizeof(result));
    result.event_type = PUBNUB_EVENT_TYPE_UNKNOWN;

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_FETCH != state->operation) {
        return result;
    }

    pn_history_fetch_parsed_t** parsed_slot =
        (pn_history_fetch_parsed_t**)&state->parsed;
    const pn_history_fetch_parsed_t* cached =
        get_fetch_parse(slot, future, state, parsed_slot);
    if (NULL == cached || channel_index >= cached->channel_count) {
        return result;
    }

    const pn_history_fetch_channel_entry_t* ch_entry =
        &cached->channel_entries[channel_index];
    if (message_index >= ch_entry->message_count) {
        return result;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    result = extract_message(serial, ch_entry, message_index);

#if PUBNUB_ENABLE_CRYPTO
    /* Attempt transparent decryption for encrypted message types. */
    if (should_decrypt_message(serial, &result)) {
        pubnub_crypto_module_t* crypto = pn_context_crypto_module(future.ctx);
        pn_history_fetch_parsed_t* fp = (pn_history_fetch_parsed_t*)state->parsed;
        if (NULL != crypto) {
            pubnub_json_value_t* tree = decrypt_message_payload(
                serial, &result, crypto, fp, channel_index, message_index);
            if (NULL != tree) {
                result.message = tree;
            } else {
                result.crypto_result = PUBNUB_ERR_CRYPTO;
            }
        }
    }
#endif

    return result;
}

#if PUBNUB_ENABLE_CRYPTO
/**
 * @brief Decrypt and parse a file message payload.
 *
 * Decodes the base64 cipher text from @p cipher_field, decrypts it via the
 * crypto module, then parses the resulting plaintext as JSON.
 *
 * @param serial    Serialization provider (must have parse vtable entry).
 * @param cipher_field  JSON string node holding base64-encoded ciphertext.
 * @param crypto    Crypto module for decryption.
 * @param allocator Allocator for intermediate decrypt buffer.
 * @return Parsed JSON tree (caller takes ownership), or NULL on failure.
 */
static pubnub_json_value_t*
decrypt_file_payload(pubnub_serialization_provider_t* serial,
                     const pubnub_json_value_t*       cipher_field,
                     pubnub_crypto_module_t*          crypto,
                     pubnub_allocator_provider_t*     allocator)
{
    if (NULL == serial->parse) {
        return NULL;
    }

    size_t      cipher_len = 0;
    const char* cipher_ptr = serial->value_as_string(cipher_field, &cipher_len);
    if (NULL == cipher_ptr || cipher_len <= 2) {
        return NULL;
    }

    uint8_t*     decrypted = NULL;
    size_t       dec_len   = 0;
    pubnub_res_t dec_rc    = pn_crypto_module_decrypt_from_base64(
        crypto, cipher_ptr, cipher_len, &decrypted, &dec_len, allocator);
    if (PUBNUB_OK != dec_rc || NULL == decrypted || 0 == dec_len) {
        return NULL;
    }

    pubnub_json_value_t* tree = serial->parse(serial, decrypted, dec_len);
    PN_FREE(allocator, decrypted);

    if (NULL != tree && PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        serial->value_destroy(serial, tree);
        return NULL;
    }

    return tree;
}
#endif

pubnub_history_file_result_t
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_fetch_messages_result_file_at(const pubnub_future_t future,
                                     const size_t          channel_index,
                                     const size_t          message_index)
{
    pubnub_history_file_result_t result = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_FETCH != state->operation) {
        return result;
    }

    pn_history_fetch_parsed_t** parsed_slot =
        (pn_history_fetch_parsed_t**)&state->parsed;
    const pn_history_fetch_parsed_t* cached =
        get_fetch_parse(slot, future, state, parsed_slot);
    if (NULL == cached || channel_index >= cached->channel_count) {
        return result;
    }

    const pn_history_fetch_channel_entry_t* ch_entry =
        &cached->channel_entries[channel_index];
    pn_history_fetch_channel_entry_t* mut =
        (pn_history_fetch_channel_entry_t*)ch_entry;
    if (message_index >= ch_entry->message_count) {
        return result;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    if (NULL == serial || NULL == serial->array_get || NULL == serial->value_type
        || NULL == serial->object_get || NULL == serial->value_as_string) {
        return result;
    }

    const pubnub_json_value_t* msg_node =
        pn_json_array_cursor_get(serial,
                                 ch_entry->messages_array,
                                 message_index,
                                 &mut->iter_cache,
                                 &mut->iter_pos,
                                 &mut->iter_valid);
    if (NULL == msg_node || PUBNUB_JSON_OBJECT != serial->value_type(msg_node)) {
        return result;
    }

    /* File messages have structure (unencrypted):
     *   {"message": {"message": ..., "file": {"id":"...", "name":"..."}}}
     * When encrypted, "message" is a base64 string that decrypts to:
     *   {"message": ..., "file": {"id":"...", "name":"..."}}
     */
    const pubnub_json_value_t* message_field =
        serial->object_get(msg_node, "message", 7);
    if (NULL == message_field) {
        return result;
    }

    /* If the message field is already an object, use it directly
     * (unencrypted file message). */
    const pubnub_json_value_t* file_root      = NULL;
    pubnub_json_value_t*       decrypted_tree = NULL;

    if (PUBNUB_JSON_OBJECT == serial->value_type(message_field)) {
        file_root = message_field;
    }
#if PUBNUB_ENABLE_CRYPTO
    else if (PUBNUB_JSON_STRING == serial->value_type(message_field)) {
        pubnub_crypto_module_t* crypto = pn_context_crypto_module(future.ctx);
        pn_history_fetch_parsed_t* fp = (pn_history_fetch_parsed_t*)state->parsed;
        if (NULL != crypto && NULL != fp->allocator) {
            decrypted_tree =
                decrypt_file_payload(serial, message_field, crypto, fp->allocator);
            if (NULL != decrypted_tree) {
                file_root = decrypted_tree;
            }
        }
    }
#endif

    if (NULL == file_root) {
        if (NULL != decrypted_tree) {
            serial->value_destroy(serial, decrypted_tree);
        }
        return result;
    }

    const pubnub_json_value_t* file_field =
        serial->object_get(file_root, "file", 4);
    if (NULL == file_field || PUBNUB_JSON_OBJECT != serial->value_type(file_field)) {
        if (NULL != decrypted_tree) {
            serial->value_destroy(serial, decrypted_tree);
        }
        return result;
    }

    /* Extract file id. */
    const pubnub_json_value_t* id_node = serial->object_get(file_field, "id", 2);
    if (NULL != id_node && PUBNUB_JSON_STRING == serial->value_type(id_node)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(id_node, &len);
        if (NULL != ptr) {
            result.id.ptr = ptr;
            result.id.len = len;
        }
    }

    /* Extract file name. */
    const pubnub_json_value_t* name_node =
        serial->object_get(file_field, "name", 4);
    if (NULL != name_node && PUBNUB_JSON_STRING == serial->value_type(name_node)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(name_node, &len);
        if (NULL != ptr) {
            result.name.ptr = ptr;
            result.name.len = len;
        }
    }

    /* Extract optional user-attached message from file envelope. */
    const pubnub_json_value_t* user_msg =
        serial->object_get(file_root, "message", 7);
    if (NULL != user_msg && PUBNUB_JSON_STRING == serial->value_type(user_msg)) {
        size_t      len = 0;
        const char* ptr = serial->value_as_string(user_msg, &len);
        if (NULL != ptr) {
            result.message.ptr = ptr;
            result.message.len = len;
        }
    }

    /* Keep decrypted tree alive so string views remain valid until
     * the next file accessor call or future release. */
    if (NULL != decrypted_tree) {
        pn_history_fetch_parsed_t* fp = (pn_history_fetch_parsed_t*)state->parsed;
        if (NULL != fp->decrypted_file_tree) {
            serial->value_destroy(serial, fp->decrypted_file_tree);
        }
        fp->decrypted_file_tree = decrypted_tree;
    }

    return result;
}

const pubnub_json_value_t*
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_fetch_messages_result_actions_at(const pubnub_future_t future,
                                        const size_t          channel_index,
                                        const size_t          message_index)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_FETCH != state->operation) {
        return NULL;
    }

    pn_history_fetch_parsed_t** parsed_slot =
        (pn_history_fetch_parsed_t**)&state->parsed;
    const pn_history_fetch_parsed_t* cached =
        get_fetch_parse(slot, future, state, parsed_slot);
    if (NULL == cached || channel_index >= cached->channel_count) {
        return NULL;
    }

    const pn_history_fetch_channel_entry_t* ch_entry =
        &cached->channel_entries[channel_index];
    pn_history_fetch_channel_entry_t* mut =
        (pn_history_fetch_channel_entry_t*)ch_entry;
    if (message_index >= ch_entry->message_count) {
        return NULL;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    if (NULL == serial || NULL == serial->array_get
        || NULL == serial->value_type || NULL == serial->object_get) {
        return NULL;
    }

    const pubnub_json_value_t* msg_node =
        pn_json_array_cursor_get(serial,
                                 ch_entry->messages_array,
                                 message_index,
                                 &mut->iter_cache,
                                 &mut->iter_pos,
                                 &mut->iter_valid);
    if (NULL == msg_node || PUBNUB_JSON_OBJECT != serial->value_type(msg_node)) {
        return NULL;
    }

    const pubnub_json_value_t* actions_field =
        serial->object_get(msg_node, "actions", 7);
    if (NULL == actions_field
        || PUBNUB_JSON_OBJECT != serial->value_type(actions_field)) {
        return NULL;
    }

    return actions_field;
}

pubnub_message_counts_result_t
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_message_counts_result(const pubnub_future_t future)
{
    pubnub_message_counts_result_t result = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_COUNTS != state->operation) {
        return result;
    }

    pn_history_counts_parsed_t** parsed_slot =
        (pn_history_counts_parsed_t**)&state->parsed;
    const pn_history_counts_parsed_t* cached =
        get_counts_parse(slot, future, state, parsed_slot);
    if (NULL == cached) {
        return result;
    }

    result.channel_count = cached->channel_count;
    return result;
}

pubnub_message_counts_channel_result_t
// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_message_counts_result_channel_at(const pubnub_future_t future,
                                        const size_t          index)
{
    pubnub_message_counts_channel_result_t result = {0};

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return result;
    }

    pn_history_state_t* state = history_state_for(slot);
    if (NULL == state || PN_HISTORY_OP_COUNTS != state->operation) {
        return result;
    }

    pn_history_counts_parsed_t** parsed_slot =
        (pn_history_counts_parsed_t**)&state->parsed;
    const pn_history_counts_parsed_t* cached =
        get_counts_parse(slot, future, state, parsed_slot);
    if (NULL == cached || index >= cached->channel_count) {
        return result;
    }

    result.name  = cached->channel_entries[index].name;
    result.count = cached->channel_entries[index].count;
    return result;
}

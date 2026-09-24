/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "files_internal.h"

#if !PUBNUB_ENABLE_FILES
#error "files_send.c requires PUBNUB_ENABLE_FILES=ON"
#endif

#include "core/core_internal.h"
#include "core/pn_string.h"

#if PUBNUB_ENABLE_CRYPTO
/* Defined in src/features/crypto/crypto_api.c when crypto is enabled. */
pubnub_res_t pn_crypto_module_encrypt(pubnub_crypto_module_t*      module,
                                      const uint8_t*               input,
                                      size_t                       input_len,
                                      uint8_t**                    output,
                                      size_t*                      output_len,
                                      pubnub_allocator_provider_t* alloc);
#else
static inline pubnub_res_t pn_crypto_module_encrypt(pubnub_crypto_module_t* module,
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
#include "core/runtime/pipeline_internal.h"
#include "core/runtime/request_internal.h"

#include <string.h>

static pubnub_res_t pn_file_dispatch_publish(pn_request_t*         slot,
                                             pn_file_send_state_t* state);

/**
 * @brief Find the content between an XML open/close tag pair.
 *
 * @param text      Start of search region.
 * @param text_end  One past the last scannable byte.
 * @param open_tag  Opening tag string (e.g., "<Code>").
 * @param open_len  Length of open_tag.
 * @param close_tag Closing tag string (e.g., "</Code>").
 * @param close_len Length of close_tag.
 * @param out_len   Receives content length on success.
 * @return Pointer to content start, or NULL if not found.
 */
static const char* pn_xml_find_tag(const char* text,
                                   const char* text_end,
                                   const char* open_tag,
                                   size_t      open_len,
                                   const char* close_tag,
                                   size_t      close_len,
                                   size_t*     out_len)
{
    const char* start = NULL;
    const char* p;

    for (p = text; p + open_len <= text_end; ++p) {
        if (0 == memcmp(p, open_tag, open_len)) {
            start = p + open_len;
            break;
        }
    }
    if (NULL == start) {
        return NULL;
    }

    for (p = start; p + close_len <= text_end; ++p) {
        if (0 == memcmp(p, close_tag, close_len)) {
            if (p > start) {
                *out_len = (size_t)(p - start);
                return start;
            }
            return NULL;
        }
    }
    return NULL;
}

/**
 * @brief Classify an S3 XML error response into an SDK error code.
 *
 * S3 returns errors as flat XML:
 * @code
 *   <Error>
 *     <Code>EntityTooLarge</Code>
 *     <Message>Your proposed upload exceeds...</Message>
 *   </Error>
 * @endcode
 *
 * Extracts <Code> to classify:
 * - "EntityTooLarge" → PUBNUB_ERR_INVALID_ARGUMENT (file exceeds
 *   server-configured limit).
 * - "AccessDenied" with <Message> containing "expired" →
 *   PUBNUB_ERR_TIMEOUT (presigned URL expired).
 * - Anything else → PUBNUB_ERR_TRANSPORT.
 *
 * @param body     Response body bytes (borrowed).
 * @param body_len Response body length.
 * @return Classified SDK error code.
 */
static pubnub_res_t pn_file_classify_s3_error(const uint8_t* body, size_t body_len)
{
    if (NULL == body || 0 == body_len) {
        return PUBNUB_ERR_TRANSPORT;
    }

    const char* text     = (const char*)body;
    const char* text_end = text + body_len;

    /* Extract <Code> content. */
    size_t      code_len = 0;
    const char* code =
        pn_xml_find_tag(text, text_end, "<Code>", 6, "</Code>", 7, &code_len);

    if (NULL == code) {
        return PUBNUB_ERR_TRANSPORT;
    }

    /* EntityTooLarge → file exceeds server limit. */
    if (14 == code_len && 0 == memcmp(code, "EntityTooLarge", 14)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* AccessDenied → check if presigned URL expired. */
    if (12 == code_len && 0 == memcmp(code, "AccessDenied", 12)) {
        size_t      msg_len = 0;
        const char* msg     = pn_xml_find_tag(
            text, text_end, "<Message>", 9, "</Message>", 10, &msg_len);
        size_t i;

        if (NULL != msg) {
            /* Case-insensitive scan for "expired" in message. */
            for (i = 0; i + 7 <= msg_len; ++i) {
                if (('e' == msg[i] || 'E' == msg[i])
                    && ('x' == msg[i + 1] || 'X' == msg[i + 1])
                    && ('p' == msg[i + 2] || 'P' == msg[i + 2])
                    && ('i' == msg[i + 3] || 'I' == msg[i + 3])
                    && ('r' == msg[i + 4] || 'R' == msg[i + 4])
                    && ('e' == msg[i + 5] || 'E' == msg[i + 5])
                    && ('d' == msg[i + 6] || 'D' == msg[i + 6])) {
                    return PUBNUB_ERR_TIMEOUT;
                }
            }
        }
    }

    return PUBNUB_ERR_TRANSPORT;
}

/**
 * @brief Reset the slot's HTTP descriptors for re-use in the next
 *        state machine step.
 *
 * Zeroes both request and response, preserving the slot's structural
 * fields (slot_id, feature_state, on_complete chain).
 */
static void pn_file_reset_slot_http(pn_request_t* slot)
{
    memset(&slot->http_request, 0, sizeof(slot->http_request));
    memset(&slot->http_response, 0, sizeof(slot->http_response));
    slot->transport_handle      = NULL;
    slot->parsed_body_tree      = NULL;
    slot->parsed_body_owner     = NULL;
    slot->parsed_body_attempted = 0;
    slot->svc_error_kind        = 0;
    slot->svc_error_classified  = 0;

    /* Clear the readiness gate: the slot is being re-armed for the next
     * state-machine step (re-dispatch), so it must NOT report ready until
     * the next terminal transition republishes it. */
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 0);
}

/**
 * @brief Transition the slot to a terminal failure state.
 *
 * Sets the result code and changes state so the caller's future
 * reports the error. After this call, the state machine is done.
 */
static void pn_file_fail_slot(pn_request_t*         slot,
                              pn_file_send_state_t* state,
                              pubnub_res_t          error)
{
    state->phase = PN_FILE_SEND_FAILED;
    slot->result = error;
    slot->state  = PN_REQUEST_FAILED;

    /* Publish the readiness gate LAST so the lock-free reader in
     * pn_request_is_ready sees result/state for this terminal step. */
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);
}

/**
 * @brief Mark the slot as successfully completed.
 */
static void pn_file_complete_slot(pn_request_t* slot, pn_file_send_state_t* state)
{
    state->phase = PN_FILE_SEND_DONE;
    slot->result = PUBNUB_OK;
    slot->state  = PN_REQUEST_COMPLETE;

    /* Publish the readiness gate LAST so the lock-free reader in
     * pn_request_is_ready sees result/state for this terminal step. */
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);
}

/**
 * @brief Build and dispatch the publish-file-message step.
 *
 * Resets the slot, builds the request, and dispatches through the
 * pipeline. On failure, marks the slot as failed.
 *
 * @return PUBNUB_OK on successful dispatch.
 */
static pubnub_res_t pn_file_dispatch_publish(pn_request_t*         slot,
                                             pn_file_send_state_t* state)
{
    const pubnub_config_t*    config = pn_context_config(state->ctx);
    pn_file_publish_inputs_t  inputs;
    pubnub_crypto_module_t*   crypto_mod = NULL;
    pn_file_publish_encoded_t encoded;
    pubnub_res_t              rc;

    if (NULL == config) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    /* Free any previously held encoded strings (defensive). */
    if (NULL != state->publish_encoded.channel) {
        PN_FREE(state->allocator, state->publish_encoded.channel);
        state->publish_encoded.channel = NULL;
    }
    if (NULL != state->publish_encoded.message) {
        PN_FREE(state->allocator, state->publish_encoded.message);
        state->publish_encoded.message = NULL;
    }

    pn_file_reset_slot_http(slot);

    memset(&inputs, 0, sizeof(inputs));
    inputs.publish_key         = config->publish_key;
    inputs.subscribe_key       = config->subscribe_key;
    inputs.channel             = state->channel;
    inputs.file_id             = state->file_id;
    inputs.file_name           = state->file_name;
    inputs.message             = state->message;
    inputs.meta                = state->meta;
    inputs.custom_message_type = state->custom_message_type;
    inputs.store               = state->store;
    inputs.ttl                 = state->ttl;

    /* Resolve crypto module for file message encryption. */
    if (PUBNUB_ENABLE_CRYPTO) {
        crypto_mod = pn_context_crypto_module(state->ctx);
    }

    memset(&encoded, 0, sizeof(encoded));

    rc = pn_file_build_publish_request(&slot->http_request,
                                       state->allocator,
                                       state->serialization,
                                       &inputs,
                                       crypto_mod,
                                       &encoded);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Set host/secure/timeout for the PubNub publish endpoint. */
    rc = pn_request_set_host(&slot->http_request, config->origin);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    slot->http_request.secure = PUBNUB_ENABLE_SECURE_TRANSPORT;
    if (0 != state->timeout_ms) {
        slot->http_request.timeout_ms = state->timeout_ms;
    }

    slot->on_complete        = pn_file_send_on_publish_complete;
    slot->user_data          = state;
    slot->response_validator = pn_file_publish_response_validator;
    slot->state              = PN_REQUEST_PENDING;
    state->phase             = PN_FILE_SEND_PUBLISHING;

    rc = pn_request_dispatch(state->pipeline, slot, state->platform);
    if (PUBNUB_OK != rc) {
        if (NULL != encoded.channel) {
            PN_FREE(state->allocator, encoded.channel);
            encoded.channel = NULL;
        }
        if (NULL != encoded.message) {
            PN_FREE(state->allocator, encoded.message);
            encoded.message = NULL;
        }
        return rc;
    }

    /* Track the encoded strings so they can be freed on retry or
     * state cleanup. The path_segments point into these buffers. */
    state->publish_encoded = encoded;

    return PUBNUB_OK;
}

void pn_file_send_on_generate_complete(pn_request_t* request,
                                       pubnub_res_t  status,
                                       void*         user_data)
{
    pn_file_send_state_t* state = (pn_file_send_state_t*)user_data;
    if (NULL == state || NULL == request) {
        return;
    }

    /* Transport or server error on generate-upload-url. */
    if (PUBNUB_OK != status) {
        pn_file_fail_slot(request, state, status);
        return;
    }

    /* Parse the generate-upload-url response. */
    pubnub_res_t rc =
        pn_file_parse_generate_url_response(state->serialization,
                                            request->http_response.body,
                                            request->http_response.body_len,
                                            state);
    if (PUBNUB_OK != rc) {
        pn_file_fail_slot(request, state, rc);
        return;
    }

    /* Parse the upload URL into host + path components. */
    rc = pn_file_parse_upload_url(state->upload_url,
                                  state->allocator,
                                  &state->upload_host,
                                  &state->upload_path);
    if (PUBNUB_OK != rc) {
        pn_file_fail_slot(request, state, rc);
        return;
    }

    /* Generate a multipart boundary. */
    rc = pn_file_generate_boundary(state->platform,
                                   state->multipart_boundary,
                                   sizeof(state->multipart_boundary));
    if (PUBNUB_OK != rc) {
        pn_file_fail_slot(request, state, rc);
        return;
    }

    /* Encrypt file content if crypto module is configured. */
    if (PUBNUB_ENABLE_CRYPTO && NULL != state->ctx) {
        pubnub_crypto_module_t* crypto_mod = pn_context_crypto_module(state->ctx);
        if (NULL != crypto_mod) {
            uint8_t* enc_out     = NULL;
            size_t   enc_out_len = 0;
            rc                   = pn_crypto_module_encrypt(crypto_mod,
                                          state->data,
                                          state->data_len,
                                          &enc_out,
                                          &enc_out_len,
                                          state->allocator);
            if (PUBNUB_OK != rc) {
                pn_file_fail_slot(request, state, rc);
                return;
            }
            state->encrypted_data = enc_out;
            state->data           = enc_out;
            state->data_len       = enc_out_len;
        }
    }

    /* Resolve content type. */
    const char* ct = (NULL != state->content_type) ? state->content_type
                                                   : "application/octet-stream";

    /* Build file content descriptor. */
    const pn_file_content_params_t file_params = {.data     = state->data,
                                                  .data_len = state->data_len,
                                                  .name     = state->file_name,
                                                  .content_type = ct};

    /* Compute multipart body size and allocate. */
    const size_t body_size = pn_file_multipart_size(state->form_fields,
                                                    state->form_field_count,
                                                    &file_params,
                                                    state->multipart_boundary);
    if (0 == body_size) {
        pn_file_fail_slot(request, state, PUBNUB_ERR_INTERNAL);
        return;
    }

    state->multipart_body =
        (uint8_t*)PN_ALLOC(state->allocator, body_size, sizeof(void*));
    if (NULL == state->multipart_body) {
        pn_file_fail_slot(request, state, PUBNUB_ERR_OUT_OF_MEMORY);
        return;
    }

    /* Encode the multipart body. */
    rc = pn_file_multipart_encode(state->form_fields,
                                  state->form_field_count,
                                  &file_params,
                                  state->multipart_boundary,
                                  state->multipart_body,
                                  body_size,
                                  &state->multipart_body_len);
    if (PUBNUB_OK != rc) {
        PN_FREE(state->allocator, state->multipart_body);
        state->multipart_body     = NULL;
        state->multipart_body_len = 0;
        pn_file_fail_slot(request, state, rc);
        return;
    }

    /* Form fields are no longer needed after encoding. Free the
     * array and destroy the parsed tree that backed the views. */
    if (NULL != state->form_fields) {
        PN_FREE(state->allocator, state->form_fields);
        state->form_fields      = NULL;
        state->form_field_count = 0;
    }
    if (NULL != state->generate_url_tree) {
        state->serialization->value_destroy(state->serialization,
                                            state->generate_url_tree);
        state->generate_url_tree = NULL;
    }

    /* Free the generate-upload-url POST body before zeroing the slot.
     * pn_file_reset_slot_http clears request->body without freeing it,
     * so we release it here while the pointer is still in state. */
    if (NULL != state->generate_url_body) {
        PN_FREE(state->allocator, state->generate_url_body);
        state->generate_url_body = NULL;
    }

    /* Reconfigure the slot for S3 upload. */
    pn_file_reset_slot_http(request);

    rc = pn_file_build_upload_request(&request->http_request,
                                      state->upload_host,
                                      state->upload_path,
                                      state->multipart_boundary,
                                      state->multipart_body,
                                      state->multipart_body_len);
    if (PUBNUB_OK != rc) {
        pn_file_fail_slot(request, state, rc);
        return;
    }

    /* Override timeout if user specified one. */
    if (0 != state->upload_timeout_ms) {
        request->http_request.timeout_ms = state->upload_timeout_ms;
    }

    /* Set up the next callback. */
    request->on_complete        = pn_file_send_on_upload_complete;
    request->user_data          = state;
    request->response_validator = NULL;

    /* Dispatch through the pipeline — middlewares skip decoration for
     * requests marked external. This preserves the curl session
     * lifecycle that pn_request_dispatch manages. */
    request->state = PN_REQUEST_PENDING;
    state->phase   = PN_FILE_SEND_UPLOADING;

    rc = pn_request_dispatch(state->pipeline, request, state->platform);
    if (PUBNUB_OK != rc) {
        pn_file_fail_slot(request, state, rc);
        return;
    }
}

void pn_file_send_on_upload_complete(pn_request_t* request,
                                     pubnub_res_t  status,
                                     void*         user_data)
{
    pn_file_send_state_t* state = (pn_file_send_state_t*)user_data;
    if (NULL == state || NULL == request) {
        return;
    }

    /* S3 upload failure is terminal (no retry). */
    if (PUBNUB_OK != status) {
        pn_file_fail_slot(request, state, status);
        return;
    }

    /* S3 upload success is HTTP 204 No Content. */
    if (204 != request->http_response.status_code) {
        pubnub_res_t s3_err = pn_file_classify_s3_error(
            request->http_response.body, request->http_response.body_len);
        pn_file_fail_slot(request, state, s3_err);
        return;
    }

    /* Free the multipart body — no longer needed. */
    if (NULL != state->multipart_body) {
        PN_FREE(state->allocator, state->multipart_body);
        state->multipart_body     = NULL;
        state->multipart_body_len = 0;
    }

    /* Dispatch publish-file-message through the pipeline. */
    pubnub_res_t rc = pn_file_dispatch_publish(request, state);
    if (PUBNUB_OK != rc) {
        /* S3 upload succeeded but publish dispatch failed. */
        state->phase    = PN_FILE_SEND_PUBLISH_FAILED;
        request->result = rc;
        request->state  = PN_REQUEST_FAILED;

        /* Re-dispatch cleared the gate; republish it LAST so the reader
         * observes this terminal failure. */
        PUBNUB_ATOMIC_STORE_U8(&request->ready, 1);
    }
}

void pn_file_send_on_publish_complete(pn_request_t* request,
                                      pubnub_res_t  status,
                                      void*         user_data)
{
    pn_file_send_state_t* state = (pn_file_send_state_t*)user_data;
    if (NULL == state || NULL == request) {
        return;
    }

    if (PUBNUB_OK == status) {
        /* Parse the publish response for timetoken. */
        pubnub_json_value_t* tree =
            pn_request_get_parsed_body(request, state->serialization);
        if (NULL != tree) {
            state->publish_tree = tree;
            /* Transfer ownership to state — prevent double-free when
             * the slot release path also tries to destroy it. */
            request->parsed_body_tree  = NULL;
            request->parsed_body_owner = NULL;
            (void)pn_file_parse_publish_response(
                state->serialization, tree, &state->timetoken);
        }
        pn_file_complete_slot(request, state);
        return;
    }

    /* S3 upload succeeded but publish failed. */
    state->phase    = PN_FILE_SEND_PUBLISH_FAILED;
    request->result = status;
    request->state  = PN_REQUEST_FAILED;

    /* Publish the readiness gate LAST so the reader observes this
     * terminal failure. */
    PUBNUB_ATOMIC_STORE_U8(&request->ready, 1);
}

void pn_file_send_state_cleanup(void*                        state_ptr,
                                pubnub_allocator_provider_t* allocator)
{
    pn_file_send_state_t* state = (pn_file_send_state_t*)state_ptr;
    if (NULL == state) {
        return;
    }

    /* Free allocator-owned strings. */
    pn_strfree(state->file_id, allocator);
    pn_strfree(state->file_name, allocator);
    pn_strfree(state->upload_url, allocator);
    pn_strfree(state->upload_host, allocator);
    pn_strfree(state->upload_path, allocator);
    pn_strfree(state->channel, allocator);
    pn_strfree(state->message, allocator);
    pn_strfree(state->meta, allocator);
    pn_strfree(state->custom_message_type, allocator);
    pn_strfree(state->content_type, allocator);

    /* Free encoded publish path strings. */
    if (NULL != state->publish_encoded.channel) {
        PN_FREE(allocator, state->publish_encoded.channel);
    }
    if (NULL != state->publish_encoded.message) {
        PN_FREE(allocator, state->publish_encoded.message);
    }

    /* Free generate-url POST body (normally freed before slot reset;
     * non-NULL only on error paths where reset was never reached). */
    if (NULL != state->generate_url_body) {
        PN_FREE(allocator, state->generate_url_body);
        state->generate_url_body = NULL;
    }

    /* Free form fields array (may already be NULL). */
    if (NULL != state->form_fields) {
        PN_FREE(allocator, state->form_fields);
    }

    /* Free encrypted file data (when crypto was active). */
    if (NULL != state->encrypted_data) {
        PN_FREE(allocator, state->encrypted_data);
    }

    /* Free file data loaded from file_path. */
    if (NULL != state->loaded_file_data) {
        PN_FREE(allocator, state->loaded_file_data);
    }

    /* Free multipart body (may already be NULL). */
    if (NULL != state->multipart_body) {
        PN_FREE(allocator, state->multipart_body);
    }

    /* Destroy parsed JSON trees. */
    if (NULL != state->generate_url_tree && NULL != state->serialization) {
        state->serialization->value_destroy(state->serialization,
                                            state->generate_url_tree);
    }
    if (NULL != state->publish_tree && NULL != state->serialization) {
        state->serialization->value_destroy(state->serialization,
                                            state->publish_tree);
    }

    /* Free the state struct itself. */
    PN_FREE(allocator, state);
}

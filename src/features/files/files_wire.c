/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "files_internal.h"

#if !PUBNUB_ENABLE_FILES
#error "files_wire.c requires PUBNUB_ENABLE_FILES=ON"
#endif

#include "core/pn_format.h"
#include "core/pn_string.h"
#include "core/protocol_common/pn_response_probe.h"
#include "core/protocol_common/pn_url_encode.h"
#include "core/runtime/middleware/middleware_internal.h"

#include "pubnub/json.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS >= 9U,
    "files publish-file operation requires at least 9 HTTP path segments");

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

/** Max bytes examined when probing the publish-file response prefix. */
#define PN_FILE_RESPONSE_PROBE_LIMIT 20

/** Buffer size for the generate-upload-url body (`{"name":"..."}`)
 *  where 64 covers the envelope and allows filenames up to ~50 chars.
 *  Filenames beyond this use allocator-based serialization. */
#define PN_FILE_GENURL_BODY_CAP 256

/**
 * @brief Serialize a small JSON value tree to a heap-allocated buffer.
 *
 * Caller owns the returned buffer and must free via @p allocator.
 * Returns NULL on failure.
 */
static uint8_t* pn_file_serialize_to_alloc(pubnub_serialization_provider_t* serial,
                                           pubnub_allocator_provider_t* allocator,
                                           const pubnub_json_value_t* value,
                                           size_t*                    out_len)
{
    /* Try a stack buffer first (covers most filenames). */
    uint8_t stack_buf[PN_FILE_GENURL_BODY_CAP];
    size_t  len = 0;

    pubnub_res_t rc =
        serial->serialize(serial, value, stack_buf, sizeof(stack_buf), &len);
    if (PUBNUB_OK == rc) {
        uint8_t* heap = (uint8_t*)PN_ALLOC(allocator, len, sizeof(void*));
        if (NULL == heap) {
            return NULL;
        }
        memcpy(heap, stack_buf, len);
        *out_len = len;
        return heap;
    }

    /* Stack buffer too small — try a larger heap allocation. */
    size_t   cap  = (size_t)PN_FILE_GENURL_BODY_CAP * 4U;
    uint8_t* heap = (uint8_t*)PN_ALLOC(allocator, cap, sizeof(void*));
    if (NULL == heap) {
        return NULL;
    }

    rc = serial->serialize(serial, value, heap, cap, &len);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, heap);
        return NULL;
    }
    *out_len = len;
    return heap;
}

pubnub_res_t
pn_file_build_generate_url_request(pubnub_http_request_t* request,
                                   pubnub_serialization_provider_t* serialization,
                                   pubnub_allocator_provider_t* allocator,
                                   const pn_file_generate_url_inputs_t* in)
{
    if (NULL == request || NULL == serialization || NULL == allocator
        || NULL == in || NULL == in->subscribe_key || NULL == in->channel
        || NULL == in->file_name) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serialization->value_create_object
        || NULL == serialization->value_create_string
        || NULL == serialization->object_set || NULL == serialization->serialize
        || NULL == serialization->value_destroy) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Encode channel into scratch (short value). */
    pubnub_string_view_t channel_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, in->channel, &channel_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Build JSON body: {"name":"<file_name>"} */
    pubnub_json_value_t* root = serialization->value_create_object(serialization);
    if (NULL == root) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    const size_t         name_len = strlen(in->file_name);
    pubnub_json_value_t* name_val =
        serialization->value_create_string(serialization, in->file_name, name_len);
    if (NULL == name_val) {
        serialization->value_destroy(serialization, root);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    rc = serialization->object_set(serialization, root, "name", 4, name_val);
    if (PUBNUB_OK != rc) {
        serialization->value_destroy(serialization, name_val);
        serialization->value_destroy(serialization, root);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Serialize to allocator-owned buffer. */
    size_t   body_len = 0;
    uint8_t* body =
        pn_file_serialize_to_alloc(serialization, allocator, root, &body_len);
    serialization->value_destroy(serialization, root);

    if (NULL == body) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Scratch-copy subscribe_key so the request is self-contained. */
    pubnub_string_view_t sub_key_view;
    rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Path: /v1/files/{sub_key}/channels/{channel}/generate-upload-url */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channels", 8};
    request->path_segments[n++] = channel_view;
    request->path_segments[n++] = (pubnub_string_view_t){"generate-upload-url", 19};
    request->path_segment_count = n;

    /* Method and headers. */
    request->method   = PUBNUB_HTTP_POST;
    request->body     = body;
    request->body_len = body_len;

    /* Content-Type: application/json header. */
    request->headers[0] = (pubnub_kv_t){
        .key   = {.ptr = "Content-Type",     .len = 12},
        .value = {.ptr = "application/json", .len = 16}
    };
    request->header_count = 1;

    return PUBNUB_OK;
}

pubnub_res_t pn_file_build_upload_request(pubnub_http_request_t* request,
                                          const char*            host,
                                          const char*            path,
                                          const char*            boundary,
                                          const uint8_t*         body,
                                          size_t                 body_len)
{
    if (NULL == request || NULL == host || NULL == path || NULL == boundary
        || NULL == body) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    request->method = PUBNUB_HTTP_POST;
    /* Raw pointer — not a config string. Lifetime is guaranteed by
     * pn_file_send_state_t; no scratch-copy needed since this slot
     * is already in the pool (no pending-to-pool relocation). */
    request->host     = host;
    request->secure   = 1;
    request->external = 1;

    /* Path is the full path+query from the presigned URL — store as
     * a single pre-encoded segment so the transport concatenates it
     * verbatim. */
    request->path_segments[0]   = (pubnub_string_view_t){path, strlen(path)};
    request->path_segment_count = 1;

    request->body     = body;
    request->body_len = body_len;

    /* Content-Type: multipart/form-data; boundary=<boundary>
     * Build the header value in scratch. */
    const char*  prefix     = "multipart/form-data; boundary=";
    const size_t prefix_len = 30;
    const size_t bound_len  = strlen(boundary);
    const size_t total      = prefix_len + bound_len;

    /* Store in scratch buffer (NUL-terminated for string safety). */
    if (request->scratch_used + total + 1 >= PUBNUB_CFG_HTTP_SCRATCH_SIZE) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    char* ct_value = request->scratch + request->scratch_used;
    memcpy(ct_value, prefix, prefix_len);
    memcpy(ct_value + prefix_len, boundary, bound_len);
    ct_value[total] = '\0';
    request->scratch_used += (unsigned int)(total + 1);

    request->headers[0] = (pubnub_kv_t){
        .key   = {.ptr = "Content-Type", .len = 12   },
        .value = {.ptr = ct_value,       .len = total}
    };
    request->header_count = 1;

    return PUBNUB_OK;
}

#if PUBNUB_ENABLE_CRYPTO
/**
 * @brief Encrypt JSON buffer and wrap in quoted base64 for wire transmission.
 *
 * Takes ownership of @p json_buf and frees it on both success and failure paths.
 *
 * @param json_buf  Plaintext JSON buffer (freed by this function).
 * @param json_len  Length of plaintext JSON.
 * @param crypto    Crypto module for encryption.
 * @param allocator Allocator for encrypted buffer.
 * @param out_data  Receives encrypted+quoted buffer on success.
 * @param out_len   Receives encrypted+quoted length on success.
 * @return PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t encrypt_and_wrap_json(uint8_t*                json_buf,
                                          size_t                  json_len,
                                          pubnub_crypto_module_t* crypto,
                                          pubnub_allocator_provider_t* allocator,
                                          uint8_t** out_data,
                                          size_t*   out_len)
{
    char*        enc_b64     = NULL;
    size_t       enc_b64_len = 0;
    pubnub_res_t enc_rc      = pn_crypto_module_encrypt_to_base64(
        crypto, json_buf, json_len, &enc_b64, &enc_b64_len, allocator);
    PN_FREE(allocator, json_buf);

    if (PUBNUB_OK != enc_rc) {
        return enc_rc;
    }

    /* Wrap in JSON quotes: "\"<base64>\"" */
    char* encrypted_payload = (char*)PN_ALLOC(allocator, enc_b64_len + 3, 1);
    if (NULL == encrypted_payload) {
        PN_FREE(allocator, enc_b64);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    encrypted_payload[0] = '"';
    memcpy(encrypted_payload + 1, enc_b64, enc_b64_len);
    encrypted_payload[enc_b64_len + 1] = '"';
    encrypted_payload[enc_b64_len + 2] = '\0';
    PN_FREE(allocator, enc_b64);

    *out_data = (uint8_t*)encrypted_payload;
    *out_len  = enc_b64_len + 2;
    return PUBNUB_OK;
}
#endif

/**
 * @brief Build and serialize the publish-file JSON message.
 *
 * Produces: {"message":<user_msg_or_empty_obj>,"file":{"id":"..","name":".."}}
 * Caller owns the returned buffer and must free via @p allocator.
 *
 * @param serial    Serialization provider (vtable already validated).
 * @param allocator Allocator for the output buffer.
 * @param in        Publish inputs (file_id, file_name, message).
 * @param out_len   Receives serialized byte count on success.
 * @return Heap-allocated serialized JSON, or NULL on failure.
 */
static uint8_t* pn_file_build_publish_json(pubnub_serialization_provider_t* serial,
                                           pubnub_allocator_provider_t* allocator,
                                           const pn_file_publish_inputs_t* in,
                                           size_t* out_len)
{
    pubnub_json_value_t* root = serial->value_create_object(serial);
    if (NULL == root) {
        return NULL;
    }

    /* "message" field — user-provided raw JSON or empty object. */
    pubnub_json_value_t* msg_val = NULL;
    if (NULL != in->message && '\0' != in->message[0]) {
        const size_t msg_len = strlen(in->message);
        msg_val              = serial->value_create_raw
                                 ? serial->value_create_raw(
                          serial, (const uint8_t*)in->message, msg_len)
                                 : NULL;
        if (NULL == msg_val) {
            msg_val = serial->value_create_string(serial, in->message, msg_len);
        }
    } else {
        msg_val = serial->value_create_object(serial);
    }
    if (NULL == msg_val) {
        serial->value_destroy(serial, root);
        return NULL;
    }

    pubnub_res_t rc = serial->object_set(serial, root, "message", 7, msg_val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, msg_val);
        serial->value_destroy(serial, root);
        return NULL;
    }

    /* "file" object with "id" and "name". */
    pubnub_json_value_t* file_obj = serial->value_create_object(serial);
    if (NULL == file_obj) {
        serial->value_destroy(serial, root);
        return NULL;
    }

    pubnub_json_value_t* id_val =
        serial->value_create_string(serial, in->file_id, strlen(in->file_id));
    if (NULL == id_val) {
        serial->value_destroy(serial, file_obj);
        serial->value_destroy(serial, root);
        return NULL;
    }
    rc = serial->object_set(serial, file_obj, "id", 2, id_val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, id_val);
        serial->value_destroy(serial, file_obj);
        serial->value_destroy(serial, root);
        return NULL;
    }

    pubnub_json_value_t* name_val =
        serial->value_create_string(serial, in->file_name, strlen(in->file_name));
    if (NULL == name_val) {
        serial->value_destroy(serial, file_obj);
        serial->value_destroy(serial, root);
        return NULL;
    }
    rc = serial->object_set(serial, file_obj, "name", 4, name_val);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, name_val);
        serial->value_destroy(serial, file_obj);
        serial->value_destroy(serial, root);
        return NULL;
    }

    rc = serial->object_set(serial, root, "file", 4, file_obj);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, file_obj);
        serial->value_destroy(serial, root);
        return NULL;
    }

    /* Serialize the tree to heap-allocated buffer. */
    uint8_t* json_buf =
        pn_file_serialize_to_alloc(serial, allocator, root, out_len);
    serial->value_destroy(serial, root);
    return json_buf;
}

/**
 * @brief Add optional query parameters for the publish-file request.
 *
 * Appends store, ttl, meta, and custom_message_type query parameters
 * when the corresponding input fields are set.
 *
 * @param request HTTP request to modify (borrowed).
 * @param in      Publish inputs (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t pn_file_add_publish_params(pubnub_http_request_t* request,
                                               const pn_file_publish_inputs_t* in)
{
    pubnub_res_t rc;

    if (0 == in->store) {
        rc = pn_request_add_query_param(request, "store", "0", PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (in->ttl > 0 && 0 != in->store) {
        char ttl_buf[16];
        (void)pn_snprintf(ttl_buf, sizeof(ttl_buf), "%d", in->ttl);
        rc = pn_request_add_query_param(request, "ttl", ttl_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != in->meta) {
        rc = pn_request_add_query_param(request, "meta", in->meta, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != in->custom_message_type) {
        rc = pn_request_add_query_param(
            request, "custom_message_type", in->custom_message_type, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_file_build_publish_request(pubnub_http_request_t* request,
                                           pubnub_allocator_provider_t* allocator,
                                           pubnub_serialization_provider_t* serial,
                                           const pn_file_publish_inputs_t* in,
                                           pubnub_crypto_module_t*    crypto,
                                           pn_file_publish_encoded_t* out)
{
    if (NULL == request || NULL == allocator || NULL == serial || NULL == in
        || NULL == out || NULL == in->publish_key || NULL == in->subscribe_key
        || NULL == in->channel || NULL == in->file_id || NULL == in->file_name) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_create_object
        || NULL == serial->value_create_string || NULL == serial->object_set
        || NULL == serial->serialize || NULL == serial->value_destroy) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    out->channel = NULL;
    out->message = NULL;

    /* Build and serialize the publish-file JSON message. */
    size_t   json_len = 0;
    uint8_t* json_buf =
        pn_file_build_publish_json(serial, allocator, in, &json_len);
    if (NULL == json_buf) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Encrypt when crypto is active. Helper takes ownership of json_buf. */
    const uint8_t* msg_to_encode     = json_buf;
    size_t         msg_to_encode_len = json_len;
    uint8_t*       encrypted_payload = NULL;

#if PUBNUB_ENABLE_CRYPTO
    if (NULL != crypto) {
        pubnub_res_t enc_rc = encrypt_and_wrap_json(
            json_buf, json_len, crypto, allocator, &encrypted_payload, &msg_to_encode_len);
        if (PUBNUB_OK != enc_rc) {
            return enc_rc;
        }
        msg_to_encode = encrypted_payload;
    }
#else
    (void)crypto;
#endif

    /* URL-encode the message (plain or encrypted) for the path segment. */
    char* encoded_message = pn_url_encode_alloc_n(
        msg_to_encode, msg_to_encode_len, allocator, PN_ENCODE_FULL);

    /* Free the source buffer (plain json_buf or encrypted_payload). */
    if (NULL != encrypted_payload) {
        PN_FREE(allocator, encrypted_payload);
    } else {
        PN_FREE(allocator, json_buf);
    }

    if (NULL == encoded_message) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* URL-encode the channel (may be long). */
    const size_t ch_len          = strlen(in->channel);
    char*        encoded_channel = pn_url_encode_alloc_n(
        (const uint8_t*)in->channel, ch_len, allocator, PN_ENCODE_FULL);
    if (NULL == encoded_channel) {
        PN_FREE(allocator, encoded_message);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Scratch-copy publish_key and subscribe_key so the request is self-contained. */
    pubnub_string_view_t pub_key_view;
    pubnub_string_view_t sub_key_view;
    pubnub_res_t         rc;

    rc = pn_request_scratch_encode(
        request, in->publish_key, &pub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, encoded_channel);
        PN_FREE(allocator, encoded_message);
        return rc;
    }
    rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, encoded_channel);
        PN_FREE(allocator, encoded_message);
        return rc;
    }

    /* Path: /v1/files/publish-file/{pub}/{sub}/0/{channel}/0/{message} */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = (pubnub_string_view_t){"publish-file", 12};
    request->path_segments[n++] = pub_key_view;
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    request->path_segments[n++] =
        (pubnub_string_view_t){encoded_channel, strlen(encoded_channel)};
    request->path_segments[n++] = (pubnub_string_view_t){"0", 1};
    request->path_segments[n++] =
        (pubnub_string_view_t){encoded_message, strlen(encoded_message)};
    request->path_segment_count = n;

    request->method = PUBNUB_HTTP_GET;
    rc              = pn_file_add_publish_params(request, in);
    if (PUBNUB_OK != rc) {
        PN_FREE(allocator, encoded_channel);
        PN_FREE(allocator, encoded_message);
        return rc;
    }

    out->channel = encoded_channel;
    out->message = encoded_message;
    return PUBNUB_OK;
}

pubnub_res_t pn_file_build_list_request(pubnub_http_request_t*       request,
                                        const pn_file_list_inputs_t* in)
{
    if (NULL == request || NULL == in || NULL == in->subscribe_key
        || NULL == in->channel) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Encode channel into scratch. */
    pubnub_string_view_t channel_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, in->channel, &channel_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Scratch-copy subscribe_key so the request is self-contained. */
    pubnub_string_view_t sub_key_view;
    rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Path: /v1/files/{sub_key}/channels/{channel}/files */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channels", 8};
    request->path_segments[n++] = channel_view;
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segment_count = n;

    request->method = PUBNUB_HTTP_GET;

    /* Optional query params. */
    if (in->limit > 0) {
        char limit_buf[16];
        (void)pn_snprintf(limit_buf, sizeof(limit_buf), "%d", in->limit);
        rc = pn_request_add_query_param(request, "limit", limit_buf, PN_ENCODE_NONE);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    if (NULL != in->next) {
        rc = pn_request_add_query_param(request, "next", in->next, PN_ENCODE_FULL);
        if (PUBNUB_OK != rc) {
            return rc;
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_file_build_delete_request(pubnub_http_request_t* request,
                                          const pn_file_delete_inputs_t* in)
{
    if (NULL == request || NULL == in || NULL == in->subscribe_key
        || NULL == in->channel || NULL == in->file_id || NULL == in->file_name) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Encode channel into scratch. */
    pubnub_string_view_t channel_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, in->channel, &channel_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Encode file_id into scratch. */
    pubnub_string_view_t id_view;
    rc = pn_request_scratch_encode(request, in->file_id, &id_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Encode file_name into scratch. */
    pubnub_string_view_t name_view;
    rc = pn_request_scratch_encode(request, in->file_name, &name_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Scratch-copy subscribe_key so the request is self-contained. */
    pubnub_string_view_t sub_key_view;
    rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Path: /v1/files/{sub_key}/channels/{channel}/files/{id}/{name} */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channels", 8};
    request->path_segments[n++] = channel_view;
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = id_view;
    request->path_segments[n++] = name_view;
    request->path_segment_count = n;

    request->method = PUBNUB_HTTP_DELETE;

    return PUBNUB_OK;
}

pubnub_res_t pn_file_build_download_request(pubnub_http_request_t* request,
                                            const pn_file_download_inputs_t* in)
{
    if (NULL == request || NULL == in || NULL == in->subscribe_key
        || NULL == in->channel || NULL == in->file_id || NULL == in->file_name) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Encode channel into scratch. */
    pubnub_string_view_t channel_view;
    pubnub_res_t         rc = pn_request_scratch_encode(
        request, in->channel, &channel_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Encode file_id into scratch. */
    pubnub_string_view_t id_view;
    rc = pn_request_scratch_encode(request, in->file_id, &id_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Encode file_name into scratch. */
    pubnub_string_view_t name_view;
    rc = pn_request_scratch_encode(request, in->file_name, &name_view, PN_ENCODE_FULL);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Scratch-copy subscribe_key so the request is self-contained. */
    pubnub_string_view_t sub_key_view;
    rc = pn_request_scratch_encode(
        request, in->subscribe_key, &sub_key_view, PN_ENCODE_NONE);
    if (PUBNUB_OK != rc) {
        return rc;
    }

    /* Path: /v1/files/{sub_key}/channels/{channel}/files/{id}/{name} */
    unsigned int n              = 0;
    request->path_segments[n++] = (pubnub_string_view_t){"v1", 2};
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = sub_key_view;
    request->path_segments[n++] = (pubnub_string_view_t){"channels", 8};
    request->path_segments[n++] = channel_view;
    request->path_segments[n++] = (pubnub_string_view_t){"files", 5};
    request->path_segments[n++] = id_view;
    request->path_segments[n++] = name_view;
    request->path_segment_count = n;

    request->method           = PUBNUB_HTTP_GET;
    request->follow_redirects = 1;

    return PUBNUB_OK;
}

/**
 * @brief Extract form fields from the JSON array into an allocated array.
 *
 * Each element must be {"key":"...","value":"..."}. The returned views
 * alias the parsed tree and are valid until the tree is destroyed.
 *
 * @param serial      Serialization provider (vtable already validated).
 * @param fields_node JSON array node containing form field objects.
 * @param allocator   Allocator for the output array.
 * @param out_fields  Receives allocated array (caller-owned).
 * @param out_count   Receives number of fields extracted.
 * @return PUBNUB_OK on success, or an error code.
 */
static pubnub_res_t
pn_file_extract_form_fields(pubnub_serialization_provider_t* serial,
                            const pubnub_json_value_t*       fields_node,
                            pubnub_allocator_provider_t*     allocator,
                            pn_file_form_field_t**           out_fields,
                            size_t*                          out_count)
{
    const size_t             field_count = serial->array_size(fields_node);
    pn_file_form_field_t*    fields      = NULL;
    size_t                   i           = 0;
    pubnub_json_array_iter_t iter;
    pubnub_json_value_t*     item = NULL;

    if (field_count > PN_FILE_MAX_FORM_FIELDS) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (field_count > 0) {
        fields = (pn_file_form_field_t*)PN_ALLOC(
            allocator, field_count * sizeof(pn_file_form_field_t), sizeof(void*));
        if (NULL == fields) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        if (0 == serial->array_iter_init(fields_node, &iter)) {
            PN_FREE(allocator, fields);
            return PUBNUB_ERR_SERIALIZATION;
        }
    }

    while (i < field_count && serial->array_iter_next(&iter, &item)) {
        if (NULL == item || PUBNUB_JSON_OBJECT != serial->value_type(item)) {
            PN_FREE(allocator, fields);
            return PUBNUB_ERR_SERIALIZATION;
        }

        const pubnub_json_value_t* fk_node = serial->object_get(item, "key", 3);
        const pubnub_json_value_t* fv_node = serial->object_get(item, "value", 5);
        if (NULL == fk_node || NULL == fv_node
            || PUBNUB_JSON_STRING != serial->value_type(fk_node)
            || PUBNUB_JSON_STRING != serial->value_type(fv_node)) {
            PN_FREE(allocator, fields);
            return PUBNUB_ERR_SERIALIZATION;
        }

        size_t      fk_len = 0;
        const char* fk_ptr = serial->value_as_string(fk_node, &fk_len);
        size_t      fv_len = 0;
        const char* fv_ptr = serial->value_as_string(fv_node, &fv_len);
        if (NULL == fk_ptr || NULL == fv_ptr) {
            PN_FREE(allocator, fields);
            return PUBNUB_ERR_SERIALIZATION;
        }

        fields[i].key   = (pubnub_string_view_t){fk_ptr, fk_len};
        fields[i].value = (pubnub_string_view_t){fv_ptr, fv_len};
        i++;
    }

    *out_fields = fields;
    *out_count  = field_count;
    return PUBNUB_OK;
}

pubnub_res_t pn_file_parse_generate_url_response(pubnub_serialization_provider_t* serial,
                                                 const uint8_t*        body,
                                                 size_t                len,
                                                 pn_file_send_state_t* state)
{
    if (NULL == serial || NULL == body || 0 == len || NULL == state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->parse || NULL == serial->value_type
        || NULL == serial->object_get || NULL == serial->value_as_string
        || NULL == serial->array_size || NULL == serial->array_iter_init
        || NULL == serial->array_iter_next || NULL == serial->value_destroy) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    pubnub_json_value_t* tree = serial->parse(serial, body, len);
    if (NULL == tree) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Extract data.id and data.name. */
    const pubnub_json_value_t* data_node = serial->object_get(tree, "data", 4);
    if (NULL == data_node || PUBNUB_JSON_OBJECT != serial->value_type(data_node)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* id_node = serial->object_get(data_node, "id", 2);
    if (NULL == id_node || PUBNUB_JSON_STRING != serial->value_type(id_node)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }
    size_t      id_len = 0;
    const char* id_ptr = serial->value_as_string(id_node, &id_len);
    if (NULL == id_ptr || 0 == id_len) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* name_node = serial->object_get(data_node, "name", 4);
    if (NULL == name_node || PUBNUB_JSON_STRING != serial->value_type(name_node)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }
    size_t      name_len = 0;
    const char* name_ptr = serial->value_as_string(name_node, &name_len);
    if (NULL == name_ptr || 0 == name_len) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Extract file_upload_request.url and form_fields[]. */
    const pubnub_json_value_t* fur_node =
        serial->object_get(tree, "file_upload_request", 19);
    if (NULL == fur_node || PUBNUB_JSON_OBJECT != serial->value_type(fur_node)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* url_node = serial->object_get(fur_node, "url", 3);
    if (NULL == url_node || PUBNUB_JSON_STRING != serial->value_type(url_node)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }
    size_t      url_len = 0;
    const char* url_ptr = serial->value_as_string(url_node, &url_len);
    if (NULL == url_ptr || 0 == url_len) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    const pubnub_json_value_t* fields_node =
        serial->object_get(fur_node, "form_fields", 11);
    if (NULL == fields_node
        || PUBNUB_JSON_ARRAY != serial->value_type(fields_node)) {
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Extract form fields into allocated array. */
    pn_file_form_field_t* fields      = NULL;
    size_t                field_count = 0;
    pubnub_res_t          rc          = pn_file_extract_form_fields(
        serial, fields_node, state->allocator, &fields, &field_count);
    if (PUBNUB_OK != rc) {
        serial->value_destroy(serial, tree);
        return rc;
    }

    /* Copy file_id and file_name (allocator-owned). */
    state->file_id = pn_strndup(id_ptr, id_len, state->allocator);
    if (NULL == state->file_id) {
        PN_FREE(state->allocator, fields);
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    state->file_name = pn_strndup(name_ptr, name_len, state->allocator);
    if (NULL == state->file_name) {
        pn_strfree(state->file_id, state->allocator);
        state->file_id = NULL;
        PN_FREE(state->allocator, fields);
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Copy upload URL (allocator-owned). */
    state->upload_url = pn_strndup(url_ptr, url_len, state->allocator);
    if (NULL == state->upload_url) {
        pn_strfree(state->file_name, state->allocator);
        state->file_name = NULL;
        pn_strfree(state->file_id, state->allocator);
        state->file_id = NULL;
        PN_FREE(state->allocator, fields);
        serial->value_destroy(serial, tree);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Store results. The tree is kept alive so form-field views
     * remain valid until the upload step consumes them. */
    state->form_fields       = fields;
    state->form_field_count  = field_count;
    state->generate_url_tree = tree;

    return PUBNUB_OK;
}

pubnub_res_t pn_file_parse_list_response(pubnub_serialization_provider_t* serial,
                                         const uint8_t*        body,
                                         size_t                len,
                                         pubnub_json_value_t** tree)
{
    if (NULL == serial || NULL == body || 0 == len || NULL == tree) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->parse) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    *tree = serial->parse(serial, body, len);
    if (NULL == *tree) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_file_parse_publish_response(pubnub_serialization_provider_t* serial,
                                            const pubnub_json_value_t* tree,
                                            pubnub_timetoken_t*        out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->ptr = NULL;
    out->len = 0;

    return pn_parse_publish_array_response(serial, tree, out);
}

pubnub_res_t pn_file_list_response_validator(const uint8_t* body,
                                             size_t         body_len,
                                             int            http_status)
{
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }

    /* Bounded scan: look for opening '{' then probe for a
     * "status":200-class envelope or absence of "error":true. */
    size_t i = 0;
    while (i < body_len && i < PN_FILE_RESPONSE_PROBE_LIMIT) {
        const uint8_t c = body[i];
        if (' ' == c || '\t' == c || '\r' == c || '\n' == c) {
            ++i;
            continue;
        }
        break;
    }

    if (i >= body_len || '{' != body[i]) {
        /* Not a JSON object — unexpected format; let the parser
         * decide whether this is a valid response. */
        return PUBNUB_OK;
    }

    /* HTTP 2xx with JSON object — assume success; the lazy parser
     * will validate structure in detail. */
    return PUBNUB_OK;
}

pubnub_res_t pn_file_publish_response_validator(const uint8_t* body,
                                                size_t         body_len,
                                                int            http_status)
{
    return pn_probe_array_status(body, body_len, http_status, 20);
}

pubnub_res_t pn_file_download_response_validator(const uint8_t* body,
                                                 size_t         body_len,
                                                 int            http_status)
{
    (void)body;
    (void)body_len;
    if (http_status >= 400) {
        return PUBNUB_ERR_SERVER;
    }
    if (PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE > 0
        && body_len > PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    return PUBNUB_OK;
}

/**
 * @brief Case-insensitively test whether @p s begins with @p prefix.
 *
 * @param s      NUL-terminated string to test.
 * @param prefix NUL-terminated ASCII prefix.
 * @retval 1 @p s begins with @p prefix (ASCII case-insensitive).
 * @retval 0 Otherwise.
 */
static int pn_file_str_starts_with_ci(const char* s, const char* prefix)
{
    size_t i = 0;
    while ('\0' != prefix[i]) {
        char a = s[i];
        char b = prefix[i];
        if ('A' <= a && a <= 'Z') {
            a = (char)(a + ('a' - 'A'));
        }
        if ('A' <= b && b <= 'Z') {
            b = (char)(b + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
        ++i;
    }
    return 1;
}

/**
 * @brief Validate the host component of a server-provided upload URL.
 *
 * Rejects request-injection bytes (CR/LF/space via
 * pn_str_has_header_unsafe_byte), embedded userinfo ('@', which would
 * let a compromised server redirect the upload to an attacker host),
 * and malformed port syntax (missing or non-numeric).
 *
 * @param host NUL-terminated host[:port] component.
 * @retval 1 Host is safe to use.
 * @retval 0 Host is empty, unsafe, or malformed.
 */
static int pn_file_upload_host_is_safe(const char* host)
{
    const char* p = host;

    if (NULL == host || '\0' == *host) {
        return 0;
    }
    if (pn_str_has_header_unsafe_byte(host)) {
        return 0;
    }
    /* Scan the host label up to an optional ':port'. Reject userinfo
     * ('@') and any embedded path/query bytes that survived the split. */
    while ('\0' != *p && ':' != *p) {
        if ('@' == *p || '/' == *p || '?' == *p || '#' == *p) {
            return 0;
        }
        ++p;
    }
    if (':' == *p) {
        ++p;
        if ('\0' == *p) {
            return 0;
        }
        while ('\0' != *p) {
            if (*p < '0' || *p > '9') {
                return 0;
            }
            ++p;
        }
    }
    return 1;
}

pubnub_res_t pn_file_parse_upload_url(const char*                  url,
                                      pubnub_allocator_provider_t* allocator,
                                      char**                       out_host,
                                      char**                       out_path)
{
    const char* scheme_end;
    const char* host_start;
    const char* path_start;
    const char* path_content;
    size_t      host_len;
    int         scheme_ok;

    if (NULL == url || NULL == allocator || NULL == out_host || NULL == out_path) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_host = NULL;
    *out_path = NULL;

    /* CR/LF/space anywhere in the server-supplied URL would let the
     * response smuggle extra request lines or headers into the upload. */
    if (pn_str_has_header_unsafe_byte(url)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Enforce the transport security policy on the presigned URL: only
     * https:// is accepted when TLS is compiled in; plaintext http:// is
     * tolerated only when secure transport is disabled at build time. */
    scheme_ok = pn_file_str_starts_with_ci(url, "https://");
    if (!PUBNUB_ENABLE_SECURE_TRANSPORT && !scheme_ok) {
        scheme_ok = pn_file_str_starts_with_ci(url, "http://");
    }
    if (!scheme_ok) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Find "://" to skip the scheme. */
    scheme_end = strstr(url, "://");
    if (NULL == scheme_end) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    host_start = scheme_end + 3;
    /* Find the next '/' after the host to split host from path. */
    path_start = strchr(host_start, '/');
    if (NULL == path_start) {
        /* URL has no path — just host. */
        if (!pn_file_upload_host_is_safe(host_start)) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        *out_host = pn_strdup(host_start, allocator);
        if (NULL == *out_host) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        /* Use "/" as default path. */
        *out_path = pn_strdup("/", allocator);
        if (NULL == *out_path) {
            pn_strfree(*out_host, allocator);
            *out_host = NULL;
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        return PUBNUB_OK;
    }

    /* Host is [host_start, path_start). */
    host_len  = (size_t)(path_start - host_start);
    *out_host = pn_strndup(host_start, host_len, allocator);
    if (NULL == *out_host) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    /* Reject userinfo ('@') and malformed ports that could redirect the
     * upload to an attacker-controlled host. */
    if (!pn_file_upload_host_is_safe(*out_host)) {
        pn_strfree(*out_host, allocator);
        *out_host = NULL;
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Path is everything after the leading '/' — the transport prepends
     * '/' before each path segment, so we strip it here to avoid a
     * double-slash in the final URL. */
    path_content = path_start + 1;
    *out_path    = pn_strdup(path_content, allocator);
    if (NULL == *out_path) {
        pn_strfree(*out_host, allocator);
        *out_host = NULL;
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    return PUBNUB_OK;
}

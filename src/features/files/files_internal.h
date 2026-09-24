/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file files_internal.h
 * @brief Internal declarations for the Files feature.
 *
 * State machine types, wire builders, response parsers, multipart
 * encoder, and cleanup functions shared across files_api.c,
 * files_wire.c, files_upload.c, and files_send.c.
 */

#ifndef PN_FILES_INTERNAL_H
#define PN_FILES_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_FILES

#include "pubnub/error.h"
#include "pubnub/features/files.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/types.h"
#include "pubnub/types_fwd.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** Forward declarations — full definitions live in their own headers. */
typedef struct pn_request  pn_request_t;
typedef struct pn_pipeline pn_pipeline_t;

/**
 * @brief Send-file state machine phases.
 *
 * The composed @ref pubnub_send_file operation chains three HTTP
 * requests behind a single future. This enum tracks which step is
 * currently in flight.
 */
typedef enum pn_file_send_phase {
    /** Requesting a presigned upload URL from PubNub. */
    PN_FILE_SEND_GENERATE_URL = 0,
    /** Uploading file content to S3 via multipart POST. */
    PN_FILE_SEND_UPLOADING,
    /** Publishing the file message to the channel. */
    PN_FILE_SEND_PUBLISHING,
    /** All steps completed successfully. */
    PN_FILE_SEND_DONE,
    /** S3 upload succeeded but publishing the file message failed. */
    PN_FILE_SEND_PUBLISH_FAILED,
    /** A non-recoverable failure occurred. */
    PN_FILE_SEND_FAILED
} pn_file_send_phase_t;

/** @brief Multipart overhead constants (byte counts of fixed literals). */
#define PN_MP_DASHDASH   2  /* "--" */
#define PN_MP_CRLF       2  /* "\r\n" */
#define PN_MP_CD_FIELD   38 /* "Content-Disposition: form-data; name=\"" */
#define PN_MP_QUOTE_CRLF 3  /* "\"\r\n" */
/* "Content-Disposition: form-data; name="file"; filename=" = 55 bytes */
#define PN_MP_CD_FILE  55
#define PN_MP_CT_LABEL 14 /* "Content-Type: " */

/**
 * @brief Single form field from the generate-upload-url response.
 *
 * Views alias the parsed JSON tree lifetime — valid until the tree
 * is destroyed during state cleanup.
 */
typedef struct pn_file_form_field {
    /** Form field name (e.g., "tagging", "Content-Type"). */
    pubnub_string_view_t key;
    /** Form field value. */
    pubnub_string_view_t value;
} pn_file_form_field_t;

/**
 * @brief Maximum form fields from generate-upload-url response.
 *
 * S3 presigned uploads typically include 6-8 fields. This ceiling
 * avoids unbounded allocation for the field array. Override via
 * @c -DPUBNUB_CFG_FILE_MAX_FORM_FIELDS=N at compile time.
 *
 * @pre Must be >= 8 (minimum fields observed in production S3
 *      presigned-POST responses).
 */
#ifndef PUBNUB_CFG_FILE_MAX_FORM_FIELDS
#define PUBNUB_CFG_FILE_MAX_FORM_FIELDS 16
#endif

#if PUBNUB_CFG_FILE_MAX_FORM_FIELDS < 8
#error "PUBNUB_CFG_FILE_MAX_FORM_FIELDS must be >= 8"
#endif

/** Internal alias for brevity. */
#define PN_FILE_MAX_FORM_FIELDS PUBNUB_CFG_FILE_MAX_FORM_FIELDS

/**
 * @brief Allocator-owned URL-encoded strings for file publish path.
 *
 * Tracked in the send state for proper cleanup on state teardown.
 */
typedef struct pn_file_publish_encoded {
    /** URL-encoded channel (allocator-owned). */
    char* channel;
    /** URL-encoded file message JSON (allocator-owned). */
    char* message;
} pn_file_publish_encoded_t;

/**
 * @brief Per-request state for the send_file multi-step operation.
 *
 * Allocated once when the send_file operation starts and freed via
 * @ref pn_file_send_state_cleanup when the slot is released.
 *
 * Holds all data that must survive across the three async steps
 * (generate-url, upload, publish) because the caller's stack frame
 * is long gone by the time callbacks fire.
 */
typedef struct pn_file_send_state {
    /** Current phase of the multi-step operation. */
    pn_file_send_phase_t phase;

    /** Server-assigned file ID (allocator-owned copy). */
    char* file_id;
    /** Final file name from server (allocator-owned copy). */
    char* file_name;

    /** Full S3 presigned upload URL (allocator-owned). */
    char* upload_url;
    /** Host portion parsed from upload_url (allocator-owned). */
    char* upload_host;
    /** Path + query portion parsed from upload_url (allocator-owned). */
    char* upload_path;

    /** Form fields from generate-url response (allocator-owned array).
     *  Valid from generate-url parse until multipart encoding completes;
     *  freed in transition to UPLOADING phase. On arena allocators,
     *  memory is not reclaimed until context destroy. */
    pn_file_form_field_t* form_fields;
    /** Number of populated form fields. */
    size_t form_field_count;

    /** Multipart-encoded body buffer (allocator-owned). */
    uint8_t* multipart_body;
    /** Length of multipart body in bytes. */
    size_t multipart_body_len;

    /** Multipart boundary string (inline, 24 chars + NUL + padding). */
    char multipart_boundary[32];

    /** Allocator-owned copy of opts.channel. */
    char* channel;
    /** Allocator-owned copy of opts.message (NULL if none). */
    char* message;
    /** Allocator-owned copy of opts.meta (NULL if none). */
    char* meta;
    /** Allocator-owned copy of opts.custom_message_type (NULL if none). */
    char* custom_message_type;
    /** Allocator-owned copy of opts.content_type (NULL if none). */
    char* content_type;

    /** Store-in-history flag from opts. */
    int store;
    /** TTL from opts. */
    unsigned int ttl;

    /** Pointer to file data for upload. When crypto is active, points
     *  to encrypted_data; otherwise borrowed from user opts. */
    const uint8_t* data;
    /** Length of file data for upload. */
    size_t data_len;
    /** Allocator-owned encrypted file content (NULL when no crypto). */
    uint8_t* encrypted_data;
    /** Allocator-owned file content loaded from file_path (NULL when
     *  data was provided directly by the caller). */
    uint8_t* loaded_file_data;

    /** S3 upload timeout override in milliseconds. */
    uint32_t upload_timeout_ms;
    /** PubNub API step timeout override in milliseconds. */
    uint32_t timeout_ms;

    /** Allocator for all owned allocations in this struct. */
    pubnub_allocator_provider_t* allocator;
    /** Context pointer for re-dispatch of subsequent steps. */
    pubnub_context_t* ctx;
    /** Transport provider for direct S3 upload (bypasses pipeline). */
    pubnub_transport_provider_t* transport;
    /** Pipeline for PubNub API steps (generate-url, publish). */
    pn_pipeline_t* pipeline;
    /** Platform provider (for timers and random). */
    pubnub_platform_provider_t* platform;
    /** Serialization provider (for JSON parsing/building). */
    pubnub_serialization_provider_t* serialization;

    /** Allocator-owned JSON body buffer from the generate-upload-url
     *  POST request ({"name":"<file_name>"}). Freed early when the
     *  slot is repurposed for the S3 upload step; the cleanup function
     *  frees it as a safety net on error paths. */
    uint8_t* generate_url_body;

    /** Parsed JSON tree from generate-url response (kept alive for
     *  form-field views). Freed during transition to upload step. */
    pubnub_json_value_t* generate_url_tree;

    /** Parsed JSON tree from publish response (kept alive for
     *  timetoken view). Freed on state cleanup. */
    pubnub_json_value_t* publish_tree;

    /** Timetoken from publish success (aliases publish_tree). */
    pubnub_timetoken_t timetoken;

    /** Allocator-owned URL-encoded strings from the publish request
     *  build. Freed on state cleanup. */
    pn_file_publish_encoded_t publish_encoded;

    /** Slot ID for the reused request slot. */
    uint16_t slot_id;
} pn_file_send_state_t;

/**
 * @brief Per-request state for @ref pubnub_list_files.
 *
 * Holds the lazily-parsed response tree for result accessors.
 * Released via @ref pn_file_list_state_cleanup.
 */
typedef struct pn_file_list_state {
    /** Parsed response JSON tree (lazy; NULL until first accessor). */
    pubnub_json_value_t* parsed;
    /** Allocator for cleanup. */
    pubnub_allocator_provider_t* allocator;
    /** Serialization provider for tree operations. */
    pubnub_serialization_provider_t* serialization;
    /** Cached forward cursor for O(1) sequential indexed accessors. */
    pubnub_json_array_iter_t iter_cache;
    /** Index the cached cursor's next step will return. */
    size_t iter_pos;
    /** Non-zero when @ref iter_cache is usable (zero = restart). */
    uint8_t iter_valid;
} pn_file_list_state_t;

/**
 * @brief Per-request state for @ref pubnub_download_file.
 *
 * Holds decrypted content when crypto is active. When no crypto is
 * configured, the response body is returned directly and this state
 * only tracks the allocator for cleanup symmetry.
 */
typedef struct pn_file_download_state {
    /** Decrypted file content (allocator-owned; NULL when no crypto). */
    uint8_t* decrypted;
    /** Length of decrypted content. */
    size_t decrypted_len;
    /** Allocator for cleanup. */
    pubnub_allocator_provider_t* allocator;
} pn_file_download_state_t;

/**
 * @brief Per-request state for @ref pubnub_publish_file_message.
 *
 * Mirrors publish's per-request state: holds allocator-owned encoded
 * strings and the parsed timetoken.
 */
typedef struct pn_file_publish_state {
    /** Parsed publish response (timetoken view). */
    pubnub_timetoken_t timetoken;
    /** Parsed body tree (kept alive for timetoken view). */
    pubnub_json_value_t* parsed_tree;
    /** Allocator-owned percent-encoded channel. */
    char* encoded_channel;
    /** Allocator-owned percent-encoded file message JSON (path segment). */
    char* encoded_message;
    /** Allocator for cleanup. */
    pubnub_allocator_provider_t* allocator;
    /** Serialization provider for tree cleanup. */
    pubnub_serialization_provider_t* serialization;
} pn_file_publish_state_t;

/**
 * @brief Inputs for the generate-upload-url request builder.
 */
typedef struct pn_file_generate_url_inputs {
    /** Subscribe key (borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (borrowed, NUL-terminated). */
    const char* channel;
    /** Desired file name (borrowed, NUL-terminated). */
    const char* file_name;
} pn_file_generate_url_inputs_t;

/**
 * @brief Inputs for the file publish request builder.
 */
typedef struct pn_file_publish_inputs {
    /** Publish key (borrowed, NUL-terminated). */
    const char* publish_key;
    /** Subscribe key (borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (borrowed, NUL-terminated). */
    const char* channel;
    /** File ID (borrowed, NUL-terminated). */
    const char* file_id;
    /** File name (borrowed, NUL-terminated). */
    const char* file_name;
    /** Optional user message JSON (borrowed, NUL-terminated; NULL to omit). */
    const char* message;
    /** Optional metadata JSON (borrowed, NUL-terminated; NULL to omit). */
    const char* meta;
    /** Optional custom message type (borrowed, NUL-terminated; NULL to omit). */
    const char* custom_message_type;
    /** Store in history (1=store, 0=don't). */
    int store;
    /** TTL in minutes (0=default). */
    unsigned int ttl;
} pn_file_publish_inputs_t;

/**
 * @brief Inputs for the list-files request builder.
 */
typedef struct pn_file_list_inputs {
    /** Subscribe key (borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (borrowed, NUL-terminated). */
    const char* channel;
    /** Max results per page (0 = server default). */
    int limit;
    /** Pagination token (NULL = first page). */
    const char* next;
} pn_file_list_inputs_t;

/**
 * @brief Inputs for the delete-file request builder.
 */
typedef struct pn_file_delete_inputs {
    /** Subscribe key (borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (borrowed, NUL-terminated). */
    const char* channel;
    /** File ID (borrowed, NUL-terminated). */
    const char* file_id;
    /** File name (borrowed, NUL-terminated). */
    const char* file_name;
} pn_file_delete_inputs_t;

/**
 * @brief Inputs for the download-file request builder.
 */
typedef struct pn_file_download_inputs {
    /** Subscribe key (borrowed, NUL-terminated). */
    const char* subscribe_key;
    /** Target channel (borrowed, NUL-terminated). */
    const char* channel;
    /** File ID (borrowed, NUL-terminated). */
    const char* file_id;
    /** File name (borrowed, NUL-terminated). */
    const char* file_name;
} pn_file_download_inputs_t;

/**
 * @brief Build the generate-upload-url POST request.
 *
 * Populates path segments, host, method, content-type header, and
 * request body with {"name":"<file_name>"}.
 *
 * @param request       HTTP request descriptor to populate.
 * @param serialization Serialization provider for body construction.
 * @param allocator     Allocator for body buffer.
 * @param in            Input parameters (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_file_build_generate_url_request(pubnub_http_request_t* request,
                                   pubnub_serialization_provider_t* serialization,
                                   pubnub_allocator_provider_t* allocator,
                                   const pn_file_generate_url_inputs_t* in);

/**
 * @brief Build the S3 upload multipart POST request.
 *
 * Populates host, path, method, content-type header (with boundary),
 * and body pointer. The multipart body must already be encoded in
 * @p body / @p body_len.
 *
 * @param request  HTTP request descriptor to populate.
 * @param host     S3 host string (borrowed, valid for request lifetime).
 * @param path     S3 path+query (borrowed, valid for request lifetime).
 * @param boundary Multipart boundary (borrowed, NUL-terminated).
 * @param body     Pre-encoded multipart body (borrowed).
 * @param body_len Length of multipart body.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_file_build_upload_request(pubnub_http_request_t* request,
                                          const char*            host,
                                          const char*            path,
                                          const char*            boundary,
                                          const uint8_t*         body,
                                          size_t                 body_len);

/**
 * @brief Build the publish-file-message GET request.
 *
 * Populates path segments and query parameters for the file publish
 * endpoint. When @p crypto is non-NULL and PUBNUB_ENABLE_CRYPTO is
 * active, the file message JSON is encrypted and base64-encoded
 * before URL-encoding into the path (matching JS SDK behavior).
 *
 * @param request   HTTP request descriptor to populate.
 * @param allocator Allocator for URL-encoded strings.
 * @param serial    Serialization provider for message JSON construction.
 * @param in        Input parameters (borrowed).
 * @param crypto    Crypto module for message encryption (NULL = no encryption).
 * @param out       Receives allocator-owned encoded strings for cleanup.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_file_build_publish_request(pubnub_http_request_t* request,
                                           pubnub_allocator_provider_t* allocator,
                                           pubnub_serialization_provider_t* serial,
                                           const pn_file_publish_inputs_t* in,
                                           pubnub_crypto_module_t*    crypto,
                                           pn_file_publish_encoded_t* out);

/**
 * @brief Build the list-files GET request.
 *
 * Populates path segments and optional limit/next query parameters.
 *
 * @param request HTTP request descriptor to populate.
 * @param in      Input parameters (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_file_build_list_request(pubnub_http_request_t*       request,
                                        const pn_file_list_inputs_t* in);

/**
 * @brief Build the delete-file DELETE request.
 *
 * Populates path segments, host, and method.
 *
 * @param request HTTP request descriptor to populate.
 * @param in      Input parameters (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_file_build_delete_request(pubnub_http_request_t* request,
                                          const pn_file_delete_inputs_t* in);

/**
 * @brief Build the download-file GET request.
 *
 * Populates path segments, host, and method.
 *
 * @param request HTTP request descriptor to populate.
 * @param in      Input parameters (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_file_build_download_request(pubnub_http_request_t* request,
                                            const pn_file_download_inputs_t* in);

/**
 * @brief Parse the generate-upload-url JSON response.
 *
 * Extracts file ID, file name, upload URL, and form fields from the
 * response body. The parsed JSON tree is stored in @p state for
 * form-field view lifetime.
 *
 * @param serial Serialization provider (borrowed).
 * @param body   Response body bytes (borrowed).
 * @param len    Response body length.
 * @param state  Send state to populate with extracted values.
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERIALIZATION on parse failure.
 */
pubnub_res_t pn_file_parse_generate_url_response(pubnub_serialization_provider_t* serial,
                                                 const uint8_t*        body,
                                                 size_t                len,
                                                 pn_file_send_state_t* state);

/**
 * @brief Parse the list-files JSON response into a tree.
 *
 * The tree is stored on the request slot's feature_state for lazy
 * access by result accessors.
 *
 * @param serial Serialization provider (borrowed).
 * @param body   Response body bytes (borrowed).
 * @param len    Response body length.
 * @param tree   Receives the parsed JSON tree (caller-owned via serial).
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERIALIZATION on parse failure.
 */
pubnub_res_t pn_file_parse_list_response(pubnub_serialization_provider_t* serial,
                                         const uint8_t*        body,
                                         size_t                len,
                                         pubnub_json_value_t** tree);

/**
 * @brief Parse the publish-file-message response for timetoken.
 *
 * Expected shape: [1, "Sent", "17234567890123456"].
 *
 * @param serial Serialization provider (borrowed).
 * @param tree   Parsed response body tree (borrowed).
 * @param out    Receives the timetoken view (aliases tree data).
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERIALIZATION on failure.
 */
pubnub_res_t pn_file_parse_publish_response(pubnub_serialization_provider_t* serial,
                                            const pubnub_json_value_t* tree,
                                            pubnub_timetoken_t*        out);

/**
 * @brief Parameters describing the file content for multipart encoding.
 */
typedef struct pn_file_content_params {
    /** File content bytes (borrowed). */
    const uint8_t* data;
    /** File content length in bytes. */
    size_t data_len;
    /** File name for Content-Disposition (borrowed, NUL-terminated). */
    const char* name;
    /** MIME type for the file part (borrowed, NUL-terminated; NULL for
     *  default "application/octet-stream"). */
    const char* content_type;
} pn_file_content_params_t;

/**
 * @brief Compute the total size of the multipart-encoded body.
 *
 * @param form_fields  Form field array (borrowed).
 * @param field_count  Number of form fields.
 * @param file         File content parameters.
 * @param boundary     Multipart boundary string (borrowed).
 * @return Total encoded body size in bytes.
 */
size_t pn_file_multipart_size(const pn_file_form_field_t*     form_fields,
                              size_t                          field_count,
                              const pn_file_content_params_t* file,
                              const char*                     boundary);

/**
 * @brief Encode the multipart form-data body.
 *
 * Writes all form fields in order, followed by the file content as
 * the final "file" field, into @p output.
 *
 * @param form_fields  Form field array (borrowed, in server order).
 * @param field_count  Number of form fields.
 * @param file         File content parameters.
 * @param boundary     Multipart boundary string (borrowed).
 * @param output       Output buffer (caller-owned).
 * @param output_cap   Capacity of @p output in bytes.
 * @param out_len      Receives bytes written on success.
 * @return PUBNUB_OK on success, PUBNUB_ERR_BUFFER_TOO_SMALL if
 *         output_cap is insufficient, or PUBNUB_ERR_INVALID_ARGUMENT if
 *         the file name or content type contains a CR, LF, or double-quote
 *         byte (which would allow MIME part-header injection).
 */
pubnub_res_t pn_file_multipart_encode(const pn_file_form_field_t* form_fields,
                                      size_t                      field_count,
                                      const pn_file_content_params_t* file,
                                      const char*                     boundary,
                                      uint8_t*                        output,
                                      size_t  output_cap,
                                      size_t* out_len);

/**
 * @brief Generate a random multipart boundary string.
 *
 * Produces a 24-character alphanumeric boundary using
 * platform->random_bytes. The result is NUL-terminated.
 *
 * @param platform      Platform provider (for random_bytes).
 * @param boundary      Output buffer (must be >= 32 bytes).
 * @param boundary_size Size of @p boundary buffer.
 * @return PUBNUB_OK on success, or PUBNUB_ERR_INTERNAL if random
 *         generation fails.
 */
pubnub_res_t pn_file_generate_boundary(pubnub_platform_provider_t* platform,
                                       char*                       boundary,
                                       size_t boundary_size);

/**
 * @brief Callback invoked when the generate-upload-url step completes.
 *
 * On success: parses the response, extracts file ID, name, upload
 * URL, and form fields. Builds the multipart body and reconfigures
 * the slot for S3 upload, then re-dispatches directly to transport.
 *
 * @param request   Completed request slot (borrowed).
 * @param status    SDK-level result code.
 * @param user_data Pointer to @ref pn_file_send_state_t.
 */
void pn_file_send_on_generate_complete(pn_request_t* request,
                                       pubnub_res_t  status,
                                       void*         user_data);

/**
 * @brief Callback invoked when the S3 upload step completes.
 *
 * On success (HTTP 204): reconfigures the slot for publish-file-
 * message and re-dispatches through the pipeline.
 * On failure: reports error to the user future immediately.
 *
 * @param request   Completed request slot (borrowed).
 * @param status    SDK-level result code.
 * @param user_data Pointer to @ref pn_file_send_state_t.
 */
void pn_file_send_on_upload_complete(pn_request_t* request,
                                     pubnub_res_t  status,
                                     void*         user_data);

/**
 * @brief Callback invoked when the publish-file-message step completes.
 *
 * On success: extracts timetoken, marks DONE, reports success.
 * On failure: marks PUBLISH_FAILED — the file exists on S3 but the
 * channel notification was not delivered. Caller can retry via
 * @ref pubnub_publish_file_message using the file_id and file_name
 * from the result accessor.
 *
 * @param request   Completed request slot (borrowed).
 * @param status    SDK-level result code.
 * @param user_data Pointer to @ref pn_file_send_state_t.
 */
void pn_file_send_on_publish_complete(pn_request_t* request,
                                      pubnub_res_t  status,
                                      void*         user_data);

/**
 * @brief Response validator for list-files.
 *
 * Checks for HTTP 2xx and minimal JSON envelope presence.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on logical success, error code otherwise.
 */
pubnub_res_t pn_file_list_response_validator(const uint8_t* body,
                                             size_t         body_len,
                                             int            http_status);

/**
 * @brief Response validator for download-file operations.
 *
 * When PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE > 0, rejects responses whose
 * body exceeds the configured size limit.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on success, PUBNUB_ERR_SERVER on HTTP error,
 *         PUBNUB_ERR_BUFFER_TOO_SMALL when body_len exceeds limit.
 */
pubnub_res_t pn_file_download_response_validator(const uint8_t* body,
                                                 size_t         body_len,
                                                 int            http_status);

/**
 * @brief Response validator for publish-file-message.
 *
 * Checks for [1,...] success pattern (same as standard publish).
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length.
 * @param http_status HTTP status code.
 * @return PUBNUB_OK on logical success, error code otherwise.
 */
pubnub_res_t pn_file_publish_response_validator(const uint8_t* body,
                                                size_t         body_len,
                                                int            http_status);

/**
 * @brief Cleanup for the send_file slot's feature_state.
 *
 * Frees all allocator-owned strings, multipart body, and parsed
 * JSON trees held in the state struct.
 *
 * @param state     Pointer to @ref pn_file_send_state_t.
 * @param allocator Allocator for deallocation.
 */
void pn_file_send_state_cleanup(void* state, pubnub_allocator_provider_t* allocator);

/**
 * @brief Cleanup for the list_files slot's feature_state.
 *
 * Destroys the parsed JSON tree.
 *
 * @param state     Pointer to @ref pn_file_list_state_t.
 * @param allocator Allocator for deallocation.
 */
void pn_file_list_state_cleanup(void* state, pubnub_allocator_provider_t* allocator);

/**
 * @brief Cleanup for the download_file slot's feature_state.
 *
 * Frees decrypted content buffer (if crypto was active).
 *
 * @param state     Pointer to @ref pn_file_download_state_t.
 * @param allocator Allocator for deallocation.
 */
void pn_file_download_state_cleanup(void*                        state,
                                    pubnub_allocator_provider_t* allocator);

/**
 * @brief Cleanup for the publish_file_message slot's feature_state.
 *
 * Frees encoded strings and destroys the parsed tree.
 *
 * @param state     Pointer to @ref pn_file_publish_state_t.
 * @param allocator Allocator for deallocation.
 */
void pn_file_publish_state_cleanup(void*                        state,
                                   pubnub_allocator_provider_t* allocator);

/**
 * @brief Parse a full URL into host and path+query components.
 *
 * Allocates separate NUL-terminated strings for the host and the
 * path (including query string). Used to decompose the S3 presigned
 * URL for the transport provider.
 *
 * @param url       Full URL (borrowed, NUL-terminated).
 * @param allocator Allocator for output strings.
 * @param out_host  Receives allocator-owned host string.
 * @param out_path  Receives allocator-owned path+query string.
 * @return PUBNUB_OK on success, PUBNUB_ERR_INVALID_ARGUMENT on
 *         malformed URL, PUBNUB_ERR_OUT_OF_MEMORY on alloc failure.
 */
pubnub_res_t pn_file_parse_upload_url(const char*                  url,
                                      pubnub_allocator_provider_t* allocator,
                                      char**                       out_host,
                                      char**                       out_path);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_FILES */

#endif /* PN_FILES_INTERNAL_H */

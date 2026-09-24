/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "files_internal.h"

#include <string.h>

/** Boundary length in characters (not including NUL). */
#define PN_FILE_BOUNDARY_LEN 24

/* PN_MP_* multipart overhead constants are defined in files_internal.h. */

/** Default MIME type when caller passes NULL. */
static const char pn_default_content_type[] = "application/octet-stream";

/** Characters used for boundary generation. */
static const char pn_boundary_charset[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** Number of valid boundary characters. */
#define PN_BOUNDARY_CHARSET_LEN 62

/**
 * @brief Compute the per-field overhead for one form field part.
 *
 * Format:
 *   --<boundary>\r\n
 *   Content-Disposition: form-data; name="<key>"\r\n
 *   \r\n
 *   <value>\r\n
 */
static size_t pn_field_part_size(size_t boundary_len, size_t key_len, size_t value_len)
{
    return PN_MP_DASHDASH + boundary_len + PN_MP_CRLF + PN_MP_CD_FIELD + key_len
         + PN_MP_QUOTE_CRLF + PN_MP_CRLF + value_len + PN_MP_CRLF;
}

/**
 * @brief Compute the file part overhead.
 *
 * Format:
 *   --<boundary>\r\n
 *   Content-Disposition: form-data; name="file"; filename="<name>"\r\n
 *   Content-Type: <content_type>\r\n
 *   \r\n
 *   <file_bytes>\r\n
 */
static size_t pn_file_part_size(size_t boundary_len,
                                size_t filename_len,
                                size_t content_type_len,
                                size_t file_len)
{
    return PN_MP_DASHDASH + boundary_len + PN_MP_CRLF + PN_MP_CD_FILE
         + filename_len + PN_MP_QUOTE_CRLF + PN_MP_CT_LABEL + content_type_len
         + PN_MP_CRLF + PN_MP_CRLF + file_len + PN_MP_CRLF;
}

/** @brief Compute the closing boundary size: --<boundary>--\r\n */
static size_t pn_closing_boundary_size(size_t boundary_len)
{
    return PN_MP_DASHDASH + boundary_len + PN_MP_DASHDASH + PN_MP_CRLF;
}

/**
 * @brief Append bytes to output buffer, advancing the write cursor.
 *
 * The caller guarantees sufficient capacity (pre-checked via size
 * computation). No bounds checking is performed here.
 */
static void pn_write(uint8_t** cursor, const void* data, size_t len)
{
    if (0 == len) {
        return;
    }
    memcpy(*cursor, data, len);
    *cursor += len;
}

/** @brief Append a NUL-terminated string (without the NUL). */
static void pn_write_str(uint8_t** cursor, const char* str)
{
    size_t len = strlen(str);
    memcpy(*cursor, str, len);
    *cursor += len;
}

/**
 * @brief Return non-zero if @p s contains a byte that would break a MIME
 *        part header (CR, LF, or double-quote). Space is allowed.
 */
static int pn_mime_value_is_unsafe(const char* s)
{
    const char* p = s;

    if (NULL == s) {
        return 0;
    }
    while ('\0' != *p) {
        if ('\r' == *p || '\n' == *p || '"' == *p) {
            return 1;
        }
        ++p;
    }
    return 0;
}

pubnub_res_t pn_file_generate_boundary(pubnub_platform_provider_t* platform,
                                       char*                       boundary,
                                       size_t boundary_size)
{
    uint8_t raw[PN_FILE_BOUNDARY_LEN];
    int     rc;
    size_t  i;

    if (NULL == platform || NULL == boundary
        || boundary_size < PN_FILE_BOUNDARY_LEN + 1) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    rc = platform->random_bytes(platform, raw, PN_FILE_BOUNDARY_LEN);
    if (0 != rc) {
        return PUBNUB_ERR_INTERNAL;
    }

    for (i = 0; i < PN_FILE_BOUNDARY_LEN; ++i) {
        boundary[i] = pn_boundary_charset[raw[i] % PN_BOUNDARY_CHARSET_LEN];
    }
    boundary[PN_FILE_BOUNDARY_LEN] = '\0';

    return PUBNUB_OK;
}

size_t pn_file_multipart_size(const pn_file_form_field_t*     form_fields,
                              size_t                          field_count,
                              const pn_file_content_params_t* file,
                              const char*                     boundary)
{
    size_t      boundary_len;
    size_t      filename_len;
    size_t      ct_len;
    size_t      total = 0;
    size_t      i;
    const char* ct;

    if (NULL == boundary || NULL == file || NULL == file->name) {
        return 0;
    }

    ct = (NULL != file->content_type) ? file->content_type : pn_default_content_type;

    boundary_len = strlen(boundary);
    filename_len = strlen(file->name);
    ct_len       = strlen(ct);

    /* Sum all form-field parts. */
    for (i = 0; i < field_count; ++i) {
        total += pn_field_part_size(
            boundary_len, form_fields[i].key.len, form_fields[i].value.len);
    }

    /* File part. */
    total += pn_file_part_size(boundary_len, filename_len, ct_len, file->data_len);

    /* Closing boundary. */
    total += pn_closing_boundary_size(boundary_len);

    return total;
}

pubnub_res_t pn_file_multipart_encode(const pn_file_form_field_t* form_fields,
                                      size_t                      field_count,
                                      const pn_file_content_params_t* file,
                                      const char*                     boundary,
                                      uint8_t*                        output,
                                      size_t  output_cap,
                                      size_t* out_len)
{
    size_t      required;
    uint8_t*    cursor;
    size_t      i;
    const char* ct;

    if (NULL == form_fields || NULL == file || NULL == file->name
        || NULL == boundary || NULL == output || NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    ct = (NULL != file->content_type) ? file->content_type : pn_default_content_type;

    if (pn_mime_value_is_unsafe(file->name) || pn_mime_value_is_unsafe(ct)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    required = pn_file_multipart_size(form_fields, field_count, file, boundary);
    if (output_cap < required) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    cursor = output;

    /* Write each form field part. */
    for (i = 0; i < field_count; ++i) {
        pn_write_str(&cursor, "--");
        pn_write_str(&cursor, boundary);
        pn_write_str(&cursor, "\r\n");
        pn_write_str(&cursor, "Content-Disposition: form-data; name=\"");
        pn_write(&cursor, form_fields[i].key.ptr, form_fields[i].key.len);
        pn_write_str(&cursor, "\"\r\n");
        pn_write_str(&cursor, "\r\n");
        pn_write(&cursor, form_fields[i].value.ptr, form_fields[i].value.len);
        pn_write_str(&cursor, "\r\n");
    }

    /* Write the file part. */
    pn_write_str(&cursor, "--");
    pn_write_str(&cursor, boundary);
    pn_write_str(&cursor, "\r\n");
    pn_write_str(&cursor,
                 "Content-Disposition: form-data; name=\"file\"; filename=\"");
    pn_write_str(&cursor, file->name);
    pn_write_str(&cursor, "\"\r\n");
    pn_write_str(&cursor, "Content-Type: ");
    pn_write_str(&cursor, ct);
    pn_write_str(&cursor, "\r\n");
    pn_write_str(&cursor, "\r\n");
    if (file->data_len > 0 && NULL != file->data) {
        pn_write(&cursor, file->data, file->data_len);
    }
    pn_write_str(&cursor, "\r\n");

    /* Closing boundary. */
    pn_write_str(&cursor, "--");
    pn_write_str(&cursor, boundary);
    pn_write_str(&cursor, "--\r\n");

    *out_len = (size_t)(cursor - output);
    return PUBNUB_OK;
}

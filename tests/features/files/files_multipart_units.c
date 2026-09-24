/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport_types.h"

/* Internal declarations shared with the feature implementation. */
#include "features/files/files_internal.h"

/* Mock platform provider that returns predictable random bytes for
 * boundary generation tests. Fills the buffer with sequential values
 * starting at 0 to produce a deterministic boundary. */
static int mock_random_bytes(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i % 256);
    }
    return 0;
}

/* Platform provider that always fails random_bytes. */
static int mock_random_bytes_fail(pubnub_platform_provider_t* self,
                                  uint8_t*                    buf,
                                  size_t                      len)
{
    (void)self;
    (void)buf;
    (void)len;
    return -1;
}

static pubnub_platform_provider_t s_mock_platform = {
    .random_bytes = mock_random_bytes,
};

static pubnub_platform_provider_t s_mock_platform_fail = {
    .random_bytes = mock_random_bytes_fail,
};

/* Helper: build a simple set of form fields for tests. */
static pn_file_form_field_t s_test_fields[2] = {
    {.key   = {.ptr = "tagging", .len = 7},
     .value = {.ptr = "<Tag>val</Tag>", .len = 14}          },
    {.key   = {.ptr = "Content-Type", .len = 12},
     .value = {.ptr = "application/octet-stream", .len = 24}},
};

static void multipart_size_computes_exact_length(void** state)
{
    (void)state;
    const char*   boundary    = "ABCDEFGHIJKLMNOPQRSTUVWX";
    const uint8_t file_data[] = {0x01, 0x02, 0x03, 0x04};

    const pn_file_content_params_t file_params = {
        .data         = file_data,
        .data_len     = sizeof(file_data),
        .name         = "test.bin",
        .content_type = "application/octet-stream"};

    size_t predicted =
        pn_file_multipart_size(s_test_fields, 2, &file_params, boundary);
    assert_true(predicted > 0);

    /* Encode into a buffer of exactly the predicted size. */
    uint8_t* buf = (uint8_t*)malloc(predicted);
    assert_non_null(buf);

    size_t       written = 0;
    pubnub_res_t rc      = pn_file_multipart_encode(
        s_test_fields, 2, &file_params, boundary, buf, predicted, &written);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(written, predicted);

    free(buf);
}

static void multipart_encode_produces_valid_body(void** state)
{
    (void)state;
    const char*   boundary    = "TestBoundary123456789012";
    const uint8_t file_data[] = "Hello, World!";

    const pn_file_content_params_t file_params = {.data         = file_data,
                                                  .data_len     = 13,
                                                  .name         = "hello.txt",
                                                  .content_type = "text/plain"};

    size_t predicted =
        pn_file_multipart_size(s_test_fields, 2, &file_params, boundary);

    uint8_t* buf = (uint8_t*)malloc(predicted + 1);
    assert_non_null(buf);
    memset(buf, 0, predicted + 1);

    size_t       written = 0;
    pubnub_res_t rc      = pn_file_multipart_encode(
        s_test_fields, 2, &file_params, boundary, buf, predicted, &written);

    assert_int_equal(rc, PUBNUB_OK);

    /* Verify boundary markers appear in order. The body must start
     * with "--<boundary>\r\n" for the first form field. */
    const char* body_str = (const char*)buf;
    assert_non_null(strstr(body_str, "--TestBoundary123456789012\r\n"));

    /* Verify form field names appear. */
    assert_non_null(strstr(body_str, "name=\"tagging\""));
    assert_non_null(strstr(body_str, "name=\"Content-Type\""));

    /* File part must appear after form fields. */
    const char* file_part = strstr(body_str, "name=\"file\"");
    assert_non_null(file_part);
    assert_non_null(strstr(file_part, "filename=\"hello.txt\""));
    assert_non_null(strstr(file_part, "Content-Type: text/plain"));

    /* File content must appear. */
    assert_non_null(strstr(file_part, "Hello, World!"));

    /* Closing boundary must end with "--". */
    assert_non_null(strstr(body_str, "--TestBoundary123456789012--\r\n"));

    /* Form fields must appear before the file part. */
    const char* tagging_pos = strstr(body_str, "name=\"tagging\"");
    assert_true(tagging_pos < file_part);

    free(buf);
}

static void multipart_encode_handles_zero_byte_file(void** state)
{
    (void)state;
    const char* boundary = "ZeroByteBoundary12345678";

    const pn_file_content_params_t file_params = {
        .data         = NULL,
        .data_len     = 0,
        .name         = "empty.dat",
        .content_type = "application/octet-stream"};

    size_t predicted =
        pn_file_multipart_size(s_test_fields, 2, &file_params, boundary);
    assert_true(predicted > 0);

    uint8_t* buf = (uint8_t*)malloc(predicted);
    assert_non_null(buf);

    size_t       written = 0;
    pubnub_res_t rc      = pn_file_multipart_encode(
        s_test_fields, 2, &file_params, boundary, buf, predicted, &written);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(written, predicted);

    /* File part still present with filename but no content between
     * the blank line and the \r\n before closing boundary. */
    const char* body_str  = (const char*)buf;
    const char* file_part = strstr(body_str, "filename=\"empty.dat\"");
    assert_non_null(file_part);

    free(buf);
}

static void multipart_encode_rejects_insufficient_buffer(void** state)
{
    (void)state;
    const char*   boundary    = "SmallBufferBoundary12345";
    const uint8_t file_data[] = {0xAA, 0xBB};

    const pn_file_content_params_t file_params = {
        .data         = file_data,
        .data_len     = sizeof(file_data),
        .name         = "test.bin",
        .content_type = "application/octet-stream"};

    size_t predicted =
        pn_file_multipart_size(s_test_fields, 2, &file_params, boundary);
    assert_true(predicted > 1);

    /* Buffer one byte too small. */
    uint8_t* buf = (uint8_t*)malloc(predicted - 1);
    assert_non_null(buf);

    size_t       written = 0;
    pubnub_res_t rc      = pn_file_multipart_encode(
        s_test_fields, 2, &file_params, boundary, buf, predicted - 1, &written);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);

    free(buf);
}

static void boundary_generation_produces_24_alphanumeric_chars(void** state)
{
    (void)state;
    char boundary[32];
    memset(boundary, 0, sizeof(boundary));

    pubnub_res_t rc =
        pn_file_generate_boundary(&s_mock_platform, boundary, sizeof(boundary));
    assert_int_equal(rc, PUBNUB_OK);

    /* Must be exactly 24 characters + NUL. */
    assert_int_equal(strlen(boundary), 24);

    /* Every character must be in [A-Za-z0-9]. */
    for (size_t i = 0; i < 24; ++i) {
        char c     = boundary[i];
        int  valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                 || (c >= '0' && c <= '9');
        assert_true(valid);
    }
}

static void boundary_generation_rejects_null_platform(void** state)
{
    (void)state;
    char boundary[32];
    pubnub_res_t rc = pn_file_generate_boundary(NULL, boundary, sizeof(boundary));
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void boundary_generation_rejects_small_buffer(void** state)
{
    (void)state;
    char         boundary[10];
    pubnub_res_t rc =
        pn_file_generate_boundary(&s_mock_platform, boundary, sizeof(boundary));
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void boundary_generation_reports_rng_failure(void** state)
{
    (void)state;
    char         boundary[32];
    pubnub_res_t rc = pn_file_generate_boundary(
        &s_mock_platform_fail, boundary, sizeof(boundary));
    assert_int_equal(rc, PUBNUB_ERR_INTERNAL);
}

static void multipart_encode_rejects_null_arguments(void** state)
{
    (void)state;
    uint8_t buf[64];
    size_t  written = 0;

    const pn_file_content_params_t file_params = {
        .data = NULL, .data_len = 0, .name = "f.txt", .content_type = "text/plain"};

    const pn_file_content_params_t file_params_no_name = {
        .data = NULL, .data_len = 0, .name = NULL, .content_type = "text/plain"};

    /* NULL form_fields. */
    assert_int_equal(
        pn_file_multipart_encode(NULL, 0, &file_params, "b", buf, 64, &written),
        PUBNUB_ERR_INVALID_ARGUMENT);

    /* NULL file (struct pointer). */
    assert_int_equal(
        pn_file_multipart_encode(s_test_fields, 2, NULL, "b", buf, 64, &written),
        PUBNUB_ERR_INVALID_ARGUMENT);

    /* NULL file->name. */
    assert_int_equal(
        pn_file_multipart_encode(
            s_test_fields, 2, &file_params_no_name, "b", buf, 64, &written),
        PUBNUB_ERR_INVALID_ARGUMENT);

    /* NULL boundary. */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &file_params, NULL, buf, 64, &written),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    /* NULL output. */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &file_params, "b", NULL, 64, &written),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    /* NULL out_len. */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &file_params, "b", buf, 64, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void multipart_encode_rejects_header_injection(void** state)
{
    (void)state;
    uint8_t buf[256];
    size_t  written = 0;

    const pn_file_content_params_t crlf_name = {.data     = NULL,
                                                .data_len = 0,
                                                .name = "a\r\nX-Injected: y",
                                                .content_type = "text/plain"};

    const pn_file_content_params_t quote_name = {.data         = NULL,
                                                 .data_len     = 0,
                                                 .name         = "a\"b.txt",
                                                 .content_type = "text/plain"};

    const pn_file_content_params_t crlf_ct = {
        .data         = NULL,
        .data_len     = 0,
        .name         = "f.txt",
        .content_type = "text/plain\r\nX-Injected: y"};

    /* Filename containing CRLF is rejected (MIME part-header injection). */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &crlf_name, "b", buf, 256, &written),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    /* Filename containing a double-quote is rejected (breaks the quoted
     * filename token). */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &quote_name, "b", buf, 256, &written),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    /* Content-Type containing CRLF is rejected. */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &crlf_ct, "b", buf, 256, &written),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void multipart_encode_allows_spaces_in_name_and_ct(void** state)
{
    (void)state;
    uint8_t buf[512];
    size_t  written = 0;

    const pn_file_content_params_t params = {.data     = NULL,
                                             .data_len = 0,
                                             .name     = "my report.txt",
                                             .content_type =
                                                 "text/plain; charset=utf-8"};

    /* Spaces are legitimate in quoted filenames and parameterized content
     * types; they must not be rejected. */
    assert_int_equal(pn_file_multipart_encode(
                         s_test_fields, 2, &params, "b", buf, 512, &written),
                     PUBNUB_OK);
    assert_true(written > 0);
}

static void multipart_size_returns_zero_on_null_inputs(void** state)
{
    (void)state;

    const pn_file_content_params_t file_params = {
        .data = NULL, .data_len = 10, .name = "f.txt", .content_type = "text/plain"};

    const pn_file_content_params_t file_params_no_name = {
        .data = NULL, .data_len = 10, .name = NULL, .content_type = "text/plain"};

    /* NULL boundary returns 0. */
    assert_int_equal(pn_file_multipart_size(s_test_fields, 2, &file_params, NULL),
                     0);

    /* NULL file returns 0. */
    assert_int_equal(pn_file_multipart_size(s_test_fields, 2, NULL, "bnd"), 0);

    /* NULL file->name returns 0. */
    assert_int_equal(
        pn_file_multipart_size(s_test_fields, 2, &file_params_no_name, "bnd"), 0);
}

static void multipart_size_uses_default_content_type_when_null(void** state)
{
    (void)state;

    const pn_file_content_params_t file_null_ct = {
        .data = NULL, .data_len = 10, .name = "f.txt", .content_type = NULL};

    const pn_file_content_params_t file_default_ct = {
        .data         = NULL,
        .data_len     = 10,
        .name         = "f.txt",
        .content_type = "application/octet-stream"};

    /* NULL content_type uses "application/octet-stream" internally. */
    size_t with_null =
        pn_file_multipart_size(s_test_fields, 2, &file_null_ct, "boundary");
    size_t with_default =
        pn_file_multipart_size(s_test_fields, 2, &file_default_ct, "boundary");
    assert_int_equal(with_null, with_default);
}

static void multipart_constants_match_string_literal_lengths(void** state)
{
    (void)state;
    assert_int_equal(PN_MP_DASHDASH, (int)strlen("--"));
    assert_int_equal(PN_MP_CRLF, (int)strlen("\r\n"));
    assert_int_equal(PN_MP_CD_FIELD,
                     (int)strlen("Content-Disposition: form-data; name=\""));
    assert_int_equal(PN_MP_QUOTE_CRLF, (int)strlen("\"\r\n"));
    assert_int_equal(
        PN_MP_CD_FILE,
        (int)strlen(
            "Content-Disposition: form-data; name=\"file\"; filename=\""));
    assert_int_equal(PN_MP_CT_LABEL, (int)strlen("Content-Type: "));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(multipart_size_computes_exact_length),
        cmocka_unit_test(multipart_encode_produces_valid_body),
        cmocka_unit_test(multipart_encode_handles_zero_byte_file),
        cmocka_unit_test(multipart_encode_rejects_insufficient_buffer),
        cmocka_unit_test(boundary_generation_produces_24_alphanumeric_chars),
        cmocka_unit_test(boundary_generation_rejects_null_platform),
        cmocka_unit_test(boundary_generation_rejects_small_buffer),
        cmocka_unit_test(boundary_generation_reports_rng_failure),
        cmocka_unit_test(multipart_encode_rejects_null_arguments),
        cmocka_unit_test(multipart_encode_rejects_header_injection),
        cmocka_unit_test(multipart_encode_allows_spaces_in_name_and_ct),
        cmocka_unit_test(multipart_size_returns_zero_on_null_inputs),
        cmocka_unit_test(multipart_size_uses_default_content_type_when_null),
        cmocka_unit_test(multipart_constants_match_string_literal_lengths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

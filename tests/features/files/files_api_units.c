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

#include "pubnub/features/files.h"
#include "pubnub/future.h"

#include "features/files/files_internal.h"

/* ================================================================== */
/* Tests: pubnub_send_file validation                                   */
/* ================================================================== */

static void send_file_rejects_null_ctx(void** state)
{
    (void)state;
    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = "ch";
    opts.file_name               = "f.txt";
    opts.data                    = (const uint8_t*)"x";
    opts.data_len                = 1;

    pubnub_future_t fut = pubnub_send_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void send_file_rejects_null_opts(void** state)
{
    (void)state;
    pubnub_future_t fut = pubnub_send_file(NULL, NULL);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void send_file_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = NULL;
    opts.file_name               = "f.txt";
    opts.data                    = (const uint8_t*)"x";
    opts.data_len                = 1;

    pubnub_future_t fut = pubnub_send_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void send_file_rejects_null_file_name_and_file_path(void** state)
{
    (void)state;
    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = "ch";
    opts.file_name               = NULL;
    opts.file_path               = NULL;
    opts.data                    = (const uint8_t*)"x";
    opts.data_len                = 1;

    pubnub_future_t fut = pubnub_send_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void send_file_accepts_file_path_without_file_name(void** state)
{
    (void)state;
    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = "ch";
    opts.file_name               = NULL;
    opts.file_path               = "ignored.txt";
    opts.data                    = (const uint8_t*)"x";
    opts.data_len                = 1;

    /* With ctx=NULL, the function rejects due to NULL ctx, NOT because
     * file_name is NULL (file_path substitutes for file_name). */
    pubnub_future_t fut = pubnub_send_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void send_file_rejects_null_data_with_nonzero_len(void** state)
{
    (void)state;
    pubnub_send_file_opts_t opts = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                 = "ch";
    opts.file_name               = "f.txt";
    opts.data                    = NULL;
    opts.data_len                = 100;

    pubnub_future_t fut = pubnub_send_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

/* No client-side file-size limit — the server enforces max upload size
 * and the SDK classifies the S3 EntityTooLarge response into
 * PUBNUB_ERR_INVALID_ARGUMENT at runtime. */

/* ================================================================== */
/* Tests: pubnub_list_files validation                                  */
/* ================================================================== */

static void list_files_rejects_null_ctx(void** state)
{
    (void)state;
    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = "ch";

    pubnub_future_t fut = pubnub_list_files(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void list_files_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = NULL;

    pubnub_future_t fut = pubnub_list_files(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ================================================================== */
/* Tests: pubnub_delete_file validation                                 */
/* ================================================================== */

static void delete_file_rejects_null_ctx(void** state)
{
    (void)state;
    pubnub_delete_file_opts_t opts = PUBNUB_DELETE_FILE_OPTS_INIT;
    opts.channel                   = "ch";
    opts.file_id                   = "id";
    opts.file_name                 = "f.txt";

    pubnub_future_t fut = pubnub_delete_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void delete_file_rejects_null_file_id(void** state)
{
    (void)state;
    pubnub_delete_file_opts_t opts = PUBNUB_DELETE_FILE_OPTS_INIT;
    opts.channel                   = "ch";
    opts.file_id                   = NULL;
    opts.file_name                 = "f.txt";

    pubnub_future_t fut = pubnub_delete_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void delete_file_rejects_null_file_name(void** state)
{
    (void)state;
    pubnub_delete_file_opts_t opts = PUBNUB_DELETE_FILE_OPTS_INIT;
    opts.channel                   = "ch";
    opts.file_id                   = "id";
    opts.file_name                 = NULL;

    pubnub_future_t fut = pubnub_delete_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ================================================================== */
/* Tests: pubnub_download_file validation                               */
/* ================================================================== */

static void download_file_rejects_null_ctx(void** state)
{
    (void)state;
    pubnub_download_file_opts_t opts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    opts.channel                     = "ch";
    opts.file_id                     = "id";
    opts.file_name                   = "f.txt";

    pubnub_future_t fut = pubnub_download_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void download_file_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_download_file_opts_t opts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    opts.channel                     = NULL;
    opts.file_id                     = "id";
    opts.file_name                   = "f.txt";

    pubnub_future_t fut = pubnub_download_file(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ================================================================== */
/* Tests: pubnub_publish_file_message validation                        */
/* ================================================================== */

static void publish_file_message_rejects_null_ctx(void** state)
{
    (void)state;
    pubnub_publish_file_message_opts_t opts = PUBNUB_PUBLISH_FILE_MESSAGE_OPTS_INIT;
    opts.channel   = "ch";
    opts.file_id   = "id";
    opts.file_name = "f.txt";

    pubnub_future_t fut = pubnub_publish_file_message(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void publish_file_message_rejects_null_file_id(void** state)
{
    (void)state;
    pubnub_publish_file_message_opts_t opts = PUBNUB_PUBLISH_FILE_MESSAGE_OPTS_INIT;
    opts.channel   = "ch";
    opts.file_id   = NULL;
    opts.file_name = "f.txt";

    pubnub_future_t fut = pubnub_publish_file_message(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ================================================================== */
/* Tests: pubnub_get_file_url validation                                */
/* ================================================================== */

static void get_file_url_rejects_null_ctx(void** state)
{
    (void)state;
    pubnub_get_file_url_opts_t opts = PUBNUB_GET_FILE_URL_OPTS_INIT;
    opts.channel                    = "ch";
    opts.file_id                    = "id";
    opts.file_name                  = "f.txt";

    char   buf[256];
    size_t len = 0;

    pubnub_res_t rc = pubnub_get_file_url(NULL, &opts, buf, sizeof(buf), &len);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void get_file_url_rejects_null_channel(void** state)
{
    (void)state;
    pubnub_get_file_url_opts_t opts = PUBNUB_GET_FILE_URL_OPTS_INIT;
    opts.channel                    = NULL;
    opts.file_id                    = "id";
    opts.file_name                  = "f.txt";

    char   buf[256];
    size_t len = 0;

    pubnub_res_t rc = pubnub_get_file_url(NULL, &opts, buf, sizeof(buf), &len);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void get_file_url_rejects_null_buf(void** state)
{
    (void)state;
    pubnub_get_file_url_opts_t opts = PUBNUB_GET_FILE_URL_OPTS_INIT;
    opts.channel                    = "ch";
    opts.file_id                    = "id";
    opts.file_name                  = "f.txt";

    size_t len = 0;

    pubnub_res_t rc = pubnub_get_file_url(NULL, &opts, NULL, 256, &len);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void publish_failed_phase_is_between_done_and_failed(void** state)
{
    (void)state;
    assert_true(PN_FILE_SEND_DONE < PN_FILE_SEND_PUBLISH_FAILED);
    assert_true(PN_FILE_SEND_PUBLISH_FAILED < PN_FILE_SEND_FAILED);
}

static void download_file_result_decrypted_defaults_to_zero(void** state)
{
    (void)state;
    pubnub_download_file_result_t r = {0};
    assert_int_equal(r.decrypted, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(send_file_rejects_null_ctx),
        cmocka_unit_test(send_file_rejects_null_opts),
        cmocka_unit_test(send_file_rejects_null_channel),
        cmocka_unit_test(send_file_rejects_null_file_name_and_file_path),
        cmocka_unit_test(send_file_accepts_file_path_without_file_name),
        cmocka_unit_test(send_file_rejects_null_data_with_nonzero_len),
        cmocka_unit_test(list_files_rejects_null_ctx),
        cmocka_unit_test(list_files_rejects_null_channel),
        cmocka_unit_test(delete_file_rejects_null_ctx),
        cmocka_unit_test(delete_file_rejects_null_file_id),
        cmocka_unit_test(delete_file_rejects_null_file_name),
        cmocka_unit_test(download_file_rejects_null_ctx),
        cmocka_unit_test(download_file_rejects_null_channel),
        cmocka_unit_test(publish_file_message_rejects_null_ctx),
        cmocka_unit_test(publish_file_message_rejects_null_file_id),
        cmocka_unit_test(get_file_url_rejects_null_ctx),
        cmocka_unit_test(get_file_url_rejects_null_channel),
        cmocka_unit_test(get_file_url_rejects_null_buf),
        cmocka_unit_test(publish_failed_phase_is_between_done_and_failed),
        cmocka_unit_test(download_file_result_decrypted_defaults_to_zero),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

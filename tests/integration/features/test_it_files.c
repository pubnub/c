/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/files.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#if PUBNUB_ENABLE_CRYPTO
#include "pubnub/features/crypto.h"
#endif

#if PUBNUB_ENABLE_SUBSCRIBE
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "it_bus.h"
#endif

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** @brief Per-test state for files integration tests. */
typedef struct files_state {
    /** Base state with contexts, channels, and cleanup queue. */
    it_test_state_t* base;
    /** Captured file id from the most recent send_file call. */
    char file_id[64];
    /** Captured file name from the most recent send_file call. */
    char file_name[64];
} files_state_t;

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    files_state_t* s = calloc(1, sizeof(*s));
    if (NULL == s) {
        return -1;
    }
    s->base = it_state_create(env);
    if (NULL == s->base) {
        free(s);
        return -1;
    }
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    files_state_t* s = *state;
    if (NULL != s) {
        it_state_destroy(s->base);
        free(s);
    }
    return 0;
}

/** Upload "Hello from C SDK" and capture file_id / file_name. */
static pubnub_res_t upload_hello(pubnub_context_t* ctx,
                                 const char*       channel,
                                 files_state_t*    fs,
                                 it_cleanup_t*     cleanup)
{
    static const uint8_t    s_hello[] = "Hello from C SDK";
    pubnub_send_file_opts_t opts      = PUBNUB_SEND_FILE_OPTS_INIT;
    opts.channel                      = channel;
    opts.data                         = s_hello;
    opts.data_len                     = sizeof(s_hello) - 1U;
    opts.content_type                 = "text/plain";
    opts.file_name                    = "pn-it-test.txt";

    pubnub_future_t fut = pubnub_send_file(ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);

    it_cleanup_add(cleanup, IT_CLEANUP_LIST_DELETE_FILES, channel, NULL);

    if (NULL != fs) {
        pubnub_send_file_result_t r = pubnub_send_file_result(fut);
        if (0U < r.id.len && r.id.len < sizeof(fs->file_id)) {
            memcpy(fs->file_id, r.id.ptr, r.id.len);
        }
        if (0U < r.name.len && r.name.len < sizeof(fs->file_name)) {
            memcpy(fs->file_name, r.name.ptr, r.name.len);
        }
    }

    if (PUBNUB_OK != st) {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        print_error("send_file failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)err.len,
                    err.ptr ? err.ptr : "");
    }
    pubnub_future_release(fut);
    return st;
}

/** Upload @p buf of @p len bytes and download; asserts content matches. */
static void roundtrip_buffer(pubnub_context_t* ctx,
                             const char*       channel,
                             const uint8_t*    buf,
                             size_t            len,
                             it_cleanup_t*     cleanup)
{
    char file_id[64]   = {0};
    char file_name[64] = {0};

    pubnub_send_file_opts_t sopts = PUBNUB_SEND_FILE_OPTS_INIT;
    sopts.channel                 = channel;
    sopts.data                    = buf;
    sopts.data_len                = len;
    sopts.content_type            = "application/octet-stream";
    sopts.file_name               = "pn-it-buf.bin";

    pubnub_future_t sfut = pubnub_send_file(ctx, &sopts);
    pubnub_res_t    sst  = pubnub_await(sfut);
    it_cleanup_add(cleanup, IT_CLEANUP_LIST_DELETE_FILES, channel, NULL);

    if (PUBNUB_OK == sst) {
        pubnub_send_file_result_t sr = pubnub_send_file_result(sfut);
        if (0U < sr.id.len && sr.id.len < sizeof(file_id)) {
            memcpy(file_id, sr.id.ptr, sr.id.len);
        }
        if (0U < sr.name.len && sr.name.len < sizeof(file_name)) {
            memcpy(file_name, sr.name.ptr, sr.name.len);
        }
    }

    if (PUBNUB_OK != sst) {
        pubnub_string_view_t err = pubnub_response_error_message(sfut);
        print_error("send_file failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(sst),
                    pubnub_response_status_code(sfut),
                    (int)err.len,
                    err.ptr ? err.ptr : "");
    }
    pubnub_future_release(sfut);
    assert_int_equal(PUBNUB_OK, (int)sst);
    pn_test_sleep_ms(IT_DELAY_FILE_PROPAGATION_MS);

    pubnub_download_file_opts_t dopts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    dopts.channel                     = channel;
    dopts.file_id                     = file_id;
    dopts.file_name                   = file_name;

    pubnub_future_t dfut = pubnub_download_file(ctx, &dopts);
    pubnub_res_t    dst  = pubnub_await(dfut);
    if (PUBNUB_OK != dst) {
        print_error("download_file failed: %s (http=%d)",
                    pubnub_res_str(dst),
                    pubnub_response_status_code(dfut));
    }
    assert_int_equal(PUBNUB_OK, (int)dst);

    pubnub_download_file_result_t dr = pubnub_download_file_result(dfut);
    assert_int_equal((int)len, (int)dr.data_len);
    assert_memory_equal(buf, dr.data, len);
    pubnub_future_release(dfut);
}

static void send_file_returns_ok_and_file_id(void** state)
{
    files_state_t* s = *state;
    print_message("channel: %s", s->base->channel);

    pubnub_res_t st =
        upload_hello(s->base->ctx, s->base->channel, s, &s->base->cleanup);
    assert_int_equal(PUBNUB_OK, (int)st);
    assert_true(0 < (int)strlen(s->file_id));
}

static void list_files_contains_uploaded_file(void** state)
{
    files_state_t* s = *state;
    print_message("channel: %s", s->base->channel);

    pubnub_res_t st =
        upload_hello(s->base->ctx, s->base->channel, s, &s->base->cleanup);
    assert_int_equal(PUBNUB_OK, (int)st);
    pn_test_sleep_ms(IT_DELAY_FILE_PROPAGATION_MS);

    pubnub_list_files_opts_t lopts = PUBNUB_LIST_FILES_OPTS_INIT;
    lopts.channel                  = s->base->channel;

    pubnub_future_t lfut = pubnub_list_files(s->base->ctx, &lopts);
    pubnub_res_t    lst  = pubnub_await(lfut);
    if (PUBNUB_OK != lst) {
        print_error("list_files failed: %s (http=%d)",
                    pubnub_res_str(lst),
                    pubnub_response_status_code(lfut));
    }
    assert_int_equal(PUBNUB_OK, (int)lst);

    pubnub_list_files_result_t lr        = pubnub_list_files_result(lfut);
    size_t                     fname_len = strlen(s->file_name);
    int                        found     = 0;
    for (uint32_t i = 0U; i < lr.count; ++i) {
        pubnub_file_info_t fi = pubnub_list_files_result_file_at(lfut, i);
        if (fname_len == fi.name.len
            && 0 == memcmp(fi.name.ptr, s->file_name, fi.name.len)) {
            found = 1;
            break;
        }
    }
    pubnub_future_release(lfut);
    assert_int_equal(1, found);
}

static void download_file_content_matches_upload(void** state)
{
    files_state_t*       s          = *state;
    static const uint8_t expected[] = "Hello from C SDK";
    print_message("channel: %s", s->base->channel);

    pubnub_res_t st =
        upload_hello(s->base->ctx, s->base->channel, s, &s->base->cleanup);
    assert_int_equal(PUBNUB_OK, (int)st);
    pn_test_sleep_ms(IT_DELAY_FILE_PROPAGATION_MS);

    pubnub_download_file_opts_t dopts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    dopts.channel                     = s->base->channel;
    dopts.file_id                     = s->file_id;
    dopts.file_name                   = s->file_name;

    pubnub_future_t dfut = pubnub_download_file(s->base->ctx, &dopts);
    pubnub_res_t    dst  = pubnub_await(dfut);
    if (PUBNUB_OK != dst) {
        print_error("download_file failed: %s (http=%d)",
                    pubnub_res_str(dst),
                    pubnub_response_status_code(dfut));
    }
    assert_int_equal(PUBNUB_OK, (int)dst);

    pubnub_download_file_result_t dr = pubnub_download_file_result(dfut);
    assert_int_equal((int)(sizeof(expected) - 1U), (int)dr.data_len);
    assert_memory_equal(expected, dr.data, sizeof(expected) - 1U);
    pubnub_future_release(dfut);
}

static void delete_file_removes_from_list(void** state)
{
    files_state_t* s = *state;
    print_message("channel: %s", s->base->channel);

    pubnub_res_t st =
        upload_hello(s->base->ctx, s->base->channel, s, &s->base->cleanup);
    assert_int_equal(PUBNUB_OK, (int)st);

    pubnub_delete_file_opts_t delopts = PUBNUB_DELETE_FILE_OPTS_INIT;
    delopts.channel                   = s->base->channel;
    delopts.file_id                   = s->file_id;
    delopts.file_name                 = s->file_name;

    pubnub_future_t delfut = pubnub_delete_file(s->base->ctx, &delopts);
    pubnub_res_t    delst  = pubnub_await(delfut);
    if (PUBNUB_OK != delst) {
        print_error("delete_file failed: %s (http=%d)",
                    pubnub_res_str(delst),
                    pubnub_response_status_code(delfut));
    }
    assert_int_equal(PUBNUB_OK, (int)delst);
    pubnub_future_release(delfut);

    pubnub_list_files_opts_t lopts = PUBNUB_LIST_FILES_OPTS_INIT;
    lopts.channel                  = s->base->channel;

    pubnub_future_t lfut = pubnub_list_files(s->base->ctx, &lopts);
    pubnub_res_t    lst  = pubnub_await(lfut);
    assert_int_equal(PUBNUB_OK, (int)lst);

    pubnub_list_files_result_t lr     = pubnub_list_files_result(lfut);
    size_t                     id_len = strlen(s->file_id);
    int                        found  = 0;
    for (uint32_t i = 0U; i < lr.count; ++i) {
        pubnub_file_info_t fi = pubnub_list_files_result_file_at(lfut, i);
        if (id_len == fi.id.len && 0 == memcmp(fi.id.ptr, s->file_id, fi.id.len)) {
            found = 1;
            break;
        }
    }
    pubnub_future_release(lfut);
    assert_int_equal(0, found);
}

static void send_encrypted_file_decrypts_on_download(void** state)
{
#if PUBNUB_ENABLE_CRYPTO
    files_state_t*       s             = *state;
    static const uint8_t expected[]    = "Hello from C SDK";
    char                 file_id[64]   = {0};
    char                 file_name[64] = {0};
    print_message("channel: %s", s->base->channel);

    pubnub_crypto_module_t* cm = pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(cm);

    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->subscribe_key;
    cfg.publish_key                = s->base->env->publish_key;
    cfg.user_id                    = s->base->user_id;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.crypto_module              = cm;

    pubnub_context_t* cctx = pubnub_create(&cfg);
    if (NULL == cctx) {
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create crypto context");
    }

    pubnub_send_file_opts_t sopts = PUBNUB_SEND_FILE_OPTS_INIT;
    sopts.channel                 = s->base->channel;
    sopts.data                    = expected;
    sopts.data_len                = sizeof(expected) - 1U;
    sopts.content_type            = "text/plain";
    sopts.file_name               = "pn-it-enc.txt";

    pubnub_future_t sfut = pubnub_send_file(cctx, &sopts);
    pubnub_res_t    sst  = pubnub_await(sfut);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_LIST_DELETE_FILES, s->base->channel, NULL);

    if (PUBNUB_OK == sst) {
        pubnub_send_file_result_t sr = pubnub_send_file_result(sfut);
        if (0U < sr.id.len && sr.id.len < sizeof(file_id)) {
            memcpy(file_id, sr.id.ptr, sr.id.len);
        }
        if (0U < sr.name.len && sr.name.len < sizeof(file_name)) {
            memcpy(file_name, sr.name.ptr, sr.name.len);
        }
    }
    if (PUBNUB_OK != sst) {
        print_error("encrypted send_file failed: %s (http=%d)",
                    pubnub_res_str(sst),
                    pubnub_response_status_code(sfut));
    }
    pubnub_future_release(sfut);
    assert_int_equal(PUBNUB_OK, (int)sst);
    pn_test_sleep_ms(IT_DELAY_FILE_PROPAGATION_MS);

    pubnub_download_file_opts_t dopts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    dopts.channel                     = s->base->channel;
    dopts.file_id                     = file_id;
    dopts.file_name                   = file_name;

    pubnub_future_t dfut = pubnub_download_file(cctx, &dopts);
    pubnub_res_t    dst  = pubnub_await(dfut);
    if (PUBNUB_OK != dst) {
        print_error("encrypted download_file failed: %s (http=%d)",
                    pubnub_res_str(dst),
                    pubnub_response_status_code(dfut));
    }
    assert_int_equal(PUBNUB_OK, (int)dst);

    pubnub_download_file_result_t dr = pubnub_download_file_result(dfut);
    assert_int_equal(1, (int)dr.decrypted);
    assert_int_equal((int)(sizeof(expected) - 1U), (int)dr.data_len);
    assert_memory_equal(expected, dr.data, sizeof(expected) - 1U);
    pubnub_future_release(dfut);

    pubnub_destroy(cctx);
    pubnub_crypto_module_destroy(cm);
#else
    (void)state;
    skip();
#endif
}

static void download_without_crypto_returns_ciphertext(void** state)
{
#if PUBNUB_ENABLE_CRYPTO
    files_state_t*       s             = *state;
    static const uint8_t expected[]    = "Hello from C SDK";
    char                 file_id[64]   = {0};
    char                 file_name[64] = {0};
    print_message("channel: %s", s->base->channel);

    pubnub_crypto_module_t* cm = pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(cm);

    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->subscribe_key;
    cfg.publish_key                = s->base->env->publish_key;
    cfg.user_id                    = s->base->user_id;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.crypto_module              = cm;

    pubnub_context_t* cctx = pubnub_create(&cfg);
    if (NULL == cctx) {
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create crypto context");
    }

    pubnub_send_file_opts_t sopts = PUBNUB_SEND_FILE_OPTS_INIT;
    sopts.channel                 = s->base->channel;
    sopts.data                    = expected;
    sopts.data_len                = sizeof(expected) - 1U;
    sopts.content_type            = "text/plain";
    sopts.file_name               = "pn-it-enc.txt";

    pubnub_future_t sfut = pubnub_send_file(cctx, &sopts);
    pubnub_res_t    sst  = pubnub_await(sfut);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_LIST_DELETE_FILES, s->base->channel, NULL);

    if (PUBNUB_OK == sst) {
        pubnub_send_file_result_t sr = pubnub_send_file_result(sfut);
        if (0U < sr.id.len && sr.id.len < sizeof(file_id)) {
            memcpy(file_id, sr.id.ptr, sr.id.len);
        }
        if (0U < sr.name.len && sr.name.len < sizeof(file_name)) {
            memcpy(file_name, sr.name.ptr, sr.name.len);
        }
    }
    if (PUBNUB_OK != sst) {
        print_error("encrypted send_file failed: %s (http=%d)",
                    pubnub_res_str(sst),
                    pubnub_response_status_code(sfut));
    }
    pubnub_future_release(sfut);
    pubnub_destroy(cctx);
    pubnub_crypto_module_destroy(cm);
    assert_int_equal(PUBNUB_OK, (int)sst);

    /* Download WITHOUT crypto: raw bytes must differ from plaintext. */
    pubnub_download_file_opts_t dopts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    dopts.channel                     = s->base->channel;
    dopts.file_id                     = file_id;
    dopts.file_name                   = file_name;

    pubnub_future_t dfut = pubnub_download_file(s->base->ctx, &dopts);
    pubnub_res_t    dst  = pubnub_await(dfut);
    if (PUBNUB_OK != dst) {
        print_error("plain download_file failed: %s (http=%d)",
                    pubnub_res_str(dst),
                    pubnub_response_status_code(dfut));
    }
    assert_int_equal(PUBNUB_OK, (int)dst);

    pubnub_download_file_result_t dr      = pubnub_download_file_result(dfut);
    size_t                        exp_len = sizeof(expected) - 1U;
    int                           differs = ((int)dr.data_len != (int)exp_len)
               || (0 != memcmp(dr.data, expected, exp_len));
    pubnub_future_release(dfut);
    assert_int_equal(1, differs);
#else
    (void)state;
    skip();
#endif
}

static void send_file_100b_round_trip(void** state)
{
    files_state_t* s   = *state;
    const size_t   len = 100U;
    print_message("channel: %s", s->base->channel);

    uint8_t* buf = malloc(len);
    assert_non_null(buf);
    for (size_t i = 0U; i < len; ++i) {
        buf[i] = (uint8_t)(i % 256U);
    }
    roundtrip_buffer(s->base->ctx, s->base->channel, buf, len, &s->base->cleanup);
    free(buf);
}

static void send_file_10kb_round_trip(void** state)
{
    files_state_t* s   = *state;
    const size_t   len = 10240U;
    print_message("channel: %s", s->base->channel);

    uint8_t* buf = malloc(len);
    assert_non_null(buf);
    for (size_t i = 0U; i < len; ++i) {
        buf[i] = (uint8_t)(i % 256U);
    }
    roundtrip_buffer(s->base->ctx, s->base->channel, buf, len, &s->base->cleanup);
    free(buf);
}

static void send_file_100kb_round_trip(void** state)
{
    files_state_t* s   = *state;
    const size_t   len = 102400U;
    print_message("channel: %s", s->base->channel);

    uint8_t* buf = malloc(len);
    assert_non_null(buf);
    for (size_t i = 0U; i < len; ++i) {
        buf[i] = (uint8_t)(i % 256U);
    }
    roundtrip_buffer(s->base->ctx, s->base->channel, buf, len, &s->base->cleanup);
    free(buf);
}

#if PUBNUB_ENABLE_SUBSCRIBE
static void on_file_event_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    it_bus_push_message((it_bus_t*)ud, ev);
}

static void on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    it_bus_push_status((it_bus_t*)ud, ev->status);
}
#endif /* PUBNUB_ENABLE_SUBSCRIBE */

static void file_event_delivered_via_subscribe(void** state)
{
#if PUBNUB_ENABLE_SUBSCRIBE
    files_state_t*              s       = *state;
    static const uint8_t        hello[] = "Hello from C SDK";
    it_bus_t*                   bus     = it_bus_create();
    pubnub_subscribe_listener_t l       = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_subscribe_event_t    ev = {0};
    print_message("channel: %s", s->base->channel);

    it_state_add_ctx2(s->base);

    l.on_file   = on_file_event_cb;
    l.on_status = on_status_cb;
    l.user_data = bus;
    h           = pubnub_add_listener(s->base->ctx2, &l);

    entity = pubnub_channel(s->base->ctx2, s->base->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));
    pn_test_sleep_ms(IT_DELAY_RECEIVE_STABILIZE_MS);

    pubnub_send_file_opts_t sopts = PUBNUB_SEND_FILE_OPTS_INIT;
    sopts.channel                 = s->base->channel;
    sopts.data                    = hello;
    sopts.data_len                = sizeof(hello) - 1U;
    sopts.content_type            = "text/plain";
    sopts.file_name               = "pn-it-event.txt";

    pubnub_future_t sfut = pubnub_send_file(s->base->ctx, &sopts);
    pubnub_res_t    sst  = pubnub_await(sfut);
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_LIST_DELETE_FILES, s->base->channel, NULL);
    if (PUBNUB_OK != sst) {
        print_error("send_file failed: %s (http=%d)",
                    pubnub_res_str(sst),
                    pubnub_response_status_code(sfut));
    }
    assert_int_equal(PUBNUB_OK, (int)sst);
    pubnub_future_release(sfut);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_FILE, (int)ev.type);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->base->ctx2, h);
    it_bus_destroy(bus);
#else
    (void)state;
    skip();
#endif
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            send_file_returns_ok_and_file_id, setup, teardown),
        cmocka_unit_test_setup_teardown(
            list_files_contains_uploaded_file, setup, teardown),
        cmocka_unit_test_setup_teardown(
            download_file_content_matches_upload, setup, teardown),
        cmocka_unit_test_setup_teardown(delete_file_removes_from_list, setup, teardown),
        cmocka_unit_test_setup_teardown(
            send_encrypted_file_decrypts_on_download, setup, teardown),
        cmocka_unit_test_setup_teardown(
            download_without_crypto_returns_ciphertext, setup, teardown),
        cmocka_unit_test_setup_teardown(send_file_100b_round_trip, setup, teardown),
        cmocka_unit_test_setup_teardown(send_file_10kb_round_trip, setup, teardown),
        cmocka_unit_test_setup_teardown(send_file_100kb_round_trip, setup, teardown),
        cmocka_unit_test_setup_teardown(
            file_event_delivered_via_subscribe, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

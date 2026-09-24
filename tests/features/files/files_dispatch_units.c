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

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/files.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MAX_CAPTURES 4

typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static int            s_in_flight;
static send_capture_t s_captures[MAX_CAPTURES];
static int            s_fake_handle_storage[MAX_CAPTURES];

static void reset_chain(void)
{
    s_send_count = 0;
    s_in_flight  = 0;
    memset(s_captures, 0, sizeof(s_captures));
}

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_CAPTURES) {
        return NULL;
    }
    s_captures[s_send_count].request  = request;
    s_captures[s_send_count].response = response;
    s_send_count++;
    s_in_flight++;
    return (pubnub_transport_handle_t*)&s_fake_handle_storage[s_send_count - 1];
}

static int chain_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void chain_cancel(pubnub_transport_provider_t* self,
                         pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_transport_provider_t s_chain_transport = {
    .send              = chain_send,
    .poll              = chain_poll,
    .cancel            = chain_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static void chain_complete_with(int index, const uint8_t* body, size_t len)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = len;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static void chain_complete_with_status(int            index,
                                       const uint8_t* body,
                                       size_t         len,
                                       int            status_code)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = len;
    resp->status_code = status_code;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

static const uint8_t k_list_files[] =
    "{\"status\":200,\"data\":["
    "{\"id\":\"file-id-1\",\"name\":\"report.pdf\","
    "\"size\":1024,\"created\":\"2025-01-01T00:00:00Z\"},"
    "{\"id\":\"file-id-2\",\"name\":\"image.png\","
    "\"size\":2048,\"created\":\"2025-01-02T00:00:00Z\"}"
    "],\"next\":\"cursor-tok\",\"count\":2}";

static void list_files_parses_indexed_results(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = "my-channel";

    pubnub_future_t fut = pubnub_list_files(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_list_files, sizeof(k_list_files) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_list_files_result_t result = pubnub_list_files_result(fut);
    assert_int_equal(2, result.count);

    pubnub_file_info_t f0 = pubnub_list_files_result_file_at(fut, 0);
    assert_true(f0.id.len > 0);
    assert_int_equal(9, f0.id.len);
    assert_memory_equal(f0.id.ptr, "file-id-1", 9);
    assert_true(f0.name.len > 0);
    assert_int_equal(10, f0.name.len);
    assert_memory_equal(f0.name.ptr, "report.pdf", 10);

    pubnub_file_info_t f1 = pubnub_list_files_result_file_at(fut, 1);
    assert_true(f1.id.len > 0);
    assert_int_equal(9, f1.id.len);
    assert_memory_equal(f1.id.ptr, "file-id-2", 9);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void list_files_bad_json_returns_error(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = "my-channel";

    pubnub_future_t fut = pubnub_list_files(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    static const uint8_t broken[] = "{not-valid-json!!!";
    chain_complete_with(0, broken, sizeof(broken) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    pubnub_list_files_result_t result = pubnub_list_files_result(fut);
    assert_int_equal(0, result.count);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_403_error_body[] =
    "{\"error\":true,\"status\":403,\"message\":\"Forbidden\"}";

static void list_files_http_403_surfaces_error(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = "my-channel";

    pubnub_future_t fut = pubnub_list_files(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with_status(
        0, k_403_error_body, sizeof(k_403_error_body) - 1, 403);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_not_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_empty_list[] =
    "{\"status\":200,\"data\":[],\"count\":0}";

static void list_files_empty_response_returns_zero_count(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = "my-channel";

    pubnub_future_t fut = pubnub_list_files(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_empty_list, sizeof(k_empty_list) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_list_files_result_t result = pubnub_list_files_result(fut);
    assert_int_equal(0, result.count);

    /* Out-of-bounds access should not crash. */
    pubnub_file_info_t oob = pubnub_list_files_result_file_at(fut, 0);
    assert_int_equal(0, oob.id.len);
    assert_null(oob.id.ptr);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(list_files_parses_indexed_results),
        cmocka_unit_test(list_files_bad_json_returns_error),
        cmocka_unit_test(list_files_http_403_surfaces_error),
        cmocka_unit_test(list_files_empty_response_returns_zero_count),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

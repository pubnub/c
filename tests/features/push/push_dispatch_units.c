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
#include "pubnub/features/push.h"
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

static const uint8_t k_push_list[] = "[\"apns-ch1\",\"apns-ch2\",\"apns-ch3\"]";

static void list_channels_parses_indexed_results(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_push_list_channels_opts_t opts = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    opts.device                           = "device-token-abc";
    opts.gateway                          = PUBNUB_PUSH_APNS2;
    opts.topic                            = "com.example.app";

    pubnub_future_t fut = pubnub_push_list_channels(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_push_list, sizeof(k_push_list) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_push_list_channels_result_t result =
        pubnub_push_list_channels_result(fut);
    assert_int_equal(3, result.channel_count);

    pubnub_string_view_t c0 = pubnub_push_list_channels_result_channel_at(fut, 0);
    assert_int_equal(8, c0.len);
    assert_memory_equal(c0.ptr, "apns-ch1", 8);

    pubnub_string_view_t c1 = pubnub_push_list_channels_result_channel_at(fut, 1);
    assert_int_equal(8, c1.len);
    assert_memory_equal(c1.ptr, "apns-ch2", 8);

    pubnub_string_view_t c2 = pubnub_push_list_channels_result_channel_at(fut, 2);
    assert_int_equal(8, c2.len);
    assert_memory_equal(c2.ptr, "apns-ch3", 8);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void list_channels_empty_array_returns_zero_count(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_push_list_channels_opts_t opts = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    opts.device                           = "device-token-abc";
    opts.gateway                          = PUBNUB_PUSH_APNS2;
    opts.topic                            = "com.example.app";

    pubnub_future_t fut = pubnub_push_list_channels(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    static const uint8_t empty[] = "[]";
    chain_complete_with(0, empty, sizeof(empty) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_push_list_channels_result_t result =
        pubnub_push_list_channels_result(fut);
    assert_int_equal(0, result.channel_count);

    /* Out-of-bounds access should not crash. */
    pubnub_string_view_t oob = pubnub_push_list_channels_result_channel_at(fut, 0);
    assert_int_equal(0, oob.len);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_push_400_body[] = "{\"error\":true,\"status\":400,"
                                         "\"message\":\"Invalid Parameters\"}";

static void list_channels_http_error_surfaces_through_future(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_push_list_channels_opts_t opts = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    opts.device                           = "device-token-abc";
    opts.gateway                          = PUBNUB_PUSH_APNS2;
    opts.topic                            = "com.example.app";

    pubnub_future_t fut = pubnub_push_list_channels(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with_status(0, k_push_400_body, sizeof(k_push_400_body) - 1, 400);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_not_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(list_channels_parses_indexed_results),
        cmocka_unit_test(list_channels_empty_array_returns_zero_count),
        cmocka_unit_test(list_channels_http_error_surfaces_through_future),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

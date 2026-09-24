/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file channel_groups_dispatch_units.c
 * @brief Positive-path integration tests proving that channel group
 *        operations dispatch through the full middleware chain and
 *        transport, and that response completion routes correctly
 *        back through the future.
 *
 * Uses a chain transport (mock send/poll/cancel) that records every
 * request submitted by the pipeline, letting assertions inspect path
 * segments, query parameters, and HTTP method without any network I/O.
 */

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
#include "pubnub/features/channel_groups.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

/* Internal accessors for slot state inspection. */
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

static const uint8_t k_cg_ok_body[] =
    "{\"status\":200,\"error\":false,\"message\":\"OK\"}";

static const uint8_t k_cg_list_body[] =
    "{\"status\":200,\"error\":false,"
    "\"payload\":{\"channels\":[\"ch1\",\"ch2\"]}}";

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

static void chain_complete_ok(int index)
{
    chain_complete_with(index, k_cg_ok_body, sizeof(k_cg_ok_body) - 1);
}

static void chain_complete_list(int index)
{
    chain_complete_with(index, k_cg_list_body, sizeof(k_cg_list_body) - 1);
}

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

/**
 * @brief Check whether a path segment matching @p needle exists in the
 *        captured request.
 */
static int request_has_path_segment(const pubnub_http_request_t* req,
                                    const char*                  needle)
{
    const size_t needle_len = strlen(needle);
    for (unsigned int i = 0; i < req->path_segment_count; i++) {
        const pubnub_string_view_t seg = req->path_segments[i];
        if (seg.len == needle_len && 0 == memcmp(seg.ptr, needle, needle_len)) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Find a query parameter by key and return its value view.
 *
 * @return Non-NULL pointer to the value view, or NULL if not found.
 */
static const pubnub_string_view_t*
request_query_value(const pubnub_http_request_t* req, const char* key)
{
    const size_t key_len = strlen(key);
    for (unsigned int i = 0; i < req->query_param_count; i++) {
        const pubnub_kv_t* p = &req->query_params[i];
        if (p->key.len == key_len && 0 == memcmp(p->key.ptr, key, key_len)) {
            return &p->value;
        }
    }
    return NULL;
}

/**
 * @brief add_channels dispatches a GET through the transport with
 *        correct path and "add" query param.
 */
static void add_channels_should_dispatch_through_transport(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_channel_group_add_opts_t opts = {
        .channel_group = "my-group",
        .channels      = "ch1,ch2",
    };
    pubnub_future_t fut = pubnub_channel_group_add_channels(ctx, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    /* Transport must have received exactly one send(). */
    assert_int_equal(s_send_count, 1);
    assert_int_equal(s_in_flight, 1);

    /* Verify path contains expected segments. */
    const pubnub_http_request_t* req = s_captures[0].request;
    assert_non_null(req);
    assert_int_equal(req->method, PUBNUB_HTTP_GET);
    assert_true(request_has_path_segment(req, "v1"));
    assert_true(request_has_path_segment(req, "channel-registration"));
    assert_true(request_has_path_segment(req, "sub-key"));
    assert_true(request_has_path_segment(req, "sub-test"));
    assert_true(request_has_path_segment(req, "channel-group"));
    assert_true(request_has_path_segment(req, "my-group"));

    /* Verify "add" query param. */
    const pubnub_string_view_t* add_val = request_query_value(req, "add");
    assert_non_null(add_val);
    assert_int_equal(add_val->len, 7);
    assert_memory_equal(add_val->ptr, "ch1,ch2", 7);

    /* Complete and verify future resolution. */
    chain_complete_ok(0);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * @brief remove_channels dispatches a GET with "remove" query param.
 */
static void remove_channels_should_dispatch_through_transport(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_channel_group_remove_opts_t opts = {
        .channel_group = "my-group",
        .channels      = "ch1",
    };
    pubnub_future_t fut = pubnub_channel_group_remove_channels(ctx, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    assert_int_equal(s_send_count, 1);

    const pubnub_http_request_t* req = s_captures[0].request;
    assert_non_null(req);
    assert_int_equal(req->method, PUBNUB_HTTP_GET);
    assert_true(request_has_path_segment(req, "channel-registration"));
    assert_true(request_has_path_segment(req, "channel-group"));
    assert_true(request_has_path_segment(req, "my-group"));

    /* Verify "remove" query param. */
    const pubnub_string_view_t* rm_val = request_query_value(req, "remove");
    assert_non_null(rm_val);
    assert_int_equal(rm_val->len, 3);
    assert_memory_equal(rm_val->ptr, "ch1", 3);

    chain_complete_ok(0);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * @brief list_channels dispatches, completes with a valid body, and
 *        the result accessor returns the parsed channel count and names.
 */
static void list_channels_should_dispatch_and_parse_response(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_channel_group_list_opts_t opts = {
        .channel_group = "my-group",
    };
    pubnub_future_t fut = pubnub_channel_group_list_channels(ctx, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    assert_int_equal(s_send_count, 1);

    const pubnub_http_request_t* req = s_captures[0].request;
    assert_non_null(req);
    assert_int_equal(req->method, PUBNUB_HTTP_GET);
    assert_true(request_has_path_segment(req, "channel-registration"));
    assert_true(request_has_path_segment(req, "channel-group"));
    assert_true(request_has_path_segment(req, "my-group"));

    /* No "add" or "remove" query param for list. */
    assert_null(request_query_value(req, "add"));
    assert_null(request_query_value(req, "remove"));

    /* Complete with list body. */
    chain_complete_list(0);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    /* Verify result accessors. */
    pubnub_channel_group_list_result_t result =
        pubnub_channel_group_list_result(fut);
    assert_int_equal(result.count, 2);

    pubnub_string_view_t ch0 = pubnub_channel_group_list_result_channel_at(fut, 0);
    assert_int_equal(ch0.len, 3);
    assert_memory_equal(ch0.ptr, "ch1", 3);

    pubnub_string_view_t ch1 = pubnub_channel_group_list_result_channel_at(fut, 1);
    assert_int_equal(ch1.len, 3);
    assert_memory_equal(ch1.ptr, "ch2", 3);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * @brief delete_group dispatches with "/remove" path suffix.
 */
static void delete_group_should_dispatch_with_remove_path(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_channel_group_remove_group_opts_t opts = {
        .channel_group = "my-group",
    };
    pubnub_future_t fut = pubnub_channel_group_remove(ctx, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    assert_int_equal(s_send_count, 1);

    const pubnub_http_request_t* req = s_captures[0].request;
    assert_non_null(req);
    assert_int_equal(req->method, PUBNUB_HTTP_GET);
    assert_true(request_has_path_segment(req, "channel-registration"));
    assert_true(request_has_path_segment(req, "channel-group"));
    assert_true(request_has_path_segment(req, "my-group"));
    assert_true(request_has_path_segment(req, "remove"));

    /* No mutation query params for delete-group. */
    assert_null(request_query_value(req, "add"));
    assert_null(request_query_value(req, "remove"));

    chain_complete_ok(0);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(add_channels_should_dispatch_through_transport),
        cmocka_unit_test(remove_channels_should_dispatch_through_transport),
        cmocka_unit_test(list_channels_should_dispatch_and_parse_response),
        cmocka_unit_test(delete_group_should_dispatch_with_remove_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

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
#include "pubnub/features/message_actions.h"
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

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

static const uint8_t k_actions_body[] =
    "{\"status\":200,\"data\":["
    "{\"type\":\"reaction\",\"value\":\"thumbs_up\","
    "\"uuid\":\"u1\",\"actionTimetoken\":\"111\","
    "\"messageTimetoken\":\"222\"},"
    "{\"type\":\"receipt\",\"value\":\"read\","
    "\"uuid\":\"u2\",\"actionTimetoken\":\"333\","
    "\"messageTimetoken\":\"444\"}"
    "],\"more\":{\"start\":\"111\",\"end\":\"444\","
    "\"limit\":\"2\"}}";

static void get_message_actions_parses_indexed(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_message_actions_opts_t opts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    opts.channel = "chat-room";

    pubnub_future_t fut = pubnub_get_message_actions(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_actions_body, sizeof(k_actions_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_get_message_actions_result_t result =
        pubnub_get_message_actions_result(fut);
    assert_int_equal(2, result.count);
    assert_true(result.has_more);

    pubnub_message_action_t a0 =
        pubnub_get_message_actions_result_action_at(fut, 0);
    assert_int_equal(8, a0.type.len);
    assert_memory_equal(a0.type.ptr, "reaction", 8);
    assert_int_equal(9, a0.value.len);
    assert_memory_equal(a0.value.ptr, "thumbs_up", 9);
    assert_int_equal(2, a0.uuid.len);
    assert_memory_equal(a0.uuid.ptr, "u1", 2);

    pubnub_message_action_t a1 =
        pubnub_get_message_actions_result_action_at(fut, 1);
    assert_int_equal(7, a1.type.len);
    assert_memory_equal(a1.type.ptr, "receipt", 7);
    assert_int_equal(4, a1.value.len);
    assert_memory_equal(a1.value.ptr, "read", 4);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(get_message_actions_parses_indexed),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

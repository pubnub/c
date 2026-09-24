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
#include "pubnub/features/presence.h"
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
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

static const uint8_t k_here_now_multi[] =
    "{\"status\":200,\"message\":\"OK\",\"service\":\"Presence\","
    "\"payload\":{\"total_channels\":2,\"total_occupancy\":3,"
    "\"channels\":{\"lobby\":{\"occupancy\":2,"
    "\"uuids\":[{\"uuid\":\"user-1\",\"state\":{\"mood\":\"happy\"}},"
    "{\"uuid\":\"user-2\"}]},\"game\":{\"occupancy\":1,"
    "\"uuids\":[{\"uuid\":\"user-3\"}]}}}}";

static void here_now_multi_channel_parses_indexed_results(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_here_now_opts_t opts = PUBNUB_HERE_NOW_OPTS_INIT;
    opts.channels               = "lobby,game";

    pubnub_future_t fut = pubnub_here_now(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_here_now_multi, sizeof(k_here_now_multi) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_here_now_result_t result = pubnub_here_now_result(fut);
    assert_int_equal(2, result.channel_count);
    assert_int_equal(3, result.total_occupancy);

    pubnub_here_now_channel_result_t ch0 =
        pubnub_here_now_result_channel_at(fut, 0);
    assert_true(ch0.name.len > 0);
    assert_true(ch0.occupant_count > 0);

    pubnub_here_now_channel_result_t ch1 =
        pubnub_here_now_result_channel_at(fut, 1);
    assert_true(ch1.name.len > 0);

    /* Find the "lobby" channel and check its occupant. */
    int lobby_idx = -1;
    if (4 == ch0.name.len && 0 == memcmp(ch0.name.ptr, "game", 4)) {
        lobby_idx = 1;
    } else {
        lobby_idx = 0;
    }

    pubnub_here_now_channel_result_t lobby =
        pubnub_here_now_result_channel_at(fut, (size_t)lobby_idx);
    assert_int_equal(5, lobby.name.len);
    assert_memory_equal(lobby.name.ptr, "lobby", 5);
    assert_int_equal(2, lobby.occupancy);
    assert_int_equal(2, lobby.occupant_count);

    pubnub_here_now_occupant_result_t occ0 =
        pubnub_here_now_result_occupant_at(fut, (size_t)lobby_idx, 0);
    assert_int_equal(6, occ0.uuid.len);
    assert_memory_equal(occ0.uuid.ptr, "user-1", 6);
    assert_true(occ0.state.len > 0);

    pubnub_here_now_occupant_result_t occ1 =
        pubnub_here_now_result_occupant_at(fut, (size_t)lobby_idx, 1);
    assert_int_equal(6, occ1.uuid.len);
    assert_memory_equal(occ1.uuid.ptr, "user-2", 6);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_where_now_body[] =
    "{\"status\":200,\"message\":\"OK\","
    "\"service\":\"Presence\","
    "\"payload\":{\"channels\":[\"ch1\",\"ch2\"]}}";

static void where_now_parses_indexed_channels(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_where_now_opts_t opts = PUBNUB_WHERE_NOW_OPTS_INIT;
    opts.uuid                    = "tester";

    pubnub_future_t fut = pubnub_where_now(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_where_now_body, sizeof(k_where_now_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_where_now_result_t result = pubnub_where_now_result(fut);
    assert_int_equal(2, result.channel_count);

    pubnub_string_view_t c0 = pubnub_where_now_result_channel_at(fut, 0);
    assert_int_equal(3, c0.len);
    assert_memory_equal(c0.ptr, "ch1", 3);

    pubnub_string_view_t c1 = pubnub_where_now_result_channel_at(fut, 1);
    assert_int_equal(3, c1.len);
    assert_memory_equal(c1.ptr, "ch2", 3);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_get_state_multi[] =
    "{\"status\":200,\"payload\":"
    "{\"ch1\":\"idle\",\"ch2\":\"active\"}}";

static void get_state_multi_channel_parses_indexed_results(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_state_opts_t opts = PUBNUB_GET_STATE_OPTS_INIT;
    opts.channels                = "ch1,ch2";
    opts.uuid                    = "tester";

    pubnub_future_t fut = pubnub_get_state(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_get_state_multi, sizeof(k_get_state_multi) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_get_state_result_t result = pubnub_get_state_result(fut);
    assert_int_equal(2, result.channel_count);

    pubnub_get_state_channel_result_t e0 =
        pubnub_get_state_result_channel_at(fut, 0);
    assert_true(e0.channel.len > 0);
    assert_non_null(e0.state);

    pubnub_get_state_channel_result_t e1 =
        pubnub_get_state_result_channel_at(fut, 1);
    assert_true(e1.channel.len > 0);
    assert_non_null(e1.state);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_here_now_403[] =
    "{\"error\":true,\"status\":403,\"message\":\"Forbidden\","
    "\"service\":\"Access Manager\"}";

static void here_now_http_403_surfaces_error(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_here_now_opts_t opts = PUBNUB_HERE_NOW_OPTS_INIT;
    opts.channels               = "secret-channel";

    pubnub_future_t fut = pubnub_here_now(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with_status(0, k_here_now_403, sizeof(k_here_now_403) - 1, 403);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_not_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_where_now_empty[] = "{\"status\":200,\"message\":\"OK\","
                                           "\"service\":\"Presence\","
                                           "\"payload\":{\"channels\":[]}}";

static void where_now_empty_channels_returns_zero(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_where_now_opts_t opts = PUBNUB_WHERE_NOW_OPTS_INIT;
    opts.uuid                    = "ghost-user";

    pubnub_future_t fut = pubnub_where_now(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_where_now_empty, sizeof(k_where_now_empty) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_where_now_result_t result = pubnub_where_now_result(fut);
    assert_int_equal(0, result.channel_count);

    /* Out-of-bounds access should not crash. */
    pubnub_string_view_t oob = pubnub_where_now_result_channel_at(fut, 0);
    assert_int_equal(0, oob.len);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(here_now_multi_channel_parses_indexed_results),
        cmocka_unit_test(where_now_parses_indexed_channels),
        cmocka_unit_test(get_state_multi_channel_parses_indexed_results),
        cmocka_unit_test(here_now_http_403_surfaces_error),
        cmocka_unit_test(where_now_empty_channels_returns_zero),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

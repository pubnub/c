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
#include "pubnub/features/app_context.h"
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
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

static const uint8_t k_uuid_list[] =
    "{\"status\":200,\"data\":["
    "{\"id\":\"uuid-1\",\"name\":\"Alice\","
    "\"updated\":\"2024-01-01T00:00:00Z\",\"eTag\":\"e1\"},"
    "{\"id\":\"uuid-2\",\"name\":\"Bob\","
    "\"updated\":\"2024-01-02T00:00:00Z\",\"eTag\":\"e2\"}"
    "],\"totalCount\":2}";

static void get_all_uuid_metadata_parses_indexed(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_all_uuid_metadata_opts_t opts =
        PUBNUB_GET_ALL_UUID_METADATA_OPTS_INIT;
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;

    pubnub_future_t fut = pubnub_get_all_uuid_metadata(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_uuid_list, sizeof(k_uuid_list) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_app_context_page_t page = pubnub_get_all_uuid_metadata_result(fut);
    assert_int_equal(2, page.count);

    pubnub_uuid_metadata_t u0 = pubnub_get_all_uuid_metadata_result_uuid_at(fut, 0);
    assert_int_equal(6, u0.id.len);
    assert_memory_equal(u0.id.ptr, "uuid-1", 6);
    assert_int_equal(5, u0.name.len);
    assert_memory_equal(u0.name.ptr, "Alice", 5);

    pubnub_uuid_metadata_t u1 = pubnub_get_all_uuid_metadata_result_uuid_at(fut, 1);
    assert_int_equal(6, u1.id.len);
    assert_memory_equal(u1.id.ptr, "uuid-2", 6);
    assert_int_equal(3, u1.name.len);
    assert_memory_equal(u1.name.ptr, "Bob", 3);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_channel_list[] =
    "{\"status\":200,\"data\":["
    "{\"id\":\"ch-1\",\"name\":\"General\","
    "\"updated\":\"2024-01-01T00:00:00Z\",\"eTag\":\"e1\"}"
    "],\"totalCount\":1}";

static void get_all_channel_metadata_parses_indexed(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_all_channel_metadata_opts_t opts =
        PUBNUB_GET_ALL_CHANNEL_METADATA_OPTS_INIT;
    opts.include = PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;

    pubnub_future_t fut = pubnub_get_all_channel_metadata(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_channel_list, sizeof(k_channel_list) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_app_context_page_t page = pubnub_get_all_channel_metadata_result(fut);
    assert_int_equal(1, page.count);

    pubnub_channel_metadata_t ch0 =
        pubnub_get_all_channel_metadata_result_channel_at(fut, 0);
    assert_int_equal(4, ch0.id.len);
    assert_memory_equal(ch0.id.ptr, "ch-1", 4);
    assert_int_equal(7, ch0.name.len);
    assert_memory_equal(ch0.name.ptr, "General", 7);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_memberships[] =
    "{\"status\":200,\"data\":["
    "{\"channel\":{\"id\":\"ch1\",\"name\":\"General\","
    "\"description\":\"Main channel\"},"
    "\"status\":\"active\",\"type\":\"member\","
    "\"updated\":\"2025-01-01T00:00:00Z\",\"eTag\":\"etag-123\"},"
    "{\"channel\":{\"id\":\"ch2\"}}"
    "],\"totalCount\":2}";

static void get_memberships_parses_indexed(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_memberships_opts_t opts = PUBNUB_GET_MEMBERSHIPS_OPTS_INIT;

    pubnub_future_t fut = pubnub_get_memberships(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_memberships, sizeof(k_memberships) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_app_context_page_t page = pubnub_get_memberships_result(fut);
    assert_true(page.count >= 1);

    pubnub_membership_t m0 = pubnub_get_memberships_result_membership_at(fut, 0);
    assert_true(m0.channel.id.len > 0);
    assert_int_equal(3, m0.channel.id.len);
    assert_memory_equal(m0.channel.id.ptr, "ch1", 3);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_members[] =
    "{\"status\":200,\"data\":["
    "{\"uuid\":{\"id\":\"user-1\",\"name\":\"Alice\","
    "\"email\":\"alice@test.com\"},"
    "\"status\":\"joined\",\"type\":\"admin\","
    "\"updated\":\"2025-06-01T12:00:00Z\",\"eTag\":\"etag-xyz\"},"
    "{\"uuid\":{\"id\":\"user-2\"}}"
    "],\"totalCount\":2}";

static void get_channel_members_parses_indexed(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_channel_members_opts_t opts = PUBNUB_GET_CHANNEL_MEMBERS_OPTS_INIT;
    opts.channel = "test-channel";

    pubnub_future_t fut = pubnub_get_channel_members(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_members, sizeof(k_members) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_app_context_page_t page = pubnub_get_channel_members_result(fut);
    assert_true(page.count >= 1);

    pubnub_member_t mb0 = pubnub_get_channel_members_result_member_at(fut, 0);
    assert_true(mb0.uuid.id.len > 0);
    assert_int_equal(6, mb0.uuid.id.len);
    assert_memory_equal(mb0.uuid.id.ptr, "user-1", 6);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(get_all_uuid_metadata_parses_indexed),
        cmocka_unit_test(get_all_channel_metadata_parses_indexed),
        cmocka_unit_test(get_memberships_parses_indexed),
        cmocka_unit_test(get_channel_members_parses_indexed),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

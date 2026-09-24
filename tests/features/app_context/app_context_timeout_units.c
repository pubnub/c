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

/* Internal accessors for slot inspection. */
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MAX_TRACKED_SLOTS 4

static int                     s_send_count;
static pubnub_http_request_t*  s_captured_requests[MAX_TRACKED_SLOTS];
static pubnub_http_response_t* s_captured_responses[MAX_TRACKED_SLOTS];
static int                     s_fake_handles[MAX_TRACKED_SLOTS];

static void reset_chain(void)
{
    s_send_count = 0;
    memset(s_captured_requests, 0, sizeof(s_captured_requests));
    memset(s_captured_responses, 0, sizeof(s_captured_responses));
}

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_TRACKED_SLOTS) {
        return NULL;
    }
    s_captured_requests[s_send_count]  = request;
    s_captured_responses[s_send_count] = response;
    s_send_count++;
    return (pubnub_transport_handle_t*)&s_fake_handles[s_send_count - 1];
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

static const uint8_t k_ok_body[] = "{\"status\":200,\"data\":{}}";

static const pubnub_membership_input_t s_membership = {
    .channel_id = "ch",
};

static void complete_and_release(pubnub_context_t* ctx,
                                 pubnub_future_t   fut,
                                 int               capture_idx)
{
    pubnub_http_response_t* resp = s_captured_responses[capture_idx];
    if (NULL != resp) {
        resp->body        = k_ok_body;
        resp->body_len    = sizeof(k_ok_body) - 1;
        resp->status_code = 200;
        resp->completion  = PUBNUB_HTTP_COMPLETE;
    }
    (void)pubnub_process(ctx);
    pubnub_future_release(fut);
}

static pubnub_config_t timeout_test_config(unsigned int txn_timeout_ms)
{
    pubnub_config_t cfg        = pubnub_config_defaults();
    cfg.subscribe_key          = "sub";
    cfg.user_id                = "tester";
    cfg.transport              = &s_chain_transport;
    cfg.transaction_timeout_ms = txn_timeout_ms;
    return cfg;
}

#if PUBNUB_CFG_NO_HEAP
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP

static uint32_t slot_timeout_ms(pubnub_context_t* ctx, pubnub_future_t fut)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    return slot->http_request.timeout_ms;
}

/* ---- set_channel_metadata ---- */

static void
set_channel_metadata_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(7500);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel    = "ch";
    opts.timeout_ms = 0;

    pubnub_future_t fut = pubnub_set_channel_metadata(ctx, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 7500);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 7500);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void set_channel_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero(
    void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(7500);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;
    opts.channel    = "ch";
    opts.timeout_ms = 2500;

    pubnub_future_t fut = pubnub_set_channel_metadata(ctx, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 2500);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 2500);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

/* ---- remove_uuid_metadata ---- */

static void
remove_uuid_metadata_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(6000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_remove_uuid_metadata(
        ctx, &(pubnub_remove_uuid_metadata_opts_t){.timeout_ms = 0});

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 6000);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 6000);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void remove_uuid_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero(
    void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(6000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_remove_uuid_metadata(
        ctx, &(pubnub_remove_uuid_metadata_opts_t){.timeout_ms = 3000});

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 3000);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 3000);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

/* ---- get_memberships ---- */

static void
get_memberships_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(8000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_get_memberships(
        ctx, &(pubnub_get_memberships_opts_t){.timeout_ms = 0});

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 8000);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 8000);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void
get_memberships_should_use_per_request_timeout_when_opts_timeout_is_nonzero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(8000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_get_memberships(
        ctx, &(pubnub_get_memberships_opts_t){.timeout_ms = 4000});

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 4000);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 4000);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

/* ---- set_memberships ---- */

static void
set_memberships_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(5500);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_set_memberships(ctx,
                                                 &(pubnub_set_memberships_opts_t){
                                                     .set       = &s_membership,
                                                     .set_count = 1,
                                                     .timeout_ms = 0,
                                                 });

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 5500);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 5500);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void
set_memberships_should_use_per_request_timeout_when_opts_timeout_is_nonzero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(5500);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_set_memberships(ctx,
                                                 &(pubnub_set_memberships_opts_t){
                                                     .set       = &s_membership,
                                                     .set_count = 1,
                                                     .timeout_ms = 1500,
                                                 });

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 1500);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 1500);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

/* ---- get_uuid_metadata ---- */

static void
get_uuid_metadata_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(9000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_uuid_metadata_opts_t opts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    opts.timeout_ms                      = 0;

    pubnub_future_t fut = pubnub_get_uuid_metadata(ctx, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 9000);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 9000);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void get_uuid_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero(
    void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(9000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_get_uuid_metadata_opts_t opts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    opts.timeout_ms                      = 4500;

    pubnub_future_t fut = pubnub_get_uuid_metadata(ctx, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 4500);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 4500);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

/* ---- set_uuid_metadata ---- */

static void
set_uuid_metadata_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(7000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.timeout_ms                      = 0;

    pubnub_future_t fut = pubnub_set_uuid_metadata(ctx, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 7000);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 7000);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void set_uuid_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero(
    void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(7000);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.timeout_ms                      = 3500;

    pubnub_future_t fut = pubnub_set_uuid_metadata(ctx, &opts);

    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(slot_timeout_ms(ctx, fut), 3500);
    assert_int_equal(s_captured_requests[0]->timeout_ms, 3500);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(
            set_channel_metadata_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            set_channel_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
        cmocka_unit_test(
            remove_uuid_metadata_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            remove_uuid_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
        cmocka_unit_test(
            get_memberships_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            get_memberships_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
        cmocka_unit_test(
            set_memberships_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            set_memberships_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
        cmocka_unit_test(
            get_uuid_metadata_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            get_uuid_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
        cmocka_unit_test(
            set_uuid_metadata_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            set_uuid_metadata_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

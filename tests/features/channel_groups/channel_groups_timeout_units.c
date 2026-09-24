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
#include "pubnub/features/channel_groups.h"
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

static const uint8_t k_ok_body[] =
    "{\"status\":200,\"payload\":{\"channels\":[],\"groups\":[]}}";

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
    cfg.publish_key            = "pub";
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

static void
channel_groups_should_use_context_timeout_when_opts_timeout_is_zero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(7500);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut =
        pubnub_channel_group_list_channels(ctx,
                                           &(pubnub_channel_group_list_opts_t){
                                               .channel_group = "cg1",
                                               .timeout_ms    = 0,
                                           });

    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(7500, slot_timeout_ms(ctx, fut));
    assert_int_equal(7500, s_captured_requests[0]->timeout_ms);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void
channel_groups_should_use_per_request_timeout_when_opts_timeout_is_nonzero(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = timeout_test_config(7500);
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut =
        pubnub_channel_group_list_channels(ctx,
                                           &(pubnub_channel_group_list_opts_t){
                                               .channel_group = "cg1",
                                               .timeout_ms    = 2500,
                                           });

    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(2500, slot_timeout_ms(ctx, fut));
    assert_int_equal(2500, s_captured_requests[0]->timeout_ms);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(
            channel_groups_should_use_context_timeout_when_opts_timeout_is_zero),
        cmocka_unit_test(
            channel_groups_should_use_per_request_timeout_when_opts_timeout_is_nonzero),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

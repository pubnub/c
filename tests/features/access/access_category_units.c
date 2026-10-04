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
#include "pubnub/features/access.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

/* Provided by the linked serialization provider. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

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
    "{\"status\":200,\"data\":{\"token\":\"test-token\"}}";

static const pubnub_access_resource_permission_t s_ch_perm = {
    .name        = "ch",
    .permissions = PUBNUB_ACCESS_READ,
};

static pubnub_config_t category_test_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "pub";
    cfg.subscribe_key   = "sub";
    cfg.secret_key      = "sec";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

/* Complete the dispatched request (slot @p capture_idx) and release it. */
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

/* Expect the grant to be accepted by preflight and dispatched. */
static void expect_dispatched(pubnub_context_t*                ctx,
                              const pubnub_grant_token_opts_t* opts)
{
    pubnub_future_t fut;

    reset_chain();
    fut = pubnub_grant_token(ctx, opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(s_send_count, 1);
    complete_and_release(ctx, fut, 0);
}

/* Expect the grant to be rejected synchronously, without dispatch. */
static void expect_invalid_argument(pubnub_context_t*                ctx,
                                    const pubnub_grant_token_opts_t* opts)
{
    pubnub_future_t fut;

    reset_chain();
    fut = pubnub_grant_token(ctx, opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(s_send_count, 0);
    pubnub_future_release(fut);
}

#if PUBNUB_CFG_NO_HEAP
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP

static void grant_category_only_passes_preflight(void** state)
{
    (void)state;
    pubnub_config_t           cfg  = category_test_config();
    pubnub_context_t*         ctx  = pubnub_create(&cfg);
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

    assert_non_null(ctx);

    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    expect_dispatched(ctx, &opts);

    opts.channels_category_permissions = 0;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;
    expect_dispatched(ctx, &opts);

    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    expect_dispatched(ctx, &opts);

    pubnub_destroy(ctx);
}

static void grant_category_with_resources_passes_preflight(void** state)
{
    (void)state;
    pubnub_config_t           cfg  = category_test_config();
    pubnub_context_t*         ctx  = pubnub_create(&cfg);
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

    assert_non_null(ctx);

    opts.ttl                           = 60;
    opts.channels                      = &s_ch_perm;
    opts.channel_count                 = 1;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;
    expect_dispatched(ctx, &opts);

    pubnub_destroy(ctx);
}

static void grant_category_only_dispatches_categories_body(void** state)
{
    (void)state;
    pubnub_config_t                  cfg    = category_test_config();
    pubnub_context_t*                ctx    = pubnub_create(&cfg);
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_grant_token_opts_t        opts   = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    pubnub_future_t                  fut;
    pubnub_json_value_t*             tree;
    const pubnub_json_value_t*       perms;
    const pubnub_json_value_t*       cats;
    const pubnub_json_value_t*       node;
    int                              val = 0;

    assert_non_null(ctx);
    reset_chain();

    opts.ttl                           = 60;
    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;
    fut                                = pubnub_grant_token(ctx, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);
    assert_int_equal(s_send_count, 1);
    assert_non_null(s_captured_requests[0]->body);
    assert_true(s_captured_requests[0]->body_len > 0);

    tree = serial->parse(
        serial, s_captured_requests[0]->body, s_captured_requests[0]->body_len);
    assert_non_null(tree);
    perms = serial->object_get(tree, "permissions", 11);
    assert_non_null(perms);
    assert_null(serial->object_get(perms, "resources", 9));
    assert_null(serial->object_get(perms, "patterns", 8));
    cats = serial->object_get(perms, "categories", 10);
    assert_non_null(cats);
    node = serial->object_get(cats, "channels", 8);
    assert_non_null(node);
    assert_int_equal(serial->value_as_int(node, &val), PUBNUB_OK);
    assert_int_equal(val, 32);
    node = serial->object_get(cats, "uuids", 5);
    assert_non_null(node);
    assert_int_equal(serial->value_as_int(node, &val), PUBNUB_OK);
    assert_int_equal(val, 32);
    serial->value_destroy(serial, tree);

    complete_and_release(ctx, fut, 0);
    pubnub_destroy(ctx);
}

static void grant_category_invalid_bits_rejected(void** state)
{
    (void)state;
    static const uint32_t bad_values[] = {
        PUBNUB_ACCESS_READ,
        PUBNUB_ACCESS_GET | PUBNUB_ACCESS_UPDATE,
        PUBNUB_ACCESS_UPDATE,
        PUBNUB_ACCESS_JOIN,
        0xFFFFFFFFU,
    };
    pubnub_config_t   cfg = category_test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    size_t            i;

    assert_non_null(ctx);

    for (i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); ++i) {
        pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

        /* Bad value alone (no other permission at all). */
        opts.ttl                           = 60;
        opts.channels_category_permissions = bad_values[i];
        expect_invalid_argument(ctx, &opts);

        opts.channels_category_permissions = 0;
        opts.uuids_category_permissions    = bad_values[i];
        expect_invalid_argument(ctx, &opts);

        /* Bad value next to a valid resource. */
        opts.channels                      = &s_ch_perm;
        opts.channel_count                 = 1;
        opts.channels_category_permissions = bad_values[i];
        opts.uuids_category_permissions    = 0;
        expect_invalid_argument(ctx, &opts);

        opts.channels_category_permissions = 0;
        opts.uuids_category_permissions    = bad_values[i];
        expect_invalid_argument(ctx, &opts);

        /* Bad value next to a valid category on the other field. */
        opts.channels_category_permissions = PUBNUB_ACCESS_GET;
        opts.uuids_category_permissions    = bad_values[i];
        expect_invalid_argument(ctx, &opts);

        opts.channels_category_permissions = bad_values[i];
        opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;
        expect_invalid_argument(ctx, &opts);
    }

    pubnub_destroy(ctx);
}

static void grant_category_ttl_still_validated(void** state)
{
    (void)state;
    pubnub_config_t           cfg  = category_test_config();
    pubnub_context_t*         ctx  = pubnub_create(&cfg);
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

    assert_non_null(ctx);

    opts.channels_category_permissions = PUBNUB_ACCESS_GET;
    opts.uuids_category_permissions    = PUBNUB_ACCESS_GET;

    opts.ttl = 0;
    expect_invalid_argument(ctx, &opts);

    opts.ttl = 43201;
    expect_invalid_argument(ctx, &opts);

    opts.ttl = 43200;
    expect_dispatched(ctx, &opts);

    pubnub_destroy(ctx);
}

static void grant_without_any_permission_still_rejected(void** state)
{
    (void)state;
    pubnub_config_t           cfg  = category_test_config();
    pubnub_context_t*         ctx  = pubnub_create(&cfg);
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;

    assert_non_null(ctx);

    opts.ttl = 60;
    expect_invalid_argument(ctx, &opts);

    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(grant_category_only_passes_preflight),
        cmocka_unit_test(grant_category_with_resources_passes_preflight),
        cmocka_unit_test(grant_category_only_dispatches_categories_body),
        cmocka_unit_test(grant_category_invalid_bits_rejected),
        cmocka_unit_test(grant_category_ttl_still_validated),
        cmocka_unit_test(grant_without_any_permission_still_rejected),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

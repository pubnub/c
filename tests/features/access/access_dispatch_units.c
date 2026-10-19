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
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    (void)request;
    (void)response;
    return NULL;
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

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

/*
 * Token from the PubNub Python SDK test suite. Contains:
 * - v=2, t=1632335843, ttl=1440
 * - uuid="myauthuuid1"
 * - res.chan.ch1=255, res.grp.cg1=255, res.uuid.uuid1=255
 * - pat.uuid.^$=1
 * - meta={score:100, color:"red", author:"pandu"}
 */
static const char* const TEST_TOKEN =
    "qEF2AkF0GmFLd-NDdHRsGQWgQ3Jlc6VEY2hhbqFjY2gxGP9DZ3JwoWNj"
    "ZzEY_0N1c3KgQ3NwY6BEdXVpZKFldXVpZDEY_0NwYXSlRGNoYW6gQ2dycK"
    "BDdXNyoENzcGOgRHV1aWShYl4kAURtZXRho2VzY29yZRhkZWNvbG9yY3Jl"
    "ZGZhdXRob3JlcGFuZHVEdXVpZGtteWF1dGh1dWlkMUNzaWdYIP2vlxHik0"
    "EPZwtgYxAW3-LsBaX_WgWdYvtAXpYbKll3";

static void parse_token_indexed_channels(void** state)
{
    (void)state;
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_parse_token_opts_t opts = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    opts.token                     = TEST_TOKEN;

    pubnub_parsed_token_t parsed = {0};
    pubnub_res_t          rc     = pubnub_parse_token(ctx, &opts, &parsed);
    assert_int_equal(PUBNUB_OK, rc);

    assert_int_equal(2, parsed.version);
    assert_int_equal(1440, parsed.ttl);
    assert_true(parsed.authorized_uuid.len > 0);
    assert_memory_equal(parsed.authorized_uuid.ptr, "myauthuuid1", 11);

    /* Exact channel resources: ch1=255. */
    assert_int_equal(1, parsed.channel_count);
    pubnub_parsed_token_resource_t ch = pubnub_parsed_token_channel_at(ctx, 0);
    assert_int_equal(3, ch.name.len);
    assert_memory_equal(ch.name.ptr, "ch1", 3);
    assert_int_equal(255, ch.permissions);

    /* Exact group resources: cg1=255. */
    assert_int_equal(1, parsed.group_count);
    pubnub_parsed_token_resource_t grp = pubnub_parsed_token_group_at(ctx, 0);
    assert_int_equal(3, grp.name.len);
    assert_memory_equal(grp.name.ptr, "cg1", 3);
    assert_int_equal(255, grp.permissions);

    /* Exact UUID resources: uuid1=255. */
    assert_int_equal(1, parsed.uuid_count);
    pubnub_parsed_token_resource_t uid = pubnub_parsed_token_uuid_at(ctx, 0);
    assert_int_equal(5, uid.name.len);
    assert_memory_equal(uid.name.ptr, "uuid1", 5);
    assert_int_equal(255, uid.permissions);

    /* Pattern UUID: ^$=1. */
    assert_int_equal(1, parsed.uuid_pattern_count);
    pubnub_parsed_token_resource_t pat =
        pubnub_parsed_token_uuid_pattern_at(ctx, 0);
    assert_int_equal(2, pat.name.len);
    assert_memory_equal(pat.name.ptr, "^$", 2);
    assert_int_equal(1, pat.permissions);

    pubnub_destroy(ctx);
}

static void parse_token_invalid_base64_returns_error(void** state)
{
    (void)state;
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_parse_token_opts_t opts = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    opts.token                     = "!!!not-valid-base64-at-all@@@###$$$";

    pubnub_parsed_token_t parsed = {0};
    pubnub_res_t          rc     = pubnub_parse_token(ctx, &opts, &parsed);
    assert_int_not_equal(PUBNUB_OK, rc);

    pubnub_destroy(ctx);
}

static void parse_token_null_token_returns_error(void** state)
{
    (void)state;
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_parse_token_opts_t opts = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    opts.token                     = NULL;

    pubnub_parsed_token_t parsed = {0};
    pubnub_res_t          rc     = pubnub_parse_token(ctx, &opts, &parsed);
    assert_int_not_equal(PUBNUB_OK, rc);

    pubnub_destroy(ctx);
}

/*
 * Category tokens (CBOR, base64url):
 * - CAT_BOTH:      v=2 t=1000 ttl=60 cat={chan:32, uuid:32}
 * - CAT_UUID_ONLY: v=2 t=1000 ttl=60 cat={uuid:32}
 * - CAT_NONE:      v=2 t=1000 ttl=60
 */
static const char* const TEST_TOKEN_CAT_BOTH =
    "pGF2AmF0GQPoY3R0bBg8Y2NhdKJkY2hhbhggZHV1aWQYIA";
static const char* const TEST_TOKEN_CAT_UUID_ONLY =
    "pGF2AmF0GQPoY3R0bBg8Y2NhdKFkdXVpZBgg";
static const char* const TEST_TOKEN_CAT_NONE = "o2F2AmF0GQPoY3R0bBg8";

static void parse_token_category_permissions_exposed(void** state)
{
    (void)state;
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_parse_token_opts_t opts = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    opts.token                     = TEST_TOKEN_CAT_BOTH;

    pubnub_parsed_token_t parsed = {0};
    assert_int_equal(PUBNUB_OK, pubnub_parse_token(ctx, &opts, &parsed));
    assert_int_equal(32, (int)parsed.channels_category_permissions);
    assert_int_equal(32, (int)parsed.uuids_category_permissions);
    assert_int_equal(0, parsed.channel_count);
    assert_int_equal(0, parsed.uuid_count);

    pubnub_destroy(ctx);
}

static void parse_token_category_reparse_replaces_previous(void** state)
{
    (void)state;
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_parse_token_opts_t opts   = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    pubnub_parsed_token_t     parsed = {0};

    opts.token = TEST_TOKEN_CAT_BOTH;
    assert_int_equal(PUBNUB_OK, pubnub_parse_token(ctx, &opts, &parsed));
    assert_int_equal(32, (int)parsed.channels_category_permissions);
    assert_int_equal(32, (int)parsed.uuids_category_permissions);

    opts.token = TEST_TOKEN_CAT_UUID_ONLY;
    assert_int_equal(PUBNUB_OK, pubnub_parse_token(ctx, &opts, &parsed));
    assert_int_equal(0, (int)parsed.channels_category_permissions);
    assert_int_equal(32, (int)parsed.uuids_category_permissions);

    opts.token = TEST_TOKEN_CAT_NONE;
    assert_int_equal(PUBNUB_OK, pubnub_parse_token(ctx, &opts, &parsed));
    assert_int_equal(0, (int)parsed.channels_category_permissions);
    assert_int_equal(0, (int)parsed.uuids_category_permissions);

    pubnub_destroy(ctx);
}

static void parse_token_failure_zeroes_category_result(void** state)
{
    (void)state;
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_parse_token_opts_t opts   = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    pubnub_parsed_token_t     parsed = {0};

    opts.token = TEST_TOKEN_CAT_BOTH;
    assert_int_equal(PUBNUB_OK, pubnub_parse_token(ctx, &opts, &parsed));
    assert_int_equal(32, (int)parsed.channels_category_permissions);

    /* Reuse the dirty result object with an undecodable token. */
    opts.token = "!!!not-valid-base64-at-all@@@###$$$";
    assert_int_not_equal(PUBNUB_OK, pubnub_parse_token(ctx, &opts, &parsed));
    assert_int_equal(0, (int)parsed.channels_category_permissions);
    assert_int_equal(0, (int)parsed.uuids_category_permissions);

    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_token_indexed_channels),
        cmocka_unit_test(parse_token_invalid_base64_returns_error),
        cmocka_unit_test(parse_token_null_token_returns_error),
        cmocka_unit_test(parse_token_category_permissions_exposed),
        cmocka_unit_test(parse_token_category_reparse_replaces_previous),
        cmocka_unit_test(parse_token_failure_zeroes_category_result),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

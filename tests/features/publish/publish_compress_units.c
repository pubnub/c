/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file publish_compress_units.c
 * @brief Coverage for the per-request @c pubnub_publish_opts_t::compress
 *        preference.
 *
 * The field is tri-state (@c DEFAULT / @c YES / @c NO) rather than a plain
 * boolean so that the zero value keeps following the compile-time
 * @c PUBNUB_ENABLE_REQUEST_COMPRESSION toggle. Most call sites build opts
 * from a designated initializer instead of @c PUBNUB_PUBLISH_OPTS_INIT, so
 * a non-zero default would silently diverge between the two styles; the
 * opts-default test below pins that invariant.
 *
 * A chain transport captures the request handed to @c send() so each test
 * can inspect the compression hint, the body bytes, and the headers the
 * compression middleware produced. No network, no timing.
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
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

/** Upper bound on captured sends any single test may need. */
#define MAX_TRACKED_SLOTS 4

/** Payload used by every dispatch test in this file. */
#define TEST_MESSAGE "\"hello-compress-flag-unit-test\""

/**
 * @brief Per-send capture entry recorded by the chain transport.
 */
typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static send_capture_t s_captures[MAX_TRACKED_SLOTS];
static int            s_fake_handle_storage[MAX_TRACKED_SLOTS];

/** @brief Successful publish body so the parser can settle the future. */
static const uint8_t k_publish_ok_body[] = "[1,\"Sent\",\"17000000000000000\"]";

/**
 * @brief Reset the chain transport's recorded state between tests.
 */
static void reset_chain(void)
{
    s_send_count = 0;
    memset(s_captures, 0, sizeof(s_captures));
}

/**
 * @brief Chain transport @c send: records the call and leaves the
 *        response PENDING so the test body controls completion.
 */
static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_TRACKED_SLOTS) {
        return NULL;
    }
    s_captures[s_send_count].request  = request;
    s_captures[s_send_count].response = response;
    s_send_count++;
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

/**
 * @brief Mark a captured response as a successful publish completion.
 */
static void chain_complete_capture(int index)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = k_publish_ok_body;
    resp->body_len    = sizeof(k_publish_ok_body) - 1;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
}

/**
 * @brief Build a config that wires only the chain transport, leaving
 *        every other provider resolved from defaults.
 */
static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "pub";
    cfg.subscribe_key   = "sub";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;

    return cfg;
}

/**
 * @retval 1 The request carries a @c Content-Encoding:gzip header.
 * @retval 0 No such header is present.
 */
static int request_has_gzip_content_encoding(const pubnub_http_request_t* req)
{
    unsigned int i = 0;

    for (i = 0; i < req->header_count; i++) {
        const pubnub_kv_t* h = &req->headers[i];
        if (16 == h->key.len && 0 == memcmp(h->key.ptr, "Content-Encoding", 16)
            && 4 == h->value.len && 0 == memcmp(h->value.ptr, "gzip", 4)) {
            return 1;
        }
    }

    return 0;
}

/**
 * @retval 1 The body starts with the gzip magic bytes.
 * @retval 0 The body is absent or not gzip-framed.
 */
static int body_is_gzip_framed(const pubnub_http_request_t* req)
{
    const uint8_t* body = (const uint8_t*)req->body;

    if (NULL == body || req->body_len < 2) {
        return 0;
    }

    return (0x1f == body[0] && 0x8b == body[1]) ? 1 : 0;
}

/**
 * @brief The zero value of @c compress must mean "follow the
 *        compile-time toggle" for BOTH initialization styles.
 *
 * This is the regression guard for the tri-state encoding: if the field
 * were ever given a non-zero default, the macro and the designated
 * initializer would disagree and POST publishes written as compound
 * literals would silently change compression behaviour.
 */
static void publish_opts_default_compress_should_be_zero_for_both_styles(void** state)
{
    (void)state;
    pubnub_publish_opts_t via_macro = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_publish_opts_t via_literal =
        (pubnub_publish_opts_t){.channel = "ch", .message = "1"};

    assert_int_equal(0, (int)PUBNUB_PUBLISH_COMPRESS_DEFAULT);
    assert_int_equal(PUBNUB_PUBLISH_COMPRESS_DEFAULT, via_macro.compress);
    assert_int_equal(PUBNUB_PUBLISH_COMPRESS_DEFAULT, via_literal.compress);
}

#if PUBNUB_CFG_NO_HEAP
/* On no-heap profiles pubnub_create is unavailable; skip dispatch tests. */
static void dispatch_tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP

/**
 * @brief Dispatch one publish and return the captured request.
 *
 * Leaves the request IN_FLIGHT; the caller completes and releases it.
 */
static pubnub_http_request_t* dispatch_publish(pubnub_context_t*       ctx,
                                               pubnub_publish_method_t method,
                                               pubnub_publish_compress_t compress,
                                               pubnub_future_t* out_fut)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;

    opts.channel  = "test-compress";
    opts.message  = TEST_MESSAGE;
    opts.method   = method;
    opts.compress = compress;

    *out_fut = pubnub_publish(ctx, &opts);

    assert_int_equal(1, s_send_count);
    assert_non_null(s_captures[0].request);

    return s_captures[0].request;
}

/**
 * @brief Settle the in-flight request and tear the context down.
 */
static void finish_publish(pubnub_context_t* ctx, pubnub_future_t fut)
{
    chain_complete_capture(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fut));
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/** @brief COMPRESS_YES + POST gzip-compresses the body. */
static void publish_compress_yes_with_post_should_compress_body(void** state)
{
    (void)state;
    pubnub_future_t        fut;
    pubnub_http_request_t* req = NULL;

    if (!PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    req = dispatch_publish(
        ctx, PUBNUB_PUBLISH_METHOD_POST, PUBNUB_PUBLISH_COMPRESS_YES, &fut);

    assert_int_equal(PUBNUB_HTTP_POST, req->method);
    assert_int_equal(1, req->compress_body);
    assert_int_equal(1, body_is_gzip_framed(req));
    assert_int_equal(1, request_has_gzip_content_encoding(req));
    assert_int_not_equal(strlen(TEST_MESSAGE), req->body_len);

    finish_publish(ctx, fut);
}

/**
 * @brief COMPRESS_DEFAULT + POST follows the compile-time toggle, i.e.
 *        behaves exactly like COMPRESS_YES on a compression-enabled build.
 */
static void publish_compress_default_with_post_should_compress_body(void** state)
{
    (void)state;
    pubnub_future_t        fut;
    pubnub_http_request_t* req = NULL;

    if (!PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    req = dispatch_publish(
        ctx, PUBNUB_PUBLISH_METHOD_POST, PUBNUB_PUBLISH_COMPRESS_DEFAULT, &fut);

    assert_int_equal(1, req->compress_body);
    assert_int_equal(1, body_is_gzip_framed(req));
    assert_int_equal(1, request_has_gzip_content_encoding(req));

    finish_publish(ctx, fut);
}

/** @brief COMPRESS_NO + POST sends the body verbatim. */
static void publish_compress_no_with_post_should_send_plain_body(void** state)
{
    (void)state;
    pubnub_future_t        fut;
    pubnub_http_request_t* req = NULL;

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    req = dispatch_publish(
        ctx, PUBNUB_PUBLISH_METHOD_POST, PUBNUB_PUBLISH_COMPRESS_NO, &fut);

    assert_int_equal(PUBNUB_HTTP_POST, req->method);
    assert_int_equal(0, req->compress_body);
    assert_int_equal(0, body_is_gzip_framed(req));
    assert_int_equal(0, request_has_gzip_content_encoding(req));

    /* Body must still be the untouched serialized message. */
    assert_non_null(req->body);
    assert_int_equal(strlen(TEST_MESSAGE), req->body_len);
    assert_memory_equal(TEST_MESSAGE, req->body, strlen(TEST_MESSAGE));

    finish_publish(ctx, fut);
}

/**
 * @brief COMPRESS_YES is ignored for GET, which has no body to compress.
 *
 * The message travels in the URL path, so the compression hint must stay
 * clear rather than switching the method behind the caller's back.
 */
static void publish_compress_yes_with_get_should_be_ignored(void** state)
{
    (void)state;
    pubnub_future_t        fut;
    pubnub_http_request_t* req = NULL;

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    req = dispatch_publish(
        ctx, PUBNUB_PUBLISH_METHOD_GET, PUBNUB_PUBLISH_COMPRESS_YES, &fut);

    assert_int_equal(PUBNUB_HTTP_GET, req->method);
    assert_int_equal(0, req->compress_body);
    assert_null(req->body);
    assert_int_equal(0, request_has_gzip_content_encoding(req));

    finish_publish(ctx, fut);
}

/**
 * @brief COMPRESS_YES is inert when the SDK is built without request
 *        compression: the body goes out uncompressed.
 */
static void publish_compress_yes_should_be_inert_when_toggle_disabled(void** state)
{
    (void)state;
    pubnub_future_t        fut;
    pubnub_http_request_t* req = NULL;

    if (PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    req = dispatch_publish(
        ctx, PUBNUB_PUBLISH_METHOD_POST, PUBNUB_PUBLISH_COMPRESS_YES, &fut);

    assert_int_equal(0, req->compress_body);
    assert_int_equal(0, body_is_gzip_framed(req));
    assert_int_equal(0, request_has_gzip_content_encoding(req));
    assert_int_equal(strlen(TEST_MESSAGE), req->body_len);
    assert_memory_equal(TEST_MESSAGE, req->body, strlen(TEST_MESSAGE));

    finish_publish(ctx, fut);
}

/**
 * @brief An empty channel string is rejected before anything is dispatched.
 *
 * Runs against a live context and pairs the rejection with a control
 * dispatch on the same context, so the error is attributable to the
 * channel alone rather than to context or config validation.
 */
static void publish_empty_channel_should_be_rejected(void** state)
{
    (void)state;
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       rejected;
    pubnub_future_t       accepted;

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    opts.channel = "";
    opts.message = TEST_MESSAGE;

    rejected = pubnub_publish(ctx, &opts);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_future_status(rejected));
    assert_int_equal(0, s_send_count);
    pubnub_future_release(rejected);

    opts.channel = "test-compress";
    accepted     = pubnub_publish(ctx, &opts);
    assert_int_equal(1, s_send_count);

    finish_publish(ctx, accepted);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(publish_opts_default_compress_should_be_zero_for_both_styles),
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(publish_compress_yes_with_post_should_compress_body),
        cmocka_unit_test(publish_compress_default_with_post_should_compress_body),
        cmocka_unit_test(publish_compress_no_with_post_should_send_plain_body),
        cmocka_unit_test(publish_compress_yes_with_get_should_be_ignored),
        cmocka_unit_test(publish_compress_yes_should_be_inert_when_toggle_disabled),
        cmocka_unit_test(publish_empty_channel_should_be_rejected),
#else
        cmocka_unit_test(dispatch_tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

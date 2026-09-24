/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file retry_middleware_units.c
 * @brief Unit tests for the retry engine middleware.
 *
 * Uses a controllable stub transport and stub platform to verify retry
 * classification, delay computation, and cancel/destroy behavior
 * without real I/O or timers.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/middleware/middleware_internal.h"
#include "core/runtime/middleware/retry_middleware_internal.h"
#include "core/runtime/request_internal.h"
#include "pubnub/config.h"

/** Stored response pointer from the last send() call (for external
 *  completion triggering). */
static pubnub_http_response_t* s_inner_response;
static pubnub_http_request_t*  s_inner_request;
static int                     s_inner_send_count;
static int                     s_inner_cancel_count;
static int                     s_fake_inner_handle;
/** Pointer passed to the most recent stub_inner_cancel() call. */
static pubnub_transport_handle_t* s_inner_cancel_last_handle;
/** When > 0, stub_inner_send returns NULL on the Nth call (1-based). */
static int s_inner_send_fail_on_call;

static pubnub_transport_handle_t* stub_inner_send(pubnub_transport_provider_t* self,
                                                  pubnub_http_request_t* request,
                                                  pubnub_http_response_t* response)
{
    (void)self;
    s_inner_response = response;
    s_inner_request  = request;
    s_inner_send_count++;
    if (s_inner_send_fail_on_call > 0
        && s_inner_send_count >= s_inner_send_fail_on_call) {
        return NULL;
    }
    return (pubnub_transport_handle_t*)&s_fake_inner_handle;
}

static int stub_inner_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    /* External test code drives completions by writing to the response
     * struct; poll() does nothing on its own. */
    return 0;
}

static void stub_inner_cancel(pubnub_transport_provider_t* self,
                              pubnub_transport_handle_t*   transport_handle)
{
    (void)self;
    s_inner_cancel_last_handle = transport_handle;
    s_inner_cancel_count++;
}

static pubnub_transport_provider_t s_stub_inner_transport = {
    .send              = stub_inner_send,
    .poll              = stub_inner_poll,
    .cancel            = stub_inner_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static pubnub_milliseconds_t s_monotonic_now;

static pubnub_milliseconds_t stub_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return s_monotonic_now;
}

/** Fill with all-zero bytes — makes jitter produce 0 (via modulo). */
static int stub_random_bytes_zero(pubnub_platform_provider_t* self,
                                  uint8_t*                    buf,
                                  size_t                      len)
{
    (void)self;
    memset(buf, 0, len);
    return 0;
}

static pubnub_platform_provider_t s_stub_platform = {
    .monotonic_ms  = stub_monotonic_ms,
    .sleep_ms      = NULL,
    .random_bytes  = stub_random_bytes_zero,
    .secure_zero   = NULL,
    .lock_size     = NULL,
    .lock_init     = NULL,
    .lock_destroy  = NULL,
    .lock_acquire  = NULL,
    .lock_release  = NULL,
    .thread_create = NULL,
    .thread_join   = NULL,
};

static void* stub_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void stub_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_stub_allocator = {
    .alloc       = stub_alloc,
    .realloc     = NULL,
    .free        = stub_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static void reset_stubs(void)
{
    s_inner_response           = NULL;
    s_inner_request            = NULL;
    s_inner_send_count         = 0;
    s_inner_cancel_count       = 0;
    s_inner_cancel_last_handle = NULL;
    s_inner_send_fail_on_call  = 0;
    s_monotonic_now            = 1000;
}

static int test_setup(void** state)
{
    (void)state;
    reset_stubs();
    return 0;
}

static void test_delay_exponential_bounds(void** state)
{
    (void)state;

    const unsigned int base = 1000;
    const unsigned int max  = 8000;

    /* attempt 0: min(max, 1000<<0) = 1000 */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(base, max, 0);
    assert_int_equal(1000, d);

    /* attempt 1: min(max, 1000<<1) = 2000 */
    d = pn_retry_delay_exponential(base, max, 1);
    assert_int_equal(2000, d);

    /* attempt 2: min(max, 1000<<2) = 4000 */
    d = pn_retry_delay_exponential(base, max, 2);
    assert_int_equal(4000, d);

    /* attempt 3: min(max, 1000<<3) = 8000 = max */
    d = pn_retry_delay_exponential(base, max, 3);
    assert_int_equal(8000, d);

    /* attempt 5: min(max, 1000<<5=32000) = 8000 (capped) */
    d = pn_retry_delay_exponential(base, max, 5);
    assert_int_equal(8000, d);
}

static void test_delay_exponential_zero_base(void** state)
{
    (void)state;

    pubnub_milliseconds_t d = pn_retry_delay_exponential(0, 8000, 3);
    assert_int_equal(0, d);
}

static void test_retry_after_integer(void** state)
{
    (void)state;

    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    const char key[]   = "Retry-After";
    const char value[] = "5";

    resp.headers[0].key.ptr   = key;
    resp.headers[0].key.len   = 11;
    resp.headers[0].value.ptr = value;
    resp.headers[0].value.len = 1;
    resp.header_count         = 1;

    pubnub_milliseconds_t ms = pn_retry_parse_retry_after(&resp);
    assert_int_equal(5000, ms);
}

static void test_retry_after_absent(void** state)
{
    (void)state;

    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    const char key[]   = "Content-Type";
    const char value[] = "application/json";

    resp.headers[0].key.ptr   = key;
    resp.headers[0].key.len   = 12;
    resp.headers[0].value.ptr = value;
    resp.headers[0].value.len = 16;
    resp.header_count         = 1;

    pubnub_milliseconds_t ms = pn_retry_parse_retry_after(&resp);
    assert_int_equal(0, ms);
}

static void test_retry_after_non_integer(void** state)
{
    (void)state;

    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    const char key[]   = "Retry-After";
    const char value[] = "Thu, 01 Dec 2022 16:00:00 GMT";

    resp.headers[0].key.ptr   = key;
    resp.headers[0].key.len   = 11;
    resp.headers[0].value.ptr = value;
    resp.headers[0].value.len = strlen(value);
    resp.header_count         = 1;

    pubnub_milliseconds_t ms = pn_retry_parse_retry_after(&resp);
    assert_int_equal(0, ms);
}

static void test_retry_after_case_insensitive(void** state)
{
    (void)state;

    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    const char key[]   = "retry-after";
    const char value[] = "3";

    resp.headers[0].key.ptr   = key;
    resp.headers[0].key.len   = 11;
    resp.headers[0].value.ptr = value;
    resp.headers[0].value.len = 1;
    resp.header_count         = 1;

    pubnub_milliseconds_t ms = pn_retry_parse_retry_after(&resp);
    assert_int_equal(3000, ms);
}

static pn_middleware_retry_t s_retry_mw;

static void init_retry_mw(pubnub_retry_policy_t policy,
                          unsigned int          max_retries,
                          unsigned int          excluded)
{
    pubnub_retry_configuration_t config;
    memset(&config, 0, sizeof(config));
    config.policy             = policy;
    config.delay_ms           = 100; /* Minimal valid delay. */
    config.maximum_delay_ms   = 1000;
    config.maximum_retry      = max_retries;
    config.excluded_endpoints = excluded;

    pn_middleware_retry_init(
        &s_retry_mw, &config, &s_stub_platform, &s_stub_inner_transport);
}

static void complete_inner_http(int status_code)
{
    assert_non_null(s_inner_response);
    s_inner_response->completion  = PUBNUB_HTTP_COMPLETE;
    s_inner_response->status_code = status_code;
}

static void complete_inner_error(pubnub_res_t error)
{
    assert_non_null(s_inner_response);
    s_inner_response->completion      = PUBNUB_HTTP_ERROR;
    s_inner_response->transport_error = error;
}

/** Fill with 0xFF bytes — produces large random values that pass
 *  rejection sampling. 0xFFFFFFFF % 1000 = 295. */
static int stub_random_bytes_ff(pubnub_platform_provider_t* self,
                                uint8_t*                    buf,
                                size_t                      len)
{
    (void)self;
    memset(buf, 0xFF, len);
    return 0;
}

static void test_jitter_applied_to_final_delay(void** state)
{
    (void)state;

    /* Use a platform that produces 0xFF random bytes.
     * 0xFFFFFFFF % 1000 = 295 ms jitter. */
    pubnub_platform_provider_t platform_ff = s_stub_platform;
    platform_ff.random_bytes               = stub_random_bytes_ff;

    pubnub_retry_configuration_t config;
    memset(&config, 0, sizeof(config));
    config.policy        = PUBNUB_RETRY_LINEAR;
    config.delay_ms      = 2000;
    config.maximum_retry = 5;

    pn_middleware_retry_t mw;
    pn_middleware_retry_init(&mw, &config, &platform_ff, &s_stub_inner_transport);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        mw.base.send(&mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Trigger retriable failure → enters WAITING with jitter. */
    complete_inner_http(503);
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, mw.slots[0].state);

    /* Timer deadline = start(1000) + delay(2000) + jitter(295) = 3295.
     * Advance to 3294 — timer should NOT have expired yet. */
    s_monotonic_now = 3294;
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, mw.slots[0].state);

    /* Advance to 3295 — timer should expire, triggering redispatch. */
    s_monotonic_now = 3295;
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, mw.slots[0].state);
    assert_int_equal(2, s_inner_send_count);
}

/** A large server Retry-After is clamped to maximum_retry_after_ms. */
static void test_retry_after_clamped_to_max(void** state)
{
    (void)state;

    /* delay_ms 100, but a huge Retry-After that must be clamped to 5000. */
    pubnub_retry_configuration_t config;
    memset(&config, 0, sizeof(config));
    config.policy                 = PUBNUB_RETRY_LINEAR;
    config.delay_ms               = 100;
    config.maximum_retry          = 5;
    config.maximum_retry_after_ms = 5000;

    pn_middleware_retry_t mw;
    pn_middleware_retry_init(&mw, &config, &s_stub_platform, &s_stub_inner_transport);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        mw.base.send(&mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Inner returns 429 with Retry-After: 3600 (1 hour). */
    assert_non_null(s_inner_response);
    s_inner_response->headers[0].key.ptr   = "Retry-After";
    s_inner_response->headers[0].key.len   = 11;
    s_inner_response->headers[0].value.ptr = "3600";
    s_inner_response->headers[0].value.len = 4;
    s_inner_response->header_count         = 1;
    complete_inner_http(429);
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, mw.slots[0].state);

    /* Zero jitter: deadline = start(1000) + clamped(5000) = 6000.
     * At 5999 still WAITING; at 6000 redispatch. Without clamping the
     * deadline would be ~3.6M ms away and this would stay WAITING. */
    s_monotonic_now = 5999;
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, mw.slots[0].state);

    s_monotonic_now = 6000;
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, mw.slots[0].state);
    assert_int_equal(2, s_inner_send_count);
}

/** maximum_retry_after_ms == 0 resolves to the compile-time default. */
static void test_retry_after_max_defaults_when_zero(void** state)
{
    (void)state;

    pubnub_retry_configuration_t config;
    memset(&config, 0, sizeof(config));
    config.policy        = PUBNUB_RETRY_LINEAR;
    config.delay_ms      = 100;
    config.maximum_retry = 5;
    /* maximum_retry_after_ms left 0. */

    pn_middleware_retry_t mw;
    pn_middleware_retry_init(&mw, &config, &s_stub_platform, &s_stub_inner_transport);

    assert_int_equal(PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS,
                     (int)mw.max_retry_after_ms);
}

static void test_jitter_zero_when_no_random(void** state)
{
    (void)state;

    /* Platform with NULL random_bytes → jitter = 0. */
    pubnub_platform_provider_t platform_no_rand = s_stub_platform;
    platform_no_rand.random_bytes               = NULL;

    pubnub_retry_configuration_t config;
    memset(&config, 0, sizeof(config));
    config.policy        = PUBNUB_RETRY_LINEAR;
    config.delay_ms      = 1000;
    config.maximum_retry = 5;

    pn_middleware_retry_t mw;
    pn_middleware_retry_init(&mw, &config, &platform_no_rand, &s_stub_inner_transport);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        mw.base.send(&mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(503);
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, mw.slots[0].state);

    /* No jitter: deadline = start(1000) + delay(1000) + 0 = 2000. */
    s_monotonic_now = 1999;
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, mw.slots[0].state);

    s_monotonic_now = 2000;
    mw.base.poll(&mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, mw.slots[0].state);
}

static void test_http_429_triggers_retry(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);

    /* Simulate inner transport completing with 429. */
    complete_inner_http(429);

    /* Poll — middleware should see completion, classify as retriable,
     * move slot to WAITING (not finalize to caller). */
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(0, visible);

    /* Caller response should still be PENDING (retry scheduled). */
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);

    /* Verify slot is in WAITING state. */
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);
}

static void test_http_503_triggers_retry(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(503);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(0, visible);
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);
}

static void test_http_400_no_retry(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(400);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, visible);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(400, caller_response.status_code);
}

static void test_http_200_no_retry(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(200);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, visible);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(200, caller_response.status_code);
}

static void test_transport_error_triggers_retry(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_error(PUBNUB_ERR_TRANSPORT);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(0, visible);
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);
}

static void test_cancelled_no_retry(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_error(PUBNUB_ERR_CANCELLED);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, visible);
    assert_int_equal(PUBNUB_HTTP_ERROR, caller_response.completion);
    assert_int_equal(PUBNUB_ERR_CANCELLED, caller_response.transport_error);
}

static void test_max_retries_exhaustion(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 2, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* First failure — should schedule retry (attempt 0 → 1). */
    complete_inner_http(503);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);

    /* Advance time past backoff, trigger re-dispatch. */
    s_monotonic_now += 2000;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(2, s_inner_send_count);

    /* Second failure — should schedule retry (attempt 1 → 2). */
    complete_inner_http(503);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);

    /* Advance time, trigger re-dispatch. */
    s_monotonic_now += 2000;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(3, s_inner_send_count);

    /* Third failure — attempt count (2) == max_retries (2), should
     * finalize to caller without scheduling another retry. */
    complete_inner_http(503);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, visible);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(503, caller_response.status_code);
}

static void test_excluded_endpoint_passthrough(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, PUBNUB_ENDPOINT_MESSAGE_SEND);

    /* Use a full pn_request_t so container_of can recover it. */
    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.feature_id = (uint8_t)PUBNUB_FEATURE_PUBLISH;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);

    /* Excluded request passes through to inner transport directly
     * (returns inner handle, not the request-as-handle pattern). */
    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);
    /* The handle is the inner transport's handle (not req.http_request). */
    assert_ptr_equal(handle, (pubnub_transport_handle_t*)&s_fake_inner_handle);

    /* No slot should be occupied — excluded requests are not tracked. */
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
}

static void test_non_excluded_endpoint_tracked(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, PUBNUB_ENDPOINT_MESSAGE_SEND);

    /* HISTORY is not excluded. */
    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.feature_id = (uint8_t)PUBNUB_FEATURE_HISTORY;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);

    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);
    /* Tracked request returns request-as-handle (not inner handle). */
    assert_ptr_equal(handle, (pubnub_transport_handle_t*)&req.http_request);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
}

static void test_cancel_during_backoff(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Trigger a retriable failure to enter WAITING state. */
    complete_inner_http(429);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

    /* Cancel during backoff. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);

    /* Verify caller response shows cancellation. */
    assert_int_equal(PUBNUB_HTTP_ERROR, caller_response.completion);
    assert_int_equal(PUBNUB_ERR_CANCELLED, caller_response.transport_error);

    /* Slot should be released. */
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
}

static void test_destroy_while_in_flight(void** state)
{
    (void)state;

    pubnub_retry_configuration_t config;
    memset(&config, 0, sizeof(config));
    config.policy        = PUBNUB_RETRY_LINEAR;
    config.delay_ms      = 100;
    config.maximum_retry = 5;

    pubnub_transport_provider_t* mw_ptr = pn_middleware_retry_create(
        &config, &s_stub_platform, &s_stub_inner_transport, &s_stub_allocator, NULL);
    assert_non_null(mw_ptr);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        mw_ptr->send(mw_ptr, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);

    /* Request is in-flight. Destroy the middleware. */
    int cancel_before = s_inner_cancel_count;
    pn_middleware_retry_destroy(mw_ptr, &s_stub_allocator);

    /* Verify the inner transport's cancel was called for the in-flight
     * request. */
    assert_int_equal(cancel_before + 1, s_inner_cancel_count);
}

static void test_successful_retry_after_backoff(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Fail with 503 → enters WAITING. */
    complete_inner_http(503);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

    /* Advance time past backoff (delay=100ms for this config). */
    s_monotonic_now += 200;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(2, s_inner_send_count);

    /* This time succeed with 200. */
    complete_inner_http(200);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, visible);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(200, caller_response.status_code);
}

/* pn_retry_delay_exponential UB-fix tests (attempt >= 32, max_delay=0). */

static void test_delay_exponential_attempt_zero(void** state)
{
    (void)state;
    /* attempt 0: delay = base_delay (no doubling). */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(1000, 8000, 0);
    assert_int_equal(1000, d);
}

static void test_delay_exponential_attempt_one(void** state)
{
    (void)state;
    /* attempt 1: delay = base*2, capped at max. */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(1000, 8000, 1);
    assert_int_equal(2000, d);

    /* attempt 1 with base close to max (3000*2=6000 < 8000). */
    d = pn_retry_delay_exponential(3000, 8000, 1);
    assert_int_equal(6000, d);

    /* attempt 1 with base just above max/2 (5000*2=10000 > 8000 → max). */
    d = pn_retry_delay_exponential(5000, 8000, 1);
    assert_int_equal(8000, d);
}

static void test_delay_exponential_attempt_31(void** state)
{
    (void)state;
    /* attempt 31 would shift by 31 bits — saturates at max. */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(1000, 8000, 31);
    assert_int_equal(8000, d);
}

static void test_delay_exponential_attempt_32(void** state)
{
    (void)state;
    /* attempt 32 was UB via left-shift by 32 — must saturate at max. */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(1000, 8000, 32);
    assert_int_equal(8000, d);
}

static void test_delay_exponential_attempt_64(void** state)
{
    (void)state;
    /* attempt 64: large shift, must saturate cleanly. */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(1000, 8000, 64);
    assert_int_equal(8000, d);
}

static void test_delay_exponential_max_delay_zero(void** state)
{
    (void)state;
    /* max_delay_ms = 0: loop condition (delay < 0u) is always false,
     * loop body never executes. Returns base_delay unchanged. */
    pubnub_milliseconds_t d = pn_retry_delay_exponential(1000, 0, 5);
    assert_int_equal(1000, d);
}

/* DONE slots are reclaimed when the core cancels at release, not on poll. */

static void test_done_slots_reclaimed_on_cancel(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t               req;
    pubnub_http_response_t     response;
    pubnub_transport_handle_t* handle;
    unsigned int               cycle;

    /* Run 2*MAX+1 successful tracked requests through the middleware,
     * reclaiming each with cancel() the way pubnub_future_release does.
     * The slot must stay DONE across the poll (its inner handle backs the
     * body until release) and only return to IDLE on cancel. If the slot
     * were never reclaimed, acquire_slot would exhaust after MAX successes
     * and later sends would degrade to passthrough (inner handle returned
     * instead of the request pointer). */
    for (cycle = 0; cycle < 2 * PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 1; cycle++) {
        memset(&req, 0, sizeof(req));
        memset(&response, 0, sizeof(response));

        handle =
            s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &response);
        assert_non_null(handle);
        /* Tracked (not degraded to passthrough): handle IS the request. */
        assert_ptr_equal(handle, (pubnub_transport_handle_t*)&req.http_request);

        complete_inner_http(200);
        s_retry_mw.base.poll(&s_retry_mw.base, 0);

        /* Terminal slot persists as DONE until the core releases it. */
        assert_int_equal(PUBNUB_HTTP_COMPLETE, response.completion);
        assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);

        /* Release: cancel reclaims the slot to IDLE. */
        s_retry_mw.base.cancel(&s_retry_mw.base, handle);
        assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
    }
}

static void test_retry_fires_after_slot_reclaim(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    unsigned int           cycle;

    /* Run MAX successful requests, reclaiming each with cancel() (as the
     * core does at release). Afterwards every slot is IDLE and available. */
    for (cycle = 0; cycle < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; cycle++) {
        memset(&req, 0, sizeof(req));
        memset(&caller_response, 0, sizeof(caller_response));

        pubnub_transport_handle_t* h = s_retry_mw.base.send(
            &s_retry_mw.base, &req.http_request, &caller_response);
        assert_non_null(h);
        complete_inner_http(200);
        s_retry_mw.base.poll(&s_retry_mw.base, 0);
        s_retry_mw.base.cancel(&s_retry_mw.base, h);
    }

    /* Now inject a retriable 503. Slot must be available. */
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(503);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);

    /* Must actually schedule a retry (WAITING), not passthrough. */
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);

    int          has_waiting = 0;
    unsigned int i;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        if (PN_RETRY_SLOT_WAITING == s_retry_mw.slots[i].state) {
            has_waiting = 1;
        }
    }
    assert_int_equal(1, has_waiting);
}

/* Generation-keyed retry slots. */

static void test_stale_generation_cancel_is_noop(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    /* Use a pn_request_t so PN_CONTAINER_OF works. */
    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Complete successfully → slot becomes DONE and stays DONE across the
     * poll. The core reclaims it at release via cancel(). */
    complete_inner_http(200);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);

    /* Simulate pool recycling: same address, new generation. */
    req.generation = 2;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle2 =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle2);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);

    /* Cancel with the OLD generation handle (which has the same pointer
     * value). find_slot_by_request should not match because generation
     * changed. The cancel delegates to inner transport as passthrough. */
    req.generation = 1;
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    req.generation = 2;

    /* The live slot must still be IN_FLIGHT — the stale cancel missed it. */
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);
}

static void test_cancel_does_not_clobber_timeout(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Simulate the core writing TIMEOUT before cancel arrives. */
    caller_response.completion      = PUBNUB_HTTP_ERROR;
    caller_response.transport_error = PUBNUB_ERR_TIMEOUT;

    s_retry_mw.base.cancel(&s_retry_mw.base, handle);

    /* Must preserve TIMEOUT, not clobber with CANCELLED. */
    assert_int_equal(PUBNUB_HTTP_ERROR, caller_response.completion);
    assert_int_equal(PUBNUB_ERR_TIMEOUT, caller_response.transport_error);
}

/** All configured retry attempts complete without the core
 *  deadline killing the request during backoff. */
static void test_all_retry_attempts_reachable(void** state)
{
    unsigned int max_retries = 6;
    unsigned int attempt;
    (void)state;
    init_retry_mw(PUBNUB_RETRY_EXPONENTIAL, max_retries, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);

    /* Drive max_retries retriable failures. Each cycle: complete
     * inner with 503, poll to trigger schedule_retry, advance time
     * past backoff, poll to trigger redispatch. */
    for (attempt = 0; attempt < max_retries; attempt++) {
        complete_inner_http(503);
        s_retry_mw.base.poll(&s_retry_mw.base, 0);
        assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

        s_monotonic_now += 60000;
        s_retry_mw.base.poll(&s_retry_mw.base, 0);
        assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    }

    /* All attempts fired: initial + max_retries redispatches. */
    assert_int_equal((int)(1 + max_retries), s_inner_send_count);

    /* Final attempt also fails — exhaustion finalizes. */
    complete_inner_http(503);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);

    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(503, caller_response.status_code);
}

/** deadline_suspended is set during backoff and cleared on
 *  redispatch. */
static void test_deadline_suspended_during_backoff(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Initially not suspended. */
    assert_int_equal(0, req.http_request.deadline_suspended);

    /* Trigger retriable failure → WAITING. */
    complete_inner_http(429);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);
    assert_int_equal(1, req.http_request.deadline_suspended);

    /* Advance time past backoff → redispatch clears the flag. */
    s_monotonic_now += 200;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(0, req.http_request.deadline_suspended);
}

/** cancel during backoff clears deadline_suspended. */
static void test_cancel_clears_deadline_suspended(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(429);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, req.http_request.deadline_suspended);

    /* Cancel during backoff. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(0, req.http_request.deadline_suspended);
}

/** CHANGE 2: When redispatch inner send returns NULL, the caller
 *  receives an immediate transport error instead of hanging. */
static void test_redispatch_null_handle_reports_error(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);

    /* First attempt fails → enters WAITING. */
    complete_inner_http(503);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

    /* Make the next inner send return NULL (simulate all transport
     * connections busy). */
    s_inner_send_fail_on_call = 2;

    /* Advance time past backoff → redispatch, inner send fails. */
    s_monotonic_now += 200;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);

    /* Caller must see an immediate transport error, not PENDING. */
    assert_int_equal(PUBNUB_HTTP_ERROR, caller_response.completion);
    assert_int_equal(PUBNUB_ERR_TRANSPORT, caller_response.transport_error);
    assert_int_equal(0, req.http_request.deadline_suspended);
}

static void test_concurrent_slots_isolate_retry_state(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t            req1;
    pubnub_http_response_t  resp1;
    pn_request_t            req2;
    pubnub_http_response_t  resp2;
    pubnub_http_response_t* saved_inner_resp1;

    memset(&req1, 0, sizeof(req1));
    memset(&resp1, 0, sizeof(resp1));
    memset(&req2, 0, sizeof(req2));
    memset(&resp2, 0, sizeof(resp2));

    /* Send request 1 through retry middleware. */
    pubnub_transport_handle_t* h1 =
        s_retry_mw.base.send(&s_retry_mw.base, &req1.http_request, &resp1);
    assert_non_null(h1);
    assert_int_equal(1, s_inner_send_count);

    /* Save the inner response pointer for req1 before sending req2
     * (stub_inner_send overwrites s_inner_response on each call). */
    saved_inner_resp1 = s_inner_response;

    /* Send request 2 through retry middleware. */
    pubnub_transport_handle_t* h2 =
        s_retry_mw.base.send(&s_retry_mw.base, &req2.http_request, &resp2);
    assert_non_null(h2);
    assert_int_equal(2, s_inner_send_count);

    /* Fail req1 with 503 (retriable) via its saved inner response. */
    saved_inner_resp1->completion  = PUBNUB_HTTP_COMPLETE;
    saved_inner_resp1->status_code = 503;

    /* Complete req2 with 200 (success) via the current inner response. */
    complete_inner_http(200);

    /* Poll: middleware should route req1 to WAITING (retry scheduled)
     * and req2 to caller-visible completion. */
    s_retry_mw.base.poll(&s_retry_mw.base, 0);

    /* Req2 must be completed successfully — req1's retry must not
     * contaminate req2's state. */
    assert_int_equal(PUBNUB_HTTP_COMPLETE, resp2.completion);
    assert_int_equal(200, resp2.status_code);

    /* Req1 must be in retry-waiting state (backoff scheduled),
     * NOT completed to the caller yet. */
    assert_int_equal(PUBNUB_HTTP_PENDING, resp1.completion);

    /* Verify at least one slot is WAITING (req1's retry). */
    int          has_waiting = 0;
    unsigned int i;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        if (PN_RETRY_SLOT_WAITING == s_retry_mw.slots[i].state) {
            has_waiting = 1;
        }
    }
    assert_int_equal(1, has_waiting);

    /* Advance time past backoff and poll again — req1 should redispatch. */
    s_monotonic_now += 2000;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(3, s_inner_send_count);

    /* Complete the retried req1 with 200. */
    complete_inner_http(200);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);

    /* Now req1 should also be completed to the caller. */
    assert_int_equal(PUBNUB_HTTP_COMPLETE, resp1.completion);
    assert_int_equal(200, resp1.status_code);
}

/** Data integrity: body data in caller_response survives the terminal poll.
 *  The poll sweep leaves the slot DONE and must NOT cancel the inner handle
 *  (whose RX buffer backs the body pointer) — that only happens when the
 *  core releases the future via cancel(). */
static void test_body_survives_done_poll(void** state)
{
    static const uint8_t fake_body[] = "Hello from transport";
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t           req;
    pubnub_http_response_t caller_response;
    memset(&req, 0, sizeof(req));
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Set body data on the internal response before completing. */
    s_inner_response->body     = fake_body;
    s_inner_response->body_len = sizeof(fake_body) - 1;
    complete_inner_http(200);

    /* Poll: finalize_slot copies internal→caller; slot stays DONE. */
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(1, visible);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);

    /* Body must still be readable in the caller's response. */
    assert_non_null(caller_response.body);
    assert_int_equal(sizeof(fake_body) - 1, (int)caller_response.body_len);
    assert_memory_equal(fake_body, caller_response.body, caller_response.body_len);
    assert_int_equal(200, caller_response.status_code);

    /* Inner cancel must NOT have been called during the poll sweep
     * (body aliases the inner RX buffer, freed only at release). */
    assert_int_equal(0, s_inner_cancel_count);
}

/** Lifecycle: cancelling the same handle twice must not crash or
 *  corrupt state. First cancel releases the slot; second falls through
 *  to passthrough (inner transport rejects the stale handle). */
static void test_double_cancel_same_handle(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);

    /* First cancel: finds the slot, cancels inner, sets IDLE. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
    assert_int_equal(1, s_inner_cancel_count);

    /* Second cancel: find_slot_by_request returns NULL (slot is IDLE),
     * falls through to passthrough. Inner transport cancel called again
     * but with the retry handle (rejected by socket_cancel's generation check). */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(2, s_inner_cancel_count);

    /* Slot must still be IDLE — no state corruption. */
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
}

/** Lifecycle: cancel of a completed (DONE) slot reclaims it. The slot keeps
 *  its request pointer after the terminal poll, so find_slot_by_request
 *  matches, the inner handle is forwarded to the inner cancel (freeing the
 *  RX buffer that backed the body), and the slot returns to IDLE. */
static void test_cancel_reclaims_done_slot(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    /* Complete: slot becomes DONE and persists across the poll. */
    complete_inner_http(200);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);

    /* Release: cancel finds the DONE slot, forwards the inner handle,
     * and reclaims the slot to IDLE. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(1, s_inner_cancel_count);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
}

/** Boundary: when all retry slots are busy, the next tracked request
 *  falls through to passthrough (inner handle returned, not tracked). */
static void test_acquire_all_slots_then_passthrough(void** state)
{
    unsigned int               i;
    pn_request_t               requests[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_http_response_t     responses[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_transport_handle_t* handles[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];

    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    /* Fill all retry slots with tracked requests. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        memset(&requests[i], 0, sizeof(requests[i]));
        memset(&responses[i], 0, sizeof(responses[i]));
        handles[i] = s_retry_mw.base.send(
            &s_retry_mw.base, &requests[i].http_request, &responses[i]);
        assert_non_null(handles[i]);
        assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[i].state);
        /* Tracked request: handle IS the request pointer. */
        assert_ptr_equal(handles[i],
                         (pubnub_transport_handle_t*)&requests[i].http_request);
    }

    /* One more tracked request: acquire_slot returns NULL → passthrough. */
    pn_request_t           overflow_req;
    pubnub_http_response_t overflow_resp;
    memset(&overflow_req, 0, sizeof(overflow_req));
    memset(&overflow_resp, 0, sizeof(overflow_resp));

    pubnub_transport_handle_t* overflow_handle = s_retry_mw.base.send(
        &s_retry_mw.base, &overflow_req.http_request, &overflow_resp);
    assert_non_null(overflow_handle);

    /* Passthrough: handle is the INNER transport handle, not request. */
    assert_ptr_equal(overflow_handle,
                     (pubnub_transport_handle_t*)&s_fake_inner_handle);

    /* The overflow request still works through the inner transport.
     * Complete it and verify the caller sees the response. */
    complete_inner_http(200);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, overflow_resp.completion);
    assert_int_equal(200, overflow_resp.status_code);
}

/** Boundary: uint16 generation wrap (65535 → 0) must not cause
 *  stale-handle false match. */
static void test_generation_wrap_uint16(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 65535;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    /* Send with generation 65535. */
    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(65535, s_retry_mw.slots[0].request_generation);

    /* Complete, then reclaim via cancel (as the core does at release). */
    complete_inner_http(200);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);

    /* Wrap: generation goes to 0. */
    req.generation = 0;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle2 =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle2);
    assert_int_equal(0, s_retry_mw.slots[0].request_generation);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);

    /* Cancel with the old generation (65535). */
    req.generation = 65535;
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    req.generation = 0;

    /* Slot must still be live — generation mismatch prevented false match. */
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(PUBNUB_HTTP_PENDING, caller_response.completion);
}

/** Adversarial: Retry-After with negative value returns 0 (first char
 *  is '-', rejected by digit check). */
static void test_retry_after_negative(void** state)
{
    (void)state;

    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    const char key[]   = "Retry-After";
    const char value[] = "-1";

    resp.headers[0].key.ptr   = key;
    resp.headers[0].key.len   = 11;
    resp.headers[0].value.ptr = value;
    resp.headers[0].value.len = 2;
    resp.header_count         = 1;

    pubnub_milliseconds_t ms = pn_retry_parse_retry_after(&resp);
    assert_int_equal(0, ms);
}

/** Adversarial: extremely large Retry-After value triggers overflow
 *  detection and returns the 1-hour cap (3600000 ms). */
static void test_retry_after_overflow(void** state)
{
    (void)state;

    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    const char key[]   = "Retry-After";
    const char value[] = "99999999999";

    resp.headers[0].key.ptr   = key;
    resp.headers[0].key.len   = 11;
    resp.headers[0].value.ptr = value;
    resp.headers[0].value.len = 11;
    resp.header_count         = 1;

    pubnub_milliseconds_t ms = pn_retry_parse_retry_after(&resp);
    /* Parser detects unsigned overflow and caps at 1 hour. */
    assert_int_equal(3600000, ms);
}

/** Drive the single-slot s_retry_mw (configured max_retries=1) through
 *  transport-error failures until it exhausts to a DONE transport-error
 *  terminal. Returns the request-as-handle from the initial send. */
static pubnub_transport_handle_t*
drive_to_transport_error_terminal(pn_request_t*           req,
                                  pubnub_http_response_t* caller_response)
{
    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req->http_request, caller_response);
    assert_non_null(handle);

    /* Attempt 0 fails with a retriable transport error → WAITING. */
    complete_inner_error(PUBNUB_ERR_TRANSPORT);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

    /* Backoff expires → redispatch (attempt 1). */
    s_monotonic_now += 2000;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);

    /* Attempt 1 fails; attempt count (1) == max_retries (1) → exhausted. */
    complete_inner_error(PUBNUB_ERR_TRANSPORT);
    s_retry_mw.base.poll(&s_retry_mw.base, 0);

    return handle;
}

/** Bug B5 (primary crash regression): a retry-tracked request that
 *  exhausts its retries after a transport-level error must leave the slot
 *  DONE with its request pointer intact, so the core's cancel() (via
 *  abort of the transport failure) resolves the slot and forwards the
 *  INNER handle — never the request pointer — to the inner transport.
 *  Forwarding the request pointer crashed the curl backend, which casts
 *  the handle to its own request type without validation. */
static void test_transport_error_exhaustion_cancel_uses_inner_handle(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 1, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        drive_to_transport_error_terminal(&req, &caller_response);

    /* Tracked request returns the request pointer as its handle. */
    assert_ptr_equal(handle, (pubnub_transport_handle_t*)&req.http_request);

    /* Error terminal must persist as DONE with request + inner handle
     * preserved (not reclaimed to IDLE by the poll sweep). */
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    assert_ptr_equal((void*)s_retry_mw.slots[0].request, (void*)&req.http_request);
    assert_non_null(s_retry_mw.slots[0].inner_handle);

    /* Core aborts by calling cancel() with the request-as-handle. The
     * redispatch already cancelled attempt 0's inner handle, so measure
     * the delta this cancel() adds rather than the absolute count. */
    int cancels_before = s_inner_cancel_count;
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);

    /* cancel() forwarded exactly one inner cancel, using the INNER
     * handle — never the request pointer. */
    assert_int_equal(cancels_before + 1, s_inner_cancel_count);
    assert_ptr_equal(s_inner_cancel_last_handle,
                     (pubnub_transport_handle_t*)&s_fake_inner_handle);
    /* The request pointer was never forwarded to the inner transport. */
    assert_true(s_inner_cancel_last_handle
                != (pubnub_transport_handle_t*)&req.http_request);

    /* Slot reclaimed to IDLE after cancel. */
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
    assert_null(s_retry_mw.slots[0].request);
    assert_null(s_retry_mw.slots[0].inner_handle);
}

/** Bug B5 (state machine): after transport-error exhaustion, and before
 *  cancel(), the slot stays DONE (not reclaimed) and still owns the
 *  request pointer and inner handle. */
static void test_transport_error_exhaustion_slot_persists(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 1, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 7;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    (void)drive_to_transport_error_terminal(&req, &caller_response);

    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    assert_ptr_equal((void*)s_retry_mw.slots[0].request, (void*)&req.http_request);
    assert_non_null(s_retry_mw.slots[0].inner_handle);

    /* Caller already received the transport error. */
    assert_int_equal(PUBNUB_HTTP_ERROR, caller_response.completion);
    assert_int_equal(PUBNUB_ERR_TRANSPORT, caller_response.transport_error);

    /* Re-polling must not recount or reclaim the persisting error slot. */
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(0, visible);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    assert_ptr_equal((void*)s_retry_mw.slots[0].request, (void*)&req.http_request);
}

/** Success path contract: a request that succeeds on the first try becomes
 *  a DONE terminal and PERSISTS across the poll sweep — the core reads the
 *  body (which aliases the inner RX buffer) and only releases the slot when
 *  it cancels the future. The inner handle is not cancelled during the poll
 *  sweep; it is forwarded (and the RX buffer freed) when the core cancels. */
static void test_success_terminal_persists_until_cancel(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);

    complete_inner_http(200);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);

    /* Terminal persists as DONE with request + inner handle preserved; no
     * inner cancel during the sweep. */
    assert_int_equal(1, visible);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    assert_ptr_equal((void*)s_retry_mw.slots[0].request, (void*)&req.http_request);
    assert_non_null(s_retry_mw.slots[0].inner_handle);
    assert_int_equal(0, s_inner_cancel_count);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(200, caller_response.status_code);

    /* A re-poll must not recount the persisting terminal slot. */
    assert_int_equal(0, s_retry_mw.base.poll(&s_retry_mw.base, 0));
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);

    /* Release: cancel forwards the inner handle (freeing the RX buffer)
     * and reclaims the slot to IDLE. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(1, s_inner_cancel_count);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
    assert_null(s_retry_mw.slots[0].request);
    assert_null(s_retry_mw.slots[0].inner_handle);
}

/** Bug B5 (passthrough cancel): an excluded-endpoint request returns the
 *  inner handle directly (not tracked). cancel() must delegate straight
 *  to the inner transport with that inner handle — find_slot_by_request()
 *  correctly returns NULL for the foreign pointer. */
static void test_passthrough_cancel_delegates_to_inner(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, PUBNUB_ENDPOINT_MESSAGE_SEND);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.feature_id = (uint8_t)PUBNUB_FEATURE_PUBLISH; /* excluded group */

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);

    /* Passthrough: handle is the inner handle, no slot tracked. */
    assert_ptr_equal(handle, (pubnub_transport_handle_t*)&s_fake_inner_handle);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);

    s_retry_mw.base.cancel(&s_retry_mw.base, handle);

    assert_int_equal(1, s_inner_cancel_count);
    assert_ptr_equal(s_inner_cancel_last_handle,
                     (pubnub_transport_handle_t*)&s_fake_inner_handle);
}

/** Bug B5 (robustness): cancel() with NULL handle or NULL self must be a
 *  no-op that never touches the inner transport and never crashes. */
static void test_cancel_null_args_are_noops(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 5, 0);

    s_retry_mw.base.cancel(&s_retry_mw.base, NULL);
    assert_int_equal(0, s_inner_cancel_count);

    s_retry_mw.base.cancel(NULL, (pubnub_transport_handle_t*)&s_fake_inner_handle);
    assert_int_equal(0, s_inner_cancel_count);
}

/** Bug B5 (idempotency): after cancel() reclaims a transport-error slot
 *  to IDLE, a second cancel() with the same (stale) handle must not match
 *  a live slot and must not crash. It falls through to passthrough (the
 *  real transport validates stale handles at the socket level). */
static void test_transport_error_double_cancel_safe(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 1, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        drive_to_transport_error_terminal(&req, &caller_response);

    /* First cancel reclaims the slot (one inner cancel on top of the
     * redispatch's earlier cancel of attempt 0). */
    int cancels_before = s_inner_cancel_count;
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
    assert_int_equal(cancels_before + 1, s_inner_cancel_count);

    /* Second cancel: slot is IDLE and request cleared → no match →
     * passthrough. No crash, slot stays IDLE. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
}

/** COMPLETE-terminal exhaustion: retries exhausted after a retriable HTTP
 *  status (503) finalize with completion == COMPLETE, not ERROR. This lands
 *  on the same DONE-slot branch as a 2xx success and PERSISTS across the
 *  finalizing poll — the core reads caller_response->body (which aliases the
 *  inner RX buffer) and reclaims the slot only when it cancels the future.
 *  The inner handle must NOT be cancelled on the poll; it is forwarded when
 *  the core cancels, which also returns the slot to IDLE for reuse. */
static void test_exhausted_http_error_persists_until_cancel(void** state)
{
    unsigned int attempt;
    int          cancels_before;
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 2, 0);

    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    pubnub_http_response_t caller_response;
    memset(&caller_response, 0, sizeof(caller_response));

    pubnub_transport_handle_t* handle =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle);
    assert_int_equal(1, s_inner_send_count);

    /* Drive max_retries retriable 503 completions (each redispatches). */
    for (attempt = 0; attempt < 2; attempt++) {
        complete_inner_http(503);
        s_retry_mw.base.poll(&s_retry_mw.base, 0);
        assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

        s_monotonic_now += 2000;
        s_retry_mw.base.poll(&s_retry_mw.base, 0);
        assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    }

    /* Final 503: attempt count (2) == max_retries (2) → exhausted. The
     * poll must not cancel the inner handle (body aliases RX buffer). */
    cancels_before = s_inner_cancel_count;
    complete_inner_http(503);
    int visible = s_retry_mw.base.poll(&s_retry_mw.base, 0);

    /* Terminal is COMPLETE with the 503 status forwarded to the caller. */
    assert_int_equal(1, visible);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, caller_response.completion);
    assert_int_equal(503, caller_response.status_code);

    /* Persists as DONE with request + inner handle preserved — not reaped. */
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);
    assert_ptr_equal((void*)s_retry_mw.slots[0].request, (void*)&req.http_request);
    assert_non_null(s_retry_mw.slots[0].inner_handle);
    assert_int_equal(cancels_before, s_inner_cancel_count);

    /* A trailing poll leaves the slot stably DONE (no recount). */
    assert_int_equal(0, s_retry_mw.base.poll(&s_retry_mw.base, 0));
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);

    /* Release: cancel finds the slot, forwards the inner handle (freeing the
     * RX buffer), and reclaims the slot to IDLE. */
    s_retry_mw.base.cancel(&s_retry_mw.base, handle);
    assert_int_equal(cancels_before + 1, s_inner_cancel_count);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);

    /* The reclaimed slot is reusable by a fresh send. */
    req.generation = 2;
    memset(&caller_response, 0, sizeof(caller_response));
    pubnub_transport_handle_t* handle2 =
        s_retry_mw.base.send(&s_retry_mw.base, &req.http_request, &caller_response);
    assert_non_null(handle2);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
}

#if PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS >= 2
/** Bug B5 (concurrency isolation): with one slot exhausted to a DONE
 *  transport-error terminal and another still IN_FLIGHT, cancelling the
 *  DONE one must reclaim only that slot and leave the IN_FLIGHT slot
 *  untouched. */
static void test_transport_error_cancel_isolates_other_slot(void** state)
{
    (void)state;
    init_retry_mw(PUBNUB_RETRY_LINEAR, 1, 0);

    pn_request_t           req1;
    pn_request_t           req2;
    pubnub_http_response_t resp1;
    pubnub_http_response_t resp2;

    memset(&req1, 0, sizeof(req1));
    memset(&req2, 0, sizeof(req2));
    memset(&resp1, 0, sizeof(resp1));
    memset(&resp2, 0, sizeof(resp2));
    req1.generation = 1;
    req2.generation = 1;

    pubnub_transport_handle_t* h1 =
        s_retry_mw.base.send(&s_retry_mw.base, &req1.http_request, &resp1);
    assert_non_null(h1);
    pubnub_transport_handle_t* h2 =
        s_retry_mw.base.send(&s_retry_mw.base, &req2.http_request, &resp2);
    assert_non_null(h2);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[1].state);

    /* Fail slot 0 with a transport error → WAITING (slot 1 untouched). */
    s_retry_mw.slots[0].internal_response.completion = PUBNUB_HTTP_ERROR;
    s_retry_mw.slots[0].internal_response.transport_error = PUBNUB_ERR_TRANSPORT;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_WAITING, s_retry_mw.slots[0].state);

    /* Backoff expires → slot 0 redispatch. */
    s_monotonic_now += 2000;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[0].state);

    /* Slot 0 fails again → exhausted → DONE error terminal. */
    s_retry_mw.slots[0].internal_response.completion = PUBNUB_HTTP_ERROR;
    s_retry_mw.slots[0].internal_response.transport_error = PUBNUB_ERR_TRANSPORT;
    s_retry_mw.base.poll(&s_retry_mw.base, 0);
    assert_int_equal(PN_RETRY_SLOT_DONE, s_retry_mw.slots[0].state);

    /* Slot 1 is still IN_FLIGHT with its request preserved. */
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[1].state);
    assert_ptr_equal((void*)s_retry_mw.slots[1].request, (void*)&req2.http_request);
    assert_int_equal(PUBNUB_HTTP_PENDING, resp2.completion);

    /* Cancel the DONE slot 0 — must not disturb slot 1. */
    s_retry_mw.base.cancel(&s_retry_mw.base, h1);
    assert_int_equal(PN_RETRY_SLOT_IDLE, s_retry_mw.slots[0].state);
    assert_int_equal(PN_RETRY_SLOT_IN_FLIGHT, s_retry_mw.slots[1].state);
    assert_ptr_equal((void*)s_retry_mw.slots[1].request, (void*)&req2.http_request);
    assert_int_equal(PUBNUB_HTTP_PENDING, resp2.completion);
}
#endif /* PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS >= 2 */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_delay_exponential_bounds, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_zero_base, test_setup),
        cmocka_unit_test_setup(test_jitter_applied_to_final_delay, test_setup),
        cmocka_unit_test_setup(test_retry_after_clamped_to_max, test_setup),
        cmocka_unit_test_setup(test_retry_after_max_defaults_when_zero, test_setup),
        cmocka_unit_test_setup(test_jitter_zero_when_no_random, test_setup),
        cmocka_unit_test_setup(test_retry_after_integer, test_setup),
        cmocka_unit_test_setup(test_retry_after_absent, test_setup),
        cmocka_unit_test_setup(test_retry_after_non_integer, test_setup),
        cmocka_unit_test_setup(test_retry_after_case_insensitive, test_setup),
        cmocka_unit_test_setup(test_http_429_triggers_retry, test_setup),
        cmocka_unit_test_setup(test_http_503_triggers_retry, test_setup),
        cmocka_unit_test_setup(test_http_400_no_retry, test_setup),
        cmocka_unit_test_setup(test_http_200_no_retry, test_setup),
        cmocka_unit_test_setup(test_transport_error_triggers_retry, test_setup),
        cmocka_unit_test_setup(test_cancelled_no_retry, test_setup),
        cmocka_unit_test_setup(test_max_retries_exhaustion, test_setup),
        cmocka_unit_test_setup(test_excluded_endpoint_passthrough, test_setup),
        cmocka_unit_test_setup(test_non_excluded_endpoint_tracked, test_setup),
        cmocka_unit_test_setup(test_cancel_during_backoff, test_setup),
        cmocka_unit_test_setup(test_destroy_while_in_flight, test_setup),
        cmocka_unit_test_setup(test_successful_retry_after_backoff, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_attempt_zero, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_attempt_one, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_attempt_31, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_attempt_32, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_attempt_64, test_setup),
        cmocka_unit_test_setup(test_delay_exponential_max_delay_zero, test_setup),
        cmocka_unit_test_setup(test_done_slots_reclaimed_on_cancel, test_setup),
        cmocka_unit_test_setup(test_retry_fires_after_slot_reclaim, test_setup),
        cmocka_unit_test_setup(test_stale_generation_cancel_is_noop, test_setup),
        cmocka_unit_test_setup(test_cancel_does_not_clobber_timeout, test_setup),
        cmocka_unit_test_setup(test_all_retry_attempts_reachable, test_setup),
        cmocka_unit_test_setup(test_deadline_suspended_during_backoff, test_setup),
        cmocka_unit_test_setup(test_cancel_clears_deadline_suspended, test_setup),
        cmocka_unit_test_setup(test_redispatch_null_handle_reports_error, test_setup),
        cmocka_unit_test_setup(test_concurrent_slots_isolate_retry_state, test_setup),
        cmocka_unit_test_setup(test_body_survives_done_poll, test_setup),
        cmocka_unit_test_setup(test_double_cancel_same_handle, test_setup),
        cmocka_unit_test_setup(test_cancel_reclaims_done_slot, test_setup),
        cmocka_unit_test_setup(test_acquire_all_slots_then_passthrough, test_setup),
        cmocka_unit_test_setup(test_generation_wrap_uint16, test_setup),
        cmocka_unit_test_setup(test_retry_after_negative, test_setup),
        cmocka_unit_test_setup(test_retry_after_overflow, test_setup),
        cmocka_unit_test_setup(
            test_transport_error_exhaustion_cancel_uses_inner_handle, test_setup),
        cmocka_unit_test_setup(test_transport_error_exhaustion_slot_persists,
                               test_setup),
        cmocka_unit_test_setup(test_success_terminal_persists_until_cancel,
                               test_setup),
        cmocka_unit_test_setup(test_passthrough_cancel_delegates_to_inner, test_setup),
        cmocka_unit_test_setup(test_cancel_null_args_are_noops, test_setup),
        cmocka_unit_test_setup(test_transport_error_double_cancel_safe, test_setup),
        cmocka_unit_test_setup(test_exhausted_http_error_persists_until_cancel,
                               test_setup),
#if PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS >= 2
        cmocka_unit_test_setup(test_transport_error_cancel_isolates_other_slot,
                               test_setup),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

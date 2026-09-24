/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file curl_transport_units.c
 * @brief Unit tests for the libcurl-backed transport provider.
 *
 * Covers the five callbacks (send, poll, cancel, init, deinit)
 * plus the vtable surface. Three styles of test:
 *
 *   - **Structural** tests exercise the callback wiring, NULL-
 *     argument guards, and init/deinit lifecycle without touching
 *     the network.
 *   - **One error-path transfer test** sends to `127.0.0.1:1`
 *     (reserved port, nothing listens there) to drive the full
 *     send -> poll -> ERROR-completion -> cancel lifecycle without
 *     requiring a live server.  libcurl's connect phase fails
 *     quickly with ECONNREFUSED on every supported platform.
 *   - **Internal-helper tests** call
 *     `pn_curl_rx_append_or_grow` directly (via the provider's
 *     internal header) to exercise the "respect NULL buf_grow"
 *     guard that the full-transfer path cannot easily reach
 *     without a live server.
 *
 * Real success-path coverage lands with `feat/example-time`
 * (runnable demo binary). Mock-server tests are deferred until a
 * feature actually needs them.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/providers/transport.h"
#include "pubnub/proxy.h"

/* Internal helper exposed for unit testing (not part of the
 * public provider ABI). */
#include "providers/transport/curl/transport_curl_internal.h"

pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc);
pubnub_allocator_provider_t* pn_allocator_default(void);

/* ======================================================================== */
/* Test fixture                                                              */
/* ======================================================================== */

typedef struct {
    pubnub_transport_provider_t* sut;
    pubnub_provider_deps_t*      deps;
} transport_fixture_t;

/**
 * @brief Bring the transport up for a single test and tear it down
 *        on teardown, mirroring the context-lifecycle path in
 *        `client.c`.
 */
static int setup_transport(void** state)
{
    transport_fixture_t* fix = (transport_fixture_t*)calloc(1, sizeof(*fix));
    assert_non_null(fix);

    fix->sut = pn_transport_default(pn_allocator_default());
    assert_non_null(fix->sut);

    fix->deps = (pubnub_provider_deps_t*)calloc(1, sizeof(*fix->deps));
    assert_non_null(fix->deps);
    fix->deps->allocator = pn_allocator_default();

    int rc = fix->sut->init(fix->sut, fix->deps);
    assert_int_equal(rc, 0);

    *state = fix;
    return 0;
}

static int teardown_transport(void** state)
{
    transport_fixture_t* fix = (transport_fixture_t*)*state;
    fix->sut->deinit(fix->sut);
    pn_allocator_default()->free(pn_allocator_default(), fix->sut);
    free(fix->deps);
    free(fix);
    *state = NULL;
    return 0;
}

/* ======================================================================== */
/* Tests: vtable surface                                                     */
/* ======================================================================== */

static void provider_should_expose_every_mandatory_callback(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_transport_provider_t* sut   = pn_transport_default(alloc);

    assert_non_null(sut);
    assert_non_null(sut->send);
    assert_non_null(sut->poll);
    assert_non_null(sut->cancel);

    alloc->free(alloc, sut);
}

static void provider_should_expose_lifecycle_callbacks(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_transport_provider_t* sut   = pn_transport_default(alloc);

    /* curl transport is per-context: init / deinit are NON-null
     * here, in contrast to the cJSON singleton which leaves them
     * NULL. Pinning the difference keeps the next PR's diff
     * honest if the shape changes. */
    assert_non_null(sut->init);
    assert_non_null(sut->deinit);

    alloc->free(alloc, sut);
}

static void pn_transport_default_should_return_distinct_instances(void** state)
{
    (void)state;

    /* Each context gets its own transport instance -- verify that
     * successive calls return distinct allocations. */
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_transport_provider_t* a     = pn_transport_default(alloc);
    pubnub_transport_provider_t* b     = pn_transport_default(alloc);

    assert_ptr_not_equal(a, b);

    alloc->free(alloc, a);
    alloc->free(alloc, b);
}

/* ======================================================================== */
/* Tests: init / deinit                                                      */
/* ======================================================================== */

static void init_should_succeed_with_valid_allocator_dep(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_transport_provider_t* sut   = pn_transport_default(alloc);
    pubnub_provider_deps_t       deps  = {0};
    deps.allocator                     = alloc;

    int rc = sut->init(sut, &deps);

    assert_int_equal(rc, 0);
    /* Matching deinit to keep the singleton clean for subsequent
     * tests; init is idempotent (ref-counted libcurl global init
     * tolerates the double-init / double-cleanup pair). */
    sut->deinit(sut);
    alloc->free(alloc, sut);
}

static void deinit_should_be_safe_on_a_freshly_initialised_provider(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_transport_provider_t* sut   = pn_transport_default(alloc);
    pubnub_provider_deps_t       deps  = {0};
    deps.allocator                     = alloc;

    assert_int_equal(sut->init(sut, &deps), 0);
    /* No in-flight transfers, no buffers acquired -- deinit must
     * be a clean tear-down of just the multi handle. */
    sut->deinit(sut);
    alloc->free(alloc, sut);
}

/* ======================================================================== */
/* Tests: send / poll / cancel -- structural and error-path                  */
/* ======================================================================== */

static void send_with_null_request_should_mark_response_as_error(void** state)
{
    transport_fixture_t*         fix      = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut      = fix->sut;
    pubnub_http_response_t       response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, NULL, &response);

    assert_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
}

static void send_with_null_response_should_return_null_without_crash(void** state)
{
    transport_fixture_t*         fix     = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut     = fix->sut;
    pubnub_http_request_t        request = {0};

    /* Contract: when response is NULL we cannot signal anything to
     * the caller -- return NULL and do not crash. The SDK core
     * won't actually call us this way (it always allocates a
     * response struct), but this pins defensive behaviour. */
    pubnub_transport_handle_t* handle = sut->send(sut, &request, NULL);

    assert_null(handle);
}

static void send_then_poll_against_unreachable_peer_should_report_error(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    /* 127.0.0.1:1 -- port 1 is reserved (tcpmux) and nothing
     * listens on it on any supported OS -- libcurl will fail connect
     * quickly with ECONNREFUSED. Exercises the full send / poll /
     * error-completion lifecycle without needing a real server. */
    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1:1";
    request.secure                = 0;
    /* One trivial path segment so the URL builder has work to do. */
    request.path_segments[0].ptr = "ping";
    request.path_segments[0].len = 4;
    request.path_segment_count   = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);
    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);

    /* Drive the event loop until libcurl reports completion. Bound
     * the spin count so a hypothetical hang fails the test rather
     * than stalling CI. */
    const int max_iterations = 200;
    int       iteration      = 0;
    while (PUBNUB_HTTP_PENDING == response.completion && iteration < max_iterations) {
        (void)sut->poll(sut, 50);
        iteration++;
    }

    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
    sut->cancel(sut, handle);
}

static void cancel_on_null_handle_should_be_a_no_op(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    /* Must not crash and must not touch the provider's state. */
    sut->cancel(sut, NULL);
}

/* ======================================================================== */
/* Tests: internal helper -- pn_curl_rx_append_or_grow                       */
/* ======================================================================== */
/*
 * These tests exercise the write-callback helper directly through
 * the provider's internal header. They cover the NULL-buf_grow
 * branch that the full-transfer error-path test cannot reach (a
 * connect failure never hands bytes to the write callback), and
 * pin the "respect the optional-callback contract" guarantee on
 * which stub-allocator users depend.
 */

/* ---- Fake allocator fixtures --------------------------------------- */

/* Fake allocator state: a single statically-sized buffer the tests
 * hand out from `buf_acquire` and reclaim from `buf_release`. Not
 * a real allocator -- just enough to instantiate a pubnub_buffer_t. */
static uint8_t fake_rx_storage[32];

static void* fake_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void fake_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t fake_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    pubnub_buffer_t buf = {
        .data    = fake_rx_storage,
        .len     = 0,
        .cap     = sizeof(fake_rx_storage),
        .purpose = purpose,
    };
    return buf;
}

static void fake_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    if (buf == NULL) {
        return;
    }
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

static int fake_buf_grow_always_fails(pubnub_allocator_provider_t* self,
                                      pubnub_buffer_t*             buf,
                                      size_t                       new_cap)
{
    (void)self;
    (void)buf;
    (void)new_cap;
    return -1;
}

/* The "arena-style" allocator: buf_grow deliberately NULL, per the
 * allocator-provider header's explicit permission for fixed-size
 * partition backends. */
static pubnub_allocator_provider_t s_null_buf_grow_allocator = {
    .alloc       = fake_alloc,
    .realloc     = NULL,
    .free        = fake_free,
    .buf_acquire = fake_buf_acquire,
    .buf_release = fake_buf_release,
    .buf_grow    = NULL,
};

/* Same shape but with a grow callback that always reports failure --
 * proves the "non-zero return aborts" path is honoured equally to
 * the "NULL pointer aborts" path. */
static pubnub_allocator_provider_t s_failing_buf_grow_allocator = {
    .alloc       = fake_alloc,
    .realloc     = NULL,
    .free        = fake_free,
    .buf_acquire = fake_buf_acquire,
    .buf_release = fake_buf_release,
    .buf_grow    = fake_buf_grow_always_fails,
};

/* ---- Tests --------------------------------------------------------- */

static void rx_append_should_write_bytes_within_capacity(void** state)
{
    (void)state;
    pubnub_buffer_t buf = s_null_buf_grow_allocator.buf_acquire(
        &s_null_buf_grow_allocator, PUBNUB_BUF_RX);
    size_t written = 0;

    const char chunk[] = "hello";
    size_t     result  = pn_curl_rx_append_or_grow(
        &s_null_buf_grow_allocator, &buf, &written, chunk, sizeof(chunk) - 1);

    assert_int_equal(result, sizeof(chunk) - 1);
    assert_int_equal(written, sizeof(chunk) - 1);
    assert_int_equal(buf.len, sizeof(chunk) - 1);
    assert_memory_equal(buf.data, chunk, sizeof(chunk) - 1);

    s_null_buf_grow_allocator.buf_release(&s_null_buf_grow_allocator, &buf);
}

static void rx_append_should_abort_when_buf_grow_is_null(void** state)
{
    (void)state;
    pubnub_buffer_t buf = s_null_buf_grow_allocator.buf_acquire(
        &s_null_buf_grow_allocator, PUBNUB_BUF_RX);
    size_t written = 0;

    /* Chunk twice the size of the fake storage forces the grow
     * branch. With buf_grow == NULL the helper must return 0
     * (abort signal to libcurl) rather than dereference the NULL
     * function pointer. */
    char oversize[sizeof(fake_rx_storage) * 2];
    memset(oversize, 'A', sizeof(oversize));

    size_t result = pn_curl_rx_append_or_grow(
        &s_null_buf_grow_allocator, &buf, &written, oversize, sizeof(oversize));

    assert_int_equal(result, 0);
    /* Bytes written counter must not advance past what fit
     * before the grow request; the buffer is left in its
     * pre-grow state. */
    assert_int_equal(written, 0);
    assert_int_equal(buf.len, 0);

    s_null_buf_grow_allocator.buf_release(&s_null_buf_grow_allocator, &buf);
}

static void rx_append_should_abort_when_buf_grow_fails(void** state)
{
    (void)state;
    pubnub_buffer_t buf = s_failing_buf_grow_allocator.buf_acquire(
        &s_failing_buf_grow_allocator, PUBNUB_BUF_RX);
    size_t written = 0;

    /* Same scenario as above but with a grow callback present that
     * returns non-zero. The contract says "treat grow failure
     * equally to NULL buf_grow", so the result must match. */
    char oversize[sizeof(fake_rx_storage) * 2];
    memset(oversize, 'B', sizeof(oversize));

    size_t result = pn_curl_rx_append_or_grow(
        &s_failing_buf_grow_allocator, &buf, &written, oversize, sizeof(oversize));

    assert_int_equal(result, 0);
    assert_int_equal(written, 0);

    s_failing_buf_grow_allocator.buf_release(&s_failing_buf_grow_allocator, &buf);
}

/* ======================================================================== */
/* Tests: URL builder -- secure flag and host:port parsing                    */
/* ======================================================================== */

/**
 * @brief Sending with secure=1 and no embedded port should succeed
 *        -- exercises the URL builder path that omits the port
 *        suffix (default 443 for https).
 */
static void send_should_succeed_when_secure_uses_default_port(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1";
    request.secure                = 1;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/**
 * @brief Sending with secure=0 and no embedded port should succeed
 *        -- exercises the HTTP (non-TLS) path with default port 80.
 */
static void send_should_succeed_when_insecure_uses_default_port(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1";
    request.secure                = 0;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/**
 * @brief Sending with an embedded non-default port in host should
 *        succeed -- exercises the URL builder path that emits the
 *        `:port` suffix from host parsing.
 */
static void send_should_succeed_when_host_has_custom_port(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1:8080";
    request.secure                = 0;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/**
 * @brief Host with embedded port matching the scheme default should
 *        succeed without emitting the port suffix in the URL.
 */
static void send_should_succeed_when_host_port_matches_default(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com:443";
    request.secure                = 1;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/**
 * @brief Bracketed IPv6 literal with explicit port should parse the
 *        port and use the bracket portion as the hostname in the URL.
 */
static void send_should_succeed_when_host_is_ipv6_bracketed_with_port(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "[::1]:8080";
    request.secure                = 0;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/**
 * @brief Bracketed IPv6 literal without a port suffix should use the
 *        scheme default and include the brackets in the URL host.
 */
static void send_should_succeed_when_host_is_ipv6_bracketed_without_port(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "[::1]";
    request.secure                = 1;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/* ======================================================================== */
/* Tests: URL builder -- path segments and query params                      */
/* ======================================================================== */

static void send_should_succeed_with_multiple_path_segments(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1:1";
    request.secure                = 0;
    request.path_segments[0].ptr  = "publish";
    request.path_segments[0].len  = 7;
    request.path_segments[1].ptr  = "demo";
    request.path_segments[1].len  = 4;
    request.path_segments[2].ptr  = "demo";
    request.path_segments[2].len  = 4;
    request.path_segments[3].ptr  = "0";
    request.path_segments[3].len  = 1;
    request.path_segments[4].ptr  = "ch1";
    request.path_segments[4].len  = 3;
    request.path_segment_count    = 5;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

static void send_should_succeed_with_query_params(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1:1";
    request.secure                = 0;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    request.query_params[0].key.ptr   = "uuid";
    request.query_params[0].key.len   = 4;
    request.query_params[0].value.ptr = "test-id";
    request.query_params[0].value.len = 7;
    request.query_params[1].key.ptr   = "pnsdk";
    request.query_params[1].key.len   = 5;
    request.query_params[1].value.ptr = "C-core%2F1.0";
    request.query_params[1].value.len = 12;
    request.query_param_count         = 2;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

static void send_should_succeed_with_path_segments_and_query_params(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1:1";
    request.secure                = 0;
    request.path_segments[0].ptr  = "v2";
    request.path_segments[0].len  = 2;
    request.path_segments[1].ptr  = "subscribe";
    request.path_segments[1].len  = 9;
    request.path_segments[2].ptr  = "demo";
    request.path_segments[2].len  = 4;
    request.path_segments[3].ptr  = "ch1";
    request.path_segments[3].len  = 3;
    request.path_segment_count    = 4;

    request.query_params[0].key.ptr   = "tt";
    request.query_params[0].key.len   = 2;
    request.query_params[0].value.ptr = "0";
    request.query_params[0].value.len = 1;
    request.query_params[1].key.ptr   = "uuid";
    request.query_params[1].key.len   = 4;
    request.query_params[1].value.ptr = "abc";
    request.query_params[1].value.len = 3;
    request.query_param_count         = 2;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/* ======================================================================== */
/* Tests: POST with body                                                     */
/* ======================================================================== */

static void send_should_succeed_with_post_body(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    static const uint8_t body[] = "{\"msg\":\"hello\"}";

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_POST;
    request.host                  = "127.0.0.1:1";
    request.secure                = 0;
    request.path_segments[0].ptr  = "publish";
    request.path_segments[0].len  = 7;
    request.path_segment_count    = 1;
    request.body                  = body;
    request.body_len              = sizeof(body) - 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/* ======================================================================== */
/* Tests: cancel immediately after send (before poll)                        */
/* ======================================================================== */

static void cancel_immediately_after_send_should_not_crash(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "127.0.0.1:1";
    request.secure                = 0;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);
    assert_non_null(handle);

    /* Cancel without ever calling poll -- must not crash, must
     * not leak (valgrind-friendly). */
    sut->cancel(sut, handle);
}

/* ======================================================================== */
/* Tests: deinit without prior init                                          */
/* ======================================================================== */

static void deinit_without_init_should_not_crash(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_transport_provider_t* sut   = pn_transport_default(alloc);

    /* deinit on a never-initialized instance -- multi is NULL, so
     * the multi-cleanup branch is skipped; the struct is freed. */
    sut->deinit(sut);
    alloc->free(alloc, sut);
}

/* ======================================================================== */
/* Tests: send with NULL host                                                */
/* ======================================================================== */

static void send_should_fail_when_host_is_null(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = NULL; /* invalid */
    request.secure                = 1;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    assert_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
}

/* ======================================================================== */
/* Tests: proxy configuration                                                */
/* ======================================================================== */

static int setup_transport_with_proxy(void** state)
{
    transport_fixture_t* fix = (transport_fixture_t*)calloc(1, sizeof(*fix));
    assert_non_null(fix);

    fix->sut = pn_transport_default(pn_allocator_default());
    assert_non_null(fix->sut);

    fix->deps = (pubnub_provider_deps_t*)calloc(1, sizeof(*fix->deps));
    assert_non_null(fix->deps);
    fix->deps->allocator = pn_allocator_default();

    /* Configure an HTTP CONNECT proxy pointing at a non-existent
     * address.  libcurl accepts the proxy config at setopt time
     * regardless of reachability -- the point is to exercise the
     * proxy option path without crashing. */
    static pubnub_proxy_config_t proxy = {
        .type = PUBNUB_PROXY_HTTP_CONNECT,
        .host = "127.0.0.1",
        .port = 9999,
        .auth = PUBNUB_PROXY_AUTH_NONE,
    };
    fix->deps->proxy = &proxy;

    int rc = fix->sut->init(fix->sut, fix->deps);
    assert_int_equal(rc, 0);

    *state = fix;
    return 0;
}

static void send_should_succeed_when_proxy_is_configured(void** state)
{
    transport_fixture_t*         fix = (transport_fixture_t*)*state;
    pubnub_transport_provider_t* sut = fix->sut;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 1;
    request.path_segments[0].ptr  = "time";
    request.path_segments[0].len  = 4;
    request.path_segment_count    = 1;

    pubnub_http_response_t response = {0};

    pubnub_transport_handle_t* handle = sut->send(sut, &request, &response);

    /* send() configures the proxy via CURLOPT_PROXY; libcurl does
     * not validate proxy reachability until the transfer starts, so
     * send must succeed. */
    assert_non_null(handle);
    assert_int_equal(response.completion, PUBNUB_HTTP_PENDING);
    sut->cancel(sut, handle);
}

/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(provider_should_expose_every_mandatory_callback),
        cmocka_unit_test(provider_should_expose_lifecycle_callbacks),
        cmocka_unit_test(pn_transport_default_should_return_distinct_instances),
        cmocka_unit_test(init_should_succeed_with_valid_allocator_dep),
        cmocka_unit_test(deinit_should_be_safe_on_a_freshly_initialised_provider),
        cmocka_unit_test_setup_teardown(
            send_with_null_request_should_mark_response_as_error,
            setup_transport,
            teardown_transport),
        cmocka_unit_test_setup_teardown(
            send_with_null_response_should_return_null_without_crash,
            setup_transport,
            teardown_transport),
        cmocka_unit_test_setup_teardown(
            send_then_poll_against_unreachable_peer_should_report_error,
            setup_transport,
            teardown_transport),
        cmocka_unit_test_setup_teardown(cancel_on_null_handle_should_be_a_no_op,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test(rx_append_should_write_bytes_within_capacity),
        cmocka_unit_test(rx_append_should_abort_when_buf_grow_is_null),
        cmocka_unit_test(rx_append_should_abort_when_buf_grow_fails),
        /* URL builder -- secure flag and host:port parsing */
        cmocka_unit_test_setup_teardown(send_should_succeed_when_secure_uses_default_port,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test_setup_teardown(send_should_succeed_when_insecure_uses_default_port,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test_setup_teardown(send_should_succeed_when_host_has_custom_port,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test_setup_teardown(send_should_succeed_when_host_port_matches_default,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test_setup_teardown(
            send_should_succeed_when_host_is_ipv6_bracketed_with_port,
            setup_transport,
            teardown_transport),
        cmocka_unit_test_setup_teardown(
            send_should_succeed_when_host_is_ipv6_bracketed_without_port,
            setup_transport,
            teardown_transport),
        /* URL builder -- path segments and query params */
        cmocka_unit_test_setup_teardown(send_should_succeed_with_multiple_path_segments,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test_setup_teardown(send_should_succeed_with_query_params,
                                        setup_transport,
                                        teardown_transport),
        cmocka_unit_test_setup_teardown(
            send_should_succeed_with_path_segments_and_query_params,
            setup_transport,
            teardown_transport),
        /* POST with body */
        cmocka_unit_test_setup_teardown(send_should_succeed_with_post_body,
                                        setup_transport,
                                        teardown_transport),
        /* Cancel immediately after send (before poll) */
        cmocka_unit_test_setup_teardown(cancel_immediately_after_send_should_not_crash,
                                        setup_transport,
                                        teardown_transport),
        /* Deinit without prior init */
        cmocka_unit_test(deinit_without_init_should_not_crash),
        /* NULL host guard */
        cmocka_unit_test_setup_teardown(send_should_fail_when_host_is_null,
                                        setup_transport,
                                        teardown_transport),
        /* Proxy configuration */
        cmocka_unit_test_setup_teardown(send_should_succeed_when_proxy_is_configured,
                                        setup_transport_with_proxy,
                                        teardown_transport),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

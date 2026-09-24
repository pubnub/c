/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file preparse_completion_units.c
 * @brief Unit tests for eager response-body parsing at completion.
 *
 * Covers the completion-time pre-parse that closes the socket
 * Connection: close use-after-free: for every user-facing feature except
 * subscribe, the response body is parsed on the poll-owning thread before
 * the readiness gate is published, so a later result accessor never reads a
 * transport rx buffer that a subsequent dispatch pass may have reclaimed.
 *
 * The tests exercise the real dispatch path (pn_dispatch_or_enqueue ->
 * pn_slot_populate) so the preparse_on_complete flag logic is verified, and
 * use the real serialization backend (pn_serialization_default) so the parse
 * genuinely dereferences the body. Freeing the body buffer after the tick and
 * then calling the accessor reproduces the reclaim; under AddressSanitizer a
 * missing eager parse surfaces as a use-after-free.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/capabilities.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

/* Real serialization backend (cjson or jsmn depending on the build). Both
 * copy parsed strings into their own storage, so the parsed tree is
 * independent of the response body after parse returns. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* A well-formed JSON array body; the real backend parses it into a tree. */
#define PREPARSE_BODY "[1,\"Sent\",\"16951176964521437\"]"

/* Transport that heap-allocates a per-request body buffer aliased into
 * response->body, mirroring how the socket transport aliases response->body
 * onto a connection rx buffer. The buffer is owned by the test (cancel is a
 * no-op) so the test controls exactly when it is reclaimed. */
static uint8_t* s_body_buf;
static int      s_body_freed;
static int      s_send_status;
static char     s_handle_backing;

static uint8_t* preparse_body_dup(void)
{
    const size_t n   = sizeof(PREPARSE_BODY) - 1;
    uint8_t*     buf = (uint8_t*)malloc(n);
    assert_non_null(buf);
    memcpy(buf, PREPARSE_BODY, n);
    return buf;
}

static void preparse_free_body(void)
{
    if (!s_body_freed && NULL != s_body_buf) {
        free(s_body_buf);
        s_body_freed = 1;
    }
}

static pubnub_transport_handle_t* preparse_send(pubnub_transport_provider_t* self,
                                                pubnub_http_request_t* request,
                                                pubnub_http_response_t* response)
{
    (void)self;

    /* Slots acquired with pn_request_pool_acquire for pool-filling have no
     * host set.  pn_process_dispatch_pending auto-dispatches them; skip body
     * allocation so the single s_body_buf pointer tracks only the requests
     * the test explicitly intends to inspect. */
    if (NULL == request->host) {
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = s_send_status;
        response->body        = NULL;
        response->body_len    = 0;
        return (pubnub_transport_handle_t*)&s_handle_backing;
    }

    s_body_buf   = preparse_body_dup();
    s_body_freed = 0;

    response->completion  = PUBNUB_HTTP_COMPLETE;
    response->status_code = s_send_status;
    response->body        = s_body_buf;
    response->body_len    = sizeof(PREPARSE_BODY) - 1;
    return (pubnub_transport_handle_t*)&s_handle_backing;
}

static int preparse_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void preparse_cancel(pubnub_transport_provider_t* self,
                            pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport = {
    .send              = preparse_send,
    .poll              = preparse_poll,
    .cancel            = preparse_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static void* stdlib_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void stdlib_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t stdlib_buf_acquire(pubnub_allocator_provider_t* self,
                                          pubnub_buf_purpose_t         purpose)
{
    (void)self;
    pubnub_buffer_t buf = {0};
    buf.data            = (uint8_t*)malloc(4096);
    buf.cap             = buf.data ? 4096 : 0;
    buf.len             = 0;
    buf.purpose         = purpose;
    return buf;
}

static void stdlib_buf_release(pubnub_allocator_provider_t* self,
                               pubnub_buffer_t*             buf)
{
    (void)self;
    if (NULL != buf && NULL != buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->cap  = 0;
    }
}

static pubnub_allocator_provider_t s_allocator = {
    .alloc       = stdlib_alloc,
    .realloc     = NULL,
    .free        = stdlib_free,
    .buf_acquire = stdlib_buf_acquire,
    .buf_release = stdlib_buf_release,
    .buf_grow    = NULL,
};

static uint64_t s_time_ms;

static pubnub_milliseconds_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return s_time_ms;
}

static pubnub_milliseconds_t mock_wall_clock(pubnub_platform_provider_t* self)
{
    (void)self;
    return s_time_ms;
}

static void mock_sleep(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    s_time_ms += ms;
}

static int mock_random(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    memset(buf, 0x42, len);
    return 0;
}

static pubnub_platform_provider_t s_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_wall_clock,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
    .secure_zero   = NULL,
    .lock_size     = NULL,
    .lock_init     = NULL,
    .lock_destroy  = NULL,
    .lock_acquire  = NULL,
    .lock_release  = NULL,
    .thread_create = NULL,
    .thread_join   = NULL,
};

static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_allocator;
    cfg.transport       = &s_transport;
    cfg.serialization   = pn_serialization_default();
    cfg.platform        = &s_platform;
    return pubnub_create(&cfg);
}

static int setup_test(void** state)
{
    (void)state;
    s_body_buf    = NULL;
    s_body_freed  = 0;
    s_send_status = 200;
    s_time_ms     = 1000;
    return 0;
}

/** @brief Dispatch a single request with the given feature id via the real
 *  dispatch path; returns the resulting direct-slot future. */
static pubnub_future_t dispatch_one(pubnub_context_t* ctx, pubnub_feature_t feature)
{
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    entry.feature_id        = (uint8_t)feature;
    return pn_dispatch_or_enqueue(ctx, &entry);
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * A directly-dispatched publish request must opt into eager parsing:
 * pn_slot_populate sets preparse_on_complete for every non-subscribe feature.
 */
static void publish_direct_dispatch_sets_preparse_flag(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_future_t    fut  = dispatch_one(ctx, PUBNUB_FEATURE_PUBLISH);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);

    assert_int_equal(slot->preparse_on_complete, 1);
    assert_int_equal(slot->parsed_body_attempted, 0);

    (void)pubnub_process(ctx);
    preparse_free_body();
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * A directly-dispatched subscribe request must NOT opt into eager parsing —
 * subscribe re-parses each long-poll response through its own slab.
 */
static void subscribe_direct_dispatch_clears_preparse_flag(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_future_t    fut  = dispatch_one(ctx, PUBNUB_FEATURE_SUBSCRIBE);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);

    assert_int_equal(slot->preparse_on_complete, 0);

    (void)pubnub_process(ctx);
    preparse_free_body();
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * Presence shares one feature id across heartbeat/leave/here_now/where_now;
 * none of them is subscribe, so they all opt into eager parsing.
 */
static void presence_direct_dispatch_sets_preparse_flag(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_future_t    fut  = dispatch_one(ctx, PUBNUB_FEATURE_PRESENCE);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);

    assert_int_equal(slot->preparse_on_complete, 1);

    (void)pubnub_process(ctx);
    preparse_free_body();
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * The core regression test: after the process tick, the response body must
 * already be parsed (parsed_body_attempted == 1, parsed_body_tree != NULL)
 * before any accessor runs. Freeing the body buffer (simulating the socket
 * connection reclaiming its rx buffer) and then calling the accessor must be
 * safe: the accessor returns the cached tree without re-reading freed memory.
 *
 * Without the eager parse, the accessor below would call the serializer on
 * the freed buffer — a use-after-free that AddressSanitizer flags.
 */
static void completion_eager_parses_body_before_accessor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_future_t    fut  = dispatch_one(ctx, PUBNUB_FEATURE_PUBLISH);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);
    assert_int_equal(slot->parsed_body_attempted, 0);

    /* Tick routes completion; the pre-parse pass runs first. */
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fut));

    /* Eager parse must already have populated the cache. */
    assert_int_equal(slot->parsed_body_attempted, 1);
    assert_non_null(slot->parsed_body_tree);
    pubnub_json_value_t* cached = slot->parsed_body_tree;

    /* Simulate the transport reclaiming the rx buffer on slot reuse. The
     * dangling alias remains in http_response.body. */
    preparse_free_body();

    /* Accessor after reclaim: must return the cached tree, never re-parse
     * the freed body. Safe under ASan precisely because of the eager parse. */
    pubnub_json_value_t* again = pn_request_get_parsed_body(slot, serial);
    assert_ptr_equal(again, cached);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * Subscribe must not be eagerly parsed: after the tick the parse cache stays
 * empty, so subscribe does not pay for a redundant parse+alloc it would only
 * repeat through its own slab.
 */
static void subscribe_body_not_preparsed_at_completion(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_future_t    fut  = dispatch_one(ctx, PUBNUB_FEATURE_SUBSCRIBE);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);

    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fut));

    /* No eager parse happened for subscribe. */
    assert_int_equal(slot->parsed_body_attempted, 0);
    assert_null(slot->parsed_body_tree);

    preparse_free_body();
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * Error responses (HTTP >= 400) carry a service-error body that accessors
 * read, so the pre-parse pass eagerly parses them too: the cached tree must
 * survive the rx buffer being reclaimed on slot reuse.
 */
static void error_status_body_is_preparsed(void** state)
{
    (void)state;
    s_send_status         = 500;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_serialization_provider_t* serial = pn_serialization_default();

    pubnub_future_t    fut  = dispatch_one(ctx, PUBNUB_FEATURE_PUBLISH);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);
    assert_int_equal(slot->preparse_on_complete, 1);

    (void)pubnub_process(ctx);

    /* Error body eagerly parsed by the pre-parse pass. */
    assert_int_equal(slot->parsed_body_attempted, 1);
    assert_non_null(slot->parsed_body_tree);
    pubnub_json_value_t* cached = slot->parsed_body_tree;

    /* Reclaiming the rx buffer must not invalidate the cached tree. */
    preparse_free_body();
    pubnub_json_value_t* again = pn_request_get_parsed_body(slot, serial);
    assert_ptr_equal(again, cached);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * Requests promoted from the pending queue must get the same eager-parse
 * opt-in as directly dispatched ones. Fills the pool, enqueues a publish
 * entry, frees a slot, and verifies the promoted slot carries the flag.
 */
static void promoted_request_sets_preparse_flag(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool     = pn_context_request_pool(ctx);
    pn_pipeline_t*     pipeline = pn_context_pipeline(ctx);
    const uint16_t     capacity = pn_context_pool_capacity(ctx);

    /* Fill every direct slot. */
    pubnub_future_t futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &futs[i]), PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue a publish entry: pool is full, so it lands in the queue. */
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host     = "ps.pndsn.com";
    entry.feature_id            = (uint8_t)PUBNUB_FEATURE_PUBLISH;
    pubnub_future_t pending_fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(pending_fut.slot_id >= capacity);

    /* Complete and release slot 0 to free a slot for promotion. */
    pn_request_t* slot0      = pn_request_pool_get(pool, futs[0].slot_id);
    slot0->http_request.host = "ps.pndsn.com";
    pn_request_dispatch(pipeline, slot0, pn_context_platform(ctx));
    (void)pubnub_process(ctx);
    preparse_free_body();
    pubnub_future_release(futs[0]);

    /* Tick promotes the queued entry into the freed slot. */
    (void)pubnub_process(ctx);

    pn_request_t* promoted = pn_request_pool_get(pool, futs[0].slot_id);
    assert_non_null(promoted);
    assert_int_equal(promoted->preparse_on_complete, 1);

    preparse_free_body();
    pubnub_future_release(pending_fut);

    /* Clean up remaining direct slots. */
    for (int i = 1; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_t* s      = pn_request_pool_get(pool, futs[i].slot_id);
        s->http_request.host = "ps.pndsn.com";
        pn_request_dispatch(pipeline, s, pn_context_platform(ctx));
        (void)pubnub_process(ctx);
        preparse_free_body();
        pubnub_future_release(futs[i]);
    }

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test_setup(publish_direct_dispatch_sets_preparse_flag, setup_test),
        cmocka_unit_test_setup(subscribe_direct_dispatch_clears_preparse_flag,
                               setup_test),
        cmocka_unit_test_setup(presence_direct_dispatch_sets_preparse_flag,
                               setup_test),
        cmocka_unit_test_setup(completion_eager_parses_body_before_accessor,
                               setup_test),
        cmocka_unit_test_setup(subscribe_body_not_preparsed_at_completion, setup_test),
        cmocka_unit_test_setup(error_status_body_is_preparsed, setup_test),
        cmocka_unit_test_setup(promoted_request_sets_preparse_flag, setup_test),
#endif /* !PUBNUB_CFG_NO_HEAP */
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

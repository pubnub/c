/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file future_consumption_units.c
 * @brief Unit tests for pubnub_await, pubnub_async, and pending queue.
 *
 * Exercises the three consumption styles (cooperative polling,
 * blocking await, asynchronous callback) and the pending queue
 * overflow/promotion mechanism.
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
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/response.h"
#include "core/core_internal.h"
#include "core/runtime/pending_queue_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

static int s_send_called;
static int s_poll_called;
static int s_complete_on_poll;
static int s_cancel_called;

/* Transport handle stubs. A void-typed handle needs backing storage;
 * use a char so we get a valid non-NULL pointer from (pubnub_transport_handle_t*)&s_handle_backing. */
static char s_handle_backing;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    (void)self;
    (void)request;
    s_send_called++;

    if (s_complete_on_poll) {
        /* Do not complete in send; completion happens in poll. */
        return (pubnub_transport_handle_t*)&s_handle_backing;
    }

    /* Immediate completion: mark response done. */
    response->completion  = PUBNUB_HTTP_COMPLETE;
    response->status_code = 200;
    response->body        = (const uint8_t*)"[1,\"Sent\",\"123\"]";
    response->body_len    = 16;
    return (pubnub_transport_handle_t*)&s_handle_backing;
}

static int mock_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    s_poll_called++;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
    s_cancel_called++;
}

static pubnub_transport_provider_t s_mock_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

/* Allocator: stdlib pass-through. */
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
    (void)purpose;
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

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = stdlib_alloc,
    .realloc     = NULL,
    .free        = stdlib_free,
    .buf_acquire = stdlib_buf_acquire,
    .buf_release = stdlib_buf_release,
    .buf_grow    = NULL,
};

/* Serialization: minimal stubs. Use an int as backing storage for
 * the opaque pubnub_json_value_t pointer. */
static int s_stub_tree_backing;

static pubnub_json_value_t* stub_parse(pubnub_serialization_provider_t* self,
                                       const uint8_t*                   data,
                                       size_t                           len)
{
    (void)self;
    (void)data;
    (void)len;
    return (pubnub_json_value_t*)&s_stub_tree_backing;
}

static pubnub_res_t stub_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    (void)value;
    (void)buf;
    (void)buf_len;
    *out_len = 0;
    return PUBNUB_OK;
}

static void stub_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    (void)self;
    (void)value;
}

static pubnub_serialization_provider_t s_mock_serialization = {
    .parse         = stub_parse,
    .serialize     = stub_serialize,
    .value_destroy = stub_value_destroy,
};

/* Platform: monotonic time with no sync primitives. */
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

static pubnub_platform_provider_t s_mock_platform = {
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

static pubnub_config_t test_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_mock_allocator;
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = &s_mock_serialization;
    cfg.platform        = &s_mock_platform;
    return cfg;
}

#if !PUBNUB_CFG_NO_HEAP
static pubnub_context_t* create_test_ctx(void)
{
    pubnub_config_t cfg = test_config();
    return pubnub_create(&cfg);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

static int setup_test(void** state)
{
    (void)state;
    s_send_called      = 0;
    s_poll_called      = 0;
    s_complete_on_poll = 0;
    s_cancel_called    = 0;
    s_time_ms          = 1000;
    return 0;
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * pubnub_await with a transport that completes immediately in send()
 * should return PUBNUB_OK without needing multiple process ticks.
 */
static void await_on_immediate_completion_returns_ok(void** state)
{
    (void)state;
    s_complete_on_poll    = 0; /* Complete in send(). */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    /* Manually acquire a slot and simulate immediate completion. */
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);

    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    /* Dispatch: send() completes inline. */
    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Await should return immediately (already complete). */
    pubnub_res_t result = pubnub_await(fut);
    assert_int_equal(result, PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * pubnub_await with a transport that requires poll() to complete
 * exercises the cooperative loop fallback.
 */
static void await_cooperative_polls_until_complete(void** state)
{
    (void)state;
    s_complete_on_poll    = 1; /* Don't complete in send. */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Slot is now IN_FLIGHT but not complete. Simulate completion
     * by marking the response after the first poll. */
    slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot->http_response.status_code = 200;
    slot->http_response.body        = (const uint8_t*)"[1,\"OK\",\"t\"]";
    slot->http_response.body_len    = 12;

    pubnub_res_t result = pubnub_await(fut);
    assert_int_equal(result, PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

static void await_on_immediate_error_returns_error(void** state)
{
    (void)state;
    pubnub_future_t bad    = PUBNUB_FUTURE_INVALID;
    pubnub_res_t    result = pubnub_await(bad);
    assert_int_equal(result, PUBNUB_ERR_INVALID_ARGUMENT);
}

static int             s_async_cb_fired;
static pubnub_res_t    s_async_cb_status;
static pubnub_future_t s_async_cb_future;

static void test_async_callback(pubnub_future_t future,
                                pubnub_res_t    status,
                                void*           user_data)
{
    (void)user_data;
    s_async_cb_fired++;
    s_async_cb_status = status;
    s_async_cb_future = future;
}

#if !PUBNUB_CFG_NO_HEAP
static void async_callback_fires_after_process(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Register async callback. */
    rc = pubnub_async(fut, test_async_callback, NULL);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_async_cb_fired, 0);

    /* Simulate transport completion. */
    slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot->http_response.status_code = 200;
    slot->http_response.body        = (const uint8_t*)"[1,\"OK\",\"t\"]";
    slot->http_response.body_len    = 12;

    /* Process tick should route completion and fire callback. */
    (void)pubnub_process(ctx);

    assert_int_equal(s_async_cb_fired, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_OK);
    assert_int_equal(s_async_cb_future.slot_id, fut.slot_id);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void async_on_already_complete_fires_immediately(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_complete_on_poll    = 0; /* Complete in send. */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Process to route the completion. */
    (void)pubnub_process(ctx);

    /* Now the future IS ready. Register callback -- should fire inline. */
    rc = pubnub_async(fut, test_async_callback, NULL);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_async_cb_fired, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void pending_queue_promotes_on_slot_release(void** state)
{
    (void)state;
    s_complete_on_poll    = 0; /* Complete in send. */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    assert_non_null(pool);
    assert_non_null(queue);

    /* Fill all pool slots (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS). */
    pubnub_future_t futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &futs[i]), PUBNUB_OK);
    }

    /* Attempting one more acquire should fail. */
    pubnub_future_t overflow_fut;
    assert_int_equal(pn_request_pool_acquire(pool, ctx, &overflow_fut),
                     PUBNUB_ERR_QUEUE_FULL);
    pn_request_pool_unlock(pool);

    /* Enqueue into the pending queue. */
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    entry.feature_id        = 0;

    pubnub_res_t rc = pn_pending_queue_enqueue(queue, &entry);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(pn_pending_queue_count(queue), 1);

    /* Complete slot 0 so it transitions to terminal. */
    pn_request_t* slot0      = pn_request_pool_get(pool, futs[0].slot_id);
    slot0->http_request.host = "ps.pndsn.com";
    pn_pipeline_t* pipeline  = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot0, pn_context_platform(ctx));

    /* Process tick to route completion. */
    (void)pubnub_process(ctx);

    /* Release slot0 -- this should trigger promotion. */
    pubnub_future_release(futs[0]);

    /* Process tick: promotes the queued entry. */
    (void)pubnub_process(ctx);
    assert_int_equal(pn_pending_queue_count(queue), 0);

    /* Clean up: complete and release remaining slots. */
    for (int i = 1; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_t* slot      = pn_request_pool_get(pool, futs[i].slot_id);
        slot->http_request.host = "ps.pndsn.com";
        pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));
        (void)pubnub_process(ctx);
        pubnub_future_release(futs[i]);
    }

    /* Process to clean up the promoted slot. */
    (void)pubnub_process(ctx);

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

static void pending_queue_full_returns_queue_full(void** state)
{
    (void)state;

    /* Test the queue in isolation. */
    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 2, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "test";

    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);
    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);
    /* Queue is now full (capacity=2). */
    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry),
                     PUBNUB_ERR_QUEUE_FULL);

    pn_pending_queue_deinit(&queue);
}

static int s_cleanup_called;

/**
 * Tracks whether a simulated pool lock is held.
 * 0 = not held, 1 = held. Used by mock_cleanup_lock_check to verify
 * cleanup fires outside the lock.
 */
static int s_lock_held;

static void mock_cleanup(void* fstate, pubnub_allocator_provider_t* alloc)
{
    (void)alloc;
    (void)fstate;
    s_cleanup_called++;
}

/**
 * Cleanup callback that asserts the simulated lock is not held.
 *
 * On non-reentrant mutexes (FreeRTOS default), invoking cleanup while
 * the pool lock is held would deadlock. This mock fails the test
 * immediately if s_lock_held is non-zero at call time.
 */
static void mock_cleanup_lock_check(void* fstate, pubnub_allocator_provider_t* alloc)
{
    (void)fstate;
    (void)alloc;
    assert_int_equal(0, s_lock_held);
    s_cleanup_called++;
}

static void release_on_pending_queue_entry_cancels(void** state)
{
    (void)state;
    s_cleanup_called = 0;

    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 4, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    /* Enqueue an entry with a feature_state and cleanup. */
    int                dummy_state = 42;
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.feature_state         = &dummy_state;
    entry.feature_state_cleanup = mock_cleanup;

    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);
    assert_int_equal(pn_pending_queue_count(&queue), 1);

    /* Cancel with out_data: cleanup should NOT fire inside cancel_at. */
    pn_pending_cancel_data_t cancel_data = {0};
    rc = pn_pending_queue_cancel_at(&queue, 0, &cancel_data);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_cleanup_called, 0);

    /* Cleanup fires when we explicitly run the extracted data. */
    pn_pending_cancel_data_run(&cancel_data);
    assert_int_equal(s_cleanup_called, 1);

    /* Attempting dequeue should find no occupied entries — empty queue
     * signals PUBNUB_IN_PROGRESS (no work ready), not invalid argument. */
    pn_pending_entry_t out;
    rc = pn_pending_queue_dequeue(&queue, &out);
    assert_int_equal(rc, PUBNUB_IN_PROGRESS);

    pn_pending_queue_deinit(&queue);
}

static void cancel_at_null_out_data_fires_cleanup_inline(void** state)
{
    (void)state;
    s_cleanup_called = 0;

    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 4, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    int                dummy_state = 99;
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.feature_state         = &dummy_state;
    entry.feature_state_cleanup = mock_cleanup;

    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);

    /* NULL out_data: cleanup fires inline (legacy behavior). */
    rc = pn_pending_queue_cancel_at(&queue, 0, NULL);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_cleanup_called, 1);

    pn_pending_queue_deinit(&queue);
}

static int s_async_cb_called;

static void mock_async_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;
    s_async_cb_called++;
    s_async_cb_status = status;
    s_async_cb_future = future;
}

static void cancel_pending_fires_async_cb_with_cancelled(void** state)
{
    (void)state;
    s_async_cb_called = 0;
    s_async_cb_status = PUBNUB_OK;
    s_cleanup_called  = 0;

    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 4, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    int                dummy_state = 7;
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.feature_state         = &dummy_state;
    entry.feature_state_cleanup = mock_cleanup;
    entry.async_cb              = mock_async_cb;
    entry.async_cb_user_data    = NULL;
    entry.map_index             = 0;

    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);

    /* Extract cancel data. */
    pn_pending_cancel_data_t cancel_data = {0};
    cancel_data.async_cb_future.ctx      = NULL;
    cancel_data.async_cb_future.slot_id  = 42;
    cancel_data.async_cb_future.status   = PUBNUB_IN_PROGRESS;

    rc = pn_pending_queue_cancel_at(&queue, 0, &cancel_data);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_cleanup_called, 0);
    assert_int_equal(s_async_cb_called, 0);

    /* Fire callbacks outside the "lock". */
    pn_pending_cancel_data_run(&cancel_data);
    assert_int_equal(s_cleanup_called, 1);
    assert_int_equal(s_async_cb_called, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_ERR_CANCELLED);
    assert_int_equal(s_async_cb_future.slot_id, 42);

    pn_pending_queue_deinit(&queue);
}

/**
 * Simulate the deinit drain loop with multiple pending entries.
 * Verifies that sequentially cancelling from head advances correctly
 * and all async_cbs fire exactly once with PUBNUB_ERR_CANCELLED.
 */
static void deinit_drain_fires_all_pending_callbacks(void** state)
{
    (void)state;
    s_async_cb_called = 0;
    s_cleanup_called  = 0;

    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 4, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    /* Enqueue 3 entries, each with async_cb and cleanup. */
    int dummy_states[3] = {10, 20, 30};
    for (int i = 0; i < 3; i++) {
        pn_pending_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.feature_state         = &dummy_states[i];
        entry.feature_state_cleanup = mock_cleanup;
        entry.async_cb              = mock_async_cb;
        entry.async_cb_user_data    = NULL;
        entry.map_index             = (uint16_t)i;
        assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);
    }
    assert_int_equal(pn_pending_queue_count(&queue), 3);

    /* cancel_at(0) advances head itself, so the loop must not touch head. */
    while (pn_pending_queue_count(&queue) > 0) {
        pn_pending_entry_t*      head_entry  = &queue.entries[queue.head];
        pn_pending_cancel_data_t cancel_data = {0};
        cancel_data.async_cb_future.ctx      = NULL;
        cancel_data.async_cb_future.slot_id =
            (uint16_t)(100 + head_entry->map_index);
        cancel_data.async_cb_future.status = PUBNUB_IN_PROGRESS;
        assert_int_equal(pn_pending_queue_cancel_at(&queue, 0, &cancel_data),
                         PUBNUB_OK);
        pn_pending_cancel_data_run(&cancel_data);
    }

    assert_int_equal(s_async_cb_called, 3);
    assert_int_equal(s_cleanup_called, 3);
    assert_int_equal(pn_pending_queue_count(&queue), 0);

    pn_pending_queue_deinit(&queue);
}

/**
 * Simulate the deinit drain loop with a pre-cancelled entry in the
 * middle (occupied=0 after a pubnub_future_release call).
 * The drain must skip the non-occupied entry without looping forever.
 */
static void deinit_drain_skips_precancelled_entries(void** state)
{
    (void)state;
    s_async_cb_called = 0;
    s_cleanup_called  = 0;

    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 4, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    /* Enqueue 3 entries. */
    int dummy_states[3] = {1, 2, 3};
    for (int i = 0; i < 3; i++) {
        pn_pending_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.feature_state         = &dummy_states[i];
        entry.feature_state_cleanup = mock_cleanup;
        entry.async_cb              = mock_async_cb;
        entry.async_cb_user_data    = NULL;
        entry.map_index             = (uint16_t)i;
        assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);
    }
    assert_int_equal(pn_pending_queue_count(&queue), 3);

    pn_pending_cancel_data_t pre_data = {0};
    pre_data.async_cb_future.ctx      = NULL;
    pre_data.async_cb_future.slot_id  = 101;
    pre_data.async_cb_future.status   = PUBNUB_IN_PROGRESS;
    rc = pn_pending_queue_cancel_at(&queue, 1, &pre_data);
    assert_int_equal(rc, PUBNUB_OK);
    pn_pending_cancel_data_run(&pre_data);

    /* After pre-cancel: the middle entry is zeroed but stays inside the ring
     * span (count=3) because head and tail still bracket live entries. */
    assert_int_equal(pn_pending_queue_count(&queue), 3);
    assert_int_equal(queue.entries[1].occupied, 0);
    assert_int_equal(s_async_cb_called, 1);
    assert_int_equal(s_cleanup_called, 1);

    /* Reset counters for the drain phase. */
    s_async_cb_called = 0;
    s_cleanup_called  = 0;

    while (pn_pending_queue_count(&queue) > 0) {
        pn_pending_entry_t*      head_entry  = &queue.entries[queue.head];
        pn_pending_cancel_data_t cancel_data = {0};
        cancel_data.async_cb_future.ctx      = NULL;
        cancel_data.async_cb_future.slot_id =
            (uint16_t)(200 + head_entry->map_index);
        cancel_data.async_cb_future.status = PUBNUB_IN_PROGRESS;
        assert_int_equal(pn_pending_queue_cancel_at(&queue, 0, &cancel_data),
                         PUBNUB_OK);
        pn_pending_cancel_data_run(&cancel_data);
    }

    /* Only entries 0 and 2 fired during drain (middle was already gone). */
    assert_int_equal(s_async_cb_called, 2);
    assert_int_equal(s_cleanup_called, 2);
    assert_int_equal(pn_pending_queue_count(&queue), 0);

    pn_pending_queue_deinit(&queue);
}

static void async_null_callback_returns_error(void** state)
{
    (void)state;
    pubnub_future_t fut = {.ctx = NULL, .slot_id = 0, .status = PUBNUB_OK};
    pubnub_res_t    rc  = pubnub_async(fut, NULL, NULL);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * Cancelling a PENDING slot (dispatched, not yet IN_FLIGHT because the
 * transport completes in poll) should transition the slot to CANCELLED
 * and fire the async callback with PUBNUB_ERR_CANCELLED.
 */
static void future_cancel_pending_fires_async_cb_with_cancelled(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_async_cb_status     = PUBNUB_OK;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);
    slot->async_cb           = test_async_callback;
    slot->async_cb_user_data = NULL;
    /* Leave on_complete NULL — async_cb is the registered completion. */
    pn_request_pool_unlock(pool);

    /* Slot is PENDING (not yet dispatched to transport). */
    assert_int_equal(slot->state, PN_REQUEST_PENDING);

    rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_OK);

    /* Cancel only records intent under the lock; the actual terminal
     * transition and transport teardown happen on the poll-owning
     * thread inside the processing tick. Drive one tick to service it. */
    (void)pubnub_process(ctx);
    assert_int_equal(slot->state, PN_REQUEST_CANCELLED);

    /* async_cb is wired via async_trampoline only when on_complete is
     * async_trampoline. Here we set async_cb directly but not
     * on_complete, so the callback is not invoked automatically by
     * cancel. The future should be ready, status PUBNUB_ERR_CANCELLED. */
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_CANCELLED);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * Cancelling an IN_FLIGHT slot triggers the transport cancel path and
 * transitions the slot to CANCELLED.
 */
static void future_cancel_in_flight_triggers_transport_cancel(void** state)
{
    (void)state;
    s_cancel_called       = 0;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Slot is now IN_FLIGHT with a non-NULL transport handle. */
    assert_int_equal(slot->state, PN_REQUEST_IN_FLIGHT);
    assert_non_null(slot->transport_handle);

    rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_OK);

    /* The transport cancel runs on the poll-owning thread, not inside
     * pubnub_future_cancel, so it never races a concurrent poll(). Drive
     * one tick so the deferred cancel reaches the transport and the slot
     * transitions to CANCELLED. */
    (void)pubnub_process(ctx);
    assert_int_equal(slot->state, PN_REQUEST_CANCELLED);
    assert_int_equal(s_cancel_called, 1);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_CANCELLED);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/**
 * Cancelling an already-terminal slot (COMPLETE) returns
 * PUBNUB_IN_PROGRESS without double-cancelling.
 */
static void future_cancel_terminal_returns_in_progress(void** state)
{
    (void)state;
    s_cancel_called       = 0;
    s_complete_on_poll    = 0; /* Complete in send(). */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Process: transport completed inline, slot should be terminal. */
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fut));

    /* Cancelling a terminal slot must return PUBNUB_IN_PROGRESS. */
    rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_IN_PROGRESS);
    assert_int_equal(s_cancel_called, 0);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

/**
 * Prove that feature_state_cleanup is NOT called while the pool lock
 * is held (extract-then-fire pattern).
 *
 * s_lock_held simulates a non-reentrant mutex (FreeRTOS default).
 * mock_cleanup_lock_check() asserts s_lock_held == 0 at call time.
 *
 * Pattern under test:
 *   1. Acquire lock (s_lock_held = 1)
 *   2. pn_pending_queue_cancel_at(..., &cancel_data)  — extracts, does NOT fire
 *   3. Release lock (s_lock_held = 0)
 *   4. pn_pending_cancel_data_run(&cancel_data)  — fires here
 */
static void cleanup_fires_outside_lock_via_cancel_data(void** state)
{
    (void)state;
    s_cleanup_called = 0;
    s_lock_held      = 0;

    pn_pending_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    pubnub_res_t rc = pn_pending_queue_init(&queue, 4, &s_mock_allocator);
    assert_int_equal(rc, PUBNUB_OK);

    int                dummy_state = 55;
    pn_pending_entry_t entry       = {0};
    entry.feature_state            = &dummy_state;
    entry.feature_state_cleanup    = mock_cleanup_lock_check;

    assert_int_equal(pn_pending_queue_enqueue(&queue, &entry), PUBNUB_OK);

    s_lock_held = 1;

    pn_pending_cancel_data_t cancel_data = {0};
    rc = pn_pending_queue_cancel_at(&queue, 0, &cancel_data);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(0, s_cleanup_called);

    s_lock_held = 0;

    pn_pending_cancel_data_run(&cancel_data);
    assert_int_equal(1, s_cleanup_called);

    pn_pending_queue_deinit(&queue);
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * Cancelling a pending-queue future via pubnub_future_cancel fires
 * the async_cb with PUBNUB_ERR_CANCELLED and returns PUBNUB_OK.
 * Subsequent pubnub_future_release is a safe no-op (no double-fire).
 */
static void future_cancel_pending_queue_fires_callback(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_async_cb_status     = PUBNUB_OK;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    assert_non_null(pool);
    assert_non_null(queue);

    uint16_t capacity = pn_context_pool_capacity(ctx);

    /* Fill all pool slots so the next dispatch goes to the pending queue. */
    pubnub_future_t slot_futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &slot_futs[i]),
                         PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue a pending entry with an async callback. */
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host  = "ps.pndsn.com";
    entry.feature_id         = 0;
    entry.async_cb           = test_async_callback;
    entry.async_cb_user_data = NULL;

    pubnub_future_t fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(fut.slot_id >= capacity);
    assert_int_equal(fut.status, PUBNUB_IN_PROGRESS);

    /* Cancel the pending-queue future. */
    pubnub_res_t rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_async_cb_fired, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_ERR_CANCELLED);

    /* Future handle must reflect the cancelled terminal state. */
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_CANCELLED);

    /* Subsequent release is a safe no-op (entry already cancelled). */
    pubnub_future_release(fut);
    assert_int_equal(s_async_cb_fired, 1);

    /* Clean up pool slots. */
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_pool_release(pool, slot_futs[i].slot_id);
    }
    pn_request_pool_unlock(pool);

    pubnub_destroy(ctx);
}

/**
 * Cancelling an already-cancelled pending-queue future returns
 * PUBNUB_ERR_INVALID_ARGUMENT without double-firing the callback.
 */
static void future_cancel_already_cancelled_pending_returns_invalid(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_async_cb_status     = PUBNUB_OK;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);

    uint16_t capacity = pn_context_pool_capacity(ctx);

    /* Fill all pool slots. */
    pubnub_future_t slot_futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &slot_futs[i]),
                         PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue a pending entry. */
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host  = "ps.pndsn.com";
    entry.feature_id         = 0;
    entry.async_cb           = test_async_callback;
    entry.async_cb_user_data = NULL;

    pubnub_future_t fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(fut.slot_id >= capacity);

    /* First cancel succeeds. */
    pubnub_res_t rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_async_cb_fired, 1);

    /* Second cancel on same future returns INVALID_ARGUMENT. */
    rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(s_async_cb_fired, 1);

    /* Clean up. */
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_pool_release(pool, slot_futs[i].slot_id);
    }
    pn_request_pool_unlock(pool);

    pubnub_destroy(ctx);
}

/**
 * Dummy completion callback for deferred-release test.
 */
static void dummy_on_complete(pn_request_t* req, pubnub_res_t status, void* ud)
{
    (void)req;
    (void)status;
    (void)ud;
}

/**
 * Releasing an IN_FLIGHT future defers the slot reset until the
 * transport completes and the process tick runs.
 */
static void future_release_in_flight_defers_to_completion(void** state)
{
    (void)state;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    slot->on_complete       = dummy_on_complete;
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Slot is now IN_FLIGHT with a live transport handle. */
    assert_int_equal(slot->state, PN_REQUEST_IN_FLIGHT);
    assert_non_null(slot->transport_handle);

    /* Release while in-flight: must NOT reset the slot. */
    pubnub_future_release(fut);
    assert_int_not_equal(slot->state, PN_REQUEST_IDLE);
    assert_int_equal(slot->release_deferred, 1);

    /* Simulate transport completion. */
    slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot->http_response.status_code = 200;
    slot->http_response.body        = (const uint8_t*)"[1,\"OK\",\"t\"]";
    slot->http_response.body_len    = 12;

    /* Process tick routes completion and honours the deferred release. */
    (void)pubnub_process(ctx);
    assert_int_equal(slot->state, PN_REQUEST_IDLE);

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP
static void release_twice_on_same_future_is_noop(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    /* Dispatch with immediate completion (s_complete_on_poll == 0). */
    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Process routes inline completion to terminal state. */
    (void)pubnub_process(ctx);
    assert_true(pn_request_is_terminal(slot));

    /* First release returns slot to IDLE. */
    pubnub_future_release(fut);
    assert_int_equal(slot->state, PN_REQUEST_IDLE);

    /* Second release must not crash or corrupt state. */
    pubnub_future_release(fut);
    assert_int_equal(slot->state, PN_REQUEST_IDLE);

    pubnub_destroy(ctx);
}

static void future_status_after_release_is_invalid_argument(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));
    (void)pubnub_process(ctx);
    pubnub_future_release(fut);

    pubnub_res_t status = pubnub_future_status(fut);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, status);

    pubnub_destroy(ctx);
}

static void future_is_ready_after_release_returns_true(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));
    (void)pubnub_process(ctx);
    pubnub_future_release(fut);

    bool ready = pubnub_future_is_ready(fut);
    assert_true(ready);

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

/**
 * pubnub_response_status_code (and all other result accessors that route
 * through pn_ready_slot_for_future) must return a zero / empty value when
 * called after pubnub_future_release.  The generation counter detects that
 * the slot was reset and prevents accessing freed slot memory.
 */
#if !PUBNUB_CFG_NO_HEAP
static void response_accessor_returns_zero_after_future_release(void** state)
{
    (void)state;
    s_complete_on_poll    = 0;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &fut));
    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_request_dispatch(pn_context_pipeline(ctx), slot, pn_context_platform(ctx));
    (void)pubnub_process(ctx);

    /* Before release: status code is accessible. */
    assert_int_equal(200, pubnub_response_status_code(fut));

    pubnub_future_release(fut);

    /* After release: accessor must return 0 (generation mismatch). */
    assert_int_equal(0, pubnub_response_status_code(fut));

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

static int s_invalid_cb_fired;

static void invalid_cb(pubnub_future_t f, pubnub_res_t st, void* ud)
{
    (void)f;
    (void)st;
    (void)ud;
    s_invalid_cb_fired++;
}

static void async_on_invalid_future_returns_error_not_fires_callback(void** state)
{
    (void)state;
    s_invalid_cb_fired = 0;

    pubnub_res_t rc = pubnub_async(PUBNUB_FUTURE_INVALID, invalid_cb, NULL);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
    assert_int_equal(0, s_invalid_cb_fired);
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * Verifies that result accessors work correctly for a promoted
 * pending-range future whose underlying slot has generation > 0.
 *
 * The accessors must validate against the generation recorded at
 * promotion: a pending-range future carries the identity epoch of its
 * pending-slot-map entry, not the slot generation.
 */
static void pending_range_future_accessor_works_after_slot_recycle(void** state)
{
    (void)state;
    s_complete_on_poll    = 0; /* Complete inline in send(). */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool     = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue    = pn_context_pending_queue(ctx);
    pn_pipeline_t*      pipeline = pn_context_pipeline(ctx);
    assert_non_null(pool);
    assert_non_null(queue);
    assert_non_null(pipeline);

    const uint16_t capacity = pn_context_pool_capacity(ctx);

    for (uint16_t cycle = 0; cycle < capacity; cycle++) {
        pn_request_pool_lock(pool);
        pubnub_future_t f;
        assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &f));
        pn_request_t* s      = pn_request_pool_get(pool, f.slot_id);
        s->http_request.host = "ps.pndsn.com";
        pn_request_pool_unlock(pool);

        pn_request_dispatch(pipeline, s, pn_context_platform(ctx));
        (void)pubnub_process(ctx);
        assert_true(pubnub_future_is_ready(f));
        pubnub_future_release(f);
    }

    /* All slots are IDLE now with generation >= 1. */
    pn_request_t* slot0 = pn_request_pool_get(pool, 0);
    assert_true(slot0->generation >= 1);

    pubnub_future_t futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &futs[i]));
    }
    pn_request_pool_unlock(pool);

    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    entry.feature_id        = 0;

    pubnub_future_t pending_fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(pending_fut.slot_id >= capacity);
    /* The epoch of a first-claimed map entry is 1; a pending future never
     * carries a pool-slot generation. */
    assert_int_equal(1, pending_fut.generation);

    pn_request_t* direct_slot      = pn_request_pool_get(pool, futs[0].slot_id);
    direct_slot->http_request.host = "ps.pndsn.com";
    pn_request_dispatch(pipeline, direct_slot, pn_context_platform(ctx));
    (void)pubnub_process(ctx);
    pubnub_future_release(futs[0]);

    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(pending_fut));
    assert_int_equal(200, pubnub_response_status_code(pending_fut));

    pubnub_future_release(pending_fut);

    /* Clean up remaining direct-slot futures. */
    for (int i = 1; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_t* s      = pn_request_pool_get(pool, futs[i].slot_id);
        s->http_request.host = "ps.pndsn.com";
        pn_request_dispatch(pipeline, s, pn_context_platform(ctx));
        (void)pubnub_process(ctx);
        pubnub_future_release(futs[i]);
    }

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP

/**
 * Enqueue to pending queue, cancel via future, verify feature state
 * is cleaned up (cleanup callback fires).
 */
static void cancel_during_pending_releases_prep_state(void** state)
{
    (void)state;
    s_cleanup_called      = 0;
    s_async_cb_fired      = 0;
    s_async_cb_status     = PUBNUB_OK;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    assert_non_null(pool);
    assert_non_null(queue);

    uint16_t capacity = pn_context_pool_capacity(ctx);

    /* Fill all pool slots. */
    pubnub_future_t slot_futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &slot_futs[i]),
                         PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue a pending entry with a cleanup callback and async_cb
     * so the cancel path fires the callback. */
    int                dummy_state = 77;
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host     = "ps.pndsn.com";
    entry.feature_id            = 0;
    entry.feature_state         = &dummy_state;
    entry.feature_state_cleanup = mock_cleanup;
    entry.async_cb              = test_async_callback;
    entry.async_cb_user_data    = NULL;

    pubnub_future_t fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(fut.slot_id >= capacity);
    assert_int_equal(s_cleanup_called, 0);

    /* Cancel the pending entry via the future. */
    pubnub_res_t rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_OK);

    /* Cleanup callback must have fired for the feature state. */
    assert_int_equal(s_cleanup_called, 1);

    /* Async callback must have fired with CANCELLED status. */
    assert_int_equal(s_async_cb_fired, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_ERR_CANCELLED);

    /* After cancel, the future must report as ready with CANCELLED. */
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_CANCELLED);

    /* Clean up pool slots. */
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_pool_release(pool, slot_futs[i].slot_id);
    }
    pn_request_pool_unlock(pool);

    pubnub_destroy(ctx);
}

/**
 * Set async callback on a pending-range future, promote it, verify
 * the callback fires with correct user_data when completed.
 */
static void* s_promote_user_data = NULL;

static void promote_async_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)future;
    (void)status;
    s_promote_user_data = user_data;
    s_async_cb_fired++;
    s_async_cb_status = status;
}

static void pending_promote_preserves_async_cb_and_user_data(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_promote_user_data   = NULL;
    s_complete_on_poll    = 0; /* Complete inline in send(). */
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool     = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue    = pn_context_pending_queue(ctx);
    pn_pipeline_t*      pipeline = pn_context_pipeline(ctx);
    assert_non_null(pool);
    assert_non_null(queue);

    uint16_t capacity = pn_context_pool_capacity(ctx);

    /* Fill all pool slots. */
    pubnub_future_t slot_futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &slot_futs[i]),
                         PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue a pending entry (no async_cb on the entry itself). */
    int                sentinel = 99;
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    entry.feature_id        = 0;

    pubnub_future_t fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(fut.slot_id >= capacity);
    assert_int_equal(s_async_cb_fired, 0);

    /* Register async callback on the pending future via public API.
     * This wires promote_async_cb + &sentinel into the pending entry's
     * async_cb / async_cb_user_data fields. When promoted, these are
     * copied into the slot and the slot's on_complete is set to
     * async_trampoline so the callback fires on completion. */
    pubnub_res_t async_rc = pubnub_async(fut, promote_async_cb, &sentinel);
    assert_int_equal(async_rc, PUBNUB_OK);
    assert_int_equal(s_async_cb_fired, 0);

    /* Complete and release slot 0 so the pending entry promotes. */
    pn_request_t* slot0      = pn_request_pool_get(pool, slot_futs[0].slot_id);
    slot0->http_request.host = "ps.pndsn.com";
    pn_request_dispatch(pipeline, slot0, pn_context_platform(ctx));
    (void)pubnub_process(ctx);
    pubnub_future_release(slot_futs[0]);

    /* Process tick: promote and dispatch. Since send() completes
     * inline, the promoted slot goes through completion. */
    (void)pubnub_process(ctx);

    /* The callback must have fired with the correct user_data. */
    assert_int_equal(s_async_cb_fired, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_OK);
    assert_ptr_equal(s_promote_user_data, &sentinel);

    pubnub_future_release(fut);

    /* Clean up remaining slots. */
    for (int i = 1; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_t* s      = pn_request_pool_get(pool, slot_futs[i].slot_id);
        s->http_request.host = "ps.pndsn.com";
        pn_request_dispatch(pipeline, s, pn_context_platform(ctx));
        (void)pubnub_process(ctx);
        pubnub_future_release(slot_futs[i]);
    }

    pubnub_destroy(ctx);
}

/**
 * Enqueue to pending, release the future without completing.
 * Verify feature state cleanup runs (no Valgrind leak).
 */
static void release_pending_future_cleans_feature_state(void** state)
{
    (void)state;
    s_cleanup_called      = 0;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    assert_non_null(pool);
    assert_non_null(queue);

    uint16_t capacity = pn_context_pool_capacity(ctx);

    /* Fill all pool slots. */
    pubnub_future_t slot_futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &slot_futs[i]),
                         PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue with cleanup. */
    int                dummy_state = 88;
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host     = "ps.pndsn.com";
    entry.feature_id            = 0;
    entry.feature_state         = &dummy_state;
    entry.feature_state_cleanup = mock_cleanup;

    pubnub_future_t fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(fut.slot_id >= capacity);
    assert_int_equal(s_cleanup_called, 0);

    /* Release the pending future without ever completing it. */
    pubnub_future_release(fut);
    assert_int_equal(s_cleanup_called, 1);

    /* Clean up pool slots. */
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_pool_release(pool, slot_futs[i].slot_id);
    }
    pn_request_pool_unlock(pool);

    pubnub_destroy(ctx);
}

/**
 * pubnub_async on a pending-queue future that was already cancelled
 * via pubnub_future_cancel must fire the callback with
 * PUBNUB_ERR_CANCELLED (not PUBNUB_ERR_INVALID_ARGUMENT).
 *
 * The cancelled sentinel slot id must be handled before the slot lookup,
 * so no invalid-argument callback fires.
 */
static void async_on_cancelled_pending_fires_cancelled(void** state)
{
    (void)state;
    s_async_cb_fired      = 0;
    s_async_cb_status     = PUBNUB_OK;
    s_complete_on_poll    = 1;
    pubnub_context_t* ctx = create_test_ctx();
    assert_non_null(ctx);

    pn_request_pool_t*  pool  = pn_context_request_pool(ctx);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    assert_non_null(pool);
    assert_non_null(queue);

    uint16_t capacity = pn_context_pool_capacity(ctx);

    /* Fill all pool slots so the next dispatch goes to pending. */
    pubnub_future_t slot_futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        assert_int_equal(pn_request_pool_acquire(pool, ctx, &slot_futs[i]),
                         PUBNUB_OK);
    }
    pn_request_pool_unlock(pool);

    /* Enqueue a pending entry (no async_cb yet). */
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    entry.feature_id        = 0;

    pubnub_future_t fut = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(fut.slot_id >= capacity);
    assert_int_equal(fut.status, PUBNUB_IN_PROGRESS);

    /* Cancel the pending-queue future. This sets the map entry to
     * PN_SLOT_ID_CANCELLED. */
    pubnub_res_t rc = pubnub_future_cancel(fut);
    assert_int_equal(rc, PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_CANCELLED);

    /* Now call pubnub_async on the already-cancelled future.
     * Must fire callback with PUBNUB_ERR_CANCELLED. */
    rc = pubnub_async(fut, test_async_callback, NULL);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_async_cb_fired, 1);
    assert_int_equal(s_async_cb_status, PUBNUB_ERR_CANCELLED);

    pubnub_future_release(fut);

    /* Clean up pool slots. */
    pn_request_pool_lock(pool);
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_request_pool_release(pool, slot_futs[i].slot_id);
    }
    pn_request_pool_unlock(pool);

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

/* Leak-tracking transport for the success-path release test. Unlike the
 * shared s_mock_transport (which returns a static handle), this transport
 * heap-allocates a per-request handle whose rx buffer backs response->body,
 * mirroring how the curl transport aliases response->body onto rx_buf. The
 * handle is freed only by cancel(), so if pubnub_future_release fails to
 * cancel a successfully-completed request the handle and its buffer leak --
 * caught here by s_leak_outstanding and by ASan/Valgrind in CI. */
typedef struct leak_handle {
    uint8_t* rx_buf;
} leak_handle_t;

static int s_leak_outstanding;
static int s_leak_cancel_called;
/* When set, leak_send returns the handle without completing so the request
 * stays IN_FLIGHT; the test drives completion on a later tick. s_leak_last_rx
 * exposes the handle-owned rx buffer so the test can alias response->body. */
static int      s_leak_complete_on_poll;
static uint8_t* s_leak_last_rx;
/* Optional re-entrancy hooks run from inside poll() / cancel() so tests can
 * observe what the SDK does while the transport is entered. */
static pubnub_transport_handle_t* s_leak_sent_handle;
static pubnub_transport_handle_t* s_leak_cancelled_handle;
static int                        s_leak_poll_called;
static int                        s_leak_wake_called;
static void (*s_leak_poll_hook)(void);
static void (*s_leak_cancel_hook)(void);

#define LEAK_BODY "[1,\"Sent\",\"17\"]"

static pubnub_transport_handle_t* leak_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    (void)self;
    (void)request;

    leak_handle_t* handle = (leak_handle_t*)malloc(sizeof(*handle));
    assert_non_null(handle);
    handle->rx_buf = (uint8_t*)malloc(sizeof(LEAK_BODY));
    assert_non_null(handle->rx_buf);
    memcpy(handle->rx_buf, LEAK_BODY, sizeof(LEAK_BODY));
    s_leak_outstanding++;
    s_leak_last_rx     = handle->rx_buf;
    s_leak_sent_handle = (pubnub_transport_handle_t*)handle;

    if (!s_leak_complete_on_poll) {
        /* Complete inline; body aliases the handle-owned rx buffer. */
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 200;
        response->body        = handle->rx_buf;
        response->body_len    = sizeof(LEAK_BODY) - 1;
    }
    return (pubnub_transport_handle_t*)handle;
}

static int leak_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    s_leak_poll_called++;
    if (NULL != s_leak_poll_hook) {
        s_leak_poll_hook();
    }
    return 0;
}

static void leak_wake(pubnub_transport_provider_t* self)
{
    (void)self;
    s_leak_wake_called++;
}

static void leak_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   transport_handle)
{
    (void)self;
    leak_handle_t* handle = (leak_handle_t*)transport_handle;
    if (NULL == handle) {
        return;
    }
    s_leak_cancelled_handle = transport_handle;
    if (NULL != s_leak_cancel_hook) {
        s_leak_cancel_hook();
    }
    free(handle->rx_buf);
    free(handle);
    s_leak_cancel_called++;
    if (s_leak_outstanding > 0) {
        s_leak_outstanding--;
    }
}

static pubnub_transport_provider_t s_leak_transport = {
    .send              = leak_send,
    .poll              = leak_poll,
    .cancel            = leak_cancel,
    .wake              = leak_wake,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static int s_release_cb_fired;

/** Async callback that releases its own future from inside the callback. */
static void release_in_callback_cb(pubnub_future_t future,
                                   pubnub_res_t    status,
                                   void*           user_data)
{
    (void)status;
    (void)user_data;
    s_release_cb_fired++;
    pubnub_future_release(future);
}

#if !PUBNUB_CFG_NO_HEAP
/**
 * A successfully-completed request keeps its transport handle live so
 * response->body stays valid; pubnub_future_release must cancel that handle
 * to free the transport's rx buffer. Without the release-time cancel the
 * handle and buffer leak on every successful request. Guards that path with
 * both an explicit outstanding-allocation count and ASan/Valgrind coverage.
 */
static void future_release_on_success_cancels_transport_handle(void** state)
{
    (void)state;
    s_leak_outstanding      = 0;
    s_leak_cancel_called    = 0;
    s_leak_complete_on_poll = 0;

    pubnub_config_t cfg   = test_config();
    cfg.transport         = &s_leak_transport;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);

    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);
    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* Drive completion routing to the terminal state. */
    rc = pubnub_await(fut);
    assert_int_equal(rc, PUBNUB_OK);

    /* Handle is intentionally kept live so the body stays readable. */
    assert_non_null(slot->transport_handle);
    assert_int_equal(s_leak_outstanding, 1);

    /* Body must be valid before release. */
    pubnub_string_view_t body = pubnub_response_body(fut);
    assert_non_null(body.ptr);
    assert_int_equal((int)body.len, (int)(sizeof(LEAK_BODY) - 1));
    assert_memory_equal(body.ptr, LEAK_BODY, sizeof(LEAK_BODY) - 1);

    /* Release must cancel the handle, freeing rx_buf (no leak). */
    pubnub_future_release(fut);
    assert_int_equal(s_leak_cancel_called, 1);
    assert_int_equal(s_leak_outstanding, 0);

    pubnub_destroy(ctx);
}

/**
 * Releasing an IN_FLIGHT future defers the release into the process tick.
 * Once the request succeeds, the tick must cancel the live transport handle
 * outside the lock so the rx buffer is freed.
 */
static void deferred_release_in_flight_success_cancels_handle(void** state)
{
    (void)state;
    s_leak_outstanding      = 0;
    s_leak_cancel_called    = 0;
    s_leak_complete_on_poll = 1;
    s_leak_last_rx          = NULL;

    pubnub_config_t cfg   = test_config();
    cfg.transport         = &s_leak_transport;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);
    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    slot->on_complete       = dummy_on_complete;
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    /* IN_FLIGHT with a live, heap-allocated transport handle. */
    assert_int_equal(slot->state, PN_REQUEST_IN_FLIGHT);
    assert_int_equal(s_leak_outstanding, 1);

    /* Release while in-flight: deferred, not yet cancelled. */
    pubnub_future_release(fut);
    assert_int_equal(slot->release_deferred, 1);
    assert_int_equal(s_leak_cancel_called, 0);

    /* Drive a successful completion; body aliases the handle rx buffer. */
    slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot->http_response.status_code = 200;
    slot->http_response.body        = s_leak_last_rx;
    slot->http_response.body_len    = sizeof(LEAK_BODY) - 1;

    /* Tick honours the deferred release AND cancels the live handle. */
    (void)pubnub_process(ctx);
    assert_int_equal(slot->state, PN_REQUEST_IDLE);
    assert_int_equal(s_leak_cancel_called, 1);
    assert_int_equal(s_leak_outstanding, 0);

    pubnub_destroy(ctx);
}

/**
 * Releasing the future from inside the async completion callback defers the
 * release into the same tick. The deferred-release path must still cancel the
 * live transport handle outside the lock so the rx buffer is freed.
 */
static void deferred_release_from_callback_cancels_handle(void** state)
{
    (void)state;
    s_leak_outstanding      = 0;
    s_leak_cancel_called    = 0;
    s_leak_complete_on_poll = 1;
    s_leak_last_rx          = NULL;
    s_release_cb_fired      = 0;

    pubnub_config_t cfg   = test_config();
    cfg.transport         = &s_leak_transport;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);
    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    rc = pubnub_async(fut, release_in_callback_cb, NULL);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_leak_outstanding, 1);

    /* Drive a successful completion; body aliases the handle rx buffer. */
    slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot->http_response.status_code = 200;
    slot->http_response.body        = s_leak_last_rx;
    slot->http_response.body_len    = sizeof(LEAK_BODY) - 1;

    /* Callback fires inside the tick and releases; the deferred-release path
     * cancels the handle after the callback returns. */
    (void)pubnub_process(ctx);
    assert_int_equal(s_release_cb_fired, 1);
    assert_int_equal(slot->state, PN_REQUEST_IDLE);
    assert_int_equal(s_leak_cancel_called, 1);
    assert_int_equal(s_leak_outstanding, 0);

    pubnub_destroy(ctx);
}

/**
 * A successfully-completed future that the caller never releases still holds a
 * live transport handle. Context teardown must sweep those terminal slots and
 * cancel the handles (while the pipeline is still alive) so the rx buffers are
 * freed rather than leaked.
 */
static void deinit_sweeps_unreleased_success_handle(void** state)
{
    (void)state;
    s_leak_outstanding      = 0;
    s_leak_cancel_called    = 0;
    s_leak_complete_on_poll = 0;

    pubnub_config_t cfg   = test_config();
    cfg.transport         = &s_leak_transport;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_pool_lock(pool);
    pubnub_future_t fut;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, ctx, &fut);
    assert_int_equal(rc, PUBNUB_OK);
    pn_request_t* slot      = pn_request_pool_get(pool, fut.slot_id);
    slot->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_pipeline_t* pipeline = pn_context_pipeline(ctx);
    pn_request_dispatch(pipeline, slot, pn_context_platform(ctx));

    rc = pubnub_await(fut);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(s_leak_outstanding, 1);

    /* Intentionally do NOT release the future. Teardown must reclaim it. */
    pubnub_destroy(ctx);
    assert_int_equal(s_leak_cancel_called, 1);
    assert_int_equal(s_leak_outstanding, 0);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

#if PUBNUB_CFG_THREAD_SAFETY && !PUBNUB_CFG_NO_HEAP

/* Platform with a fake thread group: thread_create returns a non-NULL
 * handle without starting anything, so pn_context_start_bg_thread publishes
 * a background-thread handle while the test drives pn_process_tick itself,
 * playing the part of the poll-owning thread. */
static void* fake_thread_create(pubnub_platform_provider_t*  self,
                                pubnub_allocator_provider_t* allocator,
                                void (*fn)(void*),
                                void* arg)
{
    static int handle;
    (void)self;
    (void)allocator;
    (void)fn;
    (void)arg;
    return &handle;
}

static void fake_thread_join(pubnub_platform_provider_t*  self,
                             pubnub_allocator_provider_t* allocator,
                             void*                        thread_handle)
{
    (void)self;
    (void)allocator;
    (void)thread_handle;
}

static pubnub_platform_provider_t s_bg_platform;

static void leak_reset_counters(void)
{
    s_leak_outstanding      = 0;
    s_leak_cancel_called    = 0;
    s_leak_complete_on_poll = 0;
    s_leak_last_rx          = NULL;
    s_leak_poll_called      = 0;
    s_leak_wake_called      = 0;
    s_leak_sent_handle      = NULL;
    s_leak_cancelled_handle = NULL;
    s_leak_poll_hook        = NULL;
    s_leak_cancel_hook      = NULL;
}

/* Context over the leak transport; with @p bg non-zero a fake background
 * thread handle is published. */
static pubnub_context_t* create_leak_ctx_ex(int bg, int retry)
{
    leak_reset_counters();
    pubnub_config_t cfg = test_config();
    cfg.transport       = &s_leak_transport;
    if (PUBNUB_ENABLE_RETRY && retry) {
        cfg.retry_configuration.policy = PUBNUB_RETRY_LINEAR;
    }
    if (bg) {
        s_bg_platform               = s_mock_platform;
        s_bg_platform.thread_create = fake_thread_create;
        s_bg_platform.thread_join   = fake_thread_join;
        cfg.platform                = &s_bg_platform;
    }
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);
    if (bg) {
        assert_int_equal(PUBNUB_OK, pn_context_start_bg_thread(ctx));
        assert_true(pn_context_has_bg_thread(ctx));
    }
    return ctx;
}

static pubnub_context_t* create_leak_ctx(int bg)
{
    return create_leak_ctx_ex(bg, 0);
}

static pubnub_future_t leak_dispatch(pubnub_context_t* ctx, pn_request_t** out_slot)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pubnub_future_t    fut;

    pn_request_pool_lock(pool);
    assert_int_equal(PUBNUB_OK, pn_request_pool_acquire(pool, ctx, &fut));
    *out_slot                      = pn_request_pool_get(pool, fut.slot_id);
    (*out_slot)->http_request.host = "ps.pndsn.com";
    pn_request_pool_unlock(pool);

    pn_request_dispatch(
        pn_context_pipeline(ctx), *out_slot, pn_context_platform(ctx));
    return fut;
}

static pubnub_future_t leak_terminal(pubnub_context_t* ctx, pn_request_t** out_slot)
{
    pubnub_future_t fut = leak_dispatch(ctx, out_slot);

    (void)pn_process_tick(ctx, 0);
    assert_true(pn_request_is_terminal(*out_slot));
    assert_non_null((*out_slot)->transport_handle);
    return fut;
}

static void release_terminal_bg_mode_defers_cancel_to_tick(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(1);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut  = leak_terminal(ctx, &slot);
    uint16_t          gen  = slot->generation;

    pubnub_future_release(fut);

    assert_int_equal(0, s_leak_cancel_called);
    assert_int_equal(1, s_leak_outstanding);
    assert_false(pn_request_is_idle(slot));
    assert_int_equal(gen, slot->generation);

    (void)pn_process_tick(ctx, 0);

    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(0, s_leak_outstanding);
    assert_true(pn_request_is_idle(slot));
    assert_int_equal((uint16_t)(gen + 1), slot->generation);

    pubnub_destroy(ctx);
}

#if PUBNUB_ENABLE_RETRY
/* Retry middleware hands the core its own tracking handle (the request
 * pointer); the inner transport must still receive its own handle, and the
 * retry bookkeeping must be reclaimed while the slot generation is intact. */
static void release_retry_chain_forwards_inner_handle(int bg)
{
    pubnub_context_t* ctx  = create_leak_ctx_ex(bg, 1);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut  = leak_terminal(ctx, &slot);

    assert_ptr_not_equal(slot->transport_handle, s_leak_sent_handle);

    pubnub_future_release(fut);
    if (bg) {
        assert_int_equal(0, s_leak_cancel_called);
        (void)pn_process_tick(ctx, 0);
    }

    assert_int_equal(1, s_leak_cancel_called);
    assert_ptr_equal(s_leak_cancelled_handle, s_leak_sent_handle);
    assert_int_equal(0, s_leak_outstanding);
    assert_true(pn_request_is_idle(slot));

    pubnub_destroy(ctx);
}

static void release_retry_chain_direct_forwards_inner_handle(void** state)
{
    (void)state;
    release_retry_chain_forwards_inner_handle(0);
}

static void release_retry_chain_deferred_forwards_inner_handle(void** state)
{
    (void)state;
    release_retry_chain_forwards_inner_handle(1);
}
#endif /* PUBNUB_ENABLE_RETRY */

static void release_terminal_bg_mode_wakes_transport(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(1);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut  = leak_terminal(ctx, &slot);

    s_leak_wake_called = 0;
    pubnub_future_release(fut);
    assert_int_equal(1, s_leak_wake_called);

    pubnub_destroy(ctx);
}

static void release_terminal_bg_mode_null_handle_releases_immediately(void** state)
{
    (void)state;
    pubnub_context_t*          ctx    = create_leak_ctx(1);
    pn_request_t*              slot   = NULL;
    pubnub_future_t            fut    = leak_terminal(ctx, &slot);
    pubnub_transport_handle_t* handle = slot->transport_handle;

    /* Hand the handle back to the transport so the slot is terminal with no
     * live handle, as after a failure that never produced one. */
    slot->transport_handle            = NULL;
    pubnub_transport_provider_t* head = pn_context_pipeline_chain_head(ctx);
    head->cancel(head, handle);
    assert_int_equal(1, s_leak_cancel_called);
    s_leak_wake_called = 0;

    pubnub_future_release(fut);

    assert_true(pn_request_is_idle(slot));
    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(0, s_leak_wake_called);

    pubnub_destroy(ctx);
}

static pubnub_future_t   s_hook_fut;
static int               s_cancels_seen_in_hook;
static int               s_polls_seen_in_hook;
static pubnub_res_t      s_tick_rc_in_hook;
static pubnub_context_t* s_hook_ctx;

static void hook_release_future(void)
{
    pubnub_future_release(s_hook_fut);
    s_cancels_seen_in_hook = s_leak_cancel_called;
}

static void hook_tick_from_cancel(void)
{
    s_polls_seen_in_hook = s_leak_poll_called;
    s_tick_rc_in_hook    = pn_process_tick(s_hook_ctx, 0);
    s_polls_seen_in_hook = s_leak_poll_called - s_polls_seen_in_hook;
}

static void release_during_poll_defers_to_same_tick(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(0);
    pn_request_t*     slot = NULL;

    s_hook_fut             = leak_terminal(ctx, &slot);
    s_cancels_seen_in_hook = -1;
    s_leak_poll_hook       = hook_release_future;

    (void)pn_process_tick(ctx, 0);
    s_leak_poll_hook = NULL;

    assert_int_equal(0, s_cancels_seen_in_hook);
    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(0, s_leak_outstanding);
    assert_true(pn_request_is_idle(slot));

    pubnub_destroy(ctx);
}

static void direct_release_claim_blocks_concurrent_tick(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(0);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut  = leak_terminal(ctx, &slot);

    s_hook_ctx           = ctx;
    s_tick_rc_in_hook    = PUBNUB_OK;
    s_polls_seen_in_hook = -1;
    s_leak_cancel_hook   = hook_tick_from_cancel;

    pubnub_future_release(fut);
    s_leak_cancel_hook = NULL;

    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(PUBNUB_IN_PROGRESS, s_tick_rc_in_hook);
    assert_int_equal(0, s_polls_seen_in_hook);
    assert_true(pn_request_is_idle(slot));

    s_leak_poll_called = 0;
    (void)pn_process_tick(ctx, 0);
    assert_int_equal(1, s_leak_poll_called);

    pubnub_destroy(ctx);
}

static void release_twice_in_deferral_window_cancels_once(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(1);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut  = leak_terminal(ctx, &slot);

    pubnub_future_release(fut);
    pubnub_future_release(fut);
    assert_int_equal(0, s_leak_cancel_called);

    (void)pn_process_tick(ctx, 0);
    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(0, s_leak_outstanding);

    pubnub_future_release(fut);
    assert_int_equal(1, s_leak_cancel_called);

    pubnub_destroy(ctx);
}

static void destroy_flushes_deferred_terminal_release(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(1);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut  = leak_terminal(ctx, &slot);

    pubnub_future_release(fut);
    assert_int_equal(0, s_leak_cancel_called);

    pubnub_destroy(ctx);

    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(0, s_leak_outstanding);
}

static void deferred_release_backpressure_promotes_pending(void** state)
{
    (void)state;
    pubnub_context_t*   ctx   = create_leak_ctx(1);
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    const uint16_t      cap   = pn_context_pool_capacity(ctx);
    pubnub_future_t     futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_request_t*       slots[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_pending_entry_t  entry;
    pubnub_future_t     queued;
    uint16_t            i;

    for (i = 0; i < cap; i++) {
        futs[i] = leak_dispatch(ctx, &slots[i]);
    }
    (void)pn_process_tick(ctx, 0);
    assert_int_equal(cap, s_leak_outstanding);

    pubnub_future_release(futs[0]);
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    queued                  = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(queued.slot_id >= cap);
    assert_int_equal(PUBNUB_IN_PROGRESS, queued.status);

    (void)pn_process_tick(ctx, 0);

    assert_int_equal(1, s_leak_cancel_called);
    assert_false(pn_request_is_idle(slots[0]));
    assert_int_equal(0, pn_pending_queue_count(queue));
    (void)pn_process_tick(ctx, 0);
    assert_true(pubnub_future_is_ready(queued));

    {
        uint16_t        n;
        pubnub_future_t last = PUBNUB_FUTURE_INVALID;

        for (n = 0; n <= queue->capacity; n++) {
            memset(&entry, 0, sizeof(entry));
            entry.http_request.host = "ps.pndsn.com";
            last                    = pn_dispatch_or_enqueue(ctx, &entry);
            if (PUBNUB_IN_PROGRESS != last.status) {
                break;
            }
        }
        assert_int_equal(PUBNUB_ERR_QUEUE_FULL, last.status);
    }

    pubnub_destroy(ctx);
}

static pubnub_future_t s_aba_new_fut;
static pn_request_t*   s_aba_new_slot;
static int             s_aba_fired;

/* Runs inside the tick's deferred cancel: the flag is already consumed and
 * the handle detached, so a second release of the same future sees a
 * terminal slot without a handle. */
static void hook_second_release_then_reacquire(void)
{
    if (s_aba_fired) {
        return;
    }
    s_aba_fired = 1;
    pubnub_future_release(s_hook_fut);
    s_aba_new_fut = leak_dispatch(s_hook_ctx, &s_aba_new_slot);
}

static void deferred_release_second_release_does_not_free_new_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(1);
    pn_request_t*     slot = NULL;

    s_hook_ctx     = ctx;
    s_hook_fut     = leak_terminal(ctx, &slot);
    s_aba_fired    = 0;
    s_aba_new_slot = NULL;

    pubnub_future_release(s_hook_fut);
    s_leak_cancel_hook = hook_second_release_then_reacquire;
    (void)pn_process_tick(ctx, 0);
    s_leak_cancel_hook = NULL;

    assert_int_equal(1, s_aba_fired);
    assert_non_null(s_aba_new_slot);
    /* The second release must not reclaim the slot mid-flush, so the new
     * request lands elsewhere and survives the tick's reclaim of the old
     * one. */
    assert_ptr_not_equal(slot, s_aba_new_slot);
    assert_true(pn_request_is_idle(slot));
    assert_false(pn_request_is_idle(s_aba_new_slot));
    assert_int_equal(s_aba_new_fut.generation, s_aba_new_slot->generation);
    assert_non_null(s_aba_new_slot->transport_handle);

    (void)pn_process_tick(ctx, 0);
    pubnub_future_release(s_aba_new_fut);
    (void)pn_process_tick(ctx, 0);
    assert_int_equal(0, s_leak_outstanding);

    pubnub_destroy(ctx);
}

static void release_other_cb(pubnub_future_t future, pubnub_res_t status, void* ud)
{
    (void)future;
    (void)status;
    (void)ud;
    pubnub_future_release(s_hook_fut);
    s_cancels_seen_in_hook = s_leak_cancel_called;
}

static void release_other_future_from_callback_bg_mode(void** state)
{
    (void)state;
    pubnub_context_t* ctx    = create_leak_ctx(1);
    pn_request_t*     slot_a = NULL;
    pn_request_t*     slot_b = NULL;
    pubnub_future_t   fut_b;

    s_hook_fut = leak_terminal(ctx, &slot_a);

    s_leak_complete_on_poll = 1;
    fut_b                   = leak_dispatch(ctx, &slot_b);
    assert_int_equal(PUBNUB_OK, pubnub_async(fut_b, release_other_cb, NULL));
    s_cancels_seen_in_hook = -1;

    slot_b->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot_b->http_response.status_code = 200;
    slot_b->http_response.body        = s_leak_last_rx;
    slot_b->http_response.body_len    = sizeof(LEAK_BODY) - 1;

    (void)pn_process_tick(ctx, 0);

    assert_int_equal(0, s_cancels_seen_in_hook);
    assert_int_equal(1, s_leak_cancel_called);
    assert_true(pn_request_is_idle(slot_a));

    pubnub_future_release(fut_b);
    pubnub_destroy(ctx);
}

static void future_cancel_then_release_bg_mode_single_cancel(void** state)
{
    (void)state;
    pubnub_context_t* ctx  = create_leak_ctx(1);
    pn_request_t*     slot = NULL;
    pubnub_future_t   fut;

    s_leak_complete_on_poll = 1;
    fut                     = leak_dispatch(ctx, &slot);
    assert_int_equal(PUBNUB_OK, pubnub_future_cancel(fut));
    pubnub_future_release(fut);
    assert_int_equal(0, s_leak_cancel_called);

    (void)pn_process_tick(ctx, 0);
    (void)pn_process_tick(ctx, 0);

    assert_int_equal(1, s_leak_cancel_called);
    assert_int_equal(0, s_leak_outstanding);
    assert_true(pn_request_is_idle(slot));

    pubnub_destroy(ctx);
}

static void (*s_lock_hook)(void);

static size_t hook_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return 16;
}

static int hook_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
    return 0;
}

static void hook_lock_destroy(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
}

static void hook_lock_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    void (*hook)(void) = s_lock_hook;

    (void)self;
    (void)lock;
    if (NULL != hook) {
        s_lock_hook = NULL;
        hook();
    }
}

static void hook_lock_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
}

static void hook_promote_tick(void)
{
    (void)pn_process_tick(s_hook_ctx, 0);
}

/* Cooperative context whose lock acquire runs a one-shot hook, with the pool
 * full of in-flight requests, one slot freed but not yet promoted into, and
 * two queued futures P and Q. */
static pubnub_context_t* promotion_race_setup(pubnub_future_t* futs,
                                              pubnub_future_t* out_p,
                                              pubnub_future_t* out_q)
{
    pubnub_config_t    cfg;
    pubnub_context_t*  ctx;
    pn_request_t*      slots[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pn_pending_entry_t entry;
    const uint16_t     cap = (uint16_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS;
    uint16_t           i;

    leak_reset_counters();
    s_bg_platform              = s_mock_platform;
    s_bg_platform.lock_size    = hook_lock_size;
    s_bg_platform.lock_init    = hook_lock_init;
    s_bg_platform.lock_destroy = hook_lock_destroy;
    s_bg_platform.lock_acquire = hook_lock_acquire;
    s_bg_platform.lock_release = hook_lock_release;
    cfg                        = test_config();
    cfg.transport              = &s_leak_transport;
    cfg.platform               = &s_bg_platform;
    ctx                        = pubnub_create(&cfg);
    assert_non_null(ctx);
    s_hook_ctx = ctx;

    s_leak_complete_on_poll = 1;
    for (i = 0; i < cap; i++) {
        futs[i] = leak_dispatch(ctx, &slots[i]);
    }
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    *out_p                  = pn_dispatch_or_enqueue(ctx, &entry);
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    *out_q                  = pn_dispatch_or_enqueue(ctx, &entry);
    assert_true(out_p->slot_id >= cap);
    assert_true(out_q->slot_id >= cap);

    slots[0]->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slots[0]->http_response.status_code = 200;
    slots[0]->http_response.body        = s_leak_last_rx;
    slots[0]->http_response.body_len    = sizeof(LEAK_BODY) - 1;
    (void)pn_process_tick(ctx, 0);
    assert_true(pn_request_is_terminal(slots[0]));
    pubnub_future_release(futs[0]);
    assert_true(pn_request_is_idle(slots[0]));
    assert_int_equal(2, pn_pending_queue_count(pn_context_pending_queue(ctx)));
    return ctx;
}

static void release_pending_after_promotion_race(void** state)
{
    (void)state;
    pubnub_future_t    futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_future_t    p;
    pubnub_future_t    q;
    pubnub_context_t*  ctx   = promotion_race_setup(futs, &p, &q);
    pn_request_pool_t* pool  = pn_context_request_pool(ctx);
    pn_request_t*      slot0 = pn_request_pool_get(pool, 0);

    s_lock_hook = hook_promote_tick;
    pubnub_future_release(p);
    assert_null(s_lock_hook);

    assert_false(pn_request_is_idle(slot0));
    assert_int_equal(1, slot0->release_deferred);
    assert_int_equal(1, pn_pending_queue_count(pn_context_pending_queue(ctx)));
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(q));

    pubnub_destroy(ctx);
    assert_int_equal(0, s_leak_outstanding);
}

static void cancel_pending_after_promotion_race(void** state)
{
    (void)state;
    pubnub_future_t    futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_future_t    p;
    pubnub_future_t    q;
    pubnub_context_t*  ctx   = promotion_race_setup(futs, &p, &q);
    pn_request_pool_t* pool  = pn_context_request_pool(ctx);
    pn_request_t*      slot0 = pn_request_pool_get(pool, 0);

    s_lock_hook = hook_promote_tick;
    assert_int_equal(PUBNUB_OK, pubnub_future_cancel(p));
    assert_null(s_lock_hook);

    assert_int_equal(1, slot0->cancel_requested);
    assert_int_equal(1, pn_pending_queue_count(pn_context_pending_queue(ctx)));
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(q));

    pubnub_destroy(ctx);
    assert_int_equal(0, s_leak_outstanding);
}

#endif /* PUBNUB_CFG_THREAD_SAFETY && !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test_setup(await_on_immediate_completion_returns_ok, setup_test),
        cmocka_unit_test_setup(await_cooperative_polls_until_complete, setup_test),
#endif
        cmocka_unit_test_setup(await_on_immediate_error_returns_error, setup_test),
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test_setup(async_callback_fires_after_process, setup_test),
        cmocka_unit_test_setup(async_on_already_complete_fires_immediately,
                               setup_test),
        cmocka_unit_test_setup(pending_queue_promotes_on_slot_release, setup_test),
#endif
        cmocka_unit_test_setup(pending_queue_full_returns_queue_full, setup_test),
        cmocka_unit_test_setup(release_on_pending_queue_entry_cancels, setup_test),
        cmocka_unit_test_setup(cancel_at_null_out_data_fires_cleanup_inline,
                               setup_test),
        cmocka_unit_test_setup(cancel_pending_fires_async_cb_with_cancelled,
                               setup_test),
        cmocka_unit_test_setup(deinit_drain_fires_all_pending_callbacks, setup_test),
        cmocka_unit_test_setup(deinit_drain_skips_precancelled_entries, setup_test),
        cmocka_unit_test_setup(async_null_callback_returns_error, setup_test),
        cmocka_unit_test_setup(cleanup_fires_outside_lock_via_cancel_data, setup_test),
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test_setup(
            future_cancel_pending_fires_async_cb_with_cancelled, setup_test),
        cmocka_unit_test_setup(future_cancel_in_flight_triggers_transport_cancel,
                               setup_test),
        cmocka_unit_test_setup(future_cancel_terminal_returns_in_progress, setup_test),
        cmocka_unit_test_setup(future_cancel_pending_queue_fires_callback, setup_test),
        cmocka_unit_test_setup(
            future_cancel_already_cancelled_pending_returns_invalid, setup_test),
        cmocka_unit_test_setup(future_release_in_flight_defers_to_completion,
                               setup_test),
        cmocka_unit_test_setup(future_release_on_success_cancels_transport_handle,
                               setup_test),
        cmocka_unit_test_setup(deferred_release_in_flight_success_cancels_handle,
                               setup_test),
        cmocka_unit_test_setup(deferred_release_from_callback_cancels_handle,
                               setup_test),
        cmocka_unit_test_setup(deinit_sweeps_unreleased_success_handle, setup_test),
        cmocka_unit_test_setup(release_twice_on_same_future_is_noop, setup_test),
        cmocka_unit_test_setup(future_status_after_release_is_invalid_argument,
                               setup_test),
        cmocka_unit_test_setup(future_is_ready_after_release_returns_true, setup_test),
        cmocka_unit_test_setup(
            response_accessor_returns_zero_after_future_release, setup_test),
        cmocka_unit_test_setup(
            pending_range_future_accessor_works_after_slot_recycle, setup_test),
        cmocka_unit_test_setup(cancel_during_pending_releases_prep_state, setup_test),
        cmocka_unit_test_setup(pending_promote_preserves_async_cb_and_user_data,
                               setup_test),
        cmocka_unit_test_setup(release_pending_future_cleans_feature_state,
                               setup_test),
        cmocka_unit_test_setup(async_on_cancelled_pending_fires_cancelled, setup_test),
#endif
#if PUBNUB_CFG_THREAD_SAFETY && !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test_setup(release_terminal_bg_mode_defers_cancel_to_tick,
                               setup_test),
        cmocka_unit_test_setup(release_terminal_bg_mode_wakes_transport, setup_test),
#if PUBNUB_ENABLE_RETRY
        cmocka_unit_test_setup(release_retry_chain_direct_forwards_inner_handle,
                               setup_test),
        cmocka_unit_test_setup(release_retry_chain_deferred_forwards_inner_handle,
                               setup_test),
#endif
        cmocka_unit_test_setup(
            release_terminal_bg_mode_null_handle_releases_immediately, setup_test),
        cmocka_unit_test_setup(release_during_poll_defers_to_same_tick, setup_test),
        cmocka_unit_test_setup(direct_release_claim_blocks_concurrent_tick,
                               setup_test),
        cmocka_unit_test_setup(release_twice_in_deferral_window_cancels_once,
                               setup_test),
        cmocka_unit_test_setup(destroy_flushes_deferred_terminal_release, setup_test),
        cmocka_unit_test_setup(deferred_release_backpressure_promotes_pending,
                               setup_test),
        cmocka_unit_test_setup(release_other_future_from_callback_bg_mode, setup_test),
        cmocka_unit_test_setup(
            deferred_release_second_release_does_not_free_new_request, setup_test),
        cmocka_unit_test_setup(future_cancel_then_release_bg_mode_single_cancel,
                               setup_test),
        cmocka_unit_test_setup(release_pending_after_promotion_race, setup_test),
        cmocka_unit_test_setup(cancel_pending_after_promotion_race, setup_test),
#endif
        cmocka_unit_test_setup(
            async_on_invalid_future_returns_error_not_fires_callback, setup_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "core/core_internal.h"
#include "core/runtime/pending_queue_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define PN_TEST_MAX_HANDLES 8192
#define PN_TEST_MAX_FUTURES 8192
#define PN_TEST_FUZZ_SEEDS  300

#define PN_TEST_NO_FUTURE (-1)

static pubnub_http_response_t* s_resp[PN_TEST_MAX_HANDLES];
static uint8_t                 s_want[PN_TEST_MAX_HANDLES];
static uint8_t                 s_done[PN_TEST_MAX_HANDLES];
static uint8_t                 s_live[PN_TEST_MAX_HANDLES];
static int                     s_next_handle = 1;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    int handle = s_next_handle;

    (void)self;
    (void)request;
    if (handle >= PN_TEST_MAX_HANDLES) {
        return NULL;
    }
    s_next_handle++;
    s_resp[handle] = response;
    s_live[handle] = 1;
    return (pubnub_transport_handle_t*)(intptr_t)handle;
}

static int mock_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    int h;

    (void)self;
    (void)timeout_ms;
    for (h = 1; h < s_next_handle; h++) {
        if (s_live[h] && s_want[h] && !s_done[h]) {
            pubnub_http_response_t* r = s_resp[h];

            r->completion  = PUBNUB_HTTP_COMPLETE;
            r->status_code = 200;
            r->body        = (const uint8_t*)"[1,\"Sent\",\"123\"]";
            r->body_len    = 16;
            s_done[h]      = 1;
        }
    }
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    s_live[(int)(intptr_t)handle] = 0;
}

static pubnub_transport_provider_t s_transport = {
    .send   = mock_send,
    .poll   = mock_poll,
    .cancel = mock_cancel,
};

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t mock_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    pubnub_buffer_t buf = {0};

    (void)self;
    buf.data    = (uint8_t*)malloc(4096);
    buf.cap     = (NULL != buf.data) ? 4096 : 0;
    buf.purpose = purpose;
    return buf;
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    if (NULL != buf && NULL != buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->cap  = 0;
    }
}

static pubnub_allocator_provider_t s_allocator = {
    .alloc       = mock_alloc,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
};

static int s_tree_backing;

static pubnub_json_value_t* mock_parse(pubnub_serialization_provider_t* self,
                                       const uint8_t*                   data,
                                       size_t                           len)
{
    (void)self;
    (void)data;
    (void)len;
    return (pubnub_json_value_t*)&s_tree_backing;
}

static pubnub_res_t mock_serialize(pubnub_serialization_provider_t* self,
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

static void mock_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    (void)self;
    (void)value;
}

static pubnub_serialization_provider_t s_serialization = {
    .parse         = mock_parse,
    .serialize     = mock_serialize,
    .value_destroy = mock_value_destroy,
};

static uint64_t s_time_ms;

static pubnub_milliseconds_t mock_monotonic(pubnub_platform_provider_t* self)
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
    .wall_clock_ms = mock_monotonic,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
};

typedef enum {
    PN_TEST_MODE_POLL            = 0,
    PN_TEST_MODE_ASYNC           = 1,
    PN_TEST_MODE_FIRE_AND_FORGET = 2,
} pn_test_mode_t;

typedef struct {
    pubnub_future_t future;
    int             mode;
    int             callbacks;
    int             released;
    int             cancelled;
    pubnub_res_t    final_status;
} pn_test_future_t;

static pn_test_future_t  s_futures[PN_TEST_MAX_FUTURES];
static int               s_future_count;
static pubnub_context_t* s_ctx;

static void test_async_cb(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    pn_test_future_t* f = &s_futures[(int)(intptr_t)user_data];

    f->callbacks++;
    f->final_status = status;
    pubnub_future_release(future);
    f->released = 1;
}

static void fresh_context(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    if (NULL != s_ctx) {
        pubnub_destroy(s_ctx);
        s_ctx = NULL;
    }
    memset(s_want, 0, sizeof(s_want));
    memset(s_done, 0, sizeof(s_done));
    memset(s_live, 0, sizeof(s_live));
    memset(s_futures, 0, sizeof(s_futures));
    s_next_handle  = 1;
    s_future_count = 0;
    s_time_ms      = 1000;

    cfg.subscribe_key = "sub-test";
    cfg.publish_key   = "pub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_allocator;
    cfg.transport     = &s_transport;
    cfg.serialization = &s_serialization;
    cfg.platform      = &s_platform;
    s_ctx             = pubnub_create(&cfg);
    assert_non_null(s_ctx);
}

static int teardown_context(void** state)
{
    (void)state;
    if (NULL != s_ctx) {
        pubnub_destroy(s_ctx);
        s_ctx = NULL;
    }
    return 0;
}

/** Issues a publish; returns the test-future index or PN_TEST_NO_FUTURE. */
static int issue(int mode)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_future_t       fut;
    pn_test_future_t*     f;

    opts.channel     = "ch";
    opts.message     = "\"x\"";
    opts.message_len = 3;
    fut              = pubnub_publish(s_ctx, &opts);
    if (PUBNUB_IN_PROGRESS != fut.status) {
        return PN_TEST_NO_FUTURE;
    }

    f = &s_futures[s_future_count];
    memset(f, 0, sizeof(*f));
    f->future = fut;
    f->mode   = mode;
    if (PN_TEST_MODE_ASYNC == mode) {
        assert_int_equal(
            PUBNUB_OK,
            pubnub_async(fut, test_async_cb, (void*)(intptr_t)s_future_count));
    } else if (PN_TEST_MODE_FIRE_AND_FORGET == mode) {
        pubnub_future_release(fut);
        f->released = 1;
    }
    return s_future_count++;
}

/** Marks every live transport handle as ready to complete. */
static void want_all(void)
{
    int h;

    for (h = 1; h < s_next_handle; h++) {
        if (s_live[h]) {
            s_want[h] = 1;
        }
    }
}

/** Reaps polled futures that reached a terminal status. */
static void reap_polled(void)
{
    int i;

    for (i = 0; i < s_future_count; i++) {
        pn_test_future_t* f = &s_futures[i];

        if (PN_TEST_MODE_POLL == f->mode && !f->released
            && pubnub_future_is_ready(f->future)) {
            f->final_status = pubnub_future_status(f->future);
            f->callbacks    = 1;
            pubnub_future_release(f->future);
            f->released = 1;
        }
    }
}

static void tick(void)
{
    (void)pubnub_process(s_ctx);
    reap_polled();
}

static unsigned in_use(void)
{
    return pn_context_request_pool(s_ctx)->in_use_count;
}

static uint16_t queued(void)
{
    return pn_pending_queue_count(pn_context_pending_queue(s_ctx));
}

/** Completes everything still live and drains; returns the failure count. */
static int drain_and_check(const char* name, int verbose)
{
    int bad = 0;
    int i;
    int r;

    for (r = 0; r < 40; r++) {
        want_all();
        tick();
    }
    for (i = 0; i < s_future_count; i++) {
        pn_test_future_t* f = &s_futures[i];

        if (PN_TEST_MODE_FIRE_AND_FORGET == f->mode || f->cancelled) {
            continue;
        }
        if (0 == f->callbacks) {
            bad++;
            if (verbose) {
                printf("  [%s] stuck future #%d mode=%d slot_id=%u status=%d\n",
                       name,
                       i,
                       f->mode,
                       (unsigned)f->future.slot_id,
                       (int)pubnub_future_status(f->future));
            }
        } else if (1 != f->callbacks || PUBNUB_OK != f->final_status) {
            bad++;
            if (verbose) {
                printf("  [%s] future #%d callbacks=%d final=%d\n",
                       name,
                       i,
                       f->callbacks,
                       (int)f->final_status);
            }
        }
    }
    for (i = 0; i < s_future_count; i++) {
        if (s_futures[i].callbacks > 1) {
            bad++;
        }
    }
    if (0 != in_use() || 0 != queued()) {
        bad++;
        if (verbose) {
            printf("  [%s] leak in_use=%u pending=%u\n",
                   name,
                   in_use(),
                   (unsigned)queued());
        }
    }
    return bad;
}

/** Fills the whole pool with polled futures that stay in flight. */
static void hold_pool(int* holders)
{
    int i;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        holders[i] = issue(PN_TEST_MODE_POLL);
        assert_int_not_equal(PN_TEST_NO_FUTURE, holders[i]);
    }
    assert_int_equal(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS, (int)in_use());
    assert_int_equal(0, (int)queued());
}

/** Records the final status of a polled future, then releases it. */
static void release_polled(int index)
{
    pn_test_future_t* f = &s_futures[index];

    f->final_status = pubnub_future_status(f->future);
    f->callbacks    = 1;
    pubnub_future_release(f->future);
    f->released = 1;
}

/** Completes and releases one holder so a pool slot frees up. */
static void free_one_holder(int holder_handle, int holder_future)
{
    s_want[holder_handle] = 1;
    tick();
    if (!s_futures[holder_future].released) {
        release_polled(holder_future);
    }
    tick();
}

static void init_queue(pn_pending_queue_t* queue, uint16_t capacity)
{
    memset(queue, 0, sizeof(*queue));
    assert_int_equal(PUBNUB_OK,
                     pn_pending_queue_init(queue, capacity, &s_allocator));
}

static void push(pn_pending_queue_t* queue, uint16_t tag)
{
    pn_pending_entry_t entry;

    memset(&entry, 0, sizeof(entry));
    entry.map_index = tag;
    assert_int_equal(PUBNUB_OK, pn_pending_queue_enqueue(queue, &entry));
}

static uint16_t pop_tag(pn_pending_queue_t* queue)
{
    pn_pending_entry_t out;

    assert_int_equal(PUBNUB_OK, pn_pending_queue_dequeue(queue, &out));
    return out.map_index;
}

static void queue_cancel_head_advances_head_and_count(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 4);
    push(&queue, 10);
    push(&queue, 11);
    push(&queue, 12);

    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 0, NULL));
    assert_int_equal(2, pn_pending_queue_count(&queue));
    assert_int_equal(1, queue.head);
    assert_int_equal(3, queue.tail);
    assert_int_equal(0, queue.entries[0].occupied);

    assert_int_equal(11, pop_tag(&queue));
    assert_int_equal(12, pop_tag(&queue));
    assert_int_equal(0, pn_pending_queue_count(&queue));
    pn_pending_queue_deinit(&queue);
}

static void queue_cancel_tail_rewinds_tail_and_count(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 4);
    push(&queue, 10);
    push(&queue, 11);
    push(&queue, 12);

    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 2, NULL));
    assert_int_equal(2, pn_pending_queue_count(&queue));
    assert_int_equal(0, queue.head);
    assert_int_equal(2, queue.tail);

    /* The next enqueue reuses the vacated tail position and must not
     * overwrite the live head entry. */
    push(&queue, 13);
    assert_int_equal(3, pn_pending_queue_count(&queue));
    assert_int_equal(10, pop_tag(&queue));
    assert_int_equal(11, pop_tag(&queue));
    assert_int_equal(13, pop_tag(&queue));
    pn_pending_queue_deinit(&queue);
}

static void queue_cancel_mid_keeps_ring_span(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 4);
    push(&queue, 10);
    push(&queue, 11);
    push(&queue, 12);

    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 1, NULL));
    assert_int_equal(3, pn_pending_queue_count(&queue));
    assert_int_equal(0, queue.head);
    assert_int_equal(3, queue.tail);
    assert_int_equal(0, queue.entries[1].occupied);

    /* A hole cannot be cancelled twice; the live entry behind it can. */
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_pending_queue_cancel_at(&queue, 1, NULL));
    assert_int_equal(3, pn_pending_queue_count(&queue));

    assert_int_equal(10, pop_tag(&queue));
    assert_int_equal(12, pop_tag(&queue));
    assert_int_equal(0, pn_pending_queue_count(&queue));
    assert_int_equal(queue.head, queue.tail);
    pn_pending_queue_deinit(&queue);
}

static void queue_cancel_mid_then_ends_trims_holes(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 4);
    push(&queue, 10);
    push(&queue, 11);
    push(&queue, 12);

    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 1, NULL));
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 2, NULL));
    assert_int_equal(1, pn_pending_queue_count(&queue));
    assert_int_equal(0, queue.head);
    assert_int_equal(1, queue.tail);
    assert_int_equal(10, pop_tag(&queue));

    push(&queue, 20);
    push(&queue, 21);
    push(&queue, 22);
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 1, NULL));
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 0, NULL));
    assert_int_equal(1, pn_pending_queue_count(&queue));
    assert_true(queue.entries[queue.head].occupied);
    assert_int_equal(22, pop_tag(&queue));
    pn_pending_queue_deinit(&queue);
}

static void queue_cancel_on_wrapped_ring(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 4);
    push(&queue, 1);
    push(&queue, 2);
    push(&queue, 3);
    push(&queue, 4);
    assert_int_equal(1, pop_tag(&queue));
    assert_int_equal(2, pop_tag(&queue));
    push(&queue, 5);
    push(&queue, 6);
    /* Ring holds 3,4,5,6 with head=2 and tail wrapped to 2. */
    assert_int_equal(4, pn_pending_queue_count(&queue));
    assert_int_equal(2, queue.head);
    assert_int_equal(2, queue.tail);

    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 2, NULL));
    assert_int_equal(4, pn_pending_queue_count(&queue));
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 3, NULL));
    assert_int_equal(2, pn_pending_queue_count(&queue));
    assert_int_equal(0, queue.tail);
    assert_int_equal(3, pop_tag(&queue));
    assert_int_equal(4, pop_tag(&queue));
    assert_int_equal(0, pn_pending_queue_count(&queue));
    pn_pending_queue_deinit(&queue);
}

static void queue_cancel_last_entry_resets_span(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 2);
    push(&queue, 1);
    push(&queue, 2);
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 1, NULL));
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 0, NULL));
    assert_int_equal(0, pn_pending_queue_count(&queue));
    assert_int_equal(queue.head, queue.tail);
    assert_int_equal(0, pn_pending_queue_is_full(&queue));
    push(&queue, 3);
    push(&queue, 4);
    assert_int_equal(3, pop_tag(&queue));
    assert_int_equal(4, pop_tag(&queue));
    pn_pending_queue_deinit(&queue);
}

static void queue_mid_hole_reports_full_early(void** state)
{
    pn_pending_queue_t queue;
    pn_pending_entry_t entry;

    (void)state;
    memset(&entry, 0, sizeof(entry));
    init_queue(&queue, 3);
    push(&queue, 1);
    push(&queue, 2);
    push(&queue, 3);
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 1, NULL));

    /* The hole stays inside the ring span until head or tail passes it, so
     * the queue still reports full rather than overwriting a live entry. */
    assert_int_equal(3, pn_pending_queue_count(&queue));
    assert_int_not_equal(0, pn_pending_queue_is_full(&queue));
    assert_int_equal(PUBNUB_ERR_QUEUE_FULL,
                     pn_pending_queue_enqueue(&queue, &entry));
    assert_int_equal(1, pop_tag(&queue));
    assert_int_equal(3, pop_tag(&queue));
    pn_pending_queue_deinit(&queue);
}

static void pending_cancel_head_does_not_strand_next(void** state)
{
    int holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    int a;
    int b;

    (void)state;
    fresh_context();
    hold_pool(holders);
    a = issue(PN_TEST_MODE_ASYNC);
    b = issue(PN_TEST_MODE_ASYNC);
    assert_int_not_equal(PN_TEST_NO_FUTURE, a);
    assert_int_not_equal(PN_TEST_NO_FUTURE, b);
    assert_int_equal(2, (int)queued());

    pubnub_future_release(s_futures[a].future);
    s_futures[a].released = 1;
    assert_int_equal(1, (int)queued());

    free_one_holder(1, holders[0]);
    tick();
    assert_int_equal(0, (int)queued());

    want_all();
    tick();
    tick();
    assert_int_equal(1, s_futures[b].callbacks);
    assert_int_equal(PUBNUB_OK, s_futures[b].final_status);
    assert_int_equal(1, s_futures[a].callbacks);
    assert_int_equal(PUBNUB_ERR_CANCELLED, s_futures[a].final_status);

    s_futures[a].cancelled = 1;
    assert_int_equal(0, drain_and_check("cancel-head", 1));
}

static void pending_cancel_tail_then_enqueue_keeps_head(void** state)
{
    int holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    int a;
    int b;
    int c;

    (void)state;
    fresh_context();
    hold_pool(holders);
    a = issue(PN_TEST_MODE_ASYNC);
    b = issue(PN_TEST_MODE_ASYNC);
    assert_int_equal(2, (int)queued());

    pubnub_future_release(s_futures[b].future);
    s_futures[b].released = 1;
    c                     = issue(PN_TEST_MODE_ASYNC);
    assert_int_not_equal(PN_TEST_NO_FUTURE, c);
    assert_int_equal(2, (int)queued());

    free_one_holder(1, holders[0]);
    free_one_holder(2, holders[1]);
    want_all();
    tick();
    tick();

    assert_int_equal(1, s_futures[a].callbacks);
    assert_int_equal(PUBNUB_OK, s_futures[a].final_status);
    assert_int_equal(1, s_futures[c].callbacks);
    assert_int_equal(PUBNUB_OK, s_futures[c].final_status);
    s_futures[b].cancelled = 1;
    assert_int_equal(0, drain_and_check("cancel-tail", 1));
}

static void pending_release_mid_entry_then_wrap_keeps_neighbours(void** state)
{
    int holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    int pend[3];
    int i;

    (void)state;
    if (PUBNUB_CFG_MAX_PENDING_REQUESTS < 4) {
        skip();
    }
    fresh_context();
    hold_pool(holders);
    for (i = 0; i < 3; i++) {
        pend[i] = issue(PN_TEST_MODE_ASYNC);
        assert_int_not_equal(PN_TEST_NO_FUTURE, pend[i]);
    }
    pubnub_future_release(s_futures[pend[1]].future);
    s_futures[pend[1]].released  = 1;
    s_futures[pend[1]].cancelled = 1;

    assert_int_not_equal(PN_TEST_NO_FUTURE, issue(PN_TEST_MODE_ASYNC));
    assert_int_equal(0, drain_and_check("mid-hole", 1));
    assert_int_equal(1, s_futures[pend[0]].callbacks);
    assert_int_equal(1, s_futures[pend[2]].callbacks);
}

static void pending_future_id_not_reused_while_live(void** state)
{
    int      holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    int      fillers[PUBNUB_CFG_MAX_PENDING_REQUESTS];
    int      a;
    int      a_handle;
    int      i;
    uint16_t pending_before;

    (void)state;
    fresh_context();
    hold_pool(holders);
    a = issue(PN_TEST_MODE_POLL);
    assert_int_not_equal(PN_TEST_NO_FUTURE, a);

    free_one_holder(1, holders[0]);
    assert_int_equal(0, (int)queued());
    assert_int_equal(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS, (int)in_use());
    a_handle = s_next_handle - 1;
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(s_futures[a].future));

    for (i = 0; i < PUBNUB_CFG_MAX_PENDING_REQUESTS; i++) {
        fillers[i] = issue(PN_TEST_MODE_POLL);
        assert_int_not_equal(PN_TEST_NO_FUTURE, fillers[i]);
    }

    s_want[a_handle] = 1;
    (void)pubnub_process(s_ctx);
    assert_true(pubnub_future_is_ready(s_futures[a].future));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(s_futures[a].future));

    /* Releasing A must not touch any queued request. */
    pending_before = queued();
    release_polled(a);
    assert_int_equal((int)pending_before, (int)queued());

    assert_int_equal(0, drain_and_check("not-reused", 1));
    for (i = 0; i < PUBNUB_CFG_MAX_PENDING_REQUESTS; i++) {
        assert_int_equal(PUBNUB_OK, s_futures[fillers[i]].final_status);
    }
}

static void pending_future_await_after_wrap_returns_ok(void** state)
{
    int holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    int a;
    int i;

    (void)state;
    fresh_context();
    hold_pool(holders);
    a = issue(PN_TEST_MODE_POLL);
    free_one_holder(1, holders[0]);
    for (i = 0; i < PUBNUB_CFG_MAX_PENDING_REQUESTS; i++) {
        assert_int_not_equal(PN_TEST_NO_FUTURE, issue(PN_TEST_MODE_POLL));
    }
    want_all();
    for (i = 0; i < 4 && !pubnub_future_is_ready(s_futures[a].future); i++) {
        (void)pubnub_process(s_ctx);
    }
    assert_true(pubnub_future_is_ready(s_futures[a].future));
    assert_int_equal(PUBNUB_OK, pubnub_await(s_futures[a].future));
    release_polled(a);
    assert_int_equal(0, drain_and_check("await-wrap", 1));
}

static void stale_pending_id_does_not_alias_new_request(void** state)
{
    int             holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    int             fillers[PUBNUB_CFG_MAX_PENDING_REQUESTS];
    int             a;
    int             x;
    int             i;
    pubnub_future_t stale;

    (void)state;
    fresh_context();
    hold_pool(holders);
    a = issue(PN_TEST_MODE_POLL);
    free_one_holder(1, holders[0]);
    want_all();
    (void)pubnub_process(s_ctx);
    assert_int_equal(PUBNUB_OK, pubnub_future_status(s_futures[a].future));

    stale = s_futures[a].future;
    release_polled(a);

    /* Refill the pool, then queue enough requests to cycle the identity
     * space past the stale handle. */
    x = issue(PN_TEST_MODE_POLL);
    assert_int_not_equal(PN_TEST_NO_FUTURE, x);
    for (i = 0; i < PUBNUB_CFG_MAX_PENDING_REQUESTS; i++) {
        fillers[i] = issue(PN_TEST_MODE_POLL);
        assert_int_not_equal(PN_TEST_NO_FUTURE, fillers[i]);
    }

    /* The stale handle reports an invalid/terminal state and never another
     * request's state; operating on it must not disturb queued requests. */
    assert_true(pubnub_future_is_ready(stale));
    assert_int_not_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(stale));
    assert_int_not_equal(PUBNUB_OK, pubnub_future_cancel(stale));
    pubnub_future_release(stale);
    assert_int_equal(PUBNUB_CFG_MAX_PENDING_REQUESTS, (int)queued());

    assert_int_equal(0, drain_and_check("stale", 1));
    for (i = 0; i < PUBNUB_CFG_MAX_PENDING_REQUESTS; i++) {
        assert_int_equal(PUBNUB_OK, s_futures[fillers[i]].final_status);
    }
}

/** Mixes of future modes used by the fuzzers. */
static const int s_mode_sets[2][3] = {
    {PN_TEST_MODE_ASYNC, PN_TEST_MODE_ASYNC, PN_TEST_MODE_FIRE_AND_FORGET},
    {PN_TEST_MODE_POLL,  PN_TEST_MODE_POLL,  PN_TEST_MODE_POLL           },
};

/** Returns the transport handle of the oldest live, not-yet-wanted request. */
static int oldest_unwanted_handle(void)
{
    int h;

    for (h = 1; h < s_next_handle; h++) {
        if (s_live[h] && !s_want[h]) {
            return h;
        }
    }
    return 0;
}

static int run_fuzz(int mode_set, int seed, int steps, int allow_cancel, int teardown)
{
    int step;
    int i;
    int bad = 0;

    srand((unsigned)seed * 7U + (unsigned)mode_set);
    fresh_context();
    for (step = 0; step < steps; step++) {
        int op = rand() % 7;

        if (op <= 2) {
            (void)issue(s_mode_sets[mode_set][rand() % 3]);
        } else if (3 == op) {
            int live[PN_TEST_MAX_HANDLES];
            int n = 0;
            int h;

            for (h = 1; h < s_next_handle; h++) {
                if (s_live[h] && !s_want[h]) {
                    live[n++] = h;
                }
            }
            if (n > 0) {
                s_want[live[rand() % n]] = 1;
            }
        } else if (4 == op) {
            tick();
        } else if (5 == op) {
            if (allow_cancel && s_future_count > 0) {
                pn_test_future_t* f = &s_futures[rand() % s_future_count];

                if (!f->released && 0 == f->callbacks
                    && PN_TEST_MODE_FIRE_AND_FORGET != f->mode
                    && PUBNUB_OK == pubnub_future_cancel(f->future)) {
                    f->cancelled = 1;
                }
            }
        } else {
            int h = oldest_unwanted_handle();

            if (0 != h) {
                s_want[h] = 1;
            }
        }
    }
    if (!teardown) {
        return drain_and_check("fuzz", 0);
    }

    /* Teardown with whatever is queued or in flight: every asynchronous
     * callback fires exactly once, and (under ASan) nothing leaks. */
    pubnub_destroy(s_ctx);
    s_ctx = NULL;
    for (i = 0; i < s_future_count; i++) {
        const pn_test_future_t* f = &s_futures[i];

        if (PN_TEST_MODE_ASYNC == f->mode && 1 != f->callbacks) {
            bad++;
        }
    }
    return bad;
}

static void fuzz_async_mode(void** state)
{
    int fails = 0;
    int seed;
    int steps =
        3 * (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + PUBNUB_CFG_MAX_PENDING_REQUESTS);

    (void)state;
    for (seed = 0; seed < PN_TEST_FUZZ_SEEDS; seed++) {
        if (0 != run_fuzz(0, seed, steps, 1, 0)) {
            if (fails < 3) {
                printf("async fuzz failure seed=%d\n", seed);
            }
            fails++;
        }
    }
    assert_int_equal(0, fails);
}

static void fuzz_async_mode_without_cancels(void** state)
{
    int fails = 0;
    int seed;
    int steps =
        3 * (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + PUBNUB_CFG_MAX_PENDING_REQUESTS);

    (void)state;
    for (seed = 0; seed < PN_TEST_FUZZ_SEEDS; seed++) {
        if (0 != run_fuzz(0, seed, steps, 0, 0)) {
            fails++;
        }
    }
    assert_int_equal(0, fails);
}

static void fuzz_poll_mode(void** state)
{
    int fails = 0;
    int seed;
    int steps =
        3 * (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + PUBNUB_CFG_MAX_PENDING_REQUESTS);

    (void)state;
    for (seed = 0; seed < PN_TEST_FUZZ_SEEDS; seed++) {
        if (0 != run_fuzz(1, seed, steps, 1, 0)) {
            if (fails < 3) {
                printf("poll fuzz failure seed=%d\n", seed);
            }
            fails++;
        }
    }
    assert_int_equal(0, fails);
}

static void fuzz_teardown_with_queued_entries(void** state)
{
    int fails = 0;
    int seed;
    int steps =
        3 * (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + PUBNUB_CFG_MAX_PENDING_REQUESTS);

    (void)state;
    for (seed = 0; seed < PN_TEST_FUZZ_SEEDS; seed++) {
        if (0 != run_fuzz(0, seed, steps, 1, 1)) {
            if (fails < 3) {
                printf("teardown fuzz failure seed=%d\n", seed);
            }
            fails++;
        }
    }
    assert_int_equal(0, fails);
}

static int s_state_cleanups;
static int s_entry_callbacks;

static void count_cleanup(void* fstate, pubnub_allocator_provider_t* alloc)
{
    (void)fstate;
    (void)alloc;
    s_state_cleanups++;
}

static void count_cb(pubnub_future_t f, pubnub_res_t st, void* ud)
{
    (void)f;
    (void)st;
    (void)ud;
    s_entry_callbacks++;
}

static pubnub_future_t enqueue_counted(void)
{
    static int          token;
    pn_pending_entry_t* entry = pn_prep_acquire(s_ctx);
    pubnub_future_t     fut;

    assert_non_null(entry);
    assert_int_equal(PUBNUB_OK,
                     pn_pending_entry_init(entry,
                                           (uint8_t)PUBNUB_FEATURE_PUBLISH,
                                           &token,
                                           count_cleanup,
                                           NULL,
                                           PUBNUB_HTTP_GET,
                                           s_ctx,
                                           0));
    fut = pn_dispatch_or_enqueue(s_ctx, entry);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut.status);
    assert_int_equal(PUBNUB_OK, pubnub_async(fut, count_cb, NULL));
    return fut;
}

/** Builds [A, hole(B), C] with A promoted and the pool full again. */
static void build_hole_fronted_queue(pubnub_future_t* out_b)
{
    int             holders[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_future_t a;
    pubnub_future_t c;

    fresh_context();
    hold_pool(holders);
    a      = enqueue_counted();
    *out_b = enqueue_counted();
    c      = enqueue_counted();
    (void)a;
    (void)c;
    assert_int_equal(PUBNUB_OK, pubnub_future_cancel(*out_b));
    s_want[1] = 1;
    (void)pubnub_process(s_ctx);
    pubnub_future_release(s_futures[holders[0]].future);
    s_futures[holders[0]].released = 1;
    (void)pubnub_process(s_ctx);
}

static void promote_leaves_occupied_head(void** state)
{
    pubnub_future_t           b;
    const pn_pending_queue_t* queue;

    (void)state;
    if (PUBNUB_CFG_MAX_PENDING_REQUESTS < 3) {
        skip();
    }
    build_hole_fronted_queue(&b);
    queue = pn_context_pending_queue(s_ctx);
    assert_int_equal(1, (int)pn_pending_queue_count(queue));
    assert_int_equal(1, queue->entries[queue->head].occupied);
}

static void deinit_with_hole_fronted_queue_cleans_every_entry(void** state)
{
    pubnub_future_t b;

    (void)state;
    if (PUBNUB_CFG_MAX_PENDING_REQUESTS < 3) {
        skip();
    }
    s_state_cleanups  = 0;
    s_entry_callbacks = 0;
    build_hole_fronted_queue(&b);
    pubnub_destroy(s_ctx);
    s_ctx = NULL;
    /* A is in flight (aborted at teardown), B was cancelled, C was queued:
     * each of the three requests is cleaned up and called back once. */
    assert_int_equal(3, s_state_cleanups);
    assert_int_equal(3, s_entry_callbacks);
}

static void queue_dequeue_leaves_occupied_head(void** state)
{
    pn_pending_queue_t queue;

    (void)state;
    init_queue(&queue, 4);
    push(&queue, 1);
    push(&queue, 2);
    push(&queue, 3);
    assert_int_equal(PUBNUB_OK, pn_pending_queue_cancel_at(&queue, 1, NULL));
    assert_int_equal(1, pop_tag(&queue));
    assert_int_equal(1, (int)pn_pending_queue_count(&queue));
    assert_int_equal(1, queue.entries[queue.head].occupied);
    assert_int_equal(3, pop_tag(&queue));
    pn_pending_queue_deinit(&queue);
}

int main(int argc, char** argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(queue_cancel_head_advances_head_and_count),
        cmocka_unit_test(queue_cancel_tail_rewinds_tail_and_count),
        cmocka_unit_test(queue_cancel_mid_keeps_ring_span),
        cmocka_unit_test(queue_cancel_mid_then_ends_trims_holes),
        cmocka_unit_test(queue_cancel_on_wrapped_ring),
        cmocka_unit_test(queue_cancel_last_entry_resets_span),
        cmocka_unit_test(queue_mid_hole_reports_full_early),
        cmocka_unit_test_teardown(pending_cancel_head_does_not_strand_next,
                                  teardown_context),
        cmocka_unit_test_teardown(pending_cancel_tail_then_enqueue_keeps_head,
                                  teardown_context),
        cmocka_unit_test_teardown(pending_release_mid_entry_then_wrap_keeps_neighbours,
                                  teardown_context),
        cmocka_unit_test_teardown(fuzz_async_mode_without_cancels, teardown_context),
        cmocka_unit_test_teardown(fuzz_async_mode, teardown_context),
        cmocka_unit_test_teardown(pending_future_id_not_reused_while_live,
                                  teardown_context),
        cmocka_unit_test_teardown(pending_future_await_after_wrap_returns_ok,
                                  teardown_context),
        cmocka_unit_test_teardown(stale_pending_id_does_not_alias_new_request,
                                  teardown_context),
        cmocka_unit_test_teardown(fuzz_poll_mode, teardown_context),
        cmocka_unit_test(queue_dequeue_leaves_occupied_head),
        cmocka_unit_test_teardown(promote_leaves_occupied_head, teardown_context),
        cmocka_unit_test_teardown(
            deinit_with_hole_fronted_queue_cleans_every_entry, teardown_context),
        cmocka_unit_test_teardown(fuzz_teardown_with_queued_entries, teardown_context),
    };

    if (argc > 1) {
        cmocka_set_test_filter(argv[1]);
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}

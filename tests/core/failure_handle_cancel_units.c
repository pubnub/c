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

#include "pubnub/capabilities.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MOCK_MAX_HANDLES 64

#define BODY_JSON "{\"error\":\"denied\"}"

typedef struct mock_handle {
    int in_use;
    int cancels;
} mock_handle_t;

static mock_handle_t s_handles[MOCK_MAX_HANDLES];
static int           s_sends;
static int           s_http_status;
static int           s_completion;
static pubnub_res_t  s_transport_error;
static uint64_t      s_time_ms;

static int live_handles(void)
{
    int n = 0;
    int i;
    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (s_handles[i].in_use && 0 == s_handles[i].cancels) {
            n++;
        }
    }
    return n;
}

static int over_cancelled_handles(void)
{
    int n = 0;
    int i;
    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (s_handles[i].cancels > 1) {
            n++;
        }
    }
    return n;
}

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    int i;
    (void)self;
    (void)request;

    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (!s_handles[i].in_use) {
            break;
        }
    }
    assert_true(i < MOCK_MAX_HANDLES);
    s_handles[i].in_use  = 1;
    s_handles[i].cancels = 0;
    s_sends++;

    response->completion      = (pubnub_http_completion_t)s_completion;
    response->status_code     = s_http_status;
    response->transport_error = s_transport_error;
    response->body            = (const uint8_t*)BODY_JSON;
    response->body_len        = sizeof(BODY_JSON) - 1;
    return (pubnub_transport_handle_t*)&s_handles[i];
}

static pubnub_future_t s_poll_release_fut;
static int             s_poll_release_armed;

static int mock_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;

    /* Model a user thread releasing a failed future while the poll thread
     * owns the transport. */
    if (s_poll_release_armed) {
        s_poll_release_armed = 0;
        pubnub_future_release(s_poll_release_fut);
    }
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    mock_handle_t* h = (mock_handle_t*)handle;
    (void)self;
    assert_true(h >= &s_handles[0] && h < &s_handles[MOCK_MAX_HANDLES]);
    assert_true(1 == h->in_use);
    h->cancels++;
}

static pubnub_transport_provider_t s_transport = {
    .send   = mock_send,
    .poll   = mock_poll,
    .cancel = mock_cancel,
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
    pubnub_buffer_t buf = {0};
    (void)self;
    buf.data    = (uint8_t*)malloc(4096);
    buf.cap     = (NULL != buf.data) ? 4096 : 0;
    buf.purpose = purpose;
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
    .free        = stdlib_free,
    .buf_acquire = stdlib_buf_acquire,
    .buf_release = stdlib_buf_release,
};

static pubnub_milliseconds_t mock_clock(pubnub_platform_provider_t* self)
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
    .monotonic_ms  = mock_clock,
    .wall_clock_ms = mock_clock,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
};

extern pubnub_serialization_provider_t* pn_serialization_default(void);

static pubnub_res_t reject_validator(const uint8_t* body, size_t body_len, int http_status)
{
    (void)body;
    (void)body_len;
    (void)http_status;
    return PUBNUB_ERR_SERVER;
}

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

    cfg.retry_configuration.excluded_endpoints = 0;
    cfg.retry_configuration.delay_ms           = 2000;
    cfg.retry_configuration.maximum_delay_ms   = 2000;
    cfg.retry_configuration.maximum_retry      = 1;
    return pubnub_create(&cfg);
}

static int setup_test(void** state)
{
    (void)state;
    memset(s_handles, 0, sizeof(s_handles));
    s_sends              = 0;
    s_http_status        = 200;
    s_completion         = PUBNUB_HTTP_COMPLETE;
    s_transport_error    = PUBNUB_OK;
    s_time_ms            = 1000;
    s_poll_release_armed = 0;
    return 0;
}

static pubnub_future_t dispatch_one(pubnub_context_t* ctx)
{
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host = "ps.pndsn.com";
    entry.feature_id        = (uint8_t)PUBNUB_FEATURE_TIME;
    return pn_dispatch_or_enqueue(ctx, &entry);
}

/**
 * Run one request to a terminal failure, release its future, and verify the
 * transport saw a cancel for every handle it issued.
 */
static void run_failing_request(pubnub_context_t* ctx,
                                int               use_validator,
                                pubnub_res_t      expected)
{
    pubnub_future_t    fut  = dispatch_one(ctx);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    pn_request_t*      slot = pn_request_pool_get(pool, fut.slot_id);
    int                tick;

    assert_non_null(slot);
    if (use_validator) {
        slot->response_validator = reject_validator;
    }

    for (tick = 0; tick < 50 && !pubnub_future_is_ready(fut); tick++) {
        s_time_ms += 2500;
        (void)pubnub_process(ctx);
    }
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(expected, pubnub_future_status(fut));

    pubnub_future_release(fut);
    (void)pubnub_process(ctx);
}

static void http_4xx_failure_cancels_handle_once(void** state)
{
    pubnub_context_t* ctx;
    int               i;
    (void)state;

    ctx = create_ctx();
    assert_non_null(ctx);
    s_http_status = 403;

    /* More requests than retry slots: a leaked retry slot would starve. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 2; i++) {
        run_failing_request(ctx, 0, PUBNUB_ERR_SERVER);
    }

    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
    pubnub_destroy(ctx);
    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
}

static void validator_rejection_cancels_handle_once(void** state)
{
    pubnub_context_t* ctx;
    int               i;
    (void)state;

    ctx = create_ctx();
    assert_non_null(ctx);
    s_http_status = 200;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 2; i++) {
        run_failing_request(ctx, 1, PUBNUB_ERR_SERVER);
    }

    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
    pubnub_destroy(ctx);
    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
}

static void transport_error_terminal_cancels_each_handle_once(void** state)
{
    pubnub_context_t* ctx;
    int               i;
    (void)state;

    ctx = create_ctx();
    assert_non_null(ctx);
    s_completion      = PUBNUB_HTTP_ERROR;
    s_http_status     = 0;
    s_transport_error = PUBNUB_ERR_TRANSPORT;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 2; i++) {
        run_failing_request(ctx, 0, PUBNUB_ERR_TRANSPORT);
    }

    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
    pubnub_destroy(ctx);
    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
}

static void unreleased_failed_future_is_cancelled_by_destroy(void** state)
{
    pubnub_context_t* ctx;
    pubnub_future_t   fut;
    int               tick;
    (void)state;

    ctx = create_ctx();
    assert_non_null(ctx);
    s_http_status = 404;

    fut = dispatch_one(ctx);
    for (tick = 0; tick < 50 && !pubnub_future_is_ready(fut); tick++) {
        s_time_ms += 2500;
        (void)pubnub_process(ctx);
    }
    assert_true(pubnub_future_is_ready(fut));

    pubnub_destroy(ctx);
    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
}

static pubnub_future_t s_cb_fut;
static int             s_cb_calls;

static void release_in_callback(pn_request_t* request, pubnub_res_t status, void* user_data)
{
    (void)request;
    (void)status;
    (void)user_data;
    s_cb_calls++;
    pubnub_future_release(s_cb_fut);
}

/**
 * Releasing a failed future from inside its callback defers to the tick,
 * which must cancel the handle before reclaiming the slot.
 */
static void failed_future_released_in_callback_cancels_handle(void** state)
{
    pubnub_context_t* ctx;
    pn_request_t*     slot;
    int               tick;
    (void)state;

    ctx = create_ctx();
    assert_non_null(ctx);
    s_http_status = 403;
    s_cb_calls    = 0;

    s_cb_fut = dispatch_one(ctx);
    slot = pn_request_pool_get(pn_context_request_pool(ctx), s_cb_fut.slot_id);
    assert_non_null(slot);
    slot->on_complete = release_in_callback;

    for (tick = 0; tick < 5 && 0 == s_cb_calls; tick++) {
        s_time_ms += 100;
        (void)pubnub_process(ctx);
    }
    s_time_ms += 100;
    (void)pubnub_process(ctx);

    assert_int_equal(1, s_cb_calls);
    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
    pubnub_destroy(ctx);
    assert_int_equal(0, over_cancelled_handles());
}

/**
 * A release arriving while another thread owns the transport (from inside
 * poll) is cancelled and reclaimed by the owning tick.
 */
static void failed_future_released_during_poll_is_cancelled_by_tick(void** state)
{
    pubnub_context_t* ctx;
    pubnub_future_t   fut;
    (void)state;

    ctx = create_ctx();
    assert_non_null(ctx);
    s_http_status = 404;

    fut = dispatch_one(ctx);
    s_time_ms += 100;
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(1, live_handles());

    s_poll_release_fut   = fut;
    s_poll_release_armed = 1;
    s_time_ms += 100;
    (void)pubnub_process(ctx);
    s_time_ms += 100;
    (void)pubnub_process(ctx);

    assert_int_equal(0, live_handles());
    assert_int_equal(0, over_cancelled_handles());
    pubnub_destroy(ctx);
    assert_int_equal(0, over_cancelled_handles());
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(http_4xx_failure_cancels_handle_once, setup_test),
        cmocka_unit_test_setup(validator_rejection_cancels_handle_once, setup_test),
        cmocka_unit_test_setup(transport_error_terminal_cancels_each_handle_once,
                               setup_test),
        cmocka_unit_test_setup(unreleased_failed_future_is_cancelled_by_destroy,
                               setup_test),
        cmocka_unit_test_setup(failed_future_released_in_callback_cancels_handle,
                               setup_test),
        cmocka_unit_test_setup(
            failed_future_released_during_poll_is_cancelled_by_tick, setup_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

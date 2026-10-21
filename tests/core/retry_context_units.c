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
#include "pubnub/features/time.h"
#include "pubnub/log.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MOCK_MAX_HANDLES 32
#define MOCK_STEP_MS     500
#define MAX_TICKS        400

#define TRANSACTION_TIMEOUT_MS 10000

static unsigned int s_entry_timeout_ms = TRANSACTION_TIMEOUT_MS;

typedef enum attempt_kind {
    ATTEMPT_FAIL_503,
    ATTEMPT_HANG,
    ATTEMPT_OK,
    ATTEMPT_REJECT
} attempt_kind_t;

typedef struct mock_handle {
    int                     in_use;
    int                     cancels;
    int                     aborted_pending;
    pubnub_http_response_t* response;
} mock_handle_t;

static mock_handle_t  s_handles[MOCK_MAX_HANDLES];
static attempt_kind_t s_script[16];
static int            s_script_len;
static uint64_t       s_send_times[16];
static char           s_send_hosts[16][64];
static int            s_sends;
static uint64_t       s_time_ms;

static int pending_aborts(void)
{
    int n = 0;
    int i;
    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        n += s_handles[i].aborted_pending;
    }
    return n;
}

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    attempt_kind_t kind;
    int            idx = s_sends;
    int            i;
    (void)self;

    kind = s_script[(idx < s_script_len) ? idx : (s_script_len - 1)];
    if (ATTEMPT_REJECT == kind) {
        s_send_times[idx] = s_time_ms;
        s_sends++;
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (!s_handles[i].in_use) {
            break;
        }
    }
    assert_true(i < MOCK_MAX_HANDLES);
    assert_true(idx < 16);
    s_handles[i].in_use          = 1;
    s_handles[i].cancels         = 0;
    s_handles[i].aborted_pending = 0;
    s_handles[i].response        = response;

    s_send_times[idx] = s_time_ms;
    strncpy(s_send_hosts[idx],
            (NULL != request->host) ? request->host : "(null)",
            sizeof(s_send_hosts[idx]) - 1);
    s_sends++;

    switch (kind) {
    case ATTEMPT_FAIL_503:
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 503;
        break;
    case ATTEMPT_OK:
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 200;
        break;
    case ATTEMPT_HANG:
    default: response->completion = PUBNUB_HTTP_PENDING; break;
    }
    return (pubnub_transport_handle_t*)&s_handles[i];
}

static int mock_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    mock_handle_t* h = (mock_handle_t*)handle;
    (void)self;
    assert_true(h >= &s_handles[0] && h < &s_handles[MOCK_MAX_HANDLES]);
    assert_true(1 == h->in_use);
    if (PUBNUB_HTTP_PENDING == h->response->completion) {
        h->aborted_pending++;
    }
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

#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
#define MAX_CAPTURED 64
#define MSG_CAP      256

static char s_captured[MAX_CAPTURED][MSG_CAP];
static int  s_captured_count;

static void capture_log(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    const pubnub_log_entry_text_t* text;
    (void)self;

    if (PUBNUB_LOG_ENTRY_TEXT != entry->type || MAX_CAPTURED <= s_captured_count) {
        return;
    }
    text = (const pubnub_log_entry_text_t*)entry;
    strncpy(s_captured[s_captured_count], text->message, MSG_CAP - 1);
    s_captured[s_captured_count][MSG_CAP - 1] = '\0';
    s_captured_count++;
}

static pubnub_logger_provider_t s_logger = {
    .log = capture_log,
};

static const char* find_captured(const char* needle)
{
    int i;
    for (i = 0; i < s_captured_count; i++) {
        if (NULL != strstr(s_captured[i], needle)) {
            return s_captured[i];
        }
    }
    return NULL;
}
#endif /* PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0 */

extern pubnub_serialization_provider_t* pn_serialization_default(void);

static pubnub_context_t* create_ctx(unsigned int max_retry)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_allocator;
    cfg.transport       = &s_transport;
    cfg.serialization   = pn_serialization_default();
    cfg.platform        = &s_platform;
#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
    cfg.logger    = &s_logger;
    cfg.log_level = PUBNUB_LOG_LEVEL_DEBUG;
#endif

    cfg.retry_configuration.excluded_endpoints = 0;
    cfg.retry_configuration.delay_ms           = 2000;
    cfg.retry_configuration.maximum_delay_ms   = 150000;
    cfg.retry_configuration.maximum_retry      = max_retry;
    return pubnub_create(&cfg);
}

static void script(int count, const attempt_kind_t* kinds)
{
    int i;
    memset(s_script, 0, sizeof(s_script));
    for (i = 0; i < count; i++) {
        s_script[i] = kinds[i];
    }
    s_script_len = count;
}

static int setup_test(void** state)
{
    (void)state;
    memset(s_handles, 0, sizeof(s_handles));
    memset(s_send_times, 0, sizeof(s_send_times));
    memset(s_send_hosts, 0, sizeof(s_send_hosts));
    s_sends            = 0;
    s_time_ms          = 1000;
    s_entry_timeout_ms = TRANSACTION_TIMEOUT_MS;
#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
    memset(s_captured, 0, sizeof(s_captured));
    s_captured_count = 0;
#endif
    return 0;
}

static pubnub_future_t dispatch_one(pubnub_context_t* ctx)
{
    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.host       = "ps.pndsn.com";
    entry.http_request.timeout_ms = s_entry_timeout_ms;
    entry.feature_id              = (uint8_t)PUBNUB_FEATURE_TIME;
    return pn_dispatch_or_enqueue(ctx, &entry);
}

static int run_until_ready(pubnub_context_t* ctx, pubnub_future_t fut)
{
    int tick;
    for (tick = 0; tick < MAX_TICKS && !pubnub_future_is_ready(fut); tick++) {
        s_time_ms += MOCK_STEP_MS;
        (void)pubnub_process(ctx);
    }
    return tick;
}

/**
 * The transaction timeout is per attempt: retries of fast 503s may exceed it
 * in total and must end with the server error, not a timeout.
 */
static void fast_failing_attempts_are_not_timed_out_by_old_deadline(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    (void)state;

    script(1, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = dispatch_one(ctx);
    (void)run_until_ready(ctx, fut);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_SERVER, pubnub_future_status(fut));
    assert_int_equal(5, s_sends);
    assert_int_equal(0, pending_aborts());

    pubnub_future_release(fut);
    (void)pubnub_process(ctx);
    pubnub_destroy(ctx);
}

/**
 * The deadline is armed for the redispatched attempt, not the first one.
 */
static void hanging_retry_times_out_one_budget_after_redispatch(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    pn_request_t*               slot;
    uint64_t                    timeout_ms;
    uint64_t                    done_ms;
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut  = dispatch_one(ctx);
    slot = pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_non_null(slot);
    timeout_ms = slot->http_request.timeout_ms;
    assert_true(timeout_ms > 0);

    (void)run_until_ready(ctx, fut);
    done_ms = s_time_ms;

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_TIMEOUT, pubnub_future_status(fut));
    assert_int_equal(2, s_sends);
    assert_true(done_ms >= s_send_times[1] + timeout_ms);
    assert_true(done_ms < s_send_times[1] + timeout_ms + MOCK_STEP_MS);

    pubnub_future_release(fut);
    (void)pubnub_process(ctx);
    pubnub_destroy(ctx);
}

static int unreleased_handles(void)
{
    int n = 0;
    int i;
    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (s_handles[i].in_use && 1 != s_handles[i].cancels) {
            n++;
        }
    }
    return n;
}

static void tick_ms(pubnub_context_t* ctx, uint64_t ms)
{
    s_time_ms += ms;
    (void)pubnub_process(ctx);
}

#if PUBNUB_ENABLE_TIME
/**
 * An origin change drops a retry waiting out its backoff with a terminal
 * transport error; nothing is sent to the old host again.
 */
static void origin_change_drops_waiting_retry(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503, ATTEMPT_OK};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = pubnub_time(ctx);
    tick_ms(ctx, 100);
    assert_int_equal(1, s_sends);
    assert_false(pubnub_future_is_ready(fut));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    tick_ms(ctx, 100);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_TRANSPORT, pubnub_future_status(fut));
    assert_int_equal(1, s_sends);
    pubnub_future_release(fut);
    tick_ms(ctx, 100);

    tick_ms(ctx, 20000);
    assert_int_equal(1, s_sends);
    assert_int_equal(0, unreleased_handles());

    fut = pubnub_time(ctx);
    assert_int_equal(2, s_sends);
    assert_string_equal("new.example.com", s_send_hosts[1]);
    tick_ms(ctx, 100);
    assert_true(pubnub_future_is_ready(fut));
    pubnub_future_release(fut);
    tick_ms(ctx, 100);

    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
}

/**
 * An in-flight attempt survives an origin change but is not retried when it
 * fails later, since the retry would target the old origin.
 */
static void origin_change_keeps_in_flight_attempt_but_blocks_its_retry(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_HANG, ATTEMPT_OK};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = pubnub_time(ctx);
    tick_ms(ctx, 100);
    assert_int_equal(1, s_sends);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    tick_ms(ctx, 100);
    assert_false(pubnub_future_is_ready(fut));
    assert_int_equal(0, s_handles[0].cancels);

    s_handles[0].response->completion  = PUBNUB_HTTP_COMPLETE;
    s_handles[0].response->status_code = 503;
    tick_ms(ctx, 100);
    tick_ms(ctx, 20000);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_SERVER, pubnub_future_status(fut));
    assert_int_equal(1, s_sends);

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
}

/** Setting the origin to its current value must not disturb a waiting retry. */
static void unchanged_origin_leaves_waiting_retry_alone(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503, ATTEMPT_OK};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    char                        origin[64];
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = pubnub_time(ctx);
    tick_ms(ctx, 100);
    assert_int_equal(1, s_sends);

    strncpy(origin, pubnub_get_origin(ctx), sizeof(origin) - 1);
    origin[sizeof(origin) - 1] = '\0';
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, origin));
    tick_ms(ctx, 100);
    assert_false(pubnub_future_is_ready(fut));

    (void)run_until_ready(ctx, fut);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(2, s_sends);
    assert_string_equal(s_send_hosts[0], s_send_hosts[1]);

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
}

/**
 * An origin change while idle does not affect later requests.
 */
static void origin_change_before_dispatch_does_not_drop_new_request(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503, ATTEMPT_OK};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    fut = pubnub_time(ctx);
    (void)run_until_ready(ctx, fut);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(2, s_sends);
    assert_string_equal("new.example.com", s_send_hosts[0]);
    assert_string_equal("new.example.com", s_send_hosts[1]);
    assert_int_not_equal(PUBNUB_ERR_TRANSPORT, pubnub_future_status(fut));

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
}

/** The same holds when the origin changes between two requests. */
static void origin_change_between_requests_keeps_second_request_retry(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_OK, ATTEMPT_FAIL_503, ATTEMPT_OK};
    pubnub_context_t* ctx;
    pubnub_future_t   fut;
    (void)state;

    script(3, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = pubnub_time(ctx);
    (void)run_until_ready(ctx, fut);
    pubnub_future_release(fut);
    tick_ms(ctx, 100);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    fut = pubnub_time(ctx);
    (void)run_until_ready(ctx, fut);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_send_hosts[2]);
    assert_int_not_equal(PUBNUB_ERR_TRANSPORT, pubnub_future_status(fut));

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
}
#endif /* PUBNUB_ENABLE_TIME */

/**
 * A redispatch rejected after the backoff outlasted the deadline ends with a
 * transport error, not a timeout.
 */
static void rejected_redispatch_reports_transport_error_not_timeout(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503, ATTEMPT_REJECT};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    s_entry_timeout_ms = 1000;
    fut                = dispatch_one(ctx);
    (void)run_until_ready(ctx, fut);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_ERR_TRANSPORT, pubnub_future_status(fut));
    assert_int_equal(2, s_sends);

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
}

#if PUBNUB_ENABLE_TIME && PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0 \
    && PUBNUB_LOG_ENABLED(DEBUG)
/**
 * Retry log lines carry the retry slot, request slot and generation.
 */
static void retry_logs_identify_slot_and_generation(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503, ATTEMPT_OK};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    const char*                 line;
    (void)state;

    script(2, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = pubnub_time(ctx);
    (void)run_until_ready(ctx, fut);

    line = find_captured("Retry scheduled:");
    assert_non_null(line);
    assert_non_null(strstr(line, "retry_slot=0 req_slot="));
    assert_non_null(strstr(line, " gen="));
    assert_non_null(strstr(line, " attempt=1 delay_ms="));

    line = find_captured("Retry fired:");
    assert_non_null(line);
    assert_non_null(strstr(line, "retry_slot=0 req_slot="));
    assert_non_null(strstr(line, " gen="));
    assert_non_null(strstr(line, " attempt=1"));

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
}

/** Dropping a retry on origin change is logged with the same identifiers. */
static void origin_drop_log_identifies_request(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_FAIL_503};
    pubnub_context_t*           ctx;
    pubnub_future_t             fut;
    const char*                 line;
    (void)state;

    script(1, kinds);
    ctx = create_ctx(4);
    assert_non_null(ctx);

    fut = pubnub_time(ctx);
    tick_ms(ctx, 100);
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    tick_ms(ctx, 100);

    line = find_captured("Retry dropped on origin change:");
    assert_non_null(line);
    assert_non_null(strstr(line, "retry_slot=0 req_slot="));
    assert_non_null(strstr(line, " gen="));

    pubnub_future_release(fut);
    tick_ms(ctx, 100);
    pubnub_destroy(ctx);
}
#endif

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(
            fast_failing_attempts_are_not_timed_out_by_old_deadline, setup_test),
        cmocka_unit_test_setup(
            hanging_retry_times_out_one_budget_after_redispatch, setup_test),
#if PUBNUB_ENABLE_TIME
        cmocka_unit_test_setup(origin_change_drops_waiting_retry, setup_test),
        cmocka_unit_test_setup(
            origin_change_keeps_in_flight_attempt_but_blocks_its_retry, setup_test),
        cmocka_unit_test_setup(unchanged_origin_leaves_waiting_retry_alone,
                               setup_test),
        cmocka_unit_test_setup(
            origin_change_before_dispatch_does_not_drop_new_request, setup_test),
        cmocka_unit_test_setup(
            origin_change_between_requests_keeps_second_request_retry, setup_test),
#endif
        cmocka_unit_test_setup(
            rejected_redispatch_reports_transport_error_not_timeout, setup_test),
#if PUBNUB_ENABLE_TIME && PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0 \
    && PUBNUB_LOG_ENABLED(DEBUG)
        cmocka_unit_test_setup(retry_logs_identify_slot_and_generation, setup_test),
        cmocka_unit_test_setup(origin_drop_log_identifies_request, setup_test),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

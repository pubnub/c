/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/* Live subscriptions re-issue failed requests against the new origin. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/capabilities.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MOCK_MAX_HANDLES 64
#define MAX_SENDS        64
#define MAX_STATUSES     32
#define MOCK_STEP_MS     500
#define BACKOFF_MS       2500

#define BODY_HANDSHAKE "{\"t\":{\"t\":\"17000000000000001\",\"r\":4},\"m\":[]}"
#define BODY_RECEIVE   "{\"t\":{\"t\":\"17000000000000002\",\"r\":4},\"m\":[]}"

typedef enum attempt_kind {
    ATTEMPT_OK_HANDSHAKE,
    ATTEMPT_OK_RECEIVE,
    ATTEMPT_FAIL_503,
    ATTEMPT_HANG
} attempt_kind_t;

typedef struct mock_handle {
    int                     in_use;
    int                     cancels;
    pubnub_http_response_t* response;
} mock_handle_t;

static mock_handle_t  s_handles[MOCK_MAX_HANDLES];
static attempt_kind_t s_script[MAX_SENDS];
static int            s_script_len;
static char           s_hosts[MAX_SENDS][64];
static char           s_tts[MAX_SENDS][32];
static int            s_handle_of_send[MAX_SENDS];
static int            s_sends;
static uint64_t       s_time_ms;

static pubnub_subscribe_status_t s_statuses[MAX_STATUSES];
static int                       s_status_count;

static pubnub_context_t*     s_ctx;
static pubnub_subscription_t s_sub;
static int                   s_unsubscribe_on_send = -1;

static int unreleased_handles(void)
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

static int status_count_of(pubnub_subscribe_status_t status)
{
    int n = 0;
    int i;

    for (i = 0; i < s_status_count; i++) {
        if (status == s_statuses[i]) {
            n++;
        }
    }
    return n;
}

static void find_query(const pubnub_http_request_t* request,
                       const char*                  key,
                       char*                        out,
                       size_t                       out_cap)
{
    size_t klen = strlen(key);
    size_t i;

    out[0] = '\0';
    for (i = 0; i < request->query_param_count; i++) {
        const pubnub_kv_t* q = &request->query_params[i];

        if (klen == q->key.len && 0 == memcmp(q->key.ptr, key, klen)) {
            size_t n = (q->value.len < out_cap - 1) ? q->value.len : out_cap - 1;

            memcpy(out, q->value.ptr, n);
            out[n] = '\0';
            return;
        }
    }
}

static void apply_attempt(attempt_kind_t kind, pubnub_http_response_t* response)
{
    switch (kind) {
    case ATTEMPT_OK_HANDSHAKE:
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 200;
        response->body        = (const uint8_t*)BODY_HANDSHAKE;
        response->body_len    = sizeof(BODY_HANDSHAKE) - 1;
        break;
    case ATTEMPT_OK_RECEIVE:
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 200;
        response->body        = (const uint8_t*)BODY_RECEIVE;
        response->body_len    = sizeof(BODY_RECEIVE) - 1;
        break;
    case ATTEMPT_FAIL_503:
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 503;
        break;
    case ATTEMPT_HANG:
    default: response->completion = PUBNUB_HTTP_PENDING; break;
    }
}

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    attempt_kind_t kind;
    char           tt[32];
    int            idx;
    int            i;

    (void)self;
    find_query(request, "tt", tt, sizeof(tt));

    for (i = 0; i < MOCK_MAX_HANDLES; i++) {
        if (!s_handles[i].in_use) {
            break;
        }
    }
    assert_true(i < MOCK_MAX_HANDLES);
    s_handles[i].in_use   = 1;
    s_handles[i].cancels  = 0;
    s_handles[i].response = response;

    /* Only subscribe requests (the ones carrying a cursor) follow the
     * script; presence heartbeats and leaves complete at once. */
    if ('\0' == tt[0]) {
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 200;
        response->body        = (const uint8_t*)"{\"status\":200}";
        response->body_len    = 15;
        return (pubnub_transport_handle_t*)&s_handles[i];
    }

    idx = s_sends;
    assert_true(idx < MAX_SENDS);
    kind = s_script[(idx < s_script_len) ? idx : (s_script_len - 1)];
    s_handle_of_send[idx] = i;

    strncpy(s_hosts[idx],
            (NULL != request->host) ? request->host : "(null)",
            sizeof(s_hosts[idx]) - 1);
    memcpy(s_tts[idx], tt, sizeof(tt));
    s_sends++;

    apply_attempt(kind, response);

    if (idx == s_unsubscribe_on_send) {
        s_unsubscribe_on_send = -1;
        assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(s_sub));
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

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    (void)user_data;
    if (s_status_count < MAX_STATUSES) {
        s_statuses[s_status_count++] = event->status;
    }
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
    memset(s_hosts, 0, sizeof(s_hosts));
    memset(s_tts, 0, sizeof(s_tts));
    s_sends               = 0;
    s_time_ms             = 1000;
    s_status_count        = 0;
    s_unsubscribe_on_send = -1;
    s_ctx                 = NULL;
    s_sub                 = PUBNUB_SUBSCRIPTION_INVALID;
    return 0;
}

static void tick_ms(pubnub_context_t* ctx, uint32_t ms)
{
    s_time_ms += ms;
    (void)pubnub_process(ctx);
}

/** Run enough short ticks for events to cascade through the engine. */
static void settle(pubnub_context_t* ctx)
{
    int i;

    for (i = 0; i < 4; i++) {
        tick_ms(ctx, MOCK_STEP_MS / 10);
    }
}

static pubnub_context_t* create_ctx_with_policy(pubnub_retry_policy_t policy)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    cfg.subscribe_key = "sub-test";
    cfg.publish_key   = "pub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_allocator;
    cfg.transport     = &s_transport;
    cfg.serialization = pn_serialization_default();
    cfg.platform      = &s_platform;

    cfg.retry_configuration.policy             = policy;
    cfg.retry_configuration.excluded_endpoints = 0;
    cfg.retry_configuration.delay_ms           = 2000;
    cfg.retry_configuration.maximum_delay_ms   = 2000;
    cfg.retry_configuration.maximum_retry      = 4;
    return pubnub_create(&cfg);
}

static pubnub_context_t* create_ctx(void)
{
    return create_ctx_with_policy(PUBNUB_RETRY_LINEAR);
}

/** Context with a status listener and a started subscription on "ch1". */
static pubnub_context_t* start_subscription_with_policy(pubnub_retry_policy_t policy)
{
    pubnub_subscribe_listener_t listener = {.on_status = on_status};
    pubnub_context_t*           ctx      = create_ctx_with_policy(policy);
    pubnub_entity_t             entity;

    assert_non_null(ctx);
    assert_true(PUBNUB_LISTENER_HANDLE_INVALID
                != pubnub_add_listener(ctx, &listener));
    entity = pubnub_channel(ctx, "ch1");
    s_sub  = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    assert_true(PUBNUB_SUBSCRIPTION_INVALID != s_sub);
    s_ctx = ctx;
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(s_sub));
    return ctx;
}

static pubnub_context_t* start_subscription(void)
{
    return start_subscription_with_policy(PUBNUB_RETRY_LINEAR);
}

static void teardown(pubnub_context_t* ctx)
{
    (void)pubnub_subscribe_unsubscribe_all(ctx);
    settle(ctx);
    pubnub_subscription_destroy(s_sub);
    s_sub = PUBNUB_SUBSCRIPTION_INVALID;
    pubnub_destroy(ctx);
    assert_int_equal(0, unreleased_handles());
    assert_int_equal(0, over_cancelled_handles());
}

static void assert_no_failure_status(void)
{
    assert_int_equal(
        0, status_count_of(PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY));
    assert_int_equal(0, status_count_of(PUBNUB_SUBSCRIBE_STATUS_CONNECTION_ERROR));
}

/**
 * A receive in retry backoff is re-issued from the same timetoken against the
 * new origin, with no failure status.
 */
static void receive_in_backoff_follows_new_origin(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_context_t* ctx;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);
    assert_string_equal("0", s_tts[0]);
    assert_string_equal("17000000000000001", s_tts[1]);
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTED, pubnub_subscribe_state(ctx));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_hosts[2]);
    assert_string_equal(s_tts[1], s_tts[2]);
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTED, pubnub_subscribe_state(ctx));
    assert_no_failure_status();
    assert_int_equal(1, status_count_of(PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    /* Nothing is ever sent to the old host again. */
    tick_ms(ctx, 20000);
    assert_int_equal(3, s_sends);

    teardown(ctx);
}

/** The same holds for a handshake that is waiting out a retry backoff. */
static void handshake_in_backoff_follows_new_origin(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_FAIL_503, ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG};
    pubnub_context_t* ctx;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(1, s_sends);
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTING, pubnub_subscribe_state(ctx));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_hosts[1]);
    assert_string_equal("0", s_tts[1]);
    assert_string_equal("new.example.com", s_hosts[2]);
    assert_string_equal("17000000000000001", s_tts[2]);
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTED, pubnub_subscribe_state(ctx));
    assert_no_failure_status();

    teardown(ctx);
}

/**
 * A healthy long-poll is left alone. When it completes, the next request goes
 * to the new origin with the advanced cursor.
 */
static void healthy_in_flight_receive_is_untouched(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG, ATTEMPT_HANG};
    pubnub_context_t* ctx;
    int               hs_handle;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);
    hs_handle = s_handle_of_send[1];

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    tick_ms(ctx, 20000);

    assert_int_equal(2, s_sends);
    assert_int_equal(0, s_handles[hs_handle].cancels);
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTED, pubnub_subscribe_state(ctx));
    assert_no_failure_status();

    apply_attempt(ATTEMPT_OK_RECEIVE, s_handles[hs_handle].response);
    settle(ctx);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_hosts[2]);
    assert_string_equal("17000000000000002", s_tts[2]);
    assert_no_failure_status();

    teardown(ctx);
}

/**
 * An in-flight attempt that fails after the origin changed is not retried by
 * the middleware (it would go to the old origin); the subscription re-issues
 * it against the new one instead of reporting a failure.
 */
static void stale_in_flight_failure_is_reissued(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG, ATTEMPT_HANG};
    pubnub_context_t* ctx;
    int               first;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);
    first = s_handle_of_send[1];

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    assert_int_equal(2, s_sends);

    apply_attempt(ATTEMPT_FAIL_503, s_handles[first].response);
    settle(ctx);
    tick_ms(ctx, 20000);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_hosts[2]);
    assert_string_equal(s_tts[1], s_tts[2]);
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTED, pubnub_subscribe_state(ctx));
    assert_no_failure_status();

    teardown(ctx);
}

/** A failure that is not caused by an origin change keeps its old handling. */
static void unrelated_failure_still_reports_disconnect(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG};
    pubnub_context_t*           ctx;
    int                         first;

    (void)state;
    script(2, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);
    first = s_handle_of_send[1];

    /* Client error: not retriable, not related to any origin change. */
    s_handles[first].response->completion  = PUBNUB_HTTP_COMPLETE;
    s_handles[first].response->status_code = 403;
    settle(ctx);

    assert_int_equal(2, s_sends);
    assert_int_equal(
        1, status_count_of(PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY));
    assert_int_equal(PUBNUB_SUBSCRIBE_RECONNECTING, pubnub_subscribe_state(ctx));

    teardown(ctx);
}

/** Origin changes with no subscription (or an idle one) do nothing. */
static void origin_change_while_idle_does_nothing(void** state)
{
    static const attempt_kind_t kinds[] = {ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG};
    pubnub_context_t*           ctx;

    (void)state;
    script(2, kinds);
    ctx = create_ctx();
    assert_non_null(ctx);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    assert_int_equal(0, s_sends);
    assert_int_equal(PUBNUB_SUBSCRIBE_IDLE, pubnub_subscribe_state(ctx));

    /* A later subscription simply uses the new origin. */
    {
        pubnub_subscribe_listener_t listener = {.on_status = on_status};
        pubnub_entity_t             entity;

        assert_true(PUBNUB_LISTENER_HANDLE_INVALID
                    != pubnub_add_listener(ctx, &listener));
        entity = pubnub_channel(ctx, "ch1");
        s_sub  = pubnub_subscription_create(entity, NULL);
        pubnub_entity_destroy(entity);
        s_ctx = ctx;
        assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(s_sub));
    }
    settle(ctx);
    assert_int_equal(2, s_sends);
    assert_string_equal("new.example.com", s_hosts[0]);
    assert_string_equal("new.example.com", s_hosts[1]);
    assert_no_failure_status();

    teardown(ctx);
}

/** Setting the origin to its current value changes nothing. */
static void unchanged_origin_does_not_reissue(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_context_t* ctx;
    char              origin[64];

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    strncpy(origin, pubnub_get_origin(ctx), sizeof(origin) - 1);
    origin[sizeof(origin) - 1] = '\0';
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, origin));
    settle(ctx);
    assert_int_equal(2, s_sends);

    /* The retry still goes to the unchanged origin when its backoff ends. */
    tick_ms(ctx, BACKOFF_MS);
    settle(ctx);
    assert_int_equal(3, s_sends);
    assert_string_equal(origin, s_hosts[2]);
    assert_no_failure_status();

    teardown(ctx);
}

/**
 * A burst of origin changes before the tick yields one re-issue against the
 * latest origin. Further changes while that request is in flight re-issue it
 * once each, never to a stale host, and never with a status.
 */
static void origin_storm_follows_latest_origin(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    char              host[32];
    pubnub_context_t* ctx;
    int               round;
    int               expect_sends;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "h1.example.com"));
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "h2.example.com"));
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "h3.example.com"));
    settle(ctx);
    assert_int_equal(3, s_sends);
    assert_string_equal("h3.example.com", s_hosts[2]);

    expect_sends = 3;
    for (round = 0; round < 8; round++) {
        int in_flight = s_handle_of_send[expect_sends - 1];

        (void)snprintf(host, sizeof(host), "r%d.example.com", round);
        assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, host));
        settle(ctx);
        /* The in-flight attempt is untouched until it fails. */
        assert_int_equal(expect_sends, s_sends);

        apply_attempt(ATTEMPT_FAIL_503, s_handles[in_flight].response);
        settle(ctx);
        expect_sends++;
        assert_int_equal(expect_sends, s_sends);
        assert_string_equal(host, s_hosts[expect_sends - 1]);
        assert_string_equal(s_tts[1], s_tts[expect_sends - 1]);
    }

    assert_no_failure_status();
    assert_int_equal(PUBNUB_SUBSCRIBE_CONNECTED, pubnub_subscribe_state(ctx));
    teardown(ctx);
}

/**
 * A re-issue that fails at the new origin without another origin change is a
 * normal failure: the middleware retries it and, once exhausted, the
 * application is told.
 */
static void failure_at_new_origin_is_not_reissued_again(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_FAIL_503};
    pubnub_context_t* ctx;
    int               i;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    assert_int_equal(3, s_sends);

    /* Let the middleware exhaust its retries at the new origin. */
    for (i = 0; i < 12; i++) {
        tick_ms(ctx, BACKOFF_MS);
        settle(ctx);
    }
    assert_int_equal(
        1, status_count_of(PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY));
    assert_int_equal(PUBNUB_SUBSCRIBE_RECONNECTING, pubnub_subscribe_state(ctx));
    {
        int n;

        for (n = 2; n < s_sends; n++) {
            assert_string_equal("new.example.com", s_hosts[n]);
        }
    }

    teardown(ctx);
}

/** Unsubscribing while the re-issue is being sent leaves nothing behind. */
static void unsubscribe_during_reissue_leaves_no_request(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_context_t* ctx;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    s_unsubscribe_on_send = 2;
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    settle(ctx);

    assert_int_equal(3, s_sends);
    assert_int_equal(PUBNUB_SUBSCRIBE_IDLE, pubnub_subscribe_state(ctx));
    assert_int_equal(0, unreleased_handles());
    assert_no_failure_status();
    assert_int_equal(1, status_count_of(PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED));

    tick_ms(ctx, 20000);
    assert_int_equal(3, s_sends);

    teardown(ctx);
}

/** Unsubscribing before the engine sees the failure sends nothing new. */
static void unsubscribe_before_reissue_sends_nothing(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_context_t* ctx;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(s_sub));
    settle(ctx);

    assert_int_equal(2, s_sends);
    assert_int_equal(PUBNUB_SUBSCRIBE_IDLE, pubnub_subscribe_state(ctx));
    assert_no_failure_status();

    teardown(ctx);
}

/** A disconnected subscription is not resumed by an origin change. */
static void disconnected_subscription_is_not_resumed(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG, ATTEMPT_HANG};
    pubnub_context_t* ctx;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);
    assert_int_equal(PUBNUB_OK, pubnub_subscribe_disconnect(ctx));
    settle(ctx);
    assert_int_equal(PUBNUB_SUBSCRIBE_DISCONNECTED, pubnub_subscribe_state(ctx));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    tick_ms(ctx, 20000);
    assert_int_equal(2, s_sends);
    assert_int_equal(PUBNUB_SUBSCRIBE_DISCONNECTED, pubnub_subscribe_state(ctx));

    /* The explicit reconnect goes to the new origin. */
    assert_int_equal(PUBNUB_OK, pubnub_subscribe_reconnect(ctx));
    settle(ctx);
    assert_true(s_sends >= 3);
    assert_string_equal("new.example.com", s_hosts[2]);

    teardown(ctx);
}

/**
 * The re-issue never needs a free pool slot of its own: the failed request's
 * slot is reclaimed first, so it succeeds even with every other slot busy.
 */
static void reissue_works_with_pool_otherwise_full(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_context_t* ctx;
    int               i;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    /* Occupy every other pool slot with requests that never complete. */
    s_script[2] = ATTEMPT_HANG;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS - 1; i++) {
        pn_pending_entry_t entry;

        memset(&entry, 0, sizeof(entry));
        entry.http_request.host = "ps.pndsn.com";
        entry.feature_id        = (uint8_t)PUBNUB_FEATURE_TIME;
        (void)pn_dispatch_or_enqueue(ctx, &entry);
    }
    assert_true(s_sends >= 2);

    {
        int before = s_sends;

        assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
        settle(ctx);

        assert_int_equal(before + 1, s_sends);
        assert_string_equal("new.example.com", s_hosts[before]);
        assert_string_equal(s_tts[1], s_tts[before]);
    }
    assert_no_failure_status();

    teardown(ctx);
}

/**
 * A channel change queued ahead of the failure already rebuilds the request
 * against the new origin; the engine must not cancel and resend it again.
 */
static void channel_change_ahead_of_origin_change_issues_one_request(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_FAIL_503, ATTEMPT_HANG};
    pubnub_subscription_t second;
    pubnub_context_t*     ctx;
    pubnub_entity_t       entity;

    (void)state;
    script(3, kinds);
    ctx = start_subscription();

    settle(ctx);
    assert_int_equal(2, s_sends);

    entity = pubnub_channel(ctx, "ch2");
    second = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    assert_true(PUBNUB_SUBSCRIPTION_INVALID != second);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(second));
    settle(ctx);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_hosts[2]);
    assert_no_failure_status();
    assert_int_equal(
        1, status_count_of(PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED));

    pubnub_subscription_destroy(second);
    teardown(ctx);
}

/** The re-issue does not depend on automatic retries being enabled. */
static void stale_failure_is_reissued_without_retries(void** state)
{
    static const attempt_kind_t kinds[] = {
        ATTEMPT_OK_HANDSHAKE, ATTEMPT_HANG, ATTEMPT_HANG};
    pubnub_context_t* ctx;
    int               first;

    (void)state;
    script(3, kinds);
    ctx = start_subscription_with_policy(PUBNUB_RETRY_NONE);

    settle(ctx);
    assert_int_equal(2, s_sends);
    first = s_handle_of_send[1];

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.example.com"));
    settle(ctx);
    assert_int_equal(2, s_sends);

    apply_attempt(ATTEMPT_FAIL_503, s_handles[first].response);
    settle(ctx);

    assert_int_equal(3, s_sends);
    assert_string_equal("new.example.com", s_hosts[2]);
    assert_string_equal(s_tts[1], s_tts[2]);
    assert_no_failure_status();

    teardown(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(receive_in_backoff_follows_new_origin, setup_test),
        cmocka_unit_test_setup(handshake_in_backoff_follows_new_origin, setup_test),
        cmocka_unit_test_setup(healthy_in_flight_receive_is_untouched, setup_test),
        cmocka_unit_test_setup(stale_in_flight_failure_is_reissued, setup_test),
        cmocka_unit_test_setup(unrelated_failure_still_reports_disconnect, setup_test),
        cmocka_unit_test_setup(origin_change_while_idle_does_nothing, setup_test),
        cmocka_unit_test_setup(unchanged_origin_does_not_reissue, setup_test),
        cmocka_unit_test_setup(origin_storm_follows_latest_origin, setup_test),
        cmocka_unit_test_setup(failure_at_new_origin_is_not_reissued_again,
                               setup_test),
        cmocka_unit_test_setup(unsubscribe_during_reissue_leaves_no_request,
                               setup_test),
        cmocka_unit_test_setup(unsubscribe_before_reissue_sends_nothing, setup_test),
        cmocka_unit_test_setup(disconnected_subscription_is_not_resumed, setup_test),
        cmocka_unit_test_setup(reissue_works_with_pool_otherwise_full, setup_test),
        cmocka_unit_test_setup(stale_failure_is_reissued_without_retries, setup_test),
        cmocka_unit_test_setup(
            channel_change_ahead_of_origin_change_issues_one_request, setup_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

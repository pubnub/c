/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file time_result_units.c
 * @brief Completion-path tests for pubnub_time_result_timetoken.
 *
 * Drives a time request to completion through the normal tick path with a
 * mock transport, then proves the result accessor returns digits from
 * feature-owned storage rather than the transport rx buffer. The key test
 * clobbers the response body after completion to simulate the socket
 * transport reclaiming its receive buffer on the Connection: close path;
 * with the capture fix the accessor stays correct, without it this reads
 * freed/stale memory (ASan-detectable).
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/time.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#define MAX_TRACKED_SLOTS 4

static int                     s_send_count;
static pubnub_http_request_t*  s_captured_requests[MAX_TRACKED_SLOTS];
static pubnub_http_response_t* s_captured_responses[MAX_TRACKED_SLOTS];
static int                     s_fake_handles[MAX_TRACKED_SLOTS];

/* Mutable rx buffer so tests can clobber it after completion, simulating
 * the transport reclaiming its receive buffer. */
static uint8_t s_rx[64];

static void reset_chain(void)
{
    s_send_count = 0;
    memset(s_captured_requests, 0, sizeof(s_captured_requests));
    memset(s_captured_responses, 0, sizeof(s_captured_responses));
    memset(s_rx, 0, sizeof(s_rx));
}

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_TRACKED_SLOTS) {
        return NULL;
    }
    s_captured_requests[s_send_count]  = request;
    s_captured_responses[s_send_count] = response;
    s_send_count++;
    return (pubnub_transport_handle_t*)&s_fake_handles[s_send_count - 1];
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

static pubnub_config_t result_test_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "pub";
    cfg.subscribe_key   = "sub";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

/* Load the mock rx buffer with @p body and mark the request complete. */
static void deliver_body(int capture_idx, const char* body, int status)
{
    pubnub_http_response_t* resp = s_captured_responses[capture_idx];
    size_t                  len  = strlen(body);
    assert_true(len < sizeof(s_rx));
    memcpy(s_rx, body, len);
    if (NULL != resp) {
        resp->body        = s_rx;
        resp->body_len    = len;
        resp->status_code = status;
        resp->completion  = PUBNUB_HTTP_COMPLETE;
    }
}

#if PUBNUB_CFG_NO_HEAP
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP

/* The core regression: the accessor must survive rx-buffer reclamation. */
static void result_survives_rx_buffer_clobber(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = result_test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    deliver_body(0, "[17191609868840930]", 200);
    (void)pubnub_process(ctx);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    /* Simulate the transport reclaiming its receive buffer. */
    memset(s_rx, 0, sizeof(s_rx));

    pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
    assert_int_equal(tt.len, 17);
    assert_non_null(tt.ptr);
    assert_memory_equal(tt.ptr, "17191609868840930", 17);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/* Two back-to-back requests: capture is independent per slot. */
static void result_correct_across_two_requests(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = result_test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_time(ctx);
    deliver_body(0, "[10000000000000001]", 200);
    (void)pubnub_process(ctx);
    memset(s_rx, 0, sizeof(s_rx));

    pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
    assert_int_equal(tt.len, 17);
    assert_memory_equal(tt.ptr, "10000000000000001", 17);
    pubnub_future_release(fut);

    reset_chain();
    fut = pubnub_time(ctx);
    deliver_body(0, "[20000000000000002]", 200);
    (void)pubnub_process(ctx);
    memset(s_rx, 0, sizeof(s_rx));

    tt = pubnub_time_result_timetoken(fut);
    assert_int_equal(tt.len, 17);
    assert_memory_equal(tt.ptr, "20000000000000002", 17);
    pubnub_future_release(fut);

    pubnub_destroy(ctx);
}

static void result_null_future_returns_empty(void** state)
{
    (void)state;
    pubnub_future_t    invalid = {0};
    pubnub_timetoken_t tt      = pubnub_time_result_timetoken(invalid);
    assert_null(tt.ptr);
    assert_int_equal(tt.len, 0);
}

static void result_not_ready_future_returns_empty(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = result_test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    /* No completion delivered: accessor must report nothing. */
    pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
    assert_null(tt.ptr);
    assert_int_equal(tt.len, 0);

    /* Drain to completion so the slot releases cleanly. */
    deliver_body(0, "[17000000000000000]", 200);
    (void)pubnub_process(ctx);
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void result_malformed_body_returns_empty(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = result_test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut = pubnub_time(ctx);
    /* 200 status but no digits: capture leaves tt_len == 0 and the
     * validator drives the request to a failure terminal state. */
    deliver_body(0, "[]", 200);
    (void)pubnub_process(ctx);

    pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
    assert_null(tt.ptr);
    assert_int_equal(tt.len, 0);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/* Over-capacity token: reported as absent (never overflows tt[24], and a
 * truncated token would read as a valid-but-wrong value). */
static void result_oversize_token_is_bounded(void** state)
{
    (void)state;
    reset_chain();

    pubnub_config_t   cfg = result_test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* 30-digit token exceeds the 23-digit storage capacity (24 - NUL). */
    static const char big[] = "[123456789012345678901234567890]";
    pubnub_future_t   fut   = pubnub_time(ctx);
    deliver_body(0, big, 200);
    (void)pubnub_process(ctx);
    memset(s_rx, 0, sizeof(s_rx));

    pubnub_timetoken_t tt = pubnub_time_result_timetoken(fut);
    assert_int_equal(tt.len, 0);
    assert_null(tt.ptr);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(result_survives_rx_buffer_clobber),
        cmocka_unit_test(result_correct_across_two_requests),
        cmocka_unit_test(result_null_future_returns_empty),
        cmocka_unit_test(result_not_ready_future_returns_empty),
        cmocka_unit_test(result_malformed_body_returns_empty),
        cmocka_unit_test(result_oversize_token_is_bounded),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

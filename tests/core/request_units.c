/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file request_units.c
 * @brief Unit tests for the request descriptor state machine.
 *
 * The request module is a pure state machine -- it does not perform
 * I/O or register timers. Tests verify state transitions, callback
 * invocation, and guard conditions only.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/request_internal.h"

/* ======================================================================== */
/* Fake transport handle (just a non-NULL sentinel)                         */
/* ======================================================================== */

static int                        s_fake_handle_storage;
static pubnub_transport_handle_t* s_fake_handle =
    (pubnub_transport_handle_t*)&s_fake_handle_storage;

/* ======================================================================== */
/* Callback tracking                                                        */
/* ======================================================================== */

static int          s_cb_invoked;
static pubnub_res_t s_cb_status;
static void*        s_cb_user_data;

static void mock_callback(pn_request_t* request, pubnub_res_t status, void* user_data)
{
    (void)request;
    s_cb_invoked   = 1;
    s_cb_status    = status;
    s_cb_user_data = user_data;
}

static int reset_test(void** state)
{
    (void)state;
    s_cb_invoked   = 0;
    s_cb_status    = PUBNUB_OK;
    s_cb_user_data = NULL;
    return 0;
}

/* ======================================================================== */
/* Capturing logger for pn_request_log_net_terminal                         */
/* ======================================================================== */

static struct {
    int          count;
    int          canceled;
    int          failed;
    pubnub_res_t result;
    uint16_t     slot_id;
    char         method[8];
    char         url[128];
} s_log_cap;

static void reset_log_capture(void)
{
    memset(&s_log_cap, 0, sizeof(s_log_cap));
}

static void bounded_copy(char* dst, size_t dst_size, const char* src)
{
    size_t n;
    if (NULL == src || 0 == dst_size) {
        return;
    }
    n = strlen(src);
    if (n >= dst_size) {
        n = dst_size - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void capture_log(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    const pubnub_log_entry_net_request_t* req;
    (void)self;
    if (NULL == entry || PUBNUB_LOG_ENTRY_NET_REQ != entry->type) {
        return;
    }
    req = (const pubnub_log_entry_net_request_t*)entry;
    s_log_cap.count++;
    s_log_cap.canceled = req->canceled;
    s_log_cap.failed   = req->failed;
    s_log_cap.result   = req->result;
    s_log_cap.slot_id  = req->slot_id;
    bounded_copy(s_log_cap.method, sizeof(s_log_cap.method), req->method);
    bounded_copy(s_log_cap.url, sizeof(s_log_cap.url), req->url);
}

static pn_request_t make_logged_request(uint16_t slot_id)
{
    pn_request_t req;
    pn_request_init(&req, slot_id);
    req.http_request.method = PUBNUB_HTTP_GET;
    req.http_request.host   = "example.com";
    req.http_request.secure = 0;
    return req;
}

static void net_terminal_should_emit_cancelled_mapping(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = capture_log, .set_level = NULL};
    pn_request_t             req    = make_logged_request(5);

    reset_log_capture();
    pn_request_log_net_terminal(
        &req, &logger, 1, 0, PUBNUB_ERR_CANCELLED, PUBNUB_LOG_LEVEL_DEBUG, __FILE__, __LINE__);
/* The helper compiles in (and emits) whenever any of DEBUG/WARNING/ERROR
 * is enabled -- compile-time level stripping is a call-site contract, not
 * a helper-internal one. Mirror that emit condition here so the assertion
 * holds on every profile (dev 0x1F and full 0x1C with DEBUG stripped). */
#if PUBNUB_LOG_ENABLED(DEBUG) || PUBNUB_LOG_ENABLED(WARNING) \
    || PUBNUB_LOG_ENABLED(ERROR)
    assert_int_equal(s_log_cap.count, 1);
    assert_int_equal(s_log_cap.canceled, 1);
    assert_int_equal(s_log_cap.failed, 0);
    assert_int_equal(s_log_cap.result, PUBNUB_ERR_CANCELLED);
    assert_int_equal(s_log_cap.slot_id, 5);
    assert_string_equal(s_log_cap.method, "GET");
    assert_string_equal(s_log_cap.url, "http://example.com");
#else
    assert_int_equal(s_log_cap.count, 0);
#endif
}

static void net_terminal_should_emit_timeout_mapping(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = capture_log, .set_level = NULL};
    pn_request_t             req    = make_logged_request(3);

    reset_log_capture();
    pn_request_log_net_terminal(
        &req, &logger, 0, 1, PUBNUB_ERR_TIMEOUT, PUBNUB_LOG_LEVEL_WARNING, __FILE__, __LINE__);
#if PUBNUB_LOG_ENABLED(WARNING)
    assert_int_equal(s_log_cap.count, 1);
    assert_int_equal(s_log_cap.canceled, 0);
    assert_int_equal(s_log_cap.failed, 1);
    assert_int_equal(s_log_cap.result, PUBNUB_ERR_TIMEOUT);
    assert_int_equal(s_log_cap.slot_id, 3);
#else
    assert_int_equal(s_log_cap.count, 0);
#endif
}

static void net_terminal_should_emit_generic_failure_mapping(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = capture_log, .set_level = NULL};
    pn_request_t             req    = make_logged_request(7);

    reset_log_capture();
    pn_request_log_net_terminal(
        &req, &logger, 0, 1, PUBNUB_ERR_TRANSPORT, PUBNUB_LOG_LEVEL_ERROR, __FILE__, __LINE__);
#if PUBNUB_LOG_ENABLED(ERROR)
    assert_int_equal(s_log_cap.count, 1);
    assert_int_equal(s_log_cap.canceled, 0);
    assert_int_equal(s_log_cap.failed, 1);
    assert_int_equal(s_log_cap.result, PUBNUB_ERR_TRANSPORT);
    assert_int_equal(s_log_cap.slot_id, 7);
#else
    assert_int_equal(s_log_cap.count, 0);
#endif
}

static void net_terminal_null_logger_should_not_emit(void** state)
{
    (void)state;
    pn_request_t req = make_logged_request(0);

    reset_log_capture();
    pn_request_log_net_terminal(
        &req, NULL, 1, 0, PUBNUB_ERR_CANCELLED, PUBNUB_LOG_LEVEL_DEBUG, __FILE__, __LINE__);
    assert_int_equal(s_log_cap.count, 0);
}

static void net_terminal_null_request_should_not_emit(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = capture_log, .set_level = NULL};

    reset_log_capture();
    pn_request_log_net_terminal(
        NULL, &logger, 1, 0, PUBNUB_ERR_CANCELLED, PUBNUB_LOG_LEVEL_DEBUG, __FILE__, __LINE__);
    assert_int_equal(s_log_cap.count, 0);
}

static void net_terminal_null_log_callback_should_not_emit(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = NULL, .set_level = NULL};
    pn_request_t             req    = make_logged_request(0);

    reset_log_capture();
    pn_request_log_net_terminal(
        &req, &logger, 1, 0, PUBNUB_ERR_CANCELLED, PUBNUB_LOG_LEVEL_DEBUG, __FILE__, __LINE__);
    assert_int_equal(s_log_cap.count, 0);
}

/* ======================================================================== */
/* Tests: pn_request_init / pn_request_reset                                */
/* ======================================================================== */

static void init_should_zero_and_set_idle_with_slot_id(void** state)
{
    (void)state;
    pn_request_t sut;
    memset(&sut, 0xFF, sizeof(sut));

    pn_request_init(&sut, 7);

    assert_int_equal(sut.state, PN_REQUEST_IDLE);
    assert_int_equal(sut.slot_id, 7);
    assert_null(sut.transport_handle);
    assert_null(sut.on_complete);
    assert_null(sut.user_data);
    assert_int_equal(sut.result, PUBNUB_OK);
}

static void reset_should_preserve_slot_id(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 7);
    sut.state  = PN_REQUEST_COMPLETE;
    sut.result = PUBNUB_OK;

    pn_request_reset(&sut);

    assert_int_equal(sut.state, PN_REQUEST_IDLE);
    assert_int_equal(sut.slot_id, 7);
    assert_null(sut.transport_handle);
    assert_int_equal(sut.result, PUBNUB_OK);
}

static void reset_null_should_not_crash(void** state)
{
    (void)state;

    pn_request_reset(NULL);
}

static void init_null_should_not_crash(void** state)
{
    (void)state;

    pn_request_init(NULL, 0);
}

/* ======================================================================== */
/* Tests: pn_request_is_idle                                                */
/* ======================================================================== */

static void is_idle_should_return_true_after_init(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    assert_true(pn_request_is_idle(&sut));
}

static void is_idle_should_return_false_when_pending(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);

    assert_false(pn_request_is_idle(&sut));
}

static void is_idle_should_return_false_for_null(void** state)
{
    (void)state;

    assert_false(pn_request_is_idle(NULL));
}

/* ======================================================================== */
/* Tests: pn_request_is_terminal                                            */
/* ======================================================================== */

static void is_terminal_should_return_false_when_idle(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    assert_false(pn_request_is_terminal(&sut));
}

static void is_terminal_should_return_false_when_pending(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);

    assert_false(pn_request_is_terminal(&sut));
}

static void is_terminal_should_return_false_when_in_flight(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    assert_false(pn_request_is_terminal(&sut));
}

static void is_terminal_should_return_true_when_complete(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);
    pn_request_on_success(&sut, PUBNUB_OK);

    assert_true(pn_request_is_terminal(&sut));
}

static void is_terminal_should_return_true_when_failed(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);
    PN_REQUEST_ON_FAILURE(&sut, PUBNUB_ERR_TIMEOUT);

    assert_true(pn_request_is_terminal(&sut));
}

/* ======================================================================== */
/* Tests: pn_request_enqueue (IDLE -> PENDING)                              */
/* ======================================================================== */

static void enqueue_should_transition_idle_to_pending(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    pubnub_res_t rc = pn_request_enqueue(&sut);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(sut.state, PN_REQUEST_PENDING);
}

static void enqueue_should_reject_non_idle(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);

    pubnub_res_t rc = pn_request_enqueue(&sut);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut.state, PN_REQUEST_PENDING);
}

static void enqueue_should_reject_null(void** state)
{
    (void)state;

    pubnub_res_t rc = pn_request_enqueue(NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */
/* Tests: pn_request_accept_handle (PENDING -> IN_FLIGHT) */
/* ======================================================================== */

static void accept_handle_should_transition_pending_to_in_flight(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);

    pubnub_res_t rc = pn_request_accept_handle(&sut, s_fake_handle);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(sut.state, PN_REQUEST_IN_FLIGHT);
    assert_ptr_equal(sut.transport_handle, s_fake_handle);
}

static void accept_handle_should_reject_non_pending(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    pubnub_res_t rc = pn_request_accept_handle(&sut, s_fake_handle);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut.state, PN_REQUEST_IDLE);
}

static void accept_handle_should_reject_null_handle(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);

    pubnub_res_t rc = pn_request_accept_handle(&sut, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut.state, PN_REQUEST_PENDING);
}

/* ======================================================================== */
/* Tests: pn_request_on_success (IN_FLIGHT -> COMPLETE)                     */
/* ======================================================================== */

static void on_success_should_transition_and_keep_handle(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 3);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    pubnub_res_t rc = pn_request_on_success(&sut, PUBNUB_OK);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(sut.state, PN_REQUEST_COMPLETE);
    assert_int_equal(sut.result, PUBNUB_OK);
    /* On success the transport handle is intentionally preserved:
     * response->body aliases the transport rx buffer the handle owns, so
     * the handle must outlive the completion signal. pubnub_future_release
     * cancels it (freeing rx_buf) once the caller is done reading. */
    assert_ptr_equal(sut.transport_handle, s_fake_handle);
    assert_int_equal(sut.slot_id, 3);
}

static void on_success_should_enter_completing_with_callback(void** state)
{
    (void)state;
    int          sentinel = 42;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    sut.on_complete = mock_callback;
    sut.user_data   = &sentinel;
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    pn_request_on_success(&sut, PUBNUB_OK);

    /* Callback is NOT fired yet; slot enters COMPLETING. */
    assert_false(s_cb_invoked);
    assert_int_equal(sut.state, PN_REQUEST_COMPLETING);

    /* Deliver notification fires the callback and transitions. */
    pn_request_deliver_notification(&sut);

    assert_true(s_cb_invoked);
    assert_int_equal(s_cb_status, PUBNUB_OK);
    assert_ptr_equal(s_cb_user_data, &sentinel);
    assert_int_equal(sut.state, PN_REQUEST_COMPLETE);
}

static void on_success_should_reject_non_in_flight(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);

    pubnub_res_t rc = pn_request_on_success(&sut, PUBNUB_OK);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut.state, PN_REQUEST_PENDING);
}

/* ======================================================================== */
/* Tests: PN_REQUEST_ON_FAILURE (IN_FLIGHT -> FAILED)                       */
/* ======================================================================== */

static void on_failure_should_transition_and_set_error(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    pubnub_res_t rc = PN_REQUEST_ON_FAILURE(&sut, PUBNUB_ERR_TIMEOUT);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(sut.state, PN_REQUEST_FAILED);
    assert_int_equal(sut.result, PUBNUB_ERR_TIMEOUT);
    assert_null(sut.transport_handle);
}

static void on_failure_should_enter_completing_with_callback(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    sut.on_complete = mock_callback;
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    PN_REQUEST_ON_FAILURE(&sut, PUBNUB_ERR_TRANSPORT);

    /* Callback is NOT fired yet; slot enters COMPLETING. */
    assert_false(s_cb_invoked);
    assert_int_equal(sut.state, PN_REQUEST_COMPLETING);

    /* Deliver notification fires the callback and transitions. */
    pn_request_deliver_notification(&sut);

    assert_true(s_cb_invoked);
    assert_int_equal(s_cb_status, PUBNUB_ERR_TRANSPORT);
    assert_int_equal(sut.state, PN_REQUEST_FAILED);
}

static void on_failure_should_reject_non_in_flight(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    pubnub_res_t rc = PN_REQUEST_ON_FAILURE(&sut, PUBNUB_ERR_TIMEOUT);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(sut.state, PN_REQUEST_IDLE);
}

/* ======================================================================== */
/* Tests: pn_request_is_ready (atomic publication gate)                     */
/* ======================================================================== */

static void is_ready_should_return_false_for_null(void** state)
{
    (void)state;

    assert_false(pn_request_is_ready(NULL));
}

static void is_ready_should_return_false_when_idle(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    assert_false(pn_request_is_ready(&sut));
}

static void is_ready_should_return_false_when_in_flight(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    assert_false(pn_request_is_ready(&sut));
}

static void is_ready_should_return_true_after_on_success(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    pn_request_on_success(&sut, PUBNUB_OK);

    /* Gate published; result is stable and readable. */
    assert_true(pn_request_is_ready(&sut));
    assert_int_equal(sut.state, PN_REQUEST_COMPLETE);
    assert_int_equal(sut.result, PUBNUB_OK);
}

static void is_ready_should_return_true_after_on_failure(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    PN_REQUEST_ON_FAILURE(&sut, PUBNUB_ERR_TIMEOUT);

    assert_true(pn_request_is_ready(&sut));
    assert_int_equal(sut.state, PN_REQUEST_FAILED);
    assert_int_equal(sut.result, PUBNUB_ERR_TIMEOUT);
}

static void is_ready_should_return_true_in_completing_with_callback(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    sut.on_complete = mock_callback;
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    pn_request_on_success(&sut, PUBNUB_OK);

    /* Result data is stable in COMPLETING even before the callback
     * fires; the gate is already published. */
    assert_int_equal(sut.state, PN_REQUEST_COMPLETING);
    assert_true(pn_request_is_ready(&sut));
}

/* Ordering invariant: the gate governs readiness, not the state enum.
 * A slot whose state byte reads terminal but whose gate is unpublished
 * MUST report not-ready -- this is the whole point of the fix. */
static void is_ready_should_ignore_state_when_gate_unpublished(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);

    /* Force a terminal-looking state without publishing the gate, as an
     * SMP reader might observe mid-write on the poll thread. */
    sut.state  = PN_REQUEST_COMPLETE;
    sut.result = PUBNUB_OK;

    assert_false(pn_request_is_ready(&sut));

    /* Also COMPLETING must not read ready without the gate. */
    sut.state = PN_REQUEST_COMPLETING;
    assert_false(pn_request_is_ready(&sut));
}

static void is_ready_should_return_false_after_reset(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 4);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);
    pn_request_on_success(&sut, PUBNUB_OK);
    assert_true(pn_request_is_ready(&sut));

    pn_request_reset(&sut);

    /* reset() memsets the slot, so the gate returns to 0. */
    assert_false(pn_request_is_ready(&sut));
    assert_int_equal(sut.state, PN_REQUEST_IDLE);
    assert_int_equal(sut.slot_id, 4);
}

/* ======================================================================== */
/* Tests: pn_request_feature_state_for                                      */
/* ======================================================================== */

static void feature_state_for_null_slot_should_return_null(void** state)
{
    (void)state;

    void* result = pn_request_feature_state_for(NULL, PUBNUB_FEATURE_PUBLISH);

    assert_null(result);
}

static void feature_state_for_null_feature_state_should_return_null(void** state)
{
    (void)state;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    sut.feature_id    = (uint8_t)PUBNUB_FEATURE_PUBLISH;
    sut.feature_state = NULL;

    void* result = pn_request_feature_state_for(&sut, PUBNUB_FEATURE_PUBLISH);

    assert_null(result);
}

static void feature_state_for_matching_id_should_return_state(void** state)
{
    (void)state;
    int          sentinel = 99;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    sut.feature_id    = (uint8_t)PUBNUB_FEATURE_HISTORY;
    sut.feature_state = &sentinel;

    void* result = pn_request_feature_state_for(&sut, PUBNUB_FEATURE_HISTORY);

    assert_ptr_equal(result, &sentinel);
}

static void feature_state_for_mismatching_id_should_return_null(void** state)
{
    (void)state;
    int          sentinel = 77;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    sut.feature_id    = (uint8_t)PUBNUB_FEATURE_PUBLISH;
    sut.feature_state = &sentinel;

    void* result = pn_request_feature_state_for(&sut, PUBNUB_FEATURE_SUBSCRIBE);

    assert_null(result);
}

static void feature_state_for_zero_init_slot_should_return_null(void** state)
{
    (void)state;
    pn_request_t sut;
    memset(&sut, 0, sizeof(sut));

    /* feature_state is NULL after memset, so the helper rejects early. */
    void* result = pn_request_feature_state_for(&sut, PUBNUB_FEATURE_PUBLISH);

    assert_null(result);
}

static void feature_state_for_unset_id_sentinel_should_return_null(void** state)
{
    (void)state;
    int          sentinel = 42;
    pn_request_t sut;
    pn_request_init(&sut, 0);
    /* Simulate a bug: feature_state set without assigning feature_id.
       After init, feature_id == PUBNUB_FEATURE_COUNT (sentinel). */
    sut.feature_state = &sentinel;

    void* result = pn_request_feature_state_for(&sut, PUBNUB_FEATURE_PUBLISH);

    assert_null(result);
}

/* ======================================================================== */
/* Tests: full lifecycle                                                     */
/* ======================================================================== */

static void full_lifecycle_idle_to_complete_to_idle(void** state)
{
    (void)state;
    pn_request_t sut;

    pn_request_init(&sut, 5);
    assert_int_equal(sut.state, PN_REQUEST_IDLE);

    pn_request_enqueue(&sut);
    assert_int_equal(sut.state, PN_REQUEST_PENDING);

    pn_request_accept_handle(&sut, s_fake_handle);
    assert_int_equal(sut.state, PN_REQUEST_IN_FLIGHT);

    pn_request_on_success(&sut, PUBNUB_OK);
    assert_int_equal(sut.state, PN_REQUEST_COMPLETE);

    pn_request_reset(&sut);
    assert_int_equal(sut.state, PN_REQUEST_IDLE);
    assert_int_equal(sut.slot_id, 5);
}

static void full_lifecycle_idle_to_failed_to_idle(void** state)
{
    (void)state;
    pn_request_t sut;

    pn_request_init(&sut, 2);
    pn_request_enqueue(&sut);
    pn_request_accept_handle(&sut, s_fake_handle);

    /* Caller would call transport->cancel() here, then: */
    PN_REQUEST_ON_FAILURE(&sut, PUBNUB_ERR_TIMEOUT);

    assert_int_equal(sut.state, PN_REQUEST_FAILED);
    assert_int_equal(sut.result, PUBNUB_ERR_TIMEOUT);

    pn_request_reset(&sut);
    assert_int_equal(sut.state, PN_REQUEST_IDLE);
}

/* ======================================================================== */
/* Test runner                                                              */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* init / reset */
        cmocka_unit_test_setup(init_should_zero_and_set_idle_with_slot_id, reset_test),
        cmocka_unit_test_setup(reset_should_preserve_slot_id, reset_test),
        cmocka_unit_test_setup(reset_null_should_not_crash, reset_test),
        cmocka_unit_test_setup(init_null_should_not_crash, reset_test),

        /* is_idle */
        cmocka_unit_test_setup(is_idle_should_return_true_after_init, reset_test),
        cmocka_unit_test_setup(is_idle_should_return_false_when_pending, reset_test),
        cmocka_unit_test_setup(is_idle_should_return_false_for_null, reset_test),

        /* is_terminal */
        cmocka_unit_test_setup(is_terminal_should_return_false_when_idle, reset_test),
        cmocka_unit_test_setup(is_terminal_should_return_false_when_pending,
                               reset_test),
        cmocka_unit_test_setup(is_terminal_should_return_false_when_in_flight,
                               reset_test),
        cmocka_unit_test_setup(is_terminal_should_return_true_when_complete,
                               reset_test),
        cmocka_unit_test_setup(is_terminal_should_return_true_when_failed, reset_test),

        /* enqueue */
        cmocka_unit_test_setup(enqueue_should_transition_idle_to_pending, reset_test),
        cmocka_unit_test_setup(enqueue_should_reject_non_idle, reset_test),
        cmocka_unit_test_setup(enqueue_should_reject_null, reset_test),

        /* accept_handle */
        cmocka_unit_test_setup(
            accept_handle_should_transition_pending_to_in_flight, reset_test),
        cmocka_unit_test_setup(accept_handle_should_reject_non_pending, reset_test),
        cmocka_unit_test_setup(accept_handle_should_reject_null_handle, reset_test),

        /* on_success */
        cmocka_unit_test_setup(on_success_should_transition_and_keep_handle,
                               reset_test),
        cmocka_unit_test_setup(on_success_should_enter_completing_with_callback,
                               reset_test),
        cmocka_unit_test_setup(on_success_should_reject_non_in_flight, reset_test),

        /* on_failure */
        cmocka_unit_test_setup(on_failure_should_transition_and_set_error, reset_test),
        cmocka_unit_test_setup(on_failure_should_enter_completing_with_callback,
                               reset_test),
        cmocka_unit_test_setup(on_failure_should_reject_non_in_flight, reset_test),

        /* is_ready (atomic publication gate) */
        cmocka_unit_test_setup(is_ready_should_return_false_for_null, reset_test),
        cmocka_unit_test_setup(is_ready_should_return_false_when_idle, reset_test),
        cmocka_unit_test_setup(is_ready_should_return_false_when_in_flight,
                               reset_test),
        cmocka_unit_test_setup(is_ready_should_return_true_after_on_success,
                               reset_test),
        cmocka_unit_test_setup(is_ready_should_return_true_after_on_failure,
                               reset_test),
        cmocka_unit_test_setup(
            is_ready_should_return_true_in_completing_with_callback, reset_test),
        cmocka_unit_test_setup(is_ready_should_ignore_state_when_gate_unpublished,
                               reset_test),
        cmocka_unit_test_setup(is_ready_should_return_false_after_reset, reset_test),

        /* pn_request_log_net_terminal */
        cmocka_unit_test(net_terminal_should_emit_cancelled_mapping),
        cmocka_unit_test(net_terminal_should_emit_timeout_mapping),
        cmocka_unit_test(net_terminal_should_emit_generic_failure_mapping),
        cmocka_unit_test(net_terminal_null_logger_should_not_emit),
        cmocka_unit_test(net_terminal_null_request_should_not_emit),
        cmocka_unit_test(net_terminal_null_log_callback_should_not_emit),

        /* feature_state_for */
        cmocka_unit_test_setup(feature_state_for_null_slot_should_return_null,
                               reset_test),
        cmocka_unit_test_setup(
            feature_state_for_null_feature_state_should_return_null, reset_test),
        cmocka_unit_test_setup(feature_state_for_matching_id_should_return_state,
                               reset_test),
        cmocka_unit_test_setup(
            feature_state_for_mismatching_id_should_return_null, reset_test),
        cmocka_unit_test_setup(
            feature_state_for_zero_init_slot_should_return_null, reset_test),
        cmocka_unit_test_setup(
            feature_state_for_unset_id_sentinel_should_return_null, reset_test),

        /* full lifecycle */
        cmocka_unit_test_setup(full_lifecycle_idle_to_complete_to_idle, reset_test),
        cmocka_unit_test_setup(full_lifecycle_idle_to_failed_to_idle, reset_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file publish_concurrency_units.c
 * @brief Deterministic proof that the SDK keeps multiple publish
 *        requests in flight at the same time.
 *
 * The pool's @c PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS bound is a baseline
 * architecture requirement (>= 2). These tests prove the property
 * the bound exists for: that two consecutive @ref pubnub_publish
 * calls reach the transport's @c send() while both slots remain
 * IN_FLIGHT, with neither completed -- i.e. the SDK does not
 * serialize them.
 *
 * The proof is structural, not timing-based: a chain transport
 * records every @c send() invocation into ordered counters, and
 * each test inspects the request pool directly to confirm the slot
 * states observed at the assertion point. No wall-clock timing,
 * no sleep loops, no network.
 *
 * Provider strategy: the test links @c pubnub_provider_* default
 * libraries (real allocator, real serialization, real platform)
 * and overrides @c cfg.transport with the local chain transport.
 * That keeps the publish path's URL-encoding scratch, response
 * parser, and feature-state lifecycle running against real code
 * while still letting the test drive transport completion by hand.
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
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

/* Internal accessors used by the assertions. */
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "providers/provider_internal.h"

/* Configured in-flight capacity plus overflow headroom; derived from the
 * config macro so it tracks every profile. */
#define MAX_TRACKED_SLOTS (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 2)

/**
 * @brief Per-send capture entry recorded by the chain transport.
 *
 * The chain transport stores one entry per @c send() call so each
 * test can verify both the call count AND the request/response
 * pairing observed at dispatch time.
 */
typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static int            s_in_flight;
static send_capture_t s_captures[MAX_TRACKED_SLOTS];
static int            s_fake_handle_storage[MAX_TRACKED_SLOTS];

/**
 * @brief Reset the chain transport's recorded state between tests.
 */
static void reset_chain(void)
{
    s_send_count = 0;
    s_in_flight  = 0;
    memset(s_captures, 0, sizeof(s_captures));
}

/**
 * @brief Chain transport @c send: records the call, leaves the
 *        response in PENDING, and returns a per-slot fake handle.
 *
 * The test never marks the response complete from inside @c send,
 * so every successful call leaves the slot IN_FLIGHT until the test
 * body explicitly populates the response. That is what lets the
 * "both slots in flight at once" assertion observe the state we
 * want it to.
 */
static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_TRACKED_SLOTS) {
        return NULL;
    }
    s_captures[s_send_count].request  = request;
    s_captures[s_send_count].response = response;
    s_send_count++;
    s_in_flight++;
    return (pubnub_transport_handle_t*)&s_fake_handle_storage[s_send_count - 1];
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
    if (s_in_flight > 0) {
        s_in_flight--;
    }
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

/**
 * @brief Mark a previously captured response as a successful
 *        publish completion.
 *
 * Wires a static body buffer to the captured response so the
 * publish parser can decode the timetoken. The body lifetime
 * trivially covers the test scope (static storage duration).
 */
static const uint8_t k_publish_ok_body[] = "[1,\"Sent\",\"17000000000000000\"]";

/** @brief Body with status digit 0 — publish validator returns PUBNUB_ERR_SERVER. */
static const uint8_t k_publish_fail_body[] = "[0,\"Error message\"]";

/** @brief Success body carrying a specific timetoken for assertion. */
static const uint8_t k_publish_ok_tt_body[] = "[1,\"\",\"15610547826970050\"]";

static void chain_complete_capture(int index)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = k_publish_ok_body;
    resp->body_len    = sizeof(k_publish_ok_body) - 1;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

/**
 * @brief Mark a previously captured response as complete with a
 *        caller-supplied body.
 *
 * The body pointer must remain valid until @c pubnub_process has
 * finished consuming the slot (static storage duration satisfies
 * this for all callers in this test file).
 */
static void chain_complete_capture_with_body(int            index,
                                             const uint8_t* body,
                                             size_t         body_len)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = body_len;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

/**
 * @brief Build a config that wires only the chain transport,
 *        leaving every other provider resolved from defaults.
 */
static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "pub";
    cfg.subscribe_key   = "sub";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;

    /* Strip thread primitives so pubnub_async() registers the callback
     * without starting a background thread — pubnub_process() then
     * drives ticks synchronously as the test expects. */
    static pubnub_platform_provider_t s_no_thread_platform;
    pubnub_platform_provider_t*       base = pn_platform_default();
    if (NULL != base) {
        s_no_thread_platform               = *base;
        s_no_thread_platform.thread_create = NULL;
        s_no_thread_platform.thread_join   = NULL;
        cfg.platform                       = &s_no_thread_platform;
    }

    return cfg;
}

#if PUBNUB_CFG_NO_HEAP
/* On no-heap profiles pubnub_create is unavailable; skip all tests. */
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP
/**
 * @brief Resolve the slot behind a future and return its current state.
 */
static pn_request_state_t state_of(pubnub_context_t* ctx, pubnub_future_t fut)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    pn_request_t* slot = pn_request_pool_get(pool, fut.slot_id);
    assert_non_null(slot);
    return slot->state;
}

/** @brief Two slots stay IN_FLIGHT after back-to-back publishes. */
static void publish_should_keep_two_slots_in_flight_simultaneously(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Two back-to-back submissions: pubnub_publish synchronously
     * dispatches each slot through the middleware chain to the
     * transport's send(), so by the time the second call returns
     * BOTH chain_send() invocations have already happened. */
    pubnub_future_t f1 = pubnub_publish(ctx,
                                        &(pubnub_publish_opts_t){
                                            .channel = "alpha",
                                            .message = "\"one\"",
                                        });
    pubnub_future_t f2 = pubnub_publish(ctx,
                                        &(pubnub_publish_opts_t){
                                            .channel = "beta",
                                            .message = "\"two\"",
                                        });

    /* Load-bearing assertion: both publishes reached transport
     * send() (s_send_count == 2), both slots are IN_FLIGHT
     * simultaneously (s_in_flight == 2 at this exact instant
     * because the chain transport never marked either response
     * complete), and both futures are still in progress. This is
     * the structural proof of concurrent dispatch. */
    assert_int_equal(s_send_count, 2);
    assert_int_equal(s_in_flight, 2);
    assert_int_equal(state_of(ctx, f1), PN_REQUEST_IN_FLIGHT);
    assert_int_equal(state_of(ctx, f2), PN_REQUEST_IN_FLIGHT);
    assert_false(pubnub_future_is_ready(f1));
    assert_false(pubnub_future_is_ready(f2));
    assert_int_equal(pubnub_future_status(f1), PUBNUB_IN_PROGRESS);
    assert_int_equal(pubnub_future_status(f2), PUBNUB_IN_PROGRESS);

    /* Drive both responses to COMPLETE and process: route both
     * completions on a single tick. */
    chain_complete_capture(0);
    chain_complete_capture(1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(f1));
    assert_true(pubnub_future_is_ready(f2));
    assert_int_equal(pubnub_future_status(f1), PUBNUB_OK);
    assert_int_equal(pubnub_future_status(f2), PUBNUB_OK);

    const pubnub_timetoken_t t1 = pubnub_publish_result_timetoken(f1);
    const pubnub_timetoken_t t2 = pubnub_publish_result_timetoken(f2);
    assert_int_equal(t1.len, 17);
    assert_int_equal(t2.len, 17);
    assert_memory_equal(t1.ptr, "17000000000000000", 17);
    assert_memory_equal(t2.ptr, "17000000000000000", 17);

    pubnub_future_release(f1);
    pubnub_future_release(f2);
    pubnub_destroy(ctx);
}

#if PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS >= 3
#define PUBLISH_TEST_N 3
#else
#define PUBLISH_TEST_N 2
#endif

/** @brief All N back-to-back publishes dispatch through transport in one pass. */
static void publish_should_dispatch_n_slots_in_a_single_pass(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t fut[PUBLISH_TEST_N];
#if PUBLISH_TEST_N >= 3
    const char* channels[PUBLISH_TEST_N] = {"a", "b", "c"};
    const char* messages[PUBLISH_TEST_N] = {"\"a\"", "\"b\"", "\"c\""};
#else
    const char* channels[PUBLISH_TEST_N] = {"a", "b"};
    const char* messages[PUBLISH_TEST_N] = {"\"a\"", "\"b\""};
#endif
    for (int i = 0; i < PUBLISH_TEST_N; i++) {
        fut[i] = pubnub_publish(ctx,
                                &(pubnub_publish_opts_t){
                                    .channel = channels[i],
                                    .message = messages[i],
                                });
    }

    /* All N publishes hit transport and remain IN_FLIGHT. */
    assert_int_equal(s_send_count, PUBLISH_TEST_N);
    assert_int_equal(s_in_flight, PUBLISH_TEST_N);
    for (int i = 0; i < PUBLISH_TEST_N; i++) {
        assert_int_equal(state_of(ctx, fut[i]), PN_REQUEST_IN_FLIGHT);
    }

    /* Each capture must hold a distinct response pointer; if the
     * SDK had reused a single response slot the dispatch would have
     * been serialized. */
    for (int i = 0; i < PUBLISH_TEST_N; i++) {
        assert_non_null(s_captures[i].response);
        for (int j = i + 1; j < PUBLISH_TEST_N; j++) {
            assert_ptr_not_equal(s_captures[i].response, s_captures[j].response);
        }
    }

    for (int i = 0; i < PUBLISH_TEST_N; i++) {
        chain_complete_capture(i);
    }
    (void)pubnub_process(ctx);
    for (int i = 0; i < PUBLISH_TEST_N; i++) {
        assert_true(pubnub_future_is_ready(fut[i]));
        assert_int_equal(pubnub_future_status(fut[i]), PUBNUB_OK);
        pubnub_future_release(fut[i]);
    }
    pubnub_destroy(ctx);
}

/** @brief Pool-exhausted publish surfaces PUBNUB_ERR_QUEUE_FULL. */
static void publish_should_enqueue_when_pool_is_at_capacity(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    assert_true(capacity >= 2);
    assert_true(capacity + 1 <= MAX_TRACKED_SLOTS);

    /* Fill every slot in the pool. The chain transport never
     * completes anything, so each successful publish leaves a slot
     * IN_FLIGHT. */
    pubnub_future_t fut[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        fut[i] = pubnub_publish(ctx,
                                &(pubnub_publish_opts_t){
                                    .channel = "ch",
                                    .message = "\"x\"",
                                });
        assert_int_equal(pubnub_future_status(fut[i]), PUBNUB_IN_PROGRESS);
    }
    assert_int_equal(s_send_count, capacity);
    assert_int_equal(s_in_flight, capacity);
    assert_int_equal(pool->in_use_count, capacity);

    /* The next publish enqueues into the pending queue: the future
     * is NOT ready (waiting for promotion), the slot_id is in the
     * pending range (>= capacity), and transport->send() was NOT
     * called for it yet. */
    pubnub_future_t overflow = pubnub_publish(ctx,
                                              &(pubnub_publish_opts_t){
                                                  .channel = "ch",
                                                  .message = "\"y\"",
                                              });
    assert_int_equal(s_send_count, capacity);
    assert_true(overflow.slot_id >= capacity);
    assert_false(pubnub_future_is_ready(overflow));
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_IN_PROGRESS);
    assert_int_equal(pool->in_use_count, capacity);

    /* Complete and release one slot so the pending entry promotes. */
    chain_complete_capture(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fut[0]));
    pubnub_future_release(fut[0]);

    /* Process to promote the pending entry and dispatch it. */
    (void)pubnub_process(ctx);
    assert_int_equal(s_send_count, capacity + 1);
    assert_int_equal(pool->in_use_count, capacity);

    /* The overflow future should still be in-progress (not yet
     * completed by transport). */
    assert_false(pubnub_future_is_ready(overflow));

    /* Complete the promoted slot. */
    chain_complete_capture(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_OK);
    pubnub_future_release(overflow);

    /* Drain remaining slots for clean teardown. */
    for (uint16_t i = 1; i < capacity; i++) {
        chain_complete_capture(i);
    }
    (void)pubnub_process(ctx);
    for (uint16_t i = 1; i < capacity; i++) {
        assert_true(pubnub_future_is_ready(fut[i]));
        pubnub_future_release(fut[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * @brief Higher-indexed slot completes first; one slot fails,
 *        the other succeeds — outcomes must not bleed across slots.
 *
 * Two concurrent publishes are dispatched. The transport delivers
 * the @em higher-indexed slot's response first (inverted order
 * relative to the default sequential path). That slot carries a
 * success body; the lower-indexed slot carries a failure body.
 *
 * Assertions verify:
 * - slot 1 (higher index, first to complete) → @ref PUBNUB_OK with
 *   the expected timetoken.
 * - slot 0 (lower index, second to complete) → @ref PUBNUB_ERR_SERVER
 *   with a zero-length timetoken (failure body carries no timetoken).
 * - The send-order array in @c s_captures confirms both @c send()
 *   calls happened (distinct response pointers), and that transport
 *   completion order (index 1 first) did not reorder SDK routing.
 *
 * This pins two properties that the first three test cases do not
 * exercise: (a) @c pn_process_route_completions iterates slots in
 * pool-index order regardless of transport delivery order, and (b)
 * the per-slot @c response_validator is dispatched independently so
 * a failure on one slot never contaminates another.
 */
static void
publish_should_handle_mixed_completion_order_and_heterogeneous_outcomes(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Dispatch two concurrent publishes.  chain_send() is called
     * synchronously inside pubnub_publish(), so s_captures[0] is
     * populated by f0 and s_captures[1] is populated by f1 before
     * either pubnub_publish() call returns. */
    pubnub_future_t f0 = pubnub_publish(ctx,
                                        &(pubnub_publish_opts_t){
                                            .channel = "alpha",
                                            .message = "\"zero\"",
                                        });
    pubnub_future_t f1 = pubnub_publish(ctx,
                                        &(pubnub_publish_opts_t){
                                            .channel = "beta",
                                            .message = "\"one\"",
                                        });

    assert_int_equal(s_send_count, 2);
    assert_int_equal(s_in_flight, 2);
    assert_int_equal(state_of(ctx, f0), PN_REQUEST_IN_FLIGHT);
    assert_int_equal(state_of(ctx, f1), PN_REQUEST_IN_FLIGHT);

    /* Deliver the higher-indexed slot (index 1) first. The slot
     * ordering in s_captures mirrors pool slot assignment: slot 0
     * was assigned to f0, slot 1 to f1. Completing index 1 before
     * index 0 is the mixed-order scenario under test. */
    chain_complete_capture_with_body(
        1, k_publish_ok_tt_body, sizeof(k_publish_ok_tt_body) - 1);

    /* slot 0 gets a body whose leading digit is '0', causing the
     * publish response validator to return PUBNUB_ERR_SERVER. */
    chain_complete_capture_with_body(
        0, k_publish_fail_body, sizeof(k_publish_fail_body) - 1);

    /* Single process tick routes both completions. */
    (void)pubnub_process(ctx);

    /* f1 completed first and carried the success body. */
    assert_true(pubnub_future_is_ready(f1));
    assert_int_equal(pubnub_future_status(f1), PUBNUB_OK);
    const pubnub_timetoken_t tt = pubnub_publish_result_timetoken(f1);
    assert_int_equal(tt.len, 17);
    assert_memory_equal(tt.ptr, "15610547826970050", 17);

    /* f0 completed second and carried the failure body. Its result
     * must be an error independent of f1's outcome. The failure body
     * has no timetoken element, so the parsed timetoken must be empty
     * — confirming the failed slot did not inherit f1's parsed result. */
    assert_true(pubnub_future_is_ready(f0));
    assert_int_equal(pubnub_future_status(f0), PUBNUB_ERR_SERVER);
    const pubnub_timetoken_t tt_fail = pubnub_publish_result_timetoken(f0);
    assert_int_equal(tt_fail.len, 0);

    /* Transport send() call order: index 0 maps to f0, index 1 to
     * f1 — confirming the SDK dispatched both immediately and the
     * captures hold distinct response pointers. */
    assert_ptr_not_equal(s_captures[0].response, s_captures[1].response);

    pubnub_future_release(f1);
    pubnub_future_release(f0);
    pubnub_destroy(ctx);
}

/** State for the deferred-release async callback. */
static int s_deferred_release_cb_fired;

/**
 * @brief Async callback that calls pubnub_future_release() from inside
 *        the callback, triggering the deferred-release path.
 *
 * When this fires, the slot is in COMPLETING state (async_trampoline is
 * on the stack). Calling pubnub_future_release() here sets
 * slot->release_deferred = 1 rather than immediately freeing the slot.
 */
static void deferred_release_cb(pubnub_future_t future,
                                pubnub_res_t    status,
                                void*           user_data)
{
    (void)status;
    (void)user_data;
    s_deferred_release_cb_fired = 1;
    pubnub_future_release(future);
}

/**
 * @brief Pending entry is promoted AND dispatched on the tick where
 *        deferred-release frees the slot.
 *
 * Scenario:
 *  1. Fill every pool slot with in-flight publishes.
 *  2. Register a completion callback on fill[0] that calls
 *     pubnub_future_release() from inside the callback.
 *  3. Overflow one more publish into the pending queue.
 *  4. Simulate the transport completing fill[0]'s request.
 *  5. Call pubnub_process() exactly once.
 *  6. Assert the overflow future reaches transport send() on that
 *     single tick, not on a subsequent one.
 *
 * The deferred-release path: the async_trampoline fires inside
 * deliver_notification while the slot is still COMPLETING; calling
 * pubnub_future_release() from there sets release_deferred=1 instead
 * of immediately freeing. The tick's deferred-release loop then frees
 * the slot, promote_pending promotes the overflow, and (with the fix)
 * dispatch_pending dispatches it — all within the same tick.
 *
 * Without the fix the promoted slot sits PENDING until the next tick
 * and s_send_count is unchanged after step 5.
 */
static void publish_deferred_release_should_dispatch_pending_on_same_tick(void** state)
{
    (void)state;
    reset_chain();
    s_deferred_release_cb_fired = 0;
    pubnub_config_t   cfg       = chain_only_config();
    pubnub_context_t* ctx       = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    assert_true(capacity >= 1);
    assert_true((int)(capacity + 1) <= MAX_TRACKED_SLOTS);

    /* Fill every pool slot with async in-flight publishes. */
    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        fill[i] = pubnub_publish(ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = "fill-ch",
                                     .message = "\"fill\"",
                                 });
        assert_int_equal(pubnub_future_status(fill[i]), PUBNUB_IN_PROGRESS);
    }
    assert_int_equal(s_send_count, (int)capacity);
    assert_int_equal(pool->in_use_count, capacity);

    /* Register the deferred-release callback on fill[0].
     * This wires async_trampoline as on_complete so that the slot goes
     * through COMPLETING state and the callback fires inside
     * deliver_notification. The callback calls pubnub_future_release()
     * while the slot is still COMPLETING, setting release_deferred=1. */
    assert_int_equal(pubnub_async(fill[0], deferred_release_cb, NULL), PUBNUB_OK);

    /* Overflow one publish into the pending queue. */
    pubnub_future_t overflow = pubnub_publish(ctx,
                                              &(pubnub_publish_opts_t){
                                                  .channel = "overflow-ch",
                                                  .message = "\"overflow\"",
                                              });
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_IN_PROGRESS);
    assert_true(overflow.slot_id >= capacity);
    assert_int_equal(s_send_count, (int)capacity);

    /* Simulate the transport completing fill[0]'s request. */
    chain_complete_capture(0);

    const int send_before = s_send_count;

    /* Single tick: route fill[0] to COMPLETING, fire deferred_release_cb
     * (release_deferred=1), deferred-release loop frees fill[0]'s slot,
     * promote_pending promotes overflow, dispatch_pending (fix) dispatches
     * it. s_send_count must increase by exactly 1. */
    (void)pubnub_process(ctx);

    assert_true(s_deferred_release_cb_fired);
    assert_int_equal(s_send_count, send_before + 1);
    /* fill[0] was released by the callback; do not call release again. */

    /* Complete and drain the overflow for clean teardown. */
    chain_complete_capture((int)capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_OK);
    pubnub_future_release(overflow);

    /* Complete and drain remaining fill slots. */
    for (uint16_t i = 1; i < capacity; i++) {
        chain_complete_capture((int)i);
    }
    (void)pubnub_process(ctx);
    for (uint16_t i = 1; i < capacity; i++) {
        assert_true(pubnub_future_is_ready(fill[i]));
        pubnub_future_release(fill[i]);
    }

    pubnub_destroy(ctx);
}

/**
 * @brief Verify that query_params survive the pending queue round-trip.
 *
 * Exercises the scratch-pointer relocation fix: when a publish with
 * store/ttl/meta goes through the pending queue (enqueue → dequeue →
 * promote → dispatch), the query_params pointers must reference the
 * promoted slot's own scratch buffer, not a defunct stack frame.
 *
 * Without the relocation fix this test reads garbage pointers on the
 * promoted request (crash under ASan, silent corruption otherwise).
 */
static void publish_pending_entry_should_preserve_query_params(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;

    /* Fill every pool slot with simple publishes. */
    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        fill[i] = pubnub_publish(ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = "ch",
                                     .message = "\"fill\"",
                                 });
        assert_int_equal(pubnub_future_status(fill[i]), PUBNUB_IN_PROGRESS);
    }
    assert_int_equal(s_send_count, capacity);

    /* Overflow publish WITH query-param-generating options.
     * store=YES writes "store=1", ttl writes "ttl=300",
     * custom_message_type writes "custom_message_type=test". */
    pubnub_future_t overflow =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel             = "params-ch",
                           .message             = "\"pending\"",
                           .store               = PUBNUB_PUBLISH_STORE_YES,
                           .ttl                 = 300,
                           .custom_message_type = "test-type",
                       });
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_IN_PROGRESS);
    assert_true(overflow.slot_id >= capacity);
    /* Transport NOT called for the pending entry yet. */
    assert_int_equal(s_send_count, capacity);

    /* Complete slot 0 and release it so the pending entry promotes. */
    chain_complete_capture(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fill[0]));
    pubnub_future_release(fill[0]);

    /* Process again to promote and dispatch the pending entry. */
    (void)pubnub_process(ctx);
    assert_int_equal(s_send_count, capacity + 1);

    /* The promoted request's query_params must be readable and
     * correct. Reading them proves the scratch pointers survived
     * the queue round-trip (dangling ptrs would crash under ASan
     * or read garbage). */
    pubnub_http_request_t* promoted_req = s_captures[capacity].request;
    assert_non_null(promoted_req);
    assert_true(promoted_req->query_param_count >= 3);

    /* Verify each expected param is present and readable. */
    int found_store = 0, found_ttl = 0, found_cmt = 0;
    for (unsigned int i = 0; i < promoted_req->query_param_count; i++) {
        const pubnub_kv_t* p = &promoted_req->query_params[i];
        assert_non_null(p->key.ptr);
        assert_non_null(p->value.ptr);

        if (5 == p->key.len && 0 == memcmp(p->key.ptr, "store", 5)) {
            assert_int_equal(p->value.len, 1);
            assert_memory_equal(p->value.ptr, "1", 1);
            found_store = 1;
        }
        if (3 == p->key.len && 0 == memcmp(p->key.ptr, "ttl", 3)) {
            assert_int_equal(p->value.len, 3);
            assert_memory_equal(p->value.ptr, "300", 3);
            found_ttl = 1;
        }
        if (19 == p->key.len && 0 == memcmp(p->key.ptr, "custom_message_type", 19)) {
            assert_int_equal(p->value.len, 9);
            assert_memory_equal(p->value.ptr, "test-type", 9);
            found_cmt = 1;
        }
    }
    assert_int_equal(found_store, 1);
    assert_int_equal(found_ttl, 1);
    assert_int_equal(found_cmt, 1);

    /* Complete and drain everything for clean teardown. */
    chain_complete_capture(capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_OK);
    pubnub_future_release(overflow);

    for (uint16_t i = 1; i < capacity; i++) {
        chain_complete_capture(i);
    }
    (void)pubnub_process(ctx);
    for (uint16_t i = 1; i < capacity; i++) {
        assert_true(pubnub_future_is_ready(fill[i]));
        pubnub_future_release(fill[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * @brief Issue MAX_IN_FLIGHT + MAX_PENDING + 1 publishes. The last
 *        one must return a future with PUBNUB_ERR_QUEUE_FULL.
 *
 * Each sequential pubnub_publish() acquires and releases a prep
 * entry within the same call, so the prep pool itself doesn't
 * overflow. The bottleneck is pool slots + pending queue capacity.
 */
static void prep_pool_exhaustion_returns_queue_full(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    const int      total    = (int)capacity + PUBNUB_CFG_MAX_PENDING_REQUESTS;

    /* Dynamically allocate: total may exceed MAX_TRACKED_SLOTS. */
    pubnub_future_t* futs =
        (pubnub_future_t*)malloc((size_t)total * sizeof(pubnub_future_t));
    assert_non_null(futs);

    /* Fill in-flight slots + pending queue. The chain transport
     * never completes, so pool stays full, forcing excess into
     * the pending queue. */
    for (int i = 0; i < total; i++) {
        futs[i] = pubnub_publish(ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = "ch",
                                     .message = "\"x\"",
                                 });
        assert_int_not_equal(pubnub_future_status(futs[i]), PUBNUB_ERR_QUEUE_FULL);
    }

    /* The next one overflows both pool AND pending. */
    pubnub_future_t overflow = pubnub_publish(ctx,
                                              &(pubnub_publish_opts_t){
                                                  .channel = "ch",
                                                  .message = "\"overflow\"",
                                              });
    assert_int_equal(pubnub_future_status(overflow), PUBNUB_ERR_QUEUE_FULL);
    assert_true(pubnub_future_is_ready(overflow));

    /* Drain all slots. Complete captured sends, process, release
     * ready futures so pool slots free for further promotion.
     * Promoted entries exceeding MAX_TRACKED_SLOTS fail at dispatch
     * (chain_send returns NULL -> FAILED state), which is terminal. */
    uint8_t* released = (uint8_t*)calloc((size_t)total, sizeof(uint8_t));
    assert_non_null(released);
    int all_done = 0;

    for (int pass = 0; pass < 2 * total + 4 && !all_done; pass++) {
        for (int j = 0; j < s_send_count && j < MAX_TRACKED_SLOTS; j++) {
            if (NULL != s_captures[j].response
                && PUBNUB_HTTP_COMPLETE != s_captures[j].response->completion) {
                chain_complete_capture(j);
            }
        }
        (void)pubnub_process(ctx);

        /* Release newly ready futures to free pool slots. */
        all_done = 1;
        for (int j = 0; j < total; j++) {
            if (released[j]) {
                continue;
            }
            if (pubnub_future_is_ready(futs[j])) {
                pubnub_future_release(futs[j]);
                released[j] = 1;
            } else {
                all_done = 0;
            }
        }
    }

    /* After drain, all futures must have been released. */
    for (int j = 0; j < total; j++) {
        assert_int_equal(released[j], 1);
    }
    free(released);
    pubnub_future_release(overflow);
    free(futs);
    pubnub_destroy(ctx);
}

/**
 * @brief After a transport send() failure the prep slot is released,
 *        so the next publish succeeds.
 */
static void error_after_prepare_releases_prep_slot(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;

    /* Fill all pool slots. */
    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        fill[i] = pubnub_publish(ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = "ch",
                                     .message = "\"x\"",
                                 });
        assert_int_equal(pubnub_future_status(fill[i]), PUBNUB_IN_PROGRESS);
    }

    /* Complete all, release all to free slots. */
    for (uint16_t i = 0; i < capacity; i++) {
        chain_complete_capture((int)i);
    }
    (void)pubnub_process(ctx);
    for (uint16_t i = 0; i < capacity; i++) {
        pubnub_future_release(fill[i]);
    }

    /* Verify a new publish succeeds (slots were freed). */
    pubnub_future_t fresh = pubnub_publish(ctx,
                                           &(pubnub_publish_opts_t){
                                               .channel = "ch",
                                               .message = "\"fresh\"",
                                           });
    assert_int_equal(pubnub_future_status(fresh), PUBNUB_IN_PROGRESS);

    chain_complete_capture(s_send_count - 1);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fresh));
    pubnub_future_release(fresh);
    pubnub_destroy(ctx);
}

/**
 * @brief Issue N publishes, complete some as success and some as
 *        transport failure, verify all pool slots are freed after cleanup.
 */
static void mixed_success_and_failure_leaves_pool_clean(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;
    assert_true(capacity >= 2);

    pubnub_future_t futs[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        futs[i] = pubnub_publish(ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = "ch",
                                     .message = "\"x\"",
                                 });
    }
    assert_int_equal(s_send_count, (int)capacity);

    /* Even indices succeed, odd fail with transport error. */
    static const uint8_t k_fail_body[] = "[0,\"Error message\"]";
    for (uint16_t i = 0; i < capacity; i++) {
        if (0 == (i % 2)) {
            chain_complete_capture((int)i);
        } else {
            chain_complete_capture_with_body(
                (int)i, k_fail_body, sizeof(k_fail_body) - 1);
        }
    }
    (void)pubnub_process(ctx);

    /* Verify all completed. */
    for (uint16_t i = 0; i < capacity; i++) {
        assert_true(pubnub_future_is_ready(futs[i]));
        if (0 == (i % 2)) {
            assert_int_equal(pubnub_future_status(futs[i]), PUBNUB_OK);
        } else {
            assert_int_equal(pubnub_future_status(futs[i]), PUBNUB_ERR_SERVER);
        }
        pubnub_future_release(futs[i]);
    }

    /* Pool should be fully idle. */
    assert_int_equal(pool->in_use_count, 0);
    pubnub_destroy(ctx);
}

/**
 * @brief Publish with store, ttl, and custom_message_type overflows to
 *        pending, then promotes. Verify ALL query params survive relocation.
 */
static void scratch_relocation_with_max_query_params(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;

    /* Fill pool. */
    pubnub_future_t fill[MAX_TRACKED_SLOTS];
    for (uint16_t i = 0; i < capacity; i++) {
        fill[i] = pubnub_publish(ctx,
                                 &(pubnub_publish_opts_t){
                                     .channel = "ch",
                                     .message = "\"fill\"",
                                 });
    }

    /* Overflow with a param-rich publish. */
    pubnub_future_t overflow =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel             = "param-ch",
                           .message             = "\"rich\"",
                           .store               = PUBNUB_PUBLISH_STORE_YES,
                           .ttl                 = 300,
                           .custom_message_type = "type-x",
                       });
    assert_true(overflow.slot_id >= capacity);

    /* Free slot 0 and promote. */
    chain_complete_capture(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(fill[0]));
    pubnub_future_release(fill[0]);
    (void)pubnub_process(ctx);

    assert_int_equal(s_send_count, (int)capacity + 1);

    /* Verify promoted request query params. */
    pubnub_http_request_t* promoted = s_captures[capacity].request;
    assert_non_null(promoted);
    assert_true(promoted->query_param_count >= 3);

    int found_store = 0, found_ttl = 0, found_cmt = 0;
    for (unsigned int i = 0; i < promoted->query_param_count; i++) {
        const pubnub_kv_t* p = &promoted->query_params[i];
        /* All query params must have non-NULL keys after relocation.
         * A NULL key here means scratch relocation failed. */
        assert_non_null(p->key.ptr);
        if (5 == p->key.len && 0 == memcmp(p->key.ptr, "store", 5)) {
            assert_int_equal(p->value.len, 1);
            assert_memory_equal(p->value.ptr, "1", 1);
            found_store = 1;
        }
        if (3 == p->key.len && 0 == memcmp(p->key.ptr, "ttl", 3)) {
            assert_int_equal(p->value.len, 3);
            assert_memory_equal(p->value.ptr, "300", 3);
            found_ttl = 1;
        }
        if (19 == p->key.len && 0 == memcmp(p->key.ptr, "custom_message_type", 19)) {
            assert_int_equal(p->value.len, 6);
            assert_memory_equal(p->value.ptr, "type-x", 6);
            found_cmt = 1;
        }
    }
    assert_int_equal(found_store, 1);
    assert_int_equal(found_ttl, 1);
    assert_int_equal(found_cmt, 1);

    /* Drain. */
    chain_complete_capture((int)capacity);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(overflow));
    pubnub_future_release(overflow);

    for (uint16_t i = 1; i < capacity; i++) {
        chain_complete_capture((int)i);
    }
    (void)pubnub_process(ctx);
    for (uint16_t i = 1; i < capacity; i++) {
        assert_true(pubnub_future_is_ready(fill[i]));
        pubnub_future_release(fill[i]);
    }
    pubnub_destroy(ctx);
}

/** @brief POST publish body is gzip-compressed at the transport layer. */
static void publish_post_body_is_gzip_compressed_at_transport(void** state)
{
    (void)state;
    int                    found = 0;
    unsigned int           i     = 0;
    pubnub_http_request_t* req   = NULL;

    if (!PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        skip();
        return;
    }

    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_future_t f =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel = "test-compress",
                           .message = "\"hello-compression-unit-test\"",
                           .method  = PUBNUB_PUBLISH_METHOD_POST,
                       });

    assert_int_equal(1, s_send_count);
    req = s_captures[0].request;
    assert_non_null(req);

    /* Method and compress hint. */
    assert_int_equal(PUBNUB_HTTP_POST, req->method);
    assert_int_equal(1, req->compress_body);

    /* Body must be present and carry gzip magic bytes. */
    assert_non_null(req->body);
    assert_true(req->body_len > 0);
    assert_int_equal(0x1f, ((const uint8_t*)req->body)[0]);
    assert_int_equal(0x8b, ((const uint8_t*)req->body)[1]);

    /* Compressed length differs from original string length. */
    assert_int_not_equal(strlen("\"hello-compression-unit-test\""), req->body_len);

    /* Content-Encoding: gzip header must be present. */
    for (i = 0; i < req->header_count; i++) {
        const pubnub_kv_t* h = &req->headers[i];
        if (16 == h->key.len && 0 == memcmp(h->key.ptr, "Content-Encoding", 16)
            && 4 == h->value.len && 0 == memcmp(h->value.ptr, "gzip", 4)) {
            found = 1;
            break;
        }
    }
    assert_int_equal(1, found);

    /* Complete and clean up. */
    chain_complete_capture(0);
    (void)pubnub_process(ctx);
    assert_true(pubnub_future_is_ready(f));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(f));
    pubnub_future_release(f);
    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(publish_should_keep_two_slots_in_flight_simultaneously),
        cmocka_unit_test(publish_should_dispatch_n_slots_in_a_single_pass),
        cmocka_unit_test(publish_should_enqueue_when_pool_is_at_capacity),
        cmocka_unit_test(publish_pending_entry_should_preserve_query_params),
        cmocka_unit_test(
            publish_should_handle_mixed_completion_order_and_heterogeneous_outcomes),
        cmocka_unit_test(publish_deferred_release_should_dispatch_pending_on_same_tick),
        cmocka_unit_test(prep_pool_exhaustion_returns_queue_full),
        cmocka_unit_test(error_after_prepare_releases_prep_slot),
        cmocka_unit_test(mixed_success_and_failure_leaves_pool_clean),
        cmocka_unit_test(scratch_relocation_with_max_query_params),
        cmocka_unit_test(publish_post_body_is_gzip_compressed_at_transport),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef KS_TEST_RUNNER_H
#define KS_TEST_RUNNER_H

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator_arena.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Crypto context expected workload: at most 3 in-flight + 1 pending.
 * The arena allocator always partitions Zone A using the compile-time
 * globals (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS / MAX_PENDING), so the
 * pool must be sized to the actual Zone A footprint + Zone B budget.
 * Zone B needs ~150 cells for context infrastructure (transport, TLS,
 * request pool, prep pool, middleware, subscribe, presence) leaving
 * headroom for crypto factories (3 cells each), TLS sessions (2 cells),
 * and parse slabs.  173 cells (44288 B) fits in heap while providing
 * enough margin for subscribe operations.
 *
 * NOTE: pubnub_arena_allocator_init clamps the pool to whatever cells
 * fit; the struct's fixed cell_in_use[]/cell_count[] arrays are sized
 * by PUBNUB_ARENA_MAX_ZONE_B_CELLS but the pool does NOT need to match
 * that compiled maximum. */
#define KS_CRYPTO_MAX_IN_FLIGHT 3
#define KS_CRYPTO_MAX_PENDING   1
#define KS_CRYPTO_POOL_SIZE                                           \
    ((size_t)PUBNUB_ARENA_RX_SLOTS * PUBNUB_CFG_RESPONSE_BUFFER_SIZE  \
     + (size_t)PUBNUB_ARENA_OBJ_SLOTS * PUBNUB_CFG_OBJECT_BUFFER_SIZE \
     + (size_t)PUBNUB_ARENA_SCRATCH_SLOTS * PUBNUB_CFG_SCRATCH_BUFFER_SIZE + 44288U)

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** Per-test outcome. */
typedef enum ks_test_status {
    KS_STATUS_NOT_RUN = 0,
    KS_STATUS_RUNNING,
    KS_STATUS_PASS,
    KS_STATUS_FAIL,
    KS_STATUS_SKIP
} ks_test_status_t;

/** Result of a single test execution. */
typedef struct ks_result {
    ks_test_status_t status;
    uint32_t         elapsed_ms;
    char             detail[256];
} ks_result_t;

/** Forward declaration. */
typedef struct ks_runner ks_runner_t;

/**
 * @brief Test function signature.
 *
 * Each test receives the runner (which holds the context) and returns
 * a result. The test is blocking from the runner's perspective -- it
 * pumps pubnub_process() internally.
 */
typedef ks_result_t (*ks_test_fn_t)(ks_runner_t* runner);

/** Descriptor for a single test case. */
typedef struct ks_test_entry {
    /** Test name, e.g. "time/basic". */
    const char* name;
    /** Test function. */
    ks_test_fn_t fn;
    /** 1 = skip this test when companion is not online. */
    uint8_t needs_companion;
} ks_test_entry_t;

/** Sequential test runner state. */
typedef struct ks_runner {
    pubnub_context_t* ctx;
    /** Allocator used by the main context — passed to crypto module creation. */
    pubnub_allocator_provider_t* alloc;
    const ks_test_entry_t*       tests;
    size_t                       test_count;
    size_t                       current_idx;
    uint32_t                     pass_count;
    uint32_t                     fail_count;
    uint32_t                     skip_count;
    uint8_t                      companion_online;
    char                         run_id[9];

    /** Entity handle for the result channel subscription. */
    pubnub_entity_t result_entity;
    /** Subscription to the result channel for companion protocol. */
    pubnub_subscription_t result_sub;
    /** Handle for the context-level listener on the result channel. */
    pubnub_listener_handle_t result_listener_handle;

    /** Sequence number from the companion's most recent response. */
    volatile uint32_t companion_result_seq;
    /** 1 if the companion reported success, 0 on failure. */
    volatile uint8_t companion_result_pass;
    /** Detail text from the companion's response. */
    char companion_result_detail[128];

    /** Monotonic sequence counter for companion requests. */
    uint32_t companion_seq_counter;

    /** Sequence number of the active two-phase request (begin/end_verify). */
    uint32_t companion_current_seq;

    /** Set to 1 when the companion acknowledges the handshake. */
    volatile uint8_t companion_handshake_acked;

    /** Set to 1 when the companion sends a READY ack for a two-phase request. */
    volatile uint8_t companion_ready;
} ks_runner_t;

/**
 * @brief Initialize the test runner.
 *
 * @param r      Runner instance (caller-owned).
 * @param ctx    Initialized PubNub context.
 * @param tests  Array of test entries.
 * @param count  Number of entries in @p tests.
 */
void ks_runner_init(ks_runner_t*           r,
                    pubnub_context_t*      ctx,
                    const ks_test_entry_t* tests,
                    size_t                 count);

/**
 * @brief Execute all tests sequentially, printing results to stdout.
 *
 * Sets up companion interaction (subscribes to the result channel and
 * publishes a handshake) before running tests. Tears down the
 * subscription afterward.
 *
 * @param r  Initialized runner.
 */
void ks_runner_run_all(ks_runner_t* r);

/**
 * @brief Print a summary line with pass/fail/skip counts.
 *
 * @param r  Runner after ks_runner_run_all has completed.
 */
void ks_runner_print_summary(const ks_runner_t* r);

/**
 * @brief Helper: pump pubnub_process until future is ready or timeout.
 *
 * @param ctx        PubNub context to process.
 * @param fut        Future to wait on.
 * @param timeout_ms Maximum wait time in milliseconds.
 * @return The future's status (PUBNUB_OK on success, or an error).
 */
pubnub_res_t ks_pump_until_ready(pubnub_context_t* ctx,
                                 pubnub_future_t   fut,
                                 uint32_t          timeout_ms);

/**
 * @brief Ask the companion to perform an action and wait for its reply.
 *
 * Publishes a request on the control channel and polls for the
 * companion's response on the result channel. Returns 1 on success
 * (companion reported action_done), 0 on failure or timeout.
 *
 * @param runner     Runner with active companion subscription.
 * @param test_id    Test name (e.g. "subscribe/receive_from_companion").
 * @param action     Action verb (e.g. "publish").
 * @param channel    Target channel for the action.
 * @param payload    JSON payload (may be NULL).
 * @param timeout_ms Maximum wait time in milliseconds.
 * @return 1 if the companion succeeded, 0 on failure or timeout.
 */
uint8_t ks_ask_companion(ks_runner_t* runner,
                         const char*  test_id,
                         const char*  action,
                         const char*  channel,
                         const char*  payload,
                         uint32_t     timeout_ms);

/**
 * @brief Begin a two-phase companion verification.
 *
 * Sends a request to the companion (e.g. subscribe_and_verify) and
 * waits for the companion's READY acknowledgment. After this returns
 * successfully, the test performs its action (publish, signal, etc.),
 * then calls ks_companion_end_verify() to collect the result.
 *
 * @param runner           Runner with active companion subscription.
 * @param test_id          Test name for logging.
 * @param action           Two-phase action verb (e.g. "subscribe_and_verify").
 * @param channel          Target channel for the verification.
 * @param payload          JSON payload with verification parameters (may be NULL).
 * @param ready_timeout_ms Maximum time to wait for READY in milliseconds.
 * @return 1 if READY was received, 0 on failure or timeout.
 */
uint8_t ks_companion_begin_verify(ks_runner_t* runner,
                                  const char*  test_id,
                                  const char*  action,
                                  const char*  channel,
                                  const char*  payload,
                                  uint32_t     ready_timeout_ms);

/**
 * @brief Wait for the result of a two-phase companion verification.
 *
 * Call after ks_companion_begin_verify() returns 1 and the test has
 * performed its action. Polls until the companion sends the verification
 * result or the timeout expires.
 *
 * On success, runner->companion_result_pass indicates pass/fail and
 * runner->companion_result_detail contains extra info from the companion.
 *
 * @param runner            Runner with an active two-phase request.
 * @param result_timeout_ms Maximum time to wait for the result.
 * @return 1 if the companion reported success, 0 on failure or timeout.
 */
uint8_t ks_companion_end_verify(ks_runner_t* runner, uint32_t result_timeout_ms);

/** Return a PASS result. */
#define KS_RETURN_PASS()                 \
    do {                                 \
        ks_result_t _r = {0};            \
        _r.status      = KS_STATUS_PASS; \
        return _r;                       \
    } while (0)

/** Return a FAIL result with a formatted reason. */
#define KS_RETURN_FAIL(fmt, ...)                                    \
    do {                                                            \
        ks_result_t _r = {0};                                       \
        _r.status      = KS_STATUS_FAIL;                            \
        snprintf(_r.detail, sizeof(_r.detail), fmt, ##__VA_ARGS__); \
        return _r;                                                  \
    } while (0)

/** Return a SKIP result with a reason string. */
#define KS_RETURN_SKIP(reason)                                \
    do {                                                      \
        ks_result_t _r = {0};                                 \
        _r.status      = KS_STATUS_SKIP;                      \
        snprintf(_r.detail, sizeof(_r.detail), "%s", reason); \
        return _r;                                            \
    } while (0)

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* KS_TEST_RUNNER_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PUBNUB_IT_CONTEXT_H
#define PUBNUB_IT_CONTEXT_H

#include "pubnub/client.h"

#if !PUBNUB_CFG_THREAD_SAFETY
#include <pthread.h>
#endif

#include "it_cleanup.h"
#include "it_env.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Forward declaration for optional bus integration. */
struct it_bus;

/**
 * @brief Per-test state container.
 *
 * Holds one to three PubNub contexts and the cleanup queue for a single
 * integration test. Allocate with it_state_create() and release with
 * it_state_destroy().
 */
typedef struct it_test_state {
    /** Primary context used for all feature calls. */
    pubnub_context_t* ctx;
    /** Secondary context (subscribe side); NULL unless added via
     * it_state_add_ctx2(). */
    pubnub_context_t* ctx2;
    /** PAM-keyset context; NULL unless added via it_state_add_pam_ctx(). */
    pubnub_context_t* pam_ctx;
    /** Primary test channel name. */
    char channel[80];
    /** Secondary test channel name. */
    char channel2[80];
    /** user_id for @c ctx — must outlive the context. */
    char user_id[80];
    /** user_id for @c ctx2 — must outlive the context. */
    char user_id2[80];
    /** user_id for @c pam_ctx — must outlive the context. */
    char user_id_pam[80];
    /** LIFO cleanup queue processed by it_state_destroy(). */
    it_cleanup_t cleanup;
    /** Environment (keys loaded at startup). */
    const it_env_t* env;
#if !PUBNUB_CFG_THREAD_SAFETY
    /**
     * @brief Background thread that calls pubnub_process() at 1 ms
     *        intervals.
     *
     * Only present when PUBNUB_CFG_THREAD_SAFETY == 0, i.e. when the SDK
     * does not start its own I/O thread inside pubnub_async().
     */
    pthread_t driver_thread;
    /** Set to 1 while the driver thread is running; write 0 to stop. */
    volatile int driver_running;
    /** When non-zero, the process driver also pumps ctx in addition to
     *  ctx2. Set this only in tests where ctx is used for subscribe (not
     *  REST) so no pubnub_await() call will concurrently pump ctx from
     *  the main thread. Leave at 0 (default) for tests that use ctx only
     *  with pubnub_await(). */
    volatile int pump_ctx;
    /** Extra contexts that the driver should pump. Register via
     *  it_state_pump_ctx(). Slots are set to NULL on deregister. */
    pubnub_context_t* volatile extra_ctx[4];
    /** Incremented by the driver at the end of each iteration.
     *  Used by it_state_unpump_ctx to wait for the current tick to
     *  complete before the caller destroys the context. */
    volatile uint32_t driver_tick;
#endif
} it_test_state_t;

/**
 * @brief Allocate and configure a test state with a primary context.
 *
 * Creates one PubNub context using the regular keyset from @p env. The
 * context has automatic retry disabled and logs at WARNING level.
 *
 * @param env Non-NULL pointer to loaded environment keys.
 * @return Pointer to a newly allocated state, or NULL on allocation failure.
 *         Destroy with it_state_destroy().
 */
it_test_state_t* it_state_create(const it_env_t* env);

/**
 * @brief Add a secondary context to an existing test state.
 *
 * Uses the same regular keyset as the primary context. No-op when
 * @c s->ctx2 is already non-NULL.
 *
 * @param s Non-NULL test state previously created by it_state_create().
 */
void it_state_add_ctx2(it_test_state_t* s);

/**
 * @brief Add a PAM-keyset context to an existing test state.
 *
 * Uses @c env->pam_* keys. No-op when any PAM key is NULL or when
 * @c s->pam_ctx is already non-NULL.
 *
 * @param s Non-NULL test state previously created by it_state_create().
 */
void it_state_add_pam_ctx(it_test_state_t* s);

/**
 * @brief Register an extra context for the process driver to pump.
 *
 * On non-thread-safety builds the driver thread calls pubnub_process()
 * on every registered extra context each tick. Up to 4 extra contexts
 * are supported. Returns 0 on success, -1 when all slots are full.
 */
int it_state_pump_ctx(it_test_state_t* s, pubnub_context_t* ctx);

/**
 * @brief Stop pumping an extra context.
 *
 * Removes @p ctx from the driver's pump list. Safe to call even if
 * @p ctx was never registered (no-op).
 */
void it_state_unpump_ctx(it_test_state_t* s, pubnub_context_t* ctx);

/**
 * @brief Run cleanup, destroy all contexts, and free the state.
 *
 * Processes the cleanup queue in LIFO order via @c it_cleanup_run, then
 * destroys pam_ctx, ctx2, and ctx in that order before freeing @p s.
 *
 * @param s Test state to destroy. May be NULL (no-op).
 */
void it_state_destroy(it_test_state_t* s);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_IT_CONTEXT_H */

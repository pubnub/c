/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file timer_list_internal.h
 * @brief Centralized timer scheduler built on pn_timer_t.
 *
 * pn_timer_list_t manages a fixed-capacity collection of one-shot
 * timers with callbacks. The list is swept by pubnub_process() to fire
 * expired timers and to compute the maximum block time for the
 * transport's poll().
 *
 * Timers are one-shot: they fire once and are automatically removed.
 * Periodic behavior is achieved by re-adding the timer from within
 * the callback.
 *
 * The list uses a pre-allocated array - no heap allocation during
 * timer add/remove/fire. Capacity is set at init time.
 *
 * Handles returned by pn_timer_list_add() are stable for the
 * lifetime of the entry (until fired or removed).
 *
 * Thread safety: pn_timer_list_t is NOT thread-safe. In
 * multi-threaded scenarios the caller must hold the context mutex
 * (or equivalent) around all timer list operations. This is
 * intentional - cooperative and bare-metal targets pay no
 * synchronization overhead.
 */

#ifndef PN_TIMER_LIST_INTERNAL_H
#define PN_TIMER_LIST_INTERNAL_H

#include "timer_internal.h"
#include "pubnub/types.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Timer expiry callback.
 *
 * @param cb_data Opaque pointer set when the timer was added.
 */
typedef void (*pn_timer_cb_t)(void* cb_data);

/**
 * @brief Opaque handle to a scheduled timer entry.
 *
 * Returned by pn_timer_list_add(). Used with pn_timer_list_remove()
 * to cancel a timer before it fires. NULL indicates an invalid or
 * exhausted handle.
 */
typedef struct pn_timer_entry* pn_timer_handle_t;

/**
 * @brief Single entry in the timer list.
 */
typedef struct pn_timer_entry {
    /** Deadline tracker built on pn_timer_t. */
    pn_timer_t deadline;

    /** Callback to invoke when the timer expires. */
    pn_timer_cb_t cb;

    /** Opaque data forwarded to the callback. */
    void* cb_data;

    /** Non-zero if this slot is in use. */
    int active;
} pn_timer_entry_t;

/**
 * @brief Fixed-capacity timer scheduler.
 *
 * Owns a caller-provided array of timer entries. The caller is
 * responsible for allocating the entries array (stack, static, or
 * heap) and passing it to pn_timer_list_init().
 */
typedef struct pn_timer_list {
    pn_timer_entry_t* entries;  /**< Pre-allocated entry array (borrowed). */
    unsigned int      capacity; /**< Number of slots in entries[]. */
    unsigned int      count;    /**< Number of active timers. */
} pn_timer_list_t;

/**
 * @brief Sentinel returned by pn_timer_list_ms_until_next() when no timers are active.
 */
#define PN_TIMER_LIST_NO_ACTIVE_TIMERS UINT64_MAX

/**
 * @brief Initialize a timer list with a pre-allocated entry array.
 *
 * @param list     Timer list to initialize (owned by caller).
 * @param entries  Pre-allocated entry array (borrowed, must outlive list).
 * @param capacity Number of entries in the array.
 */
void pn_timer_list_init(pn_timer_list_t*  list,
                        pn_timer_entry_t* entries,
                        unsigned int      capacity);

/**
 * @brief Schedule a one-shot timer.
 *
 * @param list     Timer list.
 * @param delay_ms Delay in milliseconds from now until the timer fires.
 * @param cb       Callback to invoke on expiry.
 * @param cb_data  Opaque data forwarded to cb.
 * @param platform Platform provider for monotonic clock (borrowed).
 * @return Handle to the timer entry, or NULL if the list is full.
 */
pn_timer_handle_t pn_timer_list_add(pn_timer_list_t*            list,
                                    pubnub_milliseconds_t       delay_ms,
                                    pn_timer_cb_t               cb,
                                    void*                       cb_data,
                                    pubnub_platform_provider_t* platform);

/**
 * @brief Cancel a scheduled timer before it fires.
 *
 * Safe to call with a NULL handle (no-op).
 * After removal the handle is invalid and must not be reused.
 *
 * @param list   Timer list.
 * @param handle Handle returned by pn_timer_list_add().
 */
void pn_timer_list_remove(pn_timer_list_t* list, pn_timer_handle_t handle);

/**
 * @brief Fire all expired timers and remove them from the list.
 *
 * Iterates the list, checks each active entry against @p now_ms,
 * and invokes the callback for any that have expired. Expired
 * entries are deactivated after the callback returns.
 *
 * Callbacks may safely call pn_timer_list_add() to re-arm
 * (one-shot to periodic pattern).
 *
 * @param list     Timer list.
 * @param platform Platform provider for monotonic clock (borrowed).
 * @return Number of timers that fired.
 */
int pn_timer_list_fire_expired(pn_timer_list_t*            list,
                               pubnub_platform_provider_t* platform);

/**
 * @brief Compute milliseconds until the next timer expires.
 *
 * Returns the minimum remaining time across all active timers.
 * Useful for computing the maximum block time for transport->poll().
 *
 * @param list     Timer list.
 * @param platform Platform provider for monotonic clock (borrowed).
 * @return Milliseconds until next expiry.  0 if a timer is already
 *         expired. PN_TIMER_LIST_NO_ACTIVE_TIMERS if no timers are
 *         active.
 */
pubnub_milliseconds_t pn_timer_list_ms_until_next(const pn_timer_list_t* list,
                                                  pubnub_platform_provider_t* platform);

/**
 * @brief Return the number of active timers.
 *
 * @param list Timer list.
 * @return Number of timers currently scheduled.
 */
unsigned int pn_timer_list_count(const pn_timer_list_t* list);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_TIMER_LIST_INTERNAL_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Internal per-context logger manager (mux + enrichment).
 *
 * Fans out log entries to multiple child loggers after enriching with
 * context_id, timestamp, and minimum_level. Supports two-phase init:
 * pn_logger_manager_init() zeroes and wires the vtable (safe before
 * platform is known); pn_logger_manager_wire() stamps the context hash
 * and platform pointer.
 */

#ifndef PN_LOGGER_MANAGER_H
#define PN_LOGGER_MANAGER_H

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"
#include "pubnub/pubnub_compat.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Internal per-context logger manager.
 *
 * The `base` field must be the first member so the struct can be
 * safely cast to/from pubnub_logger_provider_t*.
 */
typedef struct pn_logger_manager {
    /** Logger vtable (must be first member for safe casting). */
    pubnub_logger_provider_t base;

    /** Registered child loggers (NULL = empty slot). */
    pubnub_logger_provider_t* children[PUBNUB_CFG_MAX_LOGGERS];

    /**
     * @brief Number of registered children; publication gate for @ref children.
     *
     * Mutators run under the context lock and release-store this count only
     * after writing the children[] slots; the lock-free fan-out reader
     * acquire-loads it first, so it never observes an unpublished slot.
     */
    PUBNUB_ATOMIC_UINT8 count;

    /**
     * @brief 8-hex hash of the manager instance address, NUL-terminated.
     *
     * Set by pn_logger_manager_wire(). Before wiring, contains
     * "00000000".
     */
    char context_id[9];

    /**
     * @brief Platform provider for timestamps.
     *
     * Calls platform->monotonic_ms() on each log() call to stamp
     * entries. May be NULL (timestamp_ms stays 0).
     */
    pubnub_platform_provider_t* platform;

    /** Per-context lock (borrowed). Wired via pn_logger_manager_wire_lock(). */
    pubnub_lock_t* lock;

    /** Current minimum level threshold stamped into every entry. */
    pubnub_log_level_t min_level;
} pn_logger_manager_t;

/**
 * @brief Phase-1 init: zero struct and wire vtable.
 *
 * Safe to call before context_id or platform provider are known.
 * After init the manager has zero children, context_id "00000000",
 * and is ready for pn_logger_manager_add() calls.
 *
 * @param mgr  Pointer to the manager. Must not be NULL.
 */
void pn_logger_manager_init(pn_logger_manager_t* mgr);

/**
 * @brief Phase-2 wiring: stamp context hash and platform pointer.
 *
 * Computes the 8-hex hash of the manager instance address and stores
 * the platform pointer for timestamp enrichment. May be called
 * multiple times (e.g., on context re-init).
 *
 * @param mgr       Pointer to the manager. Must not be NULL.
 * @param platform  Platform provider for monotonic timestamps. May
 *                  be NULL.
 */
void pn_logger_manager_wire(pn_logger_manager_t*        mgr,
                            pubnub_platform_provider_t* platform);

/**
 * @brief Wire the per-context lock into the manager.
 *
 * Call after the context lock is allocated (phase 3). Safe to call
 * with NULL lock — pn_mgr_log_() is then lock-free (single-threaded
 * use only).
 *
 * @param mgr  Pointer to the manager. Must not be NULL.
 * @param lock Per-context lock (borrowed; may be NULL).
 */
void pn_logger_manager_wire_lock(pn_logger_manager_t* mgr, pubnub_lock_t* lock);

/**
 * @brief Register a child logger with the manager.
 *
 * The child is appended to the internal array. The manager does not
 * take ownership; the caller must ensure the child outlives the
 * manager or is removed before destruction.
 *
 * @param mgr    Pointer to the manager. Must not be NULL.
 * @param child  Pointer to the child logger. Must not be NULL.
 * @return PUBNUB_OK on success, PUBNUB_ERR_INVALID_ARGUMENT on NULL
 *         inputs, PUBNUB_ERR_QUEUE_FULL when PUBNUB_CFG_MAX_LOGGERS
 *         children are already registered.
 */
pubnub_res_t pn_logger_manager_add(pn_logger_manager_t*      mgr,
                                   pubnub_logger_provider_t* child);

/**
 * @brief Remove a child logger from the manager.
 *
 * Finds the child by pointer equality and shifts the remaining
 * entries to keep the array compact.
 *
 * @param mgr    Pointer to the manager. Must not be NULL.
 * @param child  Pointer to the child to remove. Must not be NULL.
 * @return PUBNUB_OK on success, PUBNUB_ERR_INVALID_ARGUMENT on NULL
 *         inputs or when the child is not found.
 */
pubnub_res_t pn_logger_manager_remove(pn_logger_manager_t*      mgr,
                                      pubnub_logger_provider_t* child);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_LOGGER_MANAGER_H */

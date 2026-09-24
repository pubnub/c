/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pending_queue_internal.h
 * @brief Fixed-capacity FIFO queue for requests that overflow the slot pool.
 *
 * When all request pool slots are in use, feature APIs enqueue their
 * populated HTTP request descriptors here. The process loop promotes
 * entries to real pool slots as slots are released, preserving FIFO
 * ordering.
 *
 * Thread safety: external serialization required (context mutex).
 * The queue performs no allocation - entries use fixed inline storage.
 */

#ifndef PN_PENDING_QUEUE_INTERNAL_H
#define PN_PENDING_QUEUE_INTERNAL_H

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"
#include "request_internal.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief A single entry in the pending queue.
 *
 * Stores the fully-populated HTTP request descriptor and metadata
 * needed to reconstitute a pool slot when one becomes available.
 * The entry holds a snapshot of the request; the original stack
 * data may be gone by the time promotion happens.
 */
typedef struct pn_pending_entry {
    /** Populated HTTP request (copied by value at enqueue time). */
    pubnub_http_request_t http_request;

    /** Feature that owns this pending request. */
    uint8_t feature_id;

    /** Feature-owned state (ownership transferred from caller). */
    void* feature_state;

    /** Cleanup function for feature_state. */
    void (*feature_state_cleanup)(void*, pubnub_allocator_provider_t*);

    /** Response validator probe (may be NULL). */
    pubnub_res_t (*response_validator)(const uint8_t* body,
                                       size_t         body_len,
                                       int            http_status);

    /** Feature-owned completion capture hook (may be NULL). Copied to
     *  the slot on populate/promote so it survives the pending path. */
    pn_response_capture_fn_t response_capture;

    /** Completion callback (may be NULL). */
    pn_request_cb_t on_complete;

    /** User data for on_complete. */
    void* user_data;

    /** Public async callback registered via pubnub_async() on a
     *  pending-range future. Copied to the slot on promotion. */
    pubnub_async_cb_t async_cb;

    /** User data for async_cb. */
    void* async_cb_user_data;

    /** Physical index in the pending_slot_map (set by enqueue caller). */
    uint16_t map_index;

    /** 1 if this entry is occupied, 0 if free. */
    uint8_t occupied;
} pn_pending_entry_t;

/* Stack-budget guard for embedded profiles: on 32-bit targets the budget
 * is derived from the configured inline array sizes so the assertion
 * remains valid for any valid config, not just the defaults.
 * 128U covers fixed fields, pointers, count fields, and alignment padding.
 * pubnub_string_view_t = 8 B and pubnub_kv_t = 16 B on 32-bit. */
#define PN_PENDING_ENTRY_STACK_BUDGET_U                                               \
    (128U + (size_t)PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS * 8U                            \
     + (size_t)(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS + PUBNUB_CFG_HTTP_MAX_HEADERS) * 16U \
     + (size_t)PUBNUB_CFG_HTTP_SCRATCH_SIZE)
#if !defined(__LP64__) && !defined(_WIN64) && !defined(__x86_64__)
/* Lower bound: catches unexpected struct bloat (field additions, alignment changes). */
PUBNUB_STATIC_ASSERT(sizeof(pn_pending_entry_t) <= PN_PENDING_ENTRY_STACK_BUDGET_U,
                     "pn_pending_entry_t exceeds embedded stack budget");
/* Upper bound: catches config choices that would blow a typical FreeRTOS task stack.
 * A single prep struct over 3 KB leaves less than 1 KB headroom on a 4 KB stack.
 * Raise PUBNUB_CFG_FREERTOS_TASK_STACK_SIZE if your application needs larger buffers. */
PUBNUB_STATIC_ASSERT(
    PN_PENDING_ENTRY_STACK_BUDGET_U <= 3072U,
    "Configured HTTP parameters produce a struct too large for a "
    "typical embedded task stack; reduce PUBNUB_CFG_HTTP_SCRATCH_SIZE "
    "or PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS");
#endif

/**
 * @brief Fixed-capacity FIFO pending queue.
 *
 * Implemented as a circular buffer with head/tail indices.
 * Capacity is bounded by PUBNUB_CFG_MAX_PENDING_REQUESTS.
 */
typedef struct pn_pending_queue {
    /** Circular buffer of entries (owned, allocated at init). */
    pn_pending_entry_t* entries;

    /** Maximum number of entries. */
    uint16_t capacity;

    /** Index of the oldest entry (next to dequeue). */
    uint16_t head;

    /** Index of the next free slot (where to enqueue). */
    uint16_t tail;

    /** Number of occupied entries. */
    uint16_t count;

    /** Allocator used for the entries array (borrowed). */
    pubnub_allocator_provider_t* allocator;
} pn_pending_queue_t;

/**
 * @brief Initialize the pending queue with pre-allocated storage.
 *
 * @param queue     Queue to initialize (caller-owned).
 * @param capacity  Maximum entries (must be > 0).
 * @param allocator Allocator for the entries array (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_pending_queue_init(pn_pending_queue_t*          queue,
                                   uint16_t                     capacity,
                                   pubnub_allocator_provider_t* allocator);

/**
 * @brief Tear down the queue, freeing the entries array.
 *
 * Does NOT clean up feature_state in occupied entries - the
 * caller must drain or cancel pending entries first.
 *
 * @param queue Queue to tear down (no-op if NULL or zeroed).
 */
void pn_pending_queue_deinit(pn_pending_queue_t* queue);

/**
 * @brief Enqueue a pending request entry.
 *
 * Copies the entry by value into the circular buffer. Does NOT
 * lock internally - caller must hold the context mutex.
 *
 * @param queue Queue to enqueue into.
 * @param entry Entry to copy (borrowed; queue takes a snapshot).
 * @return PUBNUB_OK on success, PUBNUB_ERR_QUEUE_FULL when full.
 */
pubnub_res_t pn_pending_queue_enqueue(pn_pending_queue_t*       queue,
                                      const pn_pending_entry_t* entry);

/**
 * @brief Dequeue the oldest entry (FIFO).
 *
 * Copies the oldest entry into @p out_entry and removes it from
 * the queue. Does NOT lock internally.
 *
 * @param queue     Queue to dequeue from.
 * @param out_entry Receives the dequeued entry on success.
 * @return PUBNUB_OK on success, PUBNUB_ERR_INVALID_ARGUMENT when empty.
 */
pubnub_res_t pn_pending_queue_dequeue(pn_pending_queue_t* queue,
                                      pn_pending_entry_t* out_entry);

/**
 * @brief Return the number of entries currently in the queue.
 *
 * @param queue Queue to query.
 * @return Number of occupied entries.
 */
uint16_t pn_pending_queue_count(const pn_pending_queue_t* queue);

/**
 * @brief Check whether the queue is full.
 *
 * @param queue Queue to query.
 * @return Non-zero if full, 0 otherwise.
 */
int pn_pending_queue_is_full(const pn_pending_queue_t* queue);

/**
 * @brief Data extracted from a cancelled pending entry.
 *
 * Populated by pn_pending_queue_cancel_at() so the caller can fire
 * callbacks outside any lock, preventing deadlock on non-reentrant
 * mutexes (FreeRTOS, bare-metal).
 *
 * The caller MUST populate @c async_cb_future before calling
 * pn_pending_cancel_data_run() — the queue has no context pointer
 * and cannot reconstruct the future handle itself.
 */
typedef struct pn_pending_cancel_data {
    /** Feature-owned state (extracted from the entry). */
    void* feature_state;

    /** Cleanup function for feature_state. */
    void (*feature_state_cleanup)(void*, pubnub_allocator_provider_t*);

    /** Allocator to pass to feature_state_cleanup. */
    pubnub_allocator_provider_t* allocator;

    /** Public async callback (from pubnub_async on a pending future). */
    pubnub_async_cb_t async_cb;

    /** User data for async_cb. */
    void* async_cb_user_data;

    /** Future handle to pass to async_cb. Must be populated by the
     *  caller before invoking pn_pending_cancel_data_run(). */
    pubnub_future_t async_cb_future;
} pn_pending_cancel_data_t;

/**
 * @brief Fire callbacks extracted from a cancelled pending entry.
 *
 * Invokes feature_state_cleanup (if non-NULL) and async_cb (if
 * non-NULL) with PUBNUB_ERR_CANCELLED. Must be called OUTSIDE any
 * SDK lock to honor the non-reentrant mutex contract.
 *
 * @param data Extracted cancel data (may be NULL — no-op).
 */
void pn_pending_cancel_data_run(pn_pending_cancel_data_t* data);

/**
 * @brief Remove the entry at @p index (logical, 0-based from head).
 *
 * Used to cancel a pending-range future. Extracts callback data into
 * @p out_data (if non-NULL) so the caller can invoke them after
 * releasing the lock. The entry is zeroed and marked unoccupied.
 *
 * If @p out_data is NULL, feature_state_cleanup is called inline
 * (legacy behavior for paths that cannot reconstruct the future).
 *
 * @param queue    Queue to modify.
 * @param index    Logical index from head (0 = oldest).
 * @param out_data Receives extracted callback data (nullable).
 * @return PUBNUB_OK on success, error if out of bounds.
 */
pubnub_res_t pn_pending_queue_cancel_at(pn_pending_queue_t*       queue,
                                        uint16_t                  index,
                                        pn_pending_cancel_data_t* out_data);

/**
 * @brief Relocate scratch-referencing pointers after a struct copy.
 *
 * `pubnub_http_request_t` contains an inline `scratch[]` array and
 * `path_segments[]/query_params[]/headers[]` whose `.ptr` fields may
 * point into that scratch buffer. After a plain struct copy
 * (`*dst = *src`), the pointer values still reference the SOURCE
 * struct's scratch memory. Call this immediately after the copy to
 * rebase them into the destination's scratch.
 *
 * Detection uses address-range comparison: scratch is an embedded
 * array inside the struct (stack or heap-allocated pending entry),
 * while external pointers (string literals in .rodata, heap allocs,
 * caller-owned strings) are in non-overlapping address regions on
 * all supported targets.
 *
 * @param dst  Destination request (just received a struct copy).
 * @param src  Source request (still alive; provides the old base).
 */
static inline void
pn_http_request_relocate_scratch_ptrs(pubnub_http_request_t*       dst,
                                      const pubnub_http_request_t* src)
{
    const uintptr_t lo    = (uintptr_t)src->scratch;
    const uintptr_t hi    = lo + PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    const ptrdiff_t delta = (ptrdiff_t)((uintptr_t)dst->scratch - lo);

    for (unsigned int i = 0; i < dst->query_param_count; i++) {
        uintptr_t kp = (uintptr_t)dst->query_params[i].key.ptr;
        uintptr_t vp = (uintptr_t)dst->query_params[i].value.ptr;
        if (kp >= lo && kp < hi) {
            dst->query_params[i].key.ptr += delta;
        }
        if (vp >= lo && vp < hi) {
            dst->query_params[i].value.ptr += delta;
        }
    }

    for (unsigned int i = 0; i < dst->header_count; i++) {
        uintptr_t kp = (uintptr_t)dst->headers[i].key.ptr;
        uintptr_t vp = (uintptr_t)dst->headers[i].value.ptr;
        if (kp >= lo && kp < hi) {
            dst->headers[i].key.ptr += delta;
        }
        if (vp >= lo && vp < hi) {
            dst->headers[i].value.ptr += delta;
        }
    }

    for (unsigned int i = 0; i < dst->path_segment_count; i++) {
        uintptr_t sp = (uintptr_t)dst->path_segments[i].ptr;
        if (sp >= lo && sp < hi) {
            dst->path_segments[i].ptr += delta;
        }
    }

    if (NULL != dst->host) {
        uintptr_t hp = (uintptr_t)dst->host;
        if (hp >= lo && hp < hi) {
            dst->host += delta;
        }
    }
}

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PENDING_QUEUE_INTERNAL_H */

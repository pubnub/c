/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file allocator_arena.c
 * @brief Two-zone arena allocator: fixed slot pools (Zone A) plus a
 *        fixed-cell pool allocator (Zone B). No libc heap is used.
 *
 * Zone A serves buf_acquire / buf_release via in-use flag arrays.
 * Zone B is divided into 256-byte cells. An allocation of N bytes
 * claims ceil(N/256) consecutive cells; freed cells are individually
 * reclaimed and can be reassembled into any consecutive run.
 */

#include "pubnub/providers/allocator_arena.h"

#include "pubnub/pubnub_compat.h"

#include <string.h>

#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
#include <stdio.h>
#endif

/** @brief Fixed cell size for Zone B allocations (bytes). */
#define PN_ARENA_CELL_SIZE 256U
/** @brief log2(PN_ARENA_CELL_SIZE) for shift-based division. */
#define PN_ARENA_CELL_SHIFT 8U

PUBNUB_STATIC_ASSERT(PN_ARENA_CELL_SIZE == (1U << PN_ARENA_CELL_SHIFT),
                     "cell size must be a power of 2");

PUBNUB_STATIC_ASSERT(PUBNUB_ARENA_MAX_ZONE_B_CELLS <= 255U,
                     "Zone B cell count exceeds uint8_t range; reduce arena "
                     "budget or increase cell size");

/** Total bytes occupied by Zone A fixed-size slot pools. */
#define PN_ARENA_ZONE_A_SIZE                                          \
    ((size_t)PUBNUB_ARENA_RX_SLOTS * PUBNUB_CFG_RESPONSE_BUFFER_SIZE  \
     + (size_t)PUBNUB_ARENA_OBJ_SLOTS * PUBNUB_CFG_OBJECT_BUFFER_SIZE \
     + (size_t)PUBNUB_ARENA_SCRATCH_SLOTS * PUBNUB_CFG_SCRATCH_BUFFER_SIZE)

PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_ARENA_POOL_SIZE == PN_ARENA_ZONE_A_SIZE + PUBNUB_CFG_ARENA_ALLOC_BUDGET,
    "ARENA_POOL_SIZE must equal Zone-A fixed regions plus ARENA_ALLOC_BUDGET");

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_ARENA_ALLOC_BUDGET >= PN_ARENA_CELL_SIZE,
                     "arena alloc budget must be at least one cell");

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_ARENA_ALLOC_BUDGET
                         == (size_t)PUBNUB_ARENA_MAX_ZONE_B_CELLS * PN_ARENA_CELL_SIZE,
                     "arena alloc budget must equal cell_count * cell_size");

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_ARENA_POOL_SIZE >= 1024U,
                     "ARENA_POOL_SIZE must be >= 1024 bytes");

PUBNUB_STATIC_ASSERT(PN_ARENA_ZONE_A_SIZE % sizeof(double) == 0, "Zone A size must be double-aligned so Zone B base inherits pool alignment");

/**
 * Zero the pool, recompute Zone B pointers, and clear all dynamic state.
 * No-op when pool or zone_b_end has not been set yet (safe for deinit
 * before any init call).
 */
static void pn_arena_full_reset(pubnub_arena_allocator_t* arena)
{
    size_t pool_size;
    size_t zone_a_size;

    if (NULL == arena->pool || NULL == arena->zone_b_end) {
        return;
    }

    pool_size   = (size_t)(arena->zone_b_end - arena->pool);
    zone_a_size = PN_ARENA_ZONE_A_SIZE;

    memset(arena->pool, 0, pool_size);

    arena->zone_b_base = arena->pool + zone_a_size;
    arena->cell_total =
        (size_t)(arena->zone_b_end - arena->zone_b_base) / PN_ARENA_CELL_SIZE;
    /* Clamp to compile-time array bound — prevents overflow when user
     * provides a pool larger than PUBNUB_CFG_ARENA_POOL_SIZE. */
    if (arena->cell_total > PUBNUB_ARENA_MAX_ZONE_B_CELLS) {
        arena->cell_total = PUBNUB_ARENA_MAX_ZONE_B_CELLS;
    }
    memset(arena->cell_in_use, 0, arena->cell_total);
    memset(arena->cell_count, 0, arena->cell_total);

    memset(arena->rx_in_use, 0, sizeof(arena->rx_in_use));
    memset(arena->obj_in_use, 0, sizeof(arena->obj_in_use));
    memset(arena->scratch_in_use, 0, sizeof(arena->scratch_in_use));
}

#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
/** @brief Count Zone B cells currently in use (debug only). */
static size_t arena_used_cells(const pubnub_arena_allocator_t* arena)
{
    size_t i;
    size_t count = 0;
    for (i = 0; i < arena->cell_total; ++i) {
        if (0 != arena->cell_in_use[i]) {
            ++count;
        }
    }
    return count;
}
#endif

/**
 * Allocate @p size bytes from Zone B.
 *
 * Claims ceil(size/256) consecutive free cells via a linear first-fit
 * scan. The returned pointer is the base of the first cell in the run.
 * All cells in the run are zero-filled before return.
 */
static void* arena_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    size_t                    n_cells;
    size_t                    run_start = 0;
    size_t                    run_len   = 0;
    size_t                    i;
    uint8_t*                  ptr;

    if (NULL == arena->pool || 0 == size) {
        return NULL;
    }

    /* Alignment beyond cell size is unsatisfiable. */
    if (align > PN_ARENA_CELL_SIZE) {
        return NULL;
    }

    n_cells = (size + (1U << PN_ARENA_CELL_SHIFT) - 1U) >> PN_ARENA_CELL_SHIFT;
    if (0 == n_cells || n_cells > 255U || n_cells > arena->cell_total) {
        return NULL;
    }

    /* Linear scan for first run of n_cells consecutive free cells. */
    for (i = 0; i < arena->cell_total; ++i) {
        if (0 == arena->cell_in_use[i]) {
            if (0 == run_len) {
                run_start = i;
            }
            ++run_len;
            if (run_len >= n_cells) {
                memset(&arena->cell_in_use[run_start], 1, n_cells);
                arena->cell_count[run_start] = (uint8_t)n_cells;
                ptr = arena->zone_b_base + run_start * PN_ARENA_CELL_SIZE;
                memset(ptr, 0, n_cells * PN_ARENA_CELL_SIZE);
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
                (void)fprintf(stderr,
                              "[arena B] alloc  +%u cells"
                              "  req=%5u B  slot=%u..%u"
                              "  used=%u/%u\n",
                              (unsigned)n_cells,
                              (unsigned)size,
                              (unsigned)run_start,
                              (unsigned)(run_start + n_cells - 1),
                              (unsigned)arena_used_cells(arena),
                              (unsigned)arena->cell_total);
#endif
                return ptr;
            }
        } else {
            run_len = 0;
        }
    }

#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
    {
        size_t budget     = (size_t)(arena->zone_b_end - arena->zone_b_base);
        size_t free_cells = 0;
        char   map[PUBNUB_ARENA_MAX_ZONE_B_CELLS + 1];
        (void)fprintf(stderr,
                      "[arena B] alloc  FAIL"
                      "       req=%5u B"
                      "  cells_needed=%u"
                      "  free=%u/%u\n",
                      (unsigned)size,
                      (unsigned)n_cells,
                      (unsigned)(arena->cell_total - arena_used_cells(arena)),
                      (unsigned)arena->cell_total);
        for (i = 0; i < arena->cell_total; ++i) {
            if (0 == arena->cell_in_use[i]) {
                ++free_cells;
                map[i] = '.';
            } else {
                map[i] = '#';
            }
        }
        map[arena->cell_total] = '\0';
        (void)fprintf(stderr,
                      "[arena] alloc failed: requested=%u cells=%u "
                      "budget=%u free_cells=%u/%u\n"
                      "[arena] cell map: %s\n",
                      (unsigned)size,
                      (unsigned)n_cells,
                      (unsigned)budget,
                      (unsigned)free_cells,
                      (unsigned)arena->cell_total,
                      map);
    }
#endif

    return NULL;
}

/**
 * Return a Zone B allocation to the cell pool.
 *
 * Looks up the cell index from the pointer offset, reads the cell count
 * stored at the first cell, and clears the in-use flags. NULL, out-of-range,
 * misaligned, and double-free pointers are silently ignored.
 */
static void arena_free(pubnub_allocator_provider_t* self, void* ptr)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    uint8_t*                  p;
    size_t                    offset;
    size_t                    idx;
    uint8_t                   n;

    if (NULL == ptr || NULL == arena->pool) {
        return;
    }

    p = (uint8_t*)ptr;

    /* Reject Zone A pointers and anything past the end. */
    if (NULL == arena->zone_b_base || p < arena->zone_b_base
        || p >= arena->zone_b_end) {
        return;
    }

    offset = (size_t)(p - arena->zone_b_base);
    if (0 != offset % PN_ARENA_CELL_SIZE) {
        return; /* Misaligned pointer — defensive. */
    }

    idx = offset >> PN_ARENA_CELL_SHIFT;
    n   = arena->cell_count[idx];
    if (0 == n) {
        return; /* Double-free guard. */
    }
    if (idx + (size_t)n > arena->cell_total) {
        return; /* Corrupt count guard. */
    }

    memset(&arena->cell_in_use[idx], 0, (size_t)n);
    arena->cell_count[idx] = 0;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
    (void)fprintf(stderr,
                  "[arena B] free   -%u cells"
                  "  was=%u..%u  used=%u/%u\n",
                  (unsigned)n,
                  (unsigned)idx,
                  (unsigned)(idx + (size_t)n - 1),
                  (unsigned)arena_used_cells(arena),
                  (unsigned)arena->cell_total);
#endif
}

/**
 * Acquire the first available slot for @p purpose.
 *
 * Returns a descriptor with @c data pointing at the slot, @c len = 0,
 * and @c cap = slot size. Returns @c {NULL, 0, 0, purpose} when all
 * slots of the requested purpose are busy (backpressure signal).
 */
static pubnub_buffer_t arena_buf_acquire(pubnub_allocator_provider_t* self,
                                         pubnub_buf_purpose_t         purpose)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    pubnub_buffer_t           empty = {0};
    size_t                    i;
    size_t                    rx_end;
    size_t                    obj_end;

    empty.purpose = purpose;

    if (NULL == arena->pool) {
        return empty;
    }

    rx_end = (size_t)PUBNUB_ARENA_RX_SLOTS * PUBNUB_CFG_RESPONSE_BUFFER_SIZE;
    obj_end =
        rx_end + (size_t)PUBNUB_ARENA_OBJ_SLOTS * PUBNUB_CFG_OBJECT_BUFFER_SIZE;

    switch (purpose) {
    case PUBNUB_BUF_RX:
        for (i = 0; i < PUBNUB_ARENA_RX_SLOTS; ++i) {
            if (0 == arena->rx_in_use[i]) {
                pubnub_buffer_t buf = {
                    .data = arena->pool + i * PUBNUB_CFG_RESPONSE_BUFFER_SIZE,
                    .len  = 0,
                    .cap  = (size_t)PUBNUB_CFG_RESPONSE_BUFFER_SIZE,
                    .purpose = purpose,
                };
                arena->rx_in_use[i] = 1;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
                {
                    size_t j;
                    size_t used = 0;
                    for (j = 0; j < PUBNUB_ARENA_RX_SLOTS; ++j) {
                        if (0 != arena->rx_in_use[j]) {
                            ++used;
                        }
                    }
                    (void)fprintf(stderr,
                                  "[arena A] buf_acquire"
                                  "  %s slot=%u"
                                  "  used=%u/%u\n",
                                  "RX     ",
                                  (unsigned)i,
                                  (unsigned)used,
                                  (unsigned)PUBNUB_ARENA_RX_SLOTS);
                }
#endif
                return buf;
            }
        }
        break;

    case PUBNUB_BUF_OBJ:
        for (i = 0; i < PUBNUB_ARENA_OBJ_SLOTS; ++i) {
            if (0 == arena->obj_in_use[i]) {
                pubnub_buffer_t buf = {
                    .data = arena->pool + rx_end + i * PUBNUB_CFG_OBJECT_BUFFER_SIZE,
                    .len     = 0,
                    .cap     = (size_t)PUBNUB_CFG_OBJECT_BUFFER_SIZE,
                    .purpose = purpose,
                };
                arena->obj_in_use[i] = 1;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
                {
                    size_t j;
                    size_t used = 0;
                    for (j = 0; j < PUBNUB_ARENA_OBJ_SLOTS; ++j) {
                        if (0 != arena->obj_in_use[j]) {
                            ++used;
                        }
                    }
                    (void)fprintf(stderr,
                                  "[arena A] buf_acquire"
                                  "  %s slot=%u"
                                  "  used=%u/%u\n",
                                  "OBJ    ",
                                  (unsigned)i,
                                  (unsigned)used,
                                  (unsigned)PUBNUB_ARENA_OBJ_SLOTS);
                }
#endif
                return buf;
            }
        }
        break;

    case PUBNUB_BUF_SCRATCH:
        for (i = 0; i < PUBNUB_ARENA_SCRATCH_SLOTS; ++i) {
            if (0 == arena->scratch_in_use[i]) {
                pubnub_buffer_t buf = {
                    .data = arena->pool + obj_end + i * PUBNUB_CFG_SCRATCH_BUFFER_SIZE,
                    .len     = 0,
                    .cap     = (size_t)PUBNUB_CFG_SCRATCH_BUFFER_SIZE,
                    .purpose = purpose,
                };
                arena->scratch_in_use[i] = 1;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
                {
                    size_t j;
                    size_t used = 0;
                    for (j = 0; j < PUBNUB_ARENA_SCRATCH_SLOTS; ++j) {
                        if (0 != arena->scratch_in_use[j]) {
                            ++used;
                        }
                    }
                    (void)fprintf(stderr,
                                  "[arena A] buf_acquire"
                                  "  %s slot=%u"
                                  "  used=%u/%u\n",
                                  "SCRATCH",
                                  (unsigned)i,
                                  (unsigned)used,
                                  (unsigned)PUBNUB_ARENA_SCRATCH_SLOTS);
                }
#endif
                return buf;
            }
        }
        break;
    default: break;
    }

#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
    {
        const char* purpose_str = "UNKNOWN";
        unsigned    bitmap      = 0;
        unsigned    total_slots = 0;
        switch (purpose) {
        case PUBNUB_BUF_RX:
            purpose_str = "RX";
            total_slots = PUBNUB_ARENA_RX_SLOTS;
            for (i = 0; i < PUBNUB_ARENA_RX_SLOTS; ++i) {
                bitmap |= (unsigned)(arena->rx_in_use[i] << i);
            }
            break;
        case PUBNUB_BUF_OBJ:
            purpose_str = "OBJ";
            total_slots = PUBNUB_ARENA_OBJ_SLOTS;
            for (i = 0; i < PUBNUB_ARENA_OBJ_SLOTS; ++i) {
                bitmap |= (unsigned)(arena->obj_in_use[i] << i);
            }
            break;
        case PUBNUB_BUF_SCRATCH:
            purpose_str = "SCRATCH";
            total_slots = PUBNUB_ARENA_SCRATCH_SLOTS;
            for (i = 0; i < PUBNUB_ARENA_SCRATCH_SLOTS; ++i) {
                bitmap |= (unsigned)(arena->scratch_in_use[i] << i);
            }
            break;
        default: break;
        }
        (void)fprintf(stderr,
                      "[arena A] buf_acquire"
                      "  %s FAIL  all %u slots in use\n",
                      purpose_str,
                      total_slots);
        (void)fprintf(stderr,
                      "[arena] buf_acquire(%s) failed:"
                      " in_use=0x%x\n",
                      purpose_str,
                      bitmap);
    }
#endif

    return empty;
}

/**
 * Release a buffer back to its Zone A slot.
 *
 * Locates the slot by comparing @c buf->data against each slot base
 * pointer (O(total_slots) <= O(8) for the embedded default), clears the
 * in-use flag, and zeroes the descriptor. Unrecognised pointers are
 * ignored defensively.
 */
static void arena_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    uint8_t*                  rx_base;
    uint8_t*                  obj_base;
    uint8_t*                  scratch_base;
    size_t                    i;

    if (NULL == buf || NULL == buf->data || NULL == arena->pool) {
        return;
    }

    rx_base  = arena->pool;
    obj_base = rx_base
             + (size_t)PUBNUB_ARENA_RX_SLOTS * PUBNUB_CFG_RESPONSE_BUFFER_SIZE;
    scratch_base =
        obj_base + (size_t)PUBNUB_ARENA_OBJ_SLOTS * PUBNUB_CFG_OBJECT_BUFFER_SIZE;

    for (i = 0; i < PUBNUB_ARENA_RX_SLOTS; ++i) {
        if (buf->data == rx_base + i * PUBNUB_CFG_RESPONSE_BUFFER_SIZE) {
            arena->rx_in_use[i] = 0;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
            (void)fprintf(stderr,
                          "[arena A] buf_release"
                          "  %s slot=%u\n",
                          "RX     ",
                          (unsigned)i);
#endif
            buf->data    = NULL;
            buf->len     = 0;
            buf->cap     = 0;
            buf->purpose = (pubnub_buf_purpose_t)0;
            return;
        }
    }

    for (i = 0; i < PUBNUB_ARENA_OBJ_SLOTS; ++i) {
        if (buf->data == obj_base + i * PUBNUB_CFG_OBJECT_BUFFER_SIZE) {
            arena->obj_in_use[i] = 0;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
            (void)fprintf(stderr,
                          "[arena A] buf_release"
                          "  %s slot=%u\n",
                          "OBJ    ",
                          (unsigned)i);
#endif
            buf->data    = NULL;
            buf->len     = 0;
            buf->cap     = 0;
            buf->purpose = (pubnub_buf_purpose_t)0;
            return;
        }
    }

    for (i = 0; i < PUBNUB_ARENA_SCRATCH_SLOTS; ++i) {
        if (buf->data == scratch_base + i * PUBNUB_CFG_SCRATCH_BUFFER_SIZE) {
            arena->scratch_in_use[i] = 0;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
            (void)fprintf(stderr,
                          "[arena A] buf_release"
                          "  %s slot=%u\n",
                          "SCRATCH",
                          (unsigned)i);
#endif
            buf->data    = NULL;
            buf->len     = 0;
            buf->cap     = 0;
            buf->purpose = (pubnub_buf_purpose_t)0;
            return;
        }
    }

    /* buf->data does not match any known Zone A slot — defensive no-op. */
}

static int arena_init(pubnub_allocator_provider_t*     self,
                      struct pubnub_platform_provider* platform)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    (void)platform;

    /* One arena instance may back several concurrently-live contexts.
     * Count each init so the last deinit is the only one that clears
     * the tracking arrays. */
    /* ref_count is uint8_t; supports up to 255 concurrent contexts sharing
     * this arena instance (well beyond any realistic embedded deployment). */
    arena->ref_count++;

    /* Restore cell_total when deinit() zeroed it. The tracking arrays
     * (cell_in_use, cell_count, Zone A in-use flags) are already in a
     * valid empty state after deinit. Pool memory is not zeroed here
     * because arena_alloc memsets returned cells on every allocation.
     * Idempotent when called without a prior deinit (cell_total is
     * already correct, so the recomputation is a harmless no-op). */
    if (NULL != arena->zone_b_base && NULL != arena->zone_b_end
        && arena->zone_b_end > arena->zone_b_base) {
        arena->cell_total =
            (size_t)(arena->zone_b_end - arena->zone_b_base) / PN_ARENA_CELL_SIZE;
        if (arena->cell_total > PUBNUB_ARENA_MAX_ZONE_B_CELLS) {
            arena->cell_total = PUBNUB_ARENA_MAX_ZONE_B_CELLS;
        }
    }

    return 0;
}

static void arena_deinit(pubnub_allocator_provider_t*     self,
                         struct pubnub_platform_provider* platform)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    (void)platform;

    if (NULL == arena->pool || NULL == arena->zone_b_end) {
        return;
    }

    /* Release one init reference. Defensive against an unbalanced
     * deinit: a call while ref_count is already zero does not underflow. */
    if (arena->ref_count > 0) {
        arena->ref_count--;
    }

    /* Other contexts still share this arena — keep their live
     * allocations and tracking state intact. */
    if (arena->ref_count > 0) {
        return;
    }

    memset(arena->cell_in_use, 0, sizeof(arena->cell_in_use));
    memset(arena->cell_count, 0, sizeof(arena->cell_count));
    arena->cell_total = 0;

    memset(arena->rx_in_use, 0, sizeof(arena->rx_in_use));
    memset(arena->obj_in_use, 0, sizeof(arena->obj_in_use));
    memset(arena->scratch_in_use, 0, sizeof(arena->scratch_in_use));
}

/**
 * @brief Reallocate a Zone B block, preferring in-place expansion.
 *
 * Grows by claiming adjacent free cells; shrinks by releasing trailing
 * cells. Falls back to alloc-copy-free when in-place is not possible.
 * Returns NULL without touching the old block on failure.
 */
static void* arena_realloc(pubnub_allocator_provider_t* self,
                           void*                        ptr,
                           size_t                       old_size,
                           size_t                       new_size,
                           size_t                       align)
{
    pubnub_arena_allocator_t* arena = (pubnub_arena_allocator_t*)self;
    uint8_t*                  p;
    size_t                    offset;
    size_t                    idx;
    uint8_t                   n_old;
    size_t                    n_new;
    size_t                    i;
    size_t                    copy_len;
    void*                     new_ptr;

    /* NULL ptr: delegate to alloc. */
    if (NULL == ptr) {
        return arena_alloc(self, new_size, align);
    }

    /* Zero new_size: free and return NULL. */
    if (0 == new_size) {
        arena_free(self, ptr);
        return NULL;
    }

    if (NULL == arena->pool || NULL == arena->zone_b_base) {
        return NULL;
    }

    p = (uint8_t*)ptr;

    /* Validate ptr is in Zone B and cell-aligned. */
    if (p < arena->zone_b_base || p >= arena->zone_b_end) {
        return NULL;
    }

    offset = (size_t)(p - arena->zone_b_base);
    if (0 != offset % PN_ARENA_CELL_SIZE) {
        return NULL;
    }

    idx   = offset >> PN_ARENA_CELL_SHIFT;
    n_old = arena->cell_count[idx];
    if (0 == n_old) {
        return NULL;
    }

    if (idx + (size_t)n_old > arena->cell_total) {
        return NULL; /* Corrupt count guard — parity with arena_free. */
    }

    n_new = (new_size + PN_ARENA_CELL_SIZE - 1U) >> PN_ARENA_CELL_SHIFT;
    if (0 == n_new || n_new > 255U || n_new > arena->cell_total) {
        return NULL;
    }

    /* Same cell coverage: nothing to do. */
    if (n_new == (size_t)n_old) {
        return ptr;
    }

    /* Shrink in place: release trailing cells. */
    if (n_new < (size_t)n_old) {
        memset(&arena->cell_in_use[idx + n_new], 0, (size_t)n_old - n_new);
        arena->cell_count[idx] = (uint8_t)n_new;
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
        (void)fprintf(stderr,
                      "[arena B] realloc shrink"
                      "    -%u cells  slot=%u..%u"
                      "  used=%u/%u  (%u->%u B)\n",
                      (unsigned)((size_t)n_old - n_new),
                      (unsigned)idx,
                      (unsigned)(idx + n_new - 1),
                      (unsigned)arena_used_cells(arena),
                      (unsigned)arena->cell_total,
                      (unsigned)old_size,
                      (unsigned)new_size);
#endif
        return ptr;
    }

    /* Grow: try in-place expansion. */
    if (idx + n_new <= arena->cell_total) {
        for (i = idx + (size_t)n_old; i < idx + n_new; ++i) {
            if (0 != arena->cell_in_use[i]) {
                goto fallback;
            }
        }
        /* Adjacent cells are free - claim them. */
        memset(&arena->cell_in_use[idx + (size_t)n_old], 1, n_new - (size_t)n_old);
        arena->cell_count[idx] = (uint8_t)n_new;
        /* Zero-fill newly claimed cells. */
        memset(arena->zone_b_base + (idx + (size_t)n_old) * PN_ARENA_CELL_SIZE,
               0,
               (n_new - (size_t)n_old) * PN_ARENA_CELL_SIZE);
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
        (void)fprintf(stderr,
                      "[arena B] realloc in-place"
                      "  +%u cells  slot=%u..%u"
                      "  used=%u/%u  (%u->%u B)\n",
                      (unsigned)(n_new - (size_t)n_old),
                      (unsigned)idx,
                      (unsigned)(idx + n_new - 1),
                      (unsigned)arena_used_cells(arena),
                      (unsigned)arena->cell_total,
                      (unsigned)old_size,
                      (unsigned)new_size);
#endif
        return ptr;
    }

fallback:
    /* In-place expansion failed; alloc-copy-free. */
    new_ptr = arena_alloc(self, new_size, align);
    if (NULL == new_ptr) {
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
        (void)fprintf(stderr,
                      "[arena B] realloc FAIL"
                      "      req=%5u B"
                      "  cells_needed=%u"
                      "  free=%u/%u\n",
                      (unsigned)new_size,
                      (unsigned)n_new,
                      (unsigned)(arena->cell_total - arena_used_cells(arena)),
                      (unsigned)arena->cell_total);
#endif
        return NULL;
    }
    copy_len = old_size;
    if (copy_len > (size_t)n_old * PN_ARENA_CELL_SIZE) {
        copy_len = (size_t)n_old * PN_ARENA_CELL_SIZE;
    }
    memcpy(new_ptr, ptr, copy_len);
    arena_free(self, ptr);
#if defined(PUBNUB_CFG_ARENA_DEBUG) && PUBNUB_CFG_ARENA_DEBUG
    (void)fprintf(stderr,
                  "[arena B] realloc copy"
                  "      old=%u new=%u cells"
                  "  used=%u/%u  (%u->%u B)\n",
                  (unsigned)n_old,
                  (unsigned)n_new,
                  (unsigned)arena_used_cells(arena),
                  (unsigned)arena->cell_total,
                  (unsigned)old_size,
                  (unsigned)new_size);
#endif
    return new_ptr;
}

static const pubnub_allocator_provider_t pn_arena_vtable = {
    .alloc       = arena_alloc,
    .realloc     = arena_realloc,
    .free        = arena_free,
    .buf_acquire = arena_buf_acquire,
    .buf_release = arena_buf_release,
    .buf_grow    = NULL,
    .init        = arena_init,
    .deinit      = arena_deinit,
};

pubnub_allocator_provider_t* pubnub_arena_allocator_init(pubnub_arena_allocator_t* arena,
                                                         uint8_t* pool,
                                                         size_t   pool_size)
{
    size_t max_zone_b;

    if (NULL == arena || NULL == pool || pool_size <= PN_ARENA_ZONE_A_SIZE) {
        return NULL;
    }

    /* Clamp pool_size so Zone B does not exceed the compile-time cell
     * array bound.  Excess tail memory is silently ignored. */
    max_zone_b = (size_t)PUBNUB_ARENA_MAX_ZONE_B_CELLS * PN_ARENA_CELL_SIZE;
    if (pool_size - PN_ARENA_ZONE_A_SIZE > max_zone_b) {
        pool_size = PN_ARENA_ZONE_A_SIZE + max_zone_b;
    }

    arena->base       = pn_arena_vtable;
    arena->pool       = pool;
    arena->zone_b_end = pool + pool_size;
    arena->ref_count  = 0;

    pn_arena_full_reset(arena);

    return &arena->base;
}

/* Forward declaration — prototype lives in provider_internal.h which
   requires an include path not available to this build target. */
pubnub_allocator_provider_t* pn_allocator_default(void);

#if PUBNUB_CFG_ARENA_POOL_OWNER_SDK
static PUBNUB_ALIGNAS(double) uint8_t s_pool[PUBNUB_CFG_ARENA_POOL_SIZE];
static pubnub_arena_allocator_t s_arena;

pubnub_allocator_provider_t* pn_allocator_default(void)
{
    static int s_initialized = 0;
    if (!s_initialized) {
        pubnub_arena_allocator_init(&s_arena, s_pool, sizeof(s_pool));
        s_initialized = 1;
    }
    return &s_arena.base;
}

#else  /* PUBNUB_CFG_ARENA_POOL_OWNER_SDK == 0: user provides pool */

pubnub_allocator_provider_t* pn_allocator_default(void)
{
    return NULL;
}

#endif /* PUBNUB_CFG_ARENA_POOL_OWNER_SDK */

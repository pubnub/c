/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/allocator_arena.h"

/* ------------------------------------------------------------------ */
/*  Zone A size for the current config (mirrors allocator_arena.c).   */
/* ------------------------------------------------------------------ */
#define TEST_ZONE_A_SIZE                                              \
    ((size_t)PUBNUB_ARENA_RX_SLOTS * PUBNUB_CFG_RESPONSE_BUFFER_SIZE  \
     + (size_t)PUBNUB_ARENA_OBJ_SLOTS * PUBNUB_CFG_OBJECT_BUFFER_SIZE \
     + (size_t)PUBNUB_ARENA_SCRATCH_SLOTS * PUBNUB_CFG_SCRATCH_BUFFER_SIZE)

/* Cell size must stay in sync with allocator_arena.c. */
#define TEST_CELL_SIZE 256U

/* ------------------------------------------------------------------ */
/*  Full-size arena for original tests.                                */
/* ------------------------------------------------------------------ */
static uint8_t                  s_full_pool[PUBNUB_CFG_ARENA_POOL_SIZE];
static pubnub_arena_allocator_t s_full_arena;

/* ------------------------------------------------------------------ */
/*  Small arena for edge-case tests that need a controlled cell count. */
/* ------------------------------------------------------------------ */
#define EDGE_ZONE_B_CELLS 8U
#define EDGE_POOL_SIZE \
    (TEST_ZONE_A_SIZE + (size_t)EDGE_ZONE_B_CELLS * TEST_CELL_SIZE)

static uint8_t                  s_edge_pool[EDGE_POOL_SIZE];
static pubnub_arena_allocator_t s_edge_arena;

/** @brief Return vtable pointer for the full-size test arena. */
static pubnub_allocator_provider_t* test_arena(void)
{
    return &s_full_arena.base;
}

/* ------------------------------------------------------------------ */
/*  Setup / teardown helpers.                                          */
/* ------------------------------------------------------------------ */

/** @brief Reset the full-size test arena between tests. */
static int setup(void** state)
{
    (void)state;
    pubnub_arena_allocator_init(&s_full_arena, s_full_pool, sizeof(s_full_pool));
    return 0;
}

/** @brief Reset the edge-case arena between tests. */
static int setup_edge(void** state)
{
    (void)state;
    pubnub_arena_allocator_init(&s_edge_arena, s_edge_pool, sizeof(s_edge_pool));
    return 0;
}

/* ================================================================== */
/*  Original tests (default arena).                                    */
/* ================================================================== */

static void alloc_returns_non_null(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    void* p = alloc->alloc(alloc, 64, 0);

    assert_non_null(p);
    alloc->free(alloc, p);
}

static void alloc_returned_memory_is_zeroed(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    char* p = (char*)alloc->alloc(alloc, 64, 0);
    assert_non_null(p);
    memset(p, 0xAB, 64);
    alloc->free(alloc, p);

    char* p2 = (char*)alloc->alloc(alloc, 64, 0);
    assert_non_null(p2);
    /* Cell-based allocator: first-fit scan reclaims the same cell. */
    assert_ptr_equal(p, p2);
    for (size_t i = 0; i < 64; ++i) {
        assert_int_equal((unsigned char)p2[i], 0);
    }
    alloc->free(alloc, p2);
}

static void free_null_is_safe(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    alloc->free(alloc, NULL);
}

static void buf_acquire_rx_pool_has_max_in_flight_slots(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    pubnub_buffer_t              bufs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];

    for (size_t i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        bufs[i] = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
        assert_non_null(bufs[i].data);
        assert_int_equal(bufs[i].cap, (size_t)PUBNUB_CFG_RESPONSE_BUFFER_SIZE);
        assert_int_equal(bufs[i].len, 0);
        assert_int_equal(bufs[i].purpose, PUBNUB_BUF_RX);
    }

    pubnub_buffer_t overflow = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    assert_null(overflow.data);
    assert_int_equal(overflow.cap, 0);

    for (size_t i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        alloc->buf_release(alloc, &bufs[i]);
    }
}

static void buf_acquire_obj_pool_has_in_flight_plus_pending_slots(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    const size_t                 n = (size_t)PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS
                   + (size_t)PUBNUB_CFG_MAX_PENDING_REQUESTS;
    pubnub_buffer_t bufs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + PUBNUB_CFG_MAX_PENDING_REQUESTS];

    for (size_t i = 0; i < n; ++i) {
        bufs[i] = alloc->buf_acquire(alloc, PUBNUB_BUF_OBJ);
        assert_non_null(bufs[i].data);
        assert_int_equal(bufs[i].cap, (size_t)PUBNUB_CFG_OBJECT_BUFFER_SIZE);
    }

    pubnub_buffer_t overflow = alloc->buf_acquire(alloc, PUBNUB_BUF_OBJ);
    assert_null(overflow.data);

    for (size_t i = 0; i < n; ++i) {
        alloc->buf_release(alloc, &bufs[i]);
    }
}

static void buf_acquire_scratch_pool_has_max_in_flight_slots(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    pubnub_buffer_t              bufs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];

    for (size_t i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        bufs[i] = alloc->buf_acquire(alloc, PUBNUB_BUF_SCRATCH);
        assert_non_null(bufs[i].data);
        assert_int_equal(bufs[i].cap, (size_t)PUBNUB_CFG_SCRATCH_BUFFER_SIZE);
    }

    pubnub_buffer_t overflow = alloc->buf_acquire(alloc, PUBNUB_BUF_SCRATCH);
    assert_null(overflow.data);
    assert_int_equal(overflow.cap, 0);

    for (size_t i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        alloc->buf_release(alloc, &bufs[i]);
    }
}

static void buf_release_makes_slot_available(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    pubnub_buffer_t              bufs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];

    for (size_t i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        bufs[i] = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    }

    alloc->buf_release(alloc, &bufs[0]);

    pubnub_buffer_t re = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    assert_non_null(re.data);
    alloc->buf_release(alloc, &re);

    for (size_t i = 1; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        alloc->buf_release(alloc, &bufs[i]);
    }
}

static void alloc_bump_exhaustion_then_recover(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    const size_t max_allocs            = PUBNUB_CFG_ARENA_ALLOC_BUDGET / 8 + 16;
    void*        ptrs[PUBNUB_CFG_ARENA_ALLOC_BUDGET / 8 + 16];
    size_t       n = 0;

    while (n < max_allocs) {
        void* p = alloc->alloc(alloc, 8, 0);
        if (NULL == p) {
            break;
        }
        ptrs[n++] = p;
    }

    assert_null(alloc->alloc(alloc, 8, 0));

    alloc->deinit(alloc, NULL);
    alloc->init(alloc, NULL);

    void* p = alloc->alloc(alloc, 64, 0);
    assert_non_null(p);
    alloc->free(alloc, p);
}

static void alloc_honours_alignment_request(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    void*                        ptrs[2];

    /* Cell-based allocator: all cells have the same alignment, which
     * is gcd(zone_b_base alignment, 256). We can only guarantee
     * sizeof(void*) alignment from the Zone A static assert. */
    ptrs[0] = alloc->alloc(alloc, 32, 1);
    assert_non_null(ptrs[0]);
    assert_int_equal((uintptr_t)ptrs[0] % sizeof(void*), 0);

    ptrs[1] = alloc->alloc(alloc, 32, sizeof(void*));
    assert_non_null(ptrs[1]);
    assert_int_equal((uintptr_t)ptrs[1] % sizeof(void*), 0);

    alloc->free(alloc, ptrs[0]);
    alloc->free(alloc, ptrs[1]);
}

static void alloc_publish_cycle_cursor_stabilises(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc      = test_arena();
    const size_t                 state_sz   = 168;
    const size_t                 channel_sz = 48;
    const size_t                 message_sz = 128;

    /* Warmup: establish high-water mark. */
    void* s0 = alloc->alloc(alloc, state_sz, 0);
    void* c0 = alloc->alloc(alloc, channel_sz, 0);
    void* m0 = alloc->alloc(alloc, message_sz, 0);
    assert_non_null(s0);
    assert_non_null(c0);
    assert_non_null(m0);
    alloc->free(alloc, m0);
    alloc->free(alloc, c0);
    alloc->free(alloc, s0);

    /* 500 cycles — all must succeed (reuse freed blocks). */
    for (int i = 0; i < 500; ++i) {
        void* s = alloc->alloc(alloc, state_sz, 0);
        void* c = alloc->alloc(alloc, channel_sz, 0);
        void* m = alloc->alloc(alloc, message_sz, 0);
        assert_non_null(s);
        assert_non_null(c);
        assert_non_null(m);
        alloc->free(alloc, m);
        alloc->free(alloc, c);
        alloc->free(alloc, s);
    }
}

static void alloc_token_rotation_cursor_stable(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    char* tok = (char*)alloc->alloc(alloc, 100, 0);
    assert_non_null(tok);

    for (int i = 0; i < 1000; ++i) {
        alloc->free(alloc, tok);
        tok = (char*)alloc->alloc(alloc, 96, 0);
        assert_non_null(tok);
    }
    alloc->free(alloc, tok);
}

static void alloc_non_fifo_free_order_no_corruption(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    void* s0 = alloc->alloc(alloc, 160, 0);
    void* c0 = alloc->alloc(alloc, 48, 0);
    void* s1 = alloc->alloc(alloc, 160, 0);
    void* c1 = alloc->alloc(alloc, 48, 0);
    assert_non_null(s0);
    assert_non_null(c0);
    assert_non_null(s1);
    assert_non_null(c1);

    /* Free in non-FIFO order. */
    alloc->free(alloc, c1);
    alloc->free(alloc, s0);
    alloc->free(alloc, c0);
    alloc->free(alloc, s1);

    void* p = alloc->alloc(alloc, 160, 0);
    assert_non_null(p);
    alloc->free(alloc, p);
}

static void deinit_bulk_free_then_reinit_serves_full_budget(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    void* a = alloc->alloc(alloc, 200, 0);
    void* b = alloc->alloc(alloc, 300, 0);
    assert_non_null(a);
    assert_non_null(b);

    /* DO NOT free a and b — test bulk-free via deinit. */
    alloc->deinit(alloc, NULL);
    alloc->init(alloc, NULL);

    void* big = alloc->alloc(alloc, PUBNUB_CFG_ARENA_ALLOC_BUDGET / 2, 0);
    assert_non_null(big);
    alloc->free(alloc, big);
}

static void buf_grow_is_null_but_realloc_is_implemented(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    /* Zone A partitions are fixed, so a purpose-tagged buffer can never
     * grow; Zone B is cell-based, so the general tier can. */
    assert_null(alloc->buf_grow);
    assert_non_null(alloc->realloc);
}

static void realloc_grows_and_shrinks_in_place_preserving_bytes(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    uint8_t* one = (uint8_t*)alloc->alloc(alloc, TEST_CELL_SIZE, sizeof(void*));
    assert_non_null(one);
    memset(one, 0x5A, TEST_CELL_SIZE);

    /* Trailing cells are free, so growth claims them without moving. */
    uint8_t* three = (uint8_t*)alloc->realloc(
        alloc, one, TEST_CELL_SIZE, 3U * TEST_CELL_SIZE, sizeof(void*));
    assert_non_null(three);
    assert_ptr_equal(three, one);

    uint8_t* back = (uint8_t*)alloc->realloc(
        alloc, three, 3U * TEST_CELL_SIZE, TEST_CELL_SIZE, sizeof(void*));
    assert_non_null(back);
    assert_ptr_equal(back, one);

    size_t i;
    for (i = 0; i < TEST_CELL_SIZE; ++i) {
        assert_int_equal(back[i], 0x5A);
    }

    alloc->free(alloc, back);
}

static void realloc_delegates_null_to_alloc_and_zero_to_free(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    void* p = alloc->realloc(alloc, NULL, 0, 128, sizeof(void*));
    assert_non_null(p);

    assert_null(alloc->realloc(alloc, p, 128, 0, sizeof(void*)));

    /* The zero-size call freed the block, so the budget is intact. */
    void* big = alloc->alloc(alloc, PUBNUB_CFG_ARENA_ALLOC_BUDGET / 2, 0);
    assert_non_null(big);
    alloc->free(alloc, big);
}

static void realloc_rejects_pointer_outside_zone_b(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();
    uint8_t                      stack_block[64];

    assert_null(alloc->realloc(
        alloc, stack_block, sizeof(stack_block), 128, sizeof(void*)));
}

static void alloc_survives_when_init_called_after_alloc(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    void* p = alloc->alloc(alloc, 128, sizeof(void*));
    assert_non_null(p);
    memset(p, 0xAB, 128);

    if (NULL != alloc->init) {
        alloc->init(alloc, NULL);
    }

    unsigned char* bytes = (unsigned char*)p;
    for (size_t i = 0; i < 128; ++i) {
        assert_int_equal(bytes[i], 0xAB);
    }
    alloc->free(alloc, p);
}

static void alloc_over_aligned_returns_null(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = test_arena();

    /* Cell size is 256; alignment > 256 is unsatisfiable. */
    void* p = alloc->alloc(alloc, 32, 512);
    assert_null(p);
}

/* ================================================================== */
/*  Edge-case tests (small dedicated arena, 8 Zone B cells).           */
/* ================================================================== */

/**
 * Test 1: Zero-init on reuse.
 * Alloc a cell, write non-zero data, free it, re-alloc same size,
 * verify returned memory is zeroed.
 */
static void edge_zero_init_on_reuse(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    size_t                       i;

    uint8_t* p = (uint8_t*)alloc->alloc(alloc, 128, 0);
    assert_non_null(p);
    memset(p, 0xDE, TEST_CELL_SIZE);
    alloc->free(alloc, p);

    uint8_t* p2 = (uint8_t*)alloc->alloc(alloc, 128, 0);
    assert_non_null(p2);
    assert_ptr_equal(p, p2);
    for (i = 0; i < TEST_CELL_SIZE; ++i) {
        assert_int_equal(p2[i], 0);
    }
    alloc->free(alloc, p2);
}

/**
 * Test 2: Fragmented pool — alloc cells 0..7, free cells 2..4,
 * alloc 3 cells (must get cells 2..4), alloc 4 cells (must fail).
 */
static void edge_fragmented_pool_scan(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        cells[EDGE_ZONE_B_CELLS];
    size_t                       i;
    void*                        three;
    void*                        four;

    /* Occupy all 8 cells with 1-cell allocations. */
    for (i = 0; i < EDGE_ZONE_B_CELLS; ++i) {
        cells[i] = alloc->alloc(alloc, 1, 0);
        assert_non_null(cells[i]);
    }

    /* Free cells 2, 3, 4 — creates a 3-cell gap in the middle. */
    alloc->free(alloc, cells[2]);
    alloc->free(alloc, cells[3]);
    alloc->free(alloc, cells[4]);

    /* Alloc 3 cells — must fit in the gap at cells 2..4. */
    three = alloc->alloc(alloc, 3 * TEST_CELL_SIZE, 0);
    assert_non_null(three);
    assert_ptr_equal(three, cells[2]);

    /* Alloc 4 cells — no 4-cell run exists (0,1 + gap used + 5,6,7). */
    four = alloc->alloc(alloc, 4 * TEST_CELL_SIZE, 0);
    assert_null(four);

    /* Cleanup. */
    alloc->free(alloc, three);
    alloc->free(alloc, cells[0]);
    alloc->free(alloc, cells[1]);
    alloc->free(alloc, cells[5]);
    alloc->free(alloc, cells[6]);
    alloc->free(alloc, cells[7]);
}

/**
 * Test 3: Full pool exhaustion — alloc all cells one by one, verify
 * the next alloc fails. Free one cell, verify 1-cell alloc succeeds.
 */
static void edge_full_pool_exhaustion(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        cells[EDGE_ZONE_B_CELLS];
    size_t                       i;
    void*                        overflow;
    void*                        reclaimed;

    for (i = 0; i < EDGE_ZONE_B_CELLS; ++i) {
        cells[i] = alloc->alloc(alloc, 1, 0);
        assert_non_null(cells[i]);
    }

    /* Pool is full — next alloc must fail. */
    overflow = alloc->alloc(alloc, 1, 0);
    assert_null(overflow);

    /* Free one cell and verify reclaim. */
    alloc->free(alloc, cells[3]);
    reclaimed = alloc->alloc(alloc, 1, 0);
    assert_non_null(reclaimed);
    assert_ptr_equal(reclaimed, cells[3]);

    /* Cleanup. */
    alloc->free(alloc, reclaimed);
    for (i = 0; i < EDGE_ZONE_B_CELLS; ++i) {
        if (3 != i) {
            alloc->free(alloc, cells[i]);
        }
    }
}

/**
 * Test 4: Double-free safety — alloc, free, free again.
 * Must not crash or corrupt state. Verify subsequent alloc works.
 */
static void edge_double_free_safety(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        p;
    void*                        p2;

    p = alloc->alloc(alloc, 64, 0);
    assert_non_null(p);

    alloc->free(alloc, p);
    /* Second free — must be silently ignored. */
    alloc->free(alloc, p);

    /* Arena must still be functional. */
    p2 = alloc->alloc(alloc, 64, 0);
    assert_non_null(p2);
    alloc->free(alloc, p2);
}

/**
 * Test 5: Zone A pointer rejection — call arena_free on a Zone A
 * pointer (rx_buf.data). Must be silently ignored without corrupting
 * Zone A slot tracking.
 */
static void edge_zone_a_pointer_rejected_by_free(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    pubnub_buffer_t              rx;
    pubnub_buffer_t              rx2;

    rx = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    assert_non_null(rx.data);

    /* Pass Zone A pointer to Zone B free — must be ignored. */
    alloc->free(alloc, rx.data);

    /* Zone A slot must still be marked in-use (buf_acquire must fail
     * if all slots are occupied after this one). Verify by releasing
     * and re-acquiring. */
    alloc->buf_release(alloc, &rx);
    rx2 = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    assert_non_null(rx2.data);
    alloc->buf_release(alloc, &rx2);
}

/**
 * Test 6: Misaligned pointer rejection — call arena_free with a
 * pointer into the middle of a Zone B cell. Must be silently ignored.
 */
static void edge_misaligned_pointer_rejected_by_free(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    uint8_t*                     misaligned;
    void*                        p;
    void*                        p2;

    /* Allocate one cell so zone_b_base + 0 is occupied. */
    p = alloc->alloc(alloc, 1, 0);
    assert_non_null(p);

    /* Construct a misaligned pointer: base + half a cell. */
    misaligned = s_edge_arena.zone_b_base + TEST_CELL_SIZE / 2;

    /* Free the misaligned pointer — must be silently ignored. */
    alloc->free(alloc, misaligned);

    /* The original allocation must still be live. Free it and
     * verify the cell is reclaimable. */
    alloc->free(alloc, p);
    p2 = alloc->alloc(alloc, 1, 0);
    assert_non_null(p2);
    assert_ptr_equal(p, p2);
    alloc->free(alloc, p2);
}

/**
 * Test 7: Large alloc — allocate all Zone B cells in one call.
 * Free and verify the pool is fully available again.
 */
static void edge_large_alloc_full_zone_b(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        big;
    void*                        small;

    big = alloc->alloc(alloc, (size_t)EDGE_ZONE_B_CELLS * TEST_CELL_SIZE, 0);
    assert_non_null(big);

    /* Pool is fully consumed — another alloc must fail. */
    small = alloc->alloc(alloc, 1, 0);
    assert_null(small);

    /* Free and verify full recovery. */
    alloc->free(alloc, big);
    big = alloc->alloc(alloc, (size_t)EDGE_ZONE_B_CELLS * TEST_CELL_SIZE, 0);
    assert_non_null(big);
    alloc->free(alloc, big);
}

/**
 * Test 8: Zero-size alloc — must return NULL without touching cells.
 */
static void edge_zero_size_alloc_returns_null(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        p;
    void*                        p2;

    p = alloc->alloc(alloc, 0, sizeof(void*));
    assert_null(p);

    /* Arena must still be fully functional. */
    p2 = alloc->alloc(alloc, 64, 0);
    assert_non_null(p2);
    alloc->free(alloc, p2);
}

/**
 * Test 9: cell_total boundary — alloc exactly cell_total cells in
 * one call succeeds. cell_total + 1 cells fails.
 */
static void edge_cell_total_boundary(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc      = &s_edge_arena.base;
    size_t                       cell_total = s_edge_arena.cell_total;
    void*                        exact;
    void*                        over;

    assert_true(cell_total == EDGE_ZONE_B_CELLS);

    /* Exactly cell_total cells — must succeed. */
    exact = alloc->alloc(alloc, cell_total * TEST_CELL_SIZE, 0);
    assert_non_null(exact);
    alloc->free(alloc, exact);

    /* cell_total + 1 cells — must fail. */
    over = alloc->alloc(alloc, (cell_total + 1) * TEST_CELL_SIZE, 0);
    assert_null(over);
}

/**
 * Test 10: Interleaved alloc/free stress — simulates real subscribe
 * loop: alloc serialization workspace (multi-cell), alloc decomp_buf
 * (small), free serialization, re-alloc serialization, verify no
 * fragmentation failure.
 */
static void edge_interleaved_alloc_free_stress(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    int                          i;

    /* Use 4 cells for "serialization" and 1 for "decomp". Total = 5
     * out of 8 cells, leaving 3 free. After freeing serialization,
     * 7 free cells (4 returned + 3 unused). Re-alloc 4 must succeed
     * because freed cells form a contiguous run at the start. */
    for (i = 0; i < 100; ++i) {
        void* ser;
        void* decomp;
        ser = alloc->alloc(alloc, 4 * TEST_CELL_SIZE, 0);
        assert_non_null(ser);

        decomp = alloc->alloc(alloc, 1 * TEST_CELL_SIZE, 0);
        assert_non_null(decomp);

        /* Free serialization — cells 0..3 return to the pool.
         * decomp occupies cell 4. */
        alloc->free(alloc, ser);

        /* Re-alloc serialization — first-fit finds cells 0..3. */
        ser = alloc->alloc(alloc, 4 * TEST_CELL_SIZE, 0);
        assert_non_null(ser);

        alloc->free(alloc, ser);
        alloc->free(alloc, decomp);
    }
}

/**
 * Test: deinit + init cycle restores usability.
 * Verifies the arena_init bug fix: after deinit zeroes cell_total,
 * init must restore it so allocations succeed.
 */
static void edge_deinit_init_restores_usability(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        p;

    /* Allocate something to confirm arena is working. */
    p = alloc->alloc(alloc, 64, 0);
    assert_non_null(p);
    alloc->free(alloc, p);

    /* deinit zeroes cell_total. */
    alloc->deinit(alloc, NULL);
    assert_int_equal(s_edge_arena.cell_total, 0);

    /* init must restore cell_total. */
    alloc->init(alloc, NULL);
    assert_int_equal(s_edge_arena.cell_total, EDGE_ZONE_B_CELLS);

    /* Arena must be fully functional after the cycle. */
    p = alloc->alloc(alloc, 64, 0);
    assert_non_null(p);
    alloc->free(alloc, p);
}

/**
 * Test: alloc request larger than total Zone B budget returns NULL.
 */
static void edge_alloc_exceeds_zone_b_returns_null(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = &s_edge_arena.base;
    void*                        p;

    p = alloc->alloc(alloc, (size_t)(EDGE_ZONE_B_CELLS + 1) * TEST_CELL_SIZE, 0);
    assert_null(p);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Original tests (default arena). */
        cmocka_unit_test_setup(alloc_returns_non_null, setup),
        cmocka_unit_test_setup(alloc_returned_memory_is_zeroed, setup),
        cmocka_unit_test_setup(free_null_is_safe, setup),
        cmocka_unit_test_setup(buf_acquire_rx_pool_has_max_in_flight_slots, setup),
        cmocka_unit_test_setup(
            buf_acquire_obj_pool_has_in_flight_plus_pending_slots, setup),
        cmocka_unit_test_setup(buf_acquire_scratch_pool_has_max_in_flight_slots,
                               setup),
        cmocka_unit_test_setup(buf_release_makes_slot_available, setup),
        cmocka_unit_test_setup(alloc_bump_exhaustion_then_recover, setup),
        cmocka_unit_test_setup(alloc_honours_alignment_request, setup),
        cmocka_unit_test_setup(alloc_publish_cycle_cursor_stabilises, setup),
        cmocka_unit_test_setup(alloc_token_rotation_cursor_stable, setup),
        cmocka_unit_test_setup(alloc_non_fifo_free_order_no_corruption, setup),
        cmocka_unit_test_setup(deinit_bulk_free_then_reinit_serves_full_budget, setup),
        cmocka_unit_test_setup(buf_grow_is_null_but_realloc_is_implemented, setup),
        cmocka_unit_test_setup(
            realloc_grows_and_shrinks_in_place_preserving_bytes, setup),
        cmocka_unit_test_setup(realloc_delegates_null_to_alloc_and_zero_to_free,
                               setup),
        cmocka_unit_test_setup(realloc_rejects_pointer_outside_zone_b, setup),
        cmocka_unit_test_setup(alloc_survives_when_init_called_after_alloc, setup),
        cmocka_unit_test_setup(alloc_over_aligned_returns_null, setup),

        /* Edge-case tests (small dedicated arena). */
        cmocka_unit_test_setup(edge_zero_init_on_reuse, setup_edge),
        cmocka_unit_test_setup(edge_fragmented_pool_scan, setup_edge),
        cmocka_unit_test_setup(edge_full_pool_exhaustion, setup_edge),
        cmocka_unit_test_setup(edge_double_free_safety, setup_edge),
        cmocka_unit_test_setup(edge_zone_a_pointer_rejected_by_free, setup_edge),
        cmocka_unit_test_setup(edge_misaligned_pointer_rejected_by_free, setup_edge),
        cmocka_unit_test_setup(edge_large_alloc_full_zone_b, setup_edge),
        cmocka_unit_test_setup(edge_zero_size_alloc_returns_null, setup_edge),
        cmocka_unit_test_setup(edge_cell_total_boundary, setup_edge),
        cmocka_unit_test_setup(edge_interleaved_alloc_free_stress, setup_edge),
        cmocka_unit_test_setup(edge_deinit_init_restores_usability, setup_edge),
        cmocka_unit_test_setup(edge_alloc_exceeds_zone_b_returns_null, setup_edge),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

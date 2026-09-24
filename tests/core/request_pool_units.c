/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file request_pool_units.c
 * @brief Unit tests for the request pool.
 *
 * Pool in isolation -- no pubnub_context_t, no pipeline. The
 * future's ctx field is populated with a mock pointer to prove it
 * round-trips verbatim. Context integration is exercised in
 * client_units.c.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/pending_queue_internal.h"
#include "core/runtime/request_pool_internal.h"

/* ======================================================================== */
/* Mock allocator with optional OOM injection                                */
/* ======================================================================== */

static int s_alloc_count;
static int s_alloc_fail_after; /* -1 = never fail; otherwise fail after N. */

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    if (s_alloc_fail_after >= 0 && s_alloc_count >= s_alloc_fail_after) {
        return NULL;
    }
    void* p = malloc(size);
    if (p != NULL) {
        s_alloc_count++;
    }
    return p;
}

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_allocator = {
    .alloc       = mock_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

/* Alloc provider with a NULL alloc function -- used to exercise
 * argument validation. */
static pubnub_allocator_provider_t s_null_alloc_fn_allocator = {
    .alloc       = NULL,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static int reset_test(void** state)
{
    (void)state;
    s_alloc_count      = 0;
    s_alloc_fail_after = -1;
    return 0;
}

/* ======================================================================== */
/* Tests: pn_request_pool_init                                               */
/* ======================================================================== */

static void init_should_allocate_capacity_slots_in_idle_state(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    memset(&sut, 0, sizeof(sut));

    pubnub_res_t rc = pn_request_pool_init(&sut, 4, &s_allocator, NULL, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(sut.capacity, 4);
    assert_int_equal(sut.in_use_count, 0);
    assert_non_null(sut.slots);
    /* Each slot starts IDLE with its slot_id set to the array index. */
    for (uint16_t i = 0; i < 4; i++) {
        assert_true(pn_request_is_idle(&sut.slots[i]));
        assert_int_equal(sut.slots[i].slot_id, i);
    }

    pn_request_pool_deinit(&sut);
}

static void init_should_reject_null_pool(void** state)
{
    (void)state;

    pubnub_res_t rc = pn_request_pool_init(NULL, 2, &s_allocator, NULL, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_allocator(void** state)
{
    (void)state;
    pn_request_pool_t sut;

    pubnub_res_t rc = pn_request_pool_init(&sut, 2, NULL, NULL, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_allocator_with_null_alloc_fn(void** state)
{
    (void)state;
    pn_request_pool_t sut;

    pubnub_res_t rc =
        pn_request_pool_init(&sut, 2, &s_null_alloc_fn_allocator, NULL, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_zero_capacity(void** state)
{
    (void)state;
    pn_request_pool_t sut;

    pubnub_res_t rc = pn_request_pool_init(&sut, 0, &s_allocator, NULL, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_return_oom_when_allocator_fails(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    s_alloc_fail_after = 0; /* First alloc fails. */

    pubnub_res_t rc = pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
}

/* ======================================================================== */
/* Tests: pn_request_pool_deinit                                             */
/* ======================================================================== */

static void deinit_should_free_slots_and_clear_fields(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 3, &s_allocator, NULL, NULL, NULL);

    pn_request_pool_deinit(&sut);

    assert_null(sut.slots);
    assert_int_equal(sut.capacity, 0);
    assert_int_equal(sut.in_use_count, 0);
    assert_null(sut.allocator);
}

static void deinit_should_be_safe_on_zero_pool(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    memset(&sut, 0, sizeof(sut));

    /* Must not crash or call into the null allocator. */
    pn_request_pool_deinit(&sut);
}

static void deinit_should_be_safe_on_null(void** state)
{
    (void)state;

    pn_request_pool_deinit(NULL);
}

/* ======================================================================== */
/* Tests: pn_request_pool_acquire                                            */
/* ======================================================================== */

static void acquire_should_populate_future_and_transition_slot_to_pending(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);
    pubnub_context_t* fake_ctx = (pubnub_context_t*)0xDEADBEEF;
    pubnub_future_t   fut;

    pubnub_res_t rc = pn_request_pool_acquire(&sut, fake_ctx, &fut);

    assert_int_equal(rc, PUBNUB_OK);
    assert_ptr_equal(fut.ctx, fake_ctx);
    assert_int_equal(fut.status, PUBNUB_IN_PROGRESS);
    assert_int_equal(fut.slot_id, 0);
    /* The claimed slot transitioned IDLE -> PENDING; the pool count
     * bumped. */
    assert_int_equal(sut.slots[0].state, PN_REQUEST_PENDING);
    assert_int_equal(sut.in_use_count, 1);

    pn_request_pool_deinit(&sut);
}

static void acquire_should_return_queue_full_when_all_slots_are_in_use(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);
    pubnub_future_t fut1, fut2, fut3;
    pn_request_pool_acquire(&sut, NULL, &fut1);
    pn_request_pool_acquire(&sut, NULL, &fut2);

    pubnub_res_t rc = pn_request_pool_acquire(&sut, NULL, &fut3);

    assert_int_equal(rc, PUBNUB_ERR_QUEUE_FULL);
    assert_int_equal(sut.in_use_count, 2);

    pn_request_pool_deinit(&sut);
}

static void acquire_should_skip_non_idle_slots_and_pick_the_next_idle_one(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 3, &s_allocator, NULL, NULL, NULL);
    pubnub_future_t first;
    pn_request_pool_acquire(&sut, NULL, &first);
    assert_int_equal(first.slot_id, 0);

    pubnub_future_t second;
    pubnub_res_t    rc = pn_request_pool_acquire(&sut, NULL, &second);

    assert_int_equal(rc, PUBNUB_OK);
    /* Slot 0 is busy; acquire must hand out slot 1. */
    assert_int_equal(second.slot_id, 1);
    assert_int_equal(sut.in_use_count, 2);

    pn_request_pool_deinit(&sut);
}

static void acquire_should_reject_null_pool(void** state)
{
    (void)state;
    pubnub_future_t fut;

    pubnub_res_t rc = pn_request_pool_acquire(NULL, NULL, &fut);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void acquire_should_reject_null_out_future(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    pubnub_res_t rc = pn_request_pool_acquire(&sut, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    pn_request_pool_deinit(&sut);
}

static void acquire_should_leave_out_future_untouched_on_queue_full(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 1, &s_allocator, NULL, NULL, NULL);
    pubnub_future_t used;
    pn_request_pool_acquire(&sut, NULL, &used);

    /* Pre-fill with a distinctive pattern so we can prove acquire
     * did not write anything to out_future on queue-full. */
    pubnub_future_t probe;
    probe.ctx     = (pubnub_context_t*)0xABADCAFE;
    probe.slot_id = 0xBEEF;
    probe.status  = PUBNUB_ERR_INTERNAL;

    pubnub_res_t rc = pn_request_pool_acquire(&sut, NULL, &probe);

    assert_int_equal(rc, PUBNUB_ERR_QUEUE_FULL);
    /* Docstring: "@p out_future is populated on success; left
     * untouched on failure."  Pins the contract. */
    assert_ptr_equal(probe.ctx, (pubnub_context_t*)0xABADCAFE);
    assert_int_equal(probe.slot_id, 0xBEEF);
    assert_int_equal(probe.status, PUBNUB_ERR_INTERNAL);

    pn_request_pool_deinit(&sut);
}

/* ======================================================================== */
/* Tests: pn_request_pool_release                                            */
/* ======================================================================== */

static void release_should_return_slot_to_idle_and_decrement_count(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);
    pubnub_future_t fut;
    pn_request_pool_acquire(&sut, NULL, &fut);
    assert_int_equal(sut.in_use_count, 1);

    pn_request_pool_release(&sut, fut.slot_id);

    assert_true(pn_request_is_idle(&sut.slots[fut.slot_id]));
    /* slot_id is preserved through reset+re-init. */
    assert_int_equal(sut.slots[fut.slot_id].slot_id, fut.slot_id);
    assert_int_equal(sut.in_use_count, 0);

    pn_request_pool_deinit(&sut);
}

static void release_should_be_safe_on_already_idle_slot(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    pn_request_pool_release(&sut, 0);

    /* No-op: count stays at 0, slot stays IDLE. */
    assert_int_equal(sut.in_use_count, 0);
    assert_true(pn_request_is_idle(&sut.slots[0]));

    pn_request_pool_deinit(&sut);
}

static void release_should_be_safe_with_out_of_bounds_slot_id(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    /* Must not crash, must not touch in_use_count. */
    pn_request_pool_release(&sut, 99);

    assert_int_equal(sut.in_use_count, 0);

    pn_request_pool_deinit(&sut);
}

static void pool_should_reuse_slot_after_release(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);
    pubnub_future_t first;
    pn_request_pool_acquire(&sut, NULL, &first);
    pn_request_pool_release(&sut, first.slot_id);

    pubnub_future_t second;
    pubnub_res_t    rc = pn_request_pool_acquire(&sut, NULL, &second);

    assert_int_equal(rc, PUBNUB_OK);
    /* The freed slot is the first IDLE one the scan finds. */
    assert_int_equal(second.slot_id, first.slot_id);

    pn_request_pool_deinit(&sut);
}

static void acquire_after_release_should_return_a_pending_slot_not_terminal(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 1, &s_allocator, NULL, NULL, NULL);
    pubnub_future_t first;
    pn_request_pool_acquire(&sut, NULL, &first);

    /* Drive the slot through a terminal state (as a real request
     * would) before releasing, so we know release doesn't just
     * see IDLE. */
    pn_request_t* slot = pn_request_pool_get(&sut, first.slot_id);
    slot->state        = PN_REQUEST_IN_FLIGHT;
    PN_REQUEST_ON_FAILURE(slot, PUBNUB_ERR_TRANSPORT);
    assert_int_equal(slot->state, PN_REQUEST_FAILED);

    pn_request_pool_release(&sut, first.slot_id);

    pubnub_future_t second;
    assert_int_equal(pn_request_pool_acquire(&sut, NULL, &second), PUBNUB_OK);
    /* The recycled slot must come out at PENDING (via enqueue),
     * not carrying forward FAILED state or the stale result. */
    pn_request_t* recycled = pn_request_pool_get(&sut, second.slot_id);
    assert_int_equal(recycled->state, PN_REQUEST_PENDING);
    assert_int_equal(recycled->result, PUBNUB_OK);

    pn_request_pool_deinit(&sut);
}

/* ======================================================================== */
/* Tests: pn_request_pool_get                                                */
/* ======================================================================== */

static void get_should_return_slot_for_valid_id(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 3, &s_allocator, NULL, NULL, NULL);

    pn_request_t* slot = pn_request_pool_get(&sut, 1);

    assert_non_null(slot);
    assert_ptr_equal(slot, &sut.slots[1]);

    pn_request_pool_deinit(&sut);
}

static void get_should_return_null_for_out_of_bounds_id(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    assert_null(pn_request_pool_get(&sut, 2));
    assert_null(pn_request_pool_get(&sut, 9999));

    pn_request_pool_deinit(&sut);
}

static void get_should_return_null_for_null_pool(void** state)
{
    (void)state;

    assert_null(pn_request_pool_get(NULL, 0));
}

/* ======================================================================== */
/* Tests: PUBNUB_SLOT_ID_INVALID sentinel contract                           */
/* ======================================================================== */

/* Pins the raw numeric contract: UINT16_MAX is outside every
 * realistic pool capacity (capacity is uint16_t, real deployments
 * use single-digit capacities), so the pool's bounds check
 * naturally rejects the sentinel. If someone ever changes the
 * sentinel value, this test fails loudly and the change must be
 * justified. */
static void sentinel_should_equal_uint16_max(void** state)
{
    (void)state;
    assert_int_equal((uint16_t)PUBNUB_SLOT_ID_INVALID, UINT16_MAX);
}

/* Pins the integration between the pool sentinel and the
 * PUBNUB_FUTURE_INVALID macro so a future refactor that forgets
 * to route the macro through the sentinel fails here. */
static void future_invalid_macro_should_carry_sentinel_slot_id(void** state)
{
    (void)state;
    pubnub_future_t invalid = PUBNUB_FUTURE_INVALID;
    assert_null(invalid.ctx);
    assert_int_equal(invalid.slot_id, PUBNUB_SLOT_ID_INVALID);
    assert_int_equal(invalid.status, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* Pins the 'second line of defence' behaviour claimed in
 * include/pubnub/future.h -- if a caller forgets the ctx-NULL
 * short-circuit and walks straight to pn_request_pool_get with the
 * sentinel, the pool's existing bounds check rejects it. */
static void get_should_return_null_for_sentinel_slot_id(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 4, &s_allocator, NULL, NULL, NULL);

    assert_null(pn_request_pool_get(&sut, PUBNUB_SLOT_ID_INVALID));

    pn_request_pool_deinit(&sut);
}

/* Counterpart to the _get test -- the publish feature's
 * failed_future ultimately flows into pubnub_future_release; this
 * pins that passing the sentinel is a no-op rather than a crash /
 * spurious in_use_count decrement. */
static void release_should_be_safe_with_sentinel_slot_id(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 4, &s_allocator, NULL, NULL, NULL);

    /* Acquire one slot so in_use_count is non-zero; we want to
     * prove release-with-sentinel does not touch it. */
    pubnub_future_t active;
    assert_int_equal(pn_request_pool_acquire(&sut, NULL, &active), PUBNUB_OK);
    assert_int_equal(sut.in_use_count, 1);

    pn_request_pool_release(&sut, PUBNUB_SLOT_ID_INVALID);

    /* Sentinel release is a no-op: count is unchanged, the active
     * slot is still pending, and releasing the real slot afterwards
     * still works. */
    assert_int_equal(sut.in_use_count, 1);
    assert_false(pn_request_is_idle(&sut.slots[active.slot_id]));
    pn_request_pool_release(&sut, active.slot_id);
    assert_int_equal(sut.in_use_count, 0);

    pn_request_pool_deinit(&sut);
}

/**
 * Create a pending entry with path_segments, query_params, AND headers
 * all pointing into scratch. Copy to a slot (simulating promotion),
 * relocate, verify ALL three view types point into the slot's scratch.
 */
static void populate_slot_relocates_all_scratch_view_types(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    pubnub_future_t fut;
    pn_request_pool_acquire(&sut, NULL, &fut);
    pn_request_t* slot = pn_request_pool_get(&sut, fut.slot_id);

    /* Build a source entry with views pointing into its own scratch. */
    pn_pending_entry_t src;
    memset(&src, 0, sizeof(src));
    memcpy(src.http_request.scratch, "pathseg", 7);
    memcpy(src.http_request.scratch + 7, "qkey", 4);
    memcpy(src.http_request.scratch + 11, "qval", 4);
    memcpy(src.http_request.scratch + 15, "hkey", 4);
    memcpy(src.http_request.scratch + 19, "hval", 4);

    src.http_request.path_segments[0] =
        (pubnub_string_view_t){(const char*)src.http_request.scratch, 7};
    src.http_request.path_segment_count = 1;

    src.http_request.query_params[0].key =
        (pubnub_string_view_t){(const char*)src.http_request.scratch + 7, 4};
    src.http_request.query_params[0].value =
        (pubnub_string_view_t){(const char*)src.http_request.scratch + 11, 4};
    src.http_request.query_param_count = 1;

    src.http_request.headers[0].key =
        (pubnub_string_view_t){(const char*)src.http_request.scratch + 15, 4};
    src.http_request.headers[0].value =
        (pubnub_string_view_t){(const char*)src.http_request.scratch + 19, 4};
    src.http_request.header_count = 1;

    /* Copy the request into the slot and relocate. */
    slot->http_request = src.http_request;
    pn_http_request_relocate_scratch_ptrs(&slot->http_request, &src.http_request);

    /* All views must now point into the slot's scratch. */
    uintptr_t lo = (uintptr_t)slot->http_request.scratch;
    uintptr_t hi = lo + PUBNUB_CFG_HTTP_SCRATCH_SIZE;

    uintptr_t path_ptr = (uintptr_t)slot->http_request.path_segments[0].ptr;
    assert_true(path_ptr >= lo && path_ptr < hi);
    assert_memory_equal(slot->http_request.path_segments[0].ptr, "pathseg", 7);

    uintptr_t qk = (uintptr_t)slot->http_request.query_params[0].key.ptr;
    uintptr_t qv = (uintptr_t)slot->http_request.query_params[0].value.ptr;
    assert_true(qk >= lo && qk < hi);
    assert_true(qv >= lo && qv < hi);
    assert_memory_equal(slot->http_request.query_params[0].key.ptr, "qkey", 4);
    assert_memory_equal(slot->http_request.query_params[0].value.ptr, "qval", 4);

    uintptr_t hk = (uintptr_t)slot->http_request.headers[0].key.ptr;
    uintptr_t hv = (uintptr_t)slot->http_request.headers[0].value.ptr;
    assert_true(hk >= lo && hk < hi);
    assert_true(hv >= lo && hv < hi);
    assert_memory_equal(slot->http_request.headers[0].key.ptr, "hkey", 4);
    assert_memory_equal(slot->http_request.headers[0].value.ptr, "hval", 4);

    pn_request_pool_deinit(&sut);
}

/**
 * Create a source entry with 0 query params, relocate to slot.
 * Must not crash.
 */
static void populate_slot_with_zero_query_params_is_safe(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    pubnub_future_t fut;
    pn_request_pool_acquire(&sut, NULL, &fut);
    pn_request_t* slot = pn_request_pool_get(&sut, fut.slot_id);

    pn_pending_entry_t src;
    memset(&src, 0, sizeof(src));
    src.http_request.query_param_count  = 0;
    src.http_request.header_count       = 0;
    src.http_request.path_segment_count = 0;

    slot->http_request = src.http_request;
    /* Must not crash with zero counts. */
    pn_http_request_relocate_scratch_ptrs(&slot->http_request, &src.http_request);

    assert_int_equal(slot->http_request.query_param_count, 0);
    assert_int_equal(slot->http_request.header_count, 0);

    pn_request_pool_deinit(&sut);
}

/**
 * Create an entry with method=POST and a body pointer, relocate to
 * slot. Verify body pointer is preserved (not corrupted by relocation,
 * since body is outside scratch).
 */
static void populate_slot_preserves_body_pointer_for_post(void** state)
{
    (void)state;
    pn_request_pool_t sut;
    pn_request_pool_init(&sut, 2, &s_allocator, NULL, NULL, NULL);

    pubnub_future_t fut;
    pn_request_pool_acquire(&sut, NULL, &fut);
    pn_request_t* slot = pn_request_pool_get(&sut, fut.slot_id);

    static const char body_data[] = "{\"key\":\"value\"}";

    pn_pending_entry_t src;
    memset(&src, 0, sizeof(src));
    src.http_request.method   = PUBNUB_HTTP_POST;
    src.http_request.body     = body_data;
    src.http_request.body_len = sizeof(body_data) - 1;

    slot->http_request = src.http_request;
    pn_http_request_relocate_scratch_ptrs(&slot->http_request, &src.http_request);

    /* Body pointer is outside scratch, so it must remain unchanged. */
    assert_ptr_equal(slot->http_request.body, body_data);
    assert_int_equal(slot->http_request.body_len, sizeof(body_data) - 1);
    assert_int_equal(slot->http_request.method, PUBNUB_HTTP_POST);

    pn_request_pool_deinit(&sut);
}

/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* init */
        cmocka_unit_test_setup(init_should_allocate_capacity_slots_in_idle_state,
                               reset_test),
        cmocka_unit_test_setup(init_should_reject_null_pool, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_allocator, reset_test),
        cmocka_unit_test_setup(init_should_reject_allocator_with_null_alloc_fn,
                               reset_test),
        cmocka_unit_test_setup(init_should_reject_zero_capacity, reset_test),
        cmocka_unit_test_setup(init_should_return_oom_when_allocator_fails,
                               reset_test),

        /* deinit */
        cmocka_unit_test_setup(deinit_should_free_slots_and_clear_fields, reset_test),
        cmocka_unit_test_setup(deinit_should_be_safe_on_zero_pool, reset_test),
        cmocka_unit_test_setup(deinit_should_be_safe_on_null, reset_test),

        /* acquire */
        cmocka_unit_test_setup(
            acquire_should_populate_future_and_transition_slot_to_pending, reset_test),
        cmocka_unit_test_setup(
            acquire_should_return_queue_full_when_all_slots_are_in_use, reset_test),
        cmocka_unit_test_setup(
            acquire_should_skip_non_idle_slots_and_pick_the_next_idle_one, reset_test),
        cmocka_unit_test_setup(acquire_should_reject_null_pool, reset_test),
        cmocka_unit_test_setup(acquire_should_reject_null_out_future, reset_test),
        cmocka_unit_test_setup(
            acquire_should_leave_out_future_untouched_on_queue_full, reset_test),

        /* release */
        cmocka_unit_test_setup(
            release_should_return_slot_to_idle_and_decrement_count, reset_test),
        cmocka_unit_test_setup(release_should_be_safe_on_already_idle_slot,
                               reset_test),
        cmocka_unit_test_setup(release_should_be_safe_with_out_of_bounds_slot_id,
                               reset_test),
        cmocka_unit_test_setup(pool_should_reuse_slot_after_release, reset_test),
        cmocka_unit_test_setup(
            acquire_after_release_should_return_a_pending_slot_not_terminal,
            reset_test),

        /* get */
        cmocka_unit_test_setup(get_should_return_slot_for_valid_id, reset_test),
        cmocka_unit_test_setup(get_should_return_null_for_out_of_bounds_id,
                               reset_test),
        cmocka_unit_test_setup(get_should_return_null_for_null_pool, reset_test),

        /* PUBNUB_SLOT_ID_INVALID sentinel */
        cmocka_unit_test_setup(sentinel_should_equal_uint16_max, reset_test),
        cmocka_unit_test_setup(future_invalid_macro_should_carry_sentinel_slot_id,
                               reset_test),
        cmocka_unit_test_setup(get_should_return_null_for_sentinel_slot_id,
                               reset_test),
        cmocka_unit_test_setup(release_should_be_safe_with_sentinel_slot_id,
                               reset_test),

        /* scratch relocation */
        cmocka_unit_test_setup(populate_slot_relocates_all_scratch_view_types,
                               reset_test),
        cmocka_unit_test_setup(populate_slot_with_zero_query_params_is_safe,
                               reset_test),
        cmocka_unit_test_setup(populate_slot_preserves_body_pointer_for_post,
                               reset_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

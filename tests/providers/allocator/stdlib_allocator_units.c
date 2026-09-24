/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file stdlib_allocator_units.c
 * @brief Unit tests for the libc-backed stdlib allocator provider.
 *
 * Covers the six callbacks (alloc, realloc, free, buf_acquire,
 * buf_release, buf_grow) and the purpose-to-capacity mapping.
 * All tests use the real allocator -- there is no mock layer
 * because the provider is the thin wrapper itself.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/providers/allocator.h"

pubnub_allocator_provider_t* pn_allocator_default(void);

/* ======================================================================== */
/* Tests: alloc / realloc / free                                             */
/* ======================================================================== */

static void alloc_should_return_non_null_for_nonzero_size(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    void* p = alloc->alloc(alloc, 64, 0);

    assert_non_null(p);
    alloc->free(alloc, p);
}

static void alloc_should_honour_natural_alignment(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    /* align=0 means "natural alignment" -- libc's malloc is required
     * to return memory aligned for any fundamental type, i.e.
     * _Alignof(max_align_t). That contract holds on both hosted
     * builds (typically 8 or 16 bytes) and on embedded stdlib-backed
     * builds (FreeRTOS + newlib on Cortex-M yields 4 or 8 bytes
     * depending on whether the target has an FPU). Embedded cores
     * raise a HardFault on unaligned word accesses, so pinning the
     * assertion to the real _Alignof(max_align_t) value -- rather
     * than a hard-coded hosted-sized constant -- is what keeps this
     * test meaningful across the profiles that may plug in this
     * provider. */
#if defined(_MSC_VER)
    /* MSVC C mode does not expose max_align_t reliably. MSVC malloc
     * aligns to MEMORY_ALLOCATION_ALIGNMENT (8 on x86, 16 on x64). */
    const size_t natural_align = sizeof(void*) * 2;
#else
    const size_t natural_align = _Alignof(max_align_t);
#endif

    void* p = alloc->alloc(alloc, 128, 0);

    assert_non_null(p);
    assert_int_equal((uintptr_t)p % natural_align, 0);
    alloc->free(alloc, p);
}

static void alloc_should_honour_over_alignment_when_supported(void** state)
{
    (void)state;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(_WIN32)
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    /* 128-byte alignment is the kind of thing that matters for
     * SIMD / DMA buffers.  aligned_alloc honours it. We don't
     * assert the exact alignment on non-C11 / Windows because the
     * provider falls back to plain malloc there. */
    void* p = alloc->alloc(alloc, 256, 128);

    assert_non_null(p);
    assert_int_equal((uintptr_t)p % 128, 0);
    alloc->free(alloc, p);
#else
    (void)state;
    skip();
#endif
}

static void free_should_accept_null(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    /* libc guarantees free(NULL) is a no-op. Must not crash. */
    alloc->free(alloc, NULL);
}

static void realloc_should_grow_and_preserve_content(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    uint8_t*                     p     = (uint8_t*)alloc->alloc(alloc, 16, 0);
    for (size_t i = 0; i < 16; i++) {
        p[i] = (uint8_t)(i * 3 + 7);
    }

    uint8_t* q = (uint8_t*)alloc->realloc(alloc, p, 16, 256, 0);

    assert_non_null(q);
    /* libc realloc preserves content up to min(old, new). */
    for (size_t i = 0; i < 16; i++) {
        assert_int_equal(q[i], (uint8_t)(i * 3 + 7));
    }
    alloc->free(alloc, q);
}

static void realloc_should_shrink_without_failing(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    uint8_t*                     p     = (uint8_t*)alloc->alloc(alloc, 1024, 0);

    uint8_t* q = (uint8_t*)alloc->realloc(alloc, p, 1024, 64, 0);

    assert_non_null(q);
    alloc->free(alloc, q);
}

/* ======================================================================== */
/* Tests: buf_acquire / buf_release                                          */
/* ======================================================================== */

static void buf_acquire_rx_should_return_response_buffer_sized_region(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    pubnub_buffer_t buf = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);

    assert_non_null(buf.data);
    assert_int_equal(buf.cap, (size_t)PUBNUB_CFG_RESPONSE_BUFFER_SIZE);
    assert_int_equal(buf.len, 0);
    assert_int_equal(buf.purpose, PUBNUB_BUF_RX);
    alloc->buf_release(alloc, &buf);
}

static void buf_acquire_obj_should_return_object_buffer_sized_region(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    pubnub_buffer_t buf = alloc->buf_acquire(alloc, PUBNUB_BUF_OBJ);

    assert_non_null(buf.data);
    assert_int_equal(buf.cap, (size_t)PUBNUB_CFG_OBJECT_BUFFER_SIZE);
    assert_int_equal(buf.len, 0);
    assert_int_equal(buf.purpose, PUBNUB_BUF_OBJ);
    alloc->buf_release(alloc, &buf);
}

static void buf_acquire_scratch_should_return_scratch_buffer_sized_region(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    pubnub_buffer_t buf = alloc->buf_acquire(alloc, PUBNUB_BUF_SCRATCH);

    assert_non_null(buf.data);
    assert_int_equal(buf.cap, (size_t)PUBNUB_CFG_SCRATCH_BUFFER_SIZE);
    assert_int_equal(buf.len, 0);
    assert_int_equal(buf.purpose, PUBNUB_BUF_SCRATCH);
    alloc->buf_release(alloc, &buf);
}

static void buf_release_should_null_the_data_pointer_and_zero_len_cap(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_buffer_t              buf = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    buf.len                          = 42; /* simulate writes */

    alloc->buf_release(alloc, &buf);

    /* After release the descriptor is zeroed -- no dangling
     * pointer, no stale length. The purpose is also cleared so a
     * double-release can't masquerade as a different purpose. */
    assert_null(buf.data);
    assert_int_equal(buf.len, 0);
    assert_int_equal(buf.cap, 0);
}

static void buf_release_should_be_safe_on_null_buffer(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    alloc->buf_release(alloc, NULL);
}

static void buf_release_should_be_idempotent(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_buffer_t              buf = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);

    alloc->buf_release(alloc, &buf);
    /* Second release on the already-freed descriptor: data is
     * NULL, libc free(NULL) is a no-op, our code mirrors that. */
    alloc->buf_release(alloc, &buf);
}

/* ======================================================================== */
/* Tests: buf_grow                                                           */
/* ======================================================================== */

static void buf_grow_should_expand_capacity_via_doubling(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_buffer_t buf         = alloc->buf_acquire(alloc, PUBNUB_BUF_SCRATCH);
    size_t          initial_cap = buf.cap;

    /* Request a capacity that's 2.5x the initial. Doubling rolls
     * forward from initial → 2*initial → 4*initial, and 4*initial
     * is the target the provider uses for the realloc. */
    int rc = alloc->buf_grow(alloc, &buf, initial_cap * 5 / 2);

    assert_int_equal(rc, 0);
    assert_non_null(buf.data);
    assert_true(buf.cap >= initial_cap * 5 / 2);
    alloc->buf_release(alloc, &buf);
}

static void buf_grow_should_be_no_op_when_already_large_enough(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_buffer_t buf      = alloc->buf_acquire(alloc, PUBNUB_BUF_SCRATCH);
    size_t          prev_cap = buf.cap;
    uint8_t*        prev_ptr = buf.data;

    int rc = alloc->buf_grow(alloc, &buf, prev_cap / 2);

    assert_int_equal(rc, 0);
    assert_int_equal(buf.cap, prev_cap);
    assert_ptr_equal(buf.data, prev_ptr);
    alloc->buf_release(alloc, &buf);
}

static void buf_grow_should_return_error_on_null_buffer(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    int rc = alloc->buf_grow(alloc, NULL, 1024);

    assert_int_not_equal(rc, 0);
}

static void buf_grow_should_return_error_on_buffer_with_null_data(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_buffer_t              buf   = {NULL, 0, 0, PUBNUB_BUF_SCRATCH};

    int rc = alloc->buf_grow(alloc, &buf, 1024);

    assert_int_not_equal(rc, 0);
}

static void buf_grow_should_preserve_content(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();
    pubnub_buffer_t buf = alloc->buf_acquire(alloc, PUBNUB_BUF_SCRATCH);
    assert_non_null(buf.data);
    for (size_t i = 0; i < 32; i++) {
        buf.data[i] = (uint8_t)(i ^ 0x5A);
    }

    int rc = alloc->buf_grow(alloc, &buf, buf.cap * 4);

    assert_int_equal(rc, 0);
    for (size_t i = 0; i < 32; i++) {
        assert_int_equal(buf.data[i], (uint8_t)(i ^ 0x5A));
    }
    alloc->buf_release(alloc, &buf);
}

/* ======================================================================== */
/* Tests: provider vtable surface                                            */
/* ======================================================================== */

static void provider_should_expose_every_required_callback(void** state)
{
    (void)state;
    pubnub_allocator_provider_t* alloc = pn_allocator_default();

    assert_non_null(alloc);
    assert_non_null(alloc->alloc);
    assert_non_null(alloc->realloc);
    assert_non_null(alloc->free);
    assert_non_null(alloc->buf_acquire);
    assert_non_null(alloc->buf_release);
    assert_non_null(alloc->buf_grow);
}

static void pn_allocator_default_should_return_same_singleton(void** state)
{
    (void)state;

    /* The provider is stateless; every call returns the same
     * address. Multiple contexts can share this instance without
     * coordination. */
    assert_ptr_equal(pn_allocator_default(), pn_allocator_default());
}

/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(alloc_should_return_non_null_for_nonzero_size),
        cmocka_unit_test(alloc_should_honour_natural_alignment),
        cmocka_unit_test(alloc_should_honour_over_alignment_when_supported),
        cmocka_unit_test(free_should_accept_null),
        cmocka_unit_test(realloc_should_grow_and_preserve_content),
        cmocka_unit_test(realloc_should_shrink_without_failing),
        cmocka_unit_test(buf_acquire_rx_should_return_response_buffer_sized_region),
        cmocka_unit_test(buf_acquire_obj_should_return_object_buffer_sized_region),
        cmocka_unit_test(buf_acquire_scratch_should_return_scratch_buffer_sized_region),
        cmocka_unit_test(buf_release_should_null_the_data_pointer_and_zero_len_cap),
        cmocka_unit_test(buf_release_should_be_safe_on_null_buffer),
        cmocka_unit_test(buf_release_should_be_idempotent),
        cmocka_unit_test(buf_grow_should_expand_capacity_via_doubling),
        cmocka_unit_test(buf_grow_should_be_no_op_when_already_large_enough),
        cmocka_unit_test(buf_grow_should_return_error_on_null_buffer),
        cmocka_unit_test(buf_grow_should_return_error_on_buffer_with_null_data),
        cmocka_unit_test(buf_grow_should_preserve_content),
        cmocka_unit_test(provider_should_expose_every_required_callback),
        cmocka_unit_test(pn_allocator_default_should_return_same_singleton),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

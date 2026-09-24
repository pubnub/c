/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file allocator_stdlib.c
 * @brief C standard-library-backed allocator provider.
 *
 * The `stdlib` allocator is the default for hosted profiles (`full`,
 * `minimal`). It wraps libc's `malloc` / `realloc` / `free` and
 * implements the purpose-tagged buffer API on top of dynamic
 * allocation - each @ref pubnub_buffer_t is a freshly-malloc'd
 * region whose size comes from a purpose-to-capacity table.
 *
 * The provider carries no per-instance state; a single static
 * singleton is returned from @ref pn_allocator_default. That keeps
 * the hot path branch-free (no `self` cast) and avoids heap
 * activity for the provider struct itself.
 */

#include "pubnub/providers/allocator.h"

#include <stdlib.h>
#include <string.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_allocator_provider_t* pn_allocator_default(void);

/**
 * @brief Default capacity in bytes for a newly-acquired buffer.
 *
 * Each purpose maps to its corresponding @c PUBNUB_CFG_*_BUFFER_SIZE
 * compile-time constant resolved via @ref config.h. Changing those
 * CMake cache variables is the intended tuning path.
 */
static size_t stdlib_default_capacity(pubnub_buf_purpose_t purpose)
{
    switch (purpose) {
    case PUBNUB_BUF_RX: return (size_t)PUBNUB_CFG_RESPONSE_BUFFER_SIZE;
    case PUBNUB_BUF_OBJ: return (size_t)PUBNUB_CFG_OBJECT_BUFFER_SIZE;
    case PUBNUB_BUF_SCRATCH: return (size_t)PUBNUB_CFG_SCRATCH_BUFFER_SIZE;
    }
    /* Unknown purpose — return 0 to signal acquire failure; the
     * caller was compiled against a newer SDK than this allocator
     * provider. */
    return 0;
}

/**
 * @brief Allocate @p size bytes with at least @p align alignment.
 *
 * libc's `malloc` already returns memory aligned to
 * `alignof(max_align_t)`, which is sufficient for every type the
 * SDK currently uses. Over-aligned requests (SIMD / page-aligned)
 * use C11's `aligned_alloc` when available. Windows is excluded
 * because its CRT does not provide `aligned_alloc`; over-aligned
 * requests on Windows fall back to `malloc` and rely on the
 * caller to verify alignment if it matters.
 *
 * The threshold for "over-aligned" is 16 bytes, which matches
 * `alignof(max_align_t)` on every mainstream x86_64 / ARM64 ABI.
 * A compile-time `_Alignof(max_align_t)` would be more precise
 * but triggers `-Wpre-c11-compat` on clang even inside a C11
 * guard, and we are not targeting platforms where max_align_t
 * exceeds 16.
 */
static void* stdlib_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(_WIN32)
    if (align > 16) {
        /* aligned_alloc requires size to be a multiple of align. */
        size_t padded = (size + align - 1) & ~(align - 1);
        return aligned_alloc(align, padded);
    }
#else
    (void)align;
#endif

    return malloc(size);
}

/**
 * @brief Reallocate a block previously returned by @ref stdlib_alloc.
 *
 * Follows C's `realloc` contract: on success, returns a pointer
 * that may or may not equal @p ptr; on failure, returns NULL and
 * leaves @p ptr valid.  @p old_size and @p align are unused for
 * stdlib (libc tracks block sizes internally and does not honour
 * over-alignment after the initial allocation).
 */
static void* stdlib_realloc(pubnub_allocator_provider_t* self,
                            void*                        ptr,
                            size_t                       old_size,
                            size_t                       new_size,
                            size_t                       align)
{
    (void)self;
    (void)old_size;
    (void)align;
    return realloc(ptr, new_size);
}

/**
 * @brief Release a block previously returned by @ref stdlib_alloc
 *        or @ref stdlib_realloc.
 *
 * `free(NULL)` is a no-op in libc, so the forwarding call is safe
 * unconditionally.
 */
static void stdlib_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

/**
 * @brief Acquire a fresh buffer sized for @p purpose.
 *
 * Allocates the backing store through `malloc`. On OOM the
 * returned buffer has `data == NULL` and `cap == 0`; the caller is
 * expected to check before using. Does not zero the backing
 * store - responsibility is with the consumer (transport fills
 * it, parsers overwrite it; zeroing would waste cycles).
 */
static pubnub_buffer_t stdlib_buf_acquire(pubnub_allocator_provider_t* self,
                                          pubnub_buf_purpose_t         purpose)
{
    (void)self;

    size_t cap = stdlib_default_capacity(purpose);
    if (0 == cap) {
        /* Unknown purpose — skip malloc(0) (implementation-defined). */
        pubnub_buffer_t empty = {.purpose = purpose};
        return empty;
    }
    uint8_t*        data = (uint8_t*)malloc(cap);
    pubnub_buffer_t buf  = {
         .data    = data,
         .len     = 0,
         .cap     = data != NULL ? cap : 0,
         .purpose = purpose,
    };
    return buf;
}

/**
 * @brief Release a buffer previously returned by @ref stdlib_buf_acquire.
 *
 * Frees the backing store and zeroes the descriptor. Safe on a
 * zero-initialized buffer (no-op) and on one whose @c data has
 * already been freed (the NULL check in `free` covers the
 * double-release case so the caller doesn't have to).
 */
static void stdlib_buf_release(pubnub_allocator_provider_t* self,
                               pubnub_buffer_t*             buf)
{
    (void)self;
    if (buf == NULL) {
        return;
    }
    free(buf->data);
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

/**
 * @brief Grow a buffer's backing store in place via @c realloc.
 *
 * Doubling strategy: starting from the current capacity, double
 * until the target capacity is at least @p new_cap, then reallocate
 * to that size. This amortises the cost of many small grows.
 *
 * Returns 0 on success, non-zero on OOM. On failure the original
 * buffer is left intact (libc's `realloc` guarantees this).
 *
 * A grow request for a capacity that already fits is a successful
 * no-op - no allocation happens.
 */
static int stdlib_buf_grow(pubnub_allocator_provider_t* self,
                           pubnub_buffer_t*             buf,
                           size_t                       new_cap)
{
    (void)self;
    if (buf == NULL || buf->data == NULL) {
        return -1;
    }
    if (new_cap <= buf->cap) {
        return 0;
    }

    /* Double up to the requested capacity. Start at 1 byte minimum
     * so empty buffers still make progress. */
    size_t target = buf->cap > 0 ? buf->cap : 1;
    while (target < new_cap) {
        size_t doubled = target * 2;
        if (doubled < target) {
            /* Overflow: bail out. */
            target = new_cap;
            break;
        }
        target = doubled;
    }

    uint8_t* new_data = (uint8_t*)realloc(buf->data, target);
    if (new_data == NULL) {
        return -1;
    }
    buf->data = new_data;
    buf->cap  = target;
    return 0;
}

/**
 * @brief File-scope singleton instance.
 *
 * The stdlib allocator is stateless, so a single instance is shared
 * by every context that selects it. Embedded and custom providers
 * instead carry per-instance state and are typically constructed
 * once per context.
 */
static pubnub_allocator_provider_t pn_stdlib_allocator = {
    .alloc       = stdlib_alloc,
    .realloc     = stdlib_realloc,
    .free        = stdlib_free,
    .buf_acquire = stdlib_buf_acquire,
    .buf_release = stdlib_buf_release,
    .buf_grow    = stdlib_buf_grow,
    .init        = NULL,
    .deinit      = NULL,
};

pubnub_allocator_provider_t* pn_allocator_default(void)
{
    return &pn_stdlib_allocator;
}

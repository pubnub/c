/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file support/test_allocator.h
 * @brief Host-side allocator for unit tests that need a working allocator.
 *
 * Tests must not reach for @c pn_allocator_default(): its behaviour is
 * profile-dependent. Hosted profiles return a ready stdlib allocator,
 * SDK-owned arena profiles return an arena that only becomes usable
 * after @c init(), and user-owned arena profiles (the embedded default,
 * @c PUBNUB_CFG_ARENA_POOL_OWNER_SDK == 0) return @c NULL outright.
 *
 * Any test that only needs "some allocator that works" should call
 * @c pn_test_allocator() instead so it behaves identically in every
 * build configuration. Tests that specifically exercise an allocator
 * implementation should construct that implementation directly.
 */

#ifndef PN_TEST_ALLOCATOR_H
#define PN_TEST_ALLOCATOR_H

#include "pubnub/providers/allocator.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/** Capacity handed out for every purpose-tagged buffer. */
#define PN_TEST_ALLOCATOR_BUF_CAP 4096U

/**
 * @brief malloc-backed alloc.
 *
 * @c align is ignored: malloc already satisfies the fundamental
 * alignment that SDK code requests. Over-aligned requests are not
 * supported and are not made by any test.
 */
static void* pn_test_alloc(struct pubnub_allocator_provider* self,
                           size_t                            size,
                           size_t                            align)
{
    (void)self;
    (void)align;
    if (0 == size) {
        return NULL;
    }
    return malloc(size);
}

static void* pn_test_realloc(struct pubnub_allocator_provider* self,
                             void*                             ptr,
                             size_t                            old_size,
                             size_t                            new_size,
                             size_t                            align)
{
    (void)self;
    (void)old_size;
    (void)align;
    if (0 == new_size) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, new_size);
}

static void pn_test_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t pn_test_buf_acquire(struct pubnub_allocator_provider* self,
                                           pubnub_buf_purpose_t purpose)
{
    pubnub_buffer_t buf = {0};

    (void)self;
    buf.data = (uint8_t*)malloc(PN_TEST_ALLOCATOR_BUF_CAP);
    if (NULL == buf.data) {
        return buf;
    }
    buf.cap     = PN_TEST_ALLOCATOR_BUF_CAP;
    buf.purpose = purpose;

    return buf;
}

static void pn_test_buf_release(struct pubnub_allocator_provider* self,
                                pubnub_buffer_t*                  buf)
{
    (void)self;
    if (NULL == buf) {
        return;
    }
    free(buf->data);
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

static int pn_test_buf_grow(struct pubnub_allocator_provider* self,
                            pubnub_buffer_t*                  buf,
                            size_t                            new_cap)
{
    uint8_t* grown;

    (void)self;
    if (NULL == buf || new_cap <= buf->cap) {
        return -1;
    }
    grown = (uint8_t*)realloc(buf->data, new_cap);
    if (NULL == grown) {
        return -1;
    }
    buf->data = grown;
    buf->cap  = new_cap;

    return 0;
}

/**
 * @brief Return a stdlib-backed allocator usable in any build profile.
 *
 * The returned provider is a shared singleton with no init/deinit
 * requirement, so callers may use it immediately and repeatedly.
 */
static pubnub_allocator_provider_t* pn_test_allocator(void)
{
    static pubnub_allocator_provider_t vtable = {
        pn_test_alloc,
        pn_test_realloc,
        pn_test_free,
        pn_test_buf_acquire,
        pn_test_buf_release,
        pn_test_buf_grow,
        NULL,
        NULL,
    };

    return &vtable;
}

#endif /* PN_TEST_ALLOCATOR_H */

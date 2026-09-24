/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "providers/allocator/mock_oom_allocator.h"

#include "pubnub/config.h"

#include <stdlib.h>

/**
 * @brief Default capacity for a buffer of @p purpose.
 *
 * Mirrors the stdlib allocator's purpose-to-capacity table so that
 * success-path acquisitions behave identically to the real provider.
 */
static size_t mock_oom_capacity(pubnub_buf_purpose_t purpose)
{
    switch (purpose) {
    case PUBNUB_BUF_RX: return (size_t)PUBNUB_CFG_RESPONSE_BUFFER_SIZE;
    case PUBNUB_BUF_OBJ: return (size_t)PUBNUB_CFG_OBJECT_BUFFER_SIZE;
    case PUBNUB_BUF_SCRATCH: return (size_t)PUBNUB_CFG_SCRATCH_BUFFER_SIZE;
    default: return 0;
    }
}

static void* mock_oom_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    pn_mock_oom_allocator_t* mock = (pn_mock_oom_allocator_t*)self;

    (void)align;
    if (PN_MOCK_OOM_NEVER != mock->alloc_fail_after
        && mock->alloc_calls >= mock->alloc_fail_after) {
        mock->alloc_calls++;
        return NULL;
    }
    mock->alloc_calls++;
    if (0 == size) {
        return NULL;
    }
    return malloc(size);
}

static void* mock_oom_realloc(pubnub_allocator_provider_t* self,
                              void*                        ptr,
                              size_t                       old_size,
                              size_t                       new_size,
                              size_t                       align)
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

static void mock_oom_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t mock_oom_buf_acquire(pubnub_allocator_provider_t* self,
                                            pubnub_buf_purpose_t purpose)
{
    pn_mock_oom_allocator_t* mock = (pn_mock_oom_allocator_t*)self;
    pubnub_buffer_t          buf  = {0};
    size_t                   cap;

    buf.purpose = purpose;
    if (PN_MOCK_OOM_NEVER != mock->buf_acquire_fail_after
        && mock->buf_acquire_calls >= mock->buf_acquire_fail_after) {
        mock->buf_acquire_calls++;
        return buf;
    }
    mock->buf_acquire_calls++;

    cap = mock_oom_capacity(purpose);
    if (0 == cap) {
        return buf;
    }
    buf.data = (uint8_t*)malloc(cap);
    if (NULL == buf.data) {
        return buf;
    }
    buf.cap = cap;

    return buf;
}

static void mock_oom_buf_release(pubnub_allocator_provider_t* self,
                                 pubnub_buffer_t*             buf)
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

static int mock_oom_buf_grow(pubnub_allocator_provider_t* self,
                             pubnub_buffer_t*             buf,
                             size_t                       new_cap)
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

void pn_mock_oom_init(pn_mock_oom_allocator_t* mock)
{
    if (NULL == mock) {
        return;
    }
    mock->base.alloc       = mock_oom_alloc;
    mock->base.realloc     = mock_oom_realloc;
    mock->base.free        = mock_oom_free;
    mock->base.buf_acquire = mock_oom_buf_acquire;
    mock->base.buf_release = mock_oom_buf_release;
    mock->base.buf_grow    = mock_oom_buf_grow;
    mock->base.init        = NULL;
    mock->base.deinit      = NULL;
    pn_mock_oom_reset(mock);
}

void pn_mock_oom_reset(pn_mock_oom_allocator_t* mock)
{
    if (NULL == mock) {
        return;
    }
    mock->alloc_calls            = 0;
    mock->buf_acquire_calls      = 0;
    mock->alloc_fail_after       = PN_MOCK_OOM_NEVER;
    mock->buf_acquire_fail_after = PN_MOCK_OOM_NEVER;
}

void pn_mock_oom_fail_alloc_after(pn_mock_oom_allocator_t* mock, long n)
{
    if (NULL == mock) {
        return;
    }
    mock->alloc_fail_after = n;
}

void pn_mock_oom_fail_buf_acquire_after(pn_mock_oom_allocator_t* mock, long n)
{
    if (NULL == mock) {
        return;
    }
    mock->buf_acquire_fail_after = n;
}

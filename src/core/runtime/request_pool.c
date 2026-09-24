/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file request_pool.c
 * @brief Request pool.
 *
 * Pure data-structure layer. Holds no context reference and calls
 * nothing from the core library - the public future query API
 * (pubnub_future_is_ready / pubnub_future_status) lives in
 * src/core/future.c, which does the context -> pool lookup.
 */

#include "request_pool_internal.h"
#include "pn_logger_manager.h"

#include "pubnub/config.h"

#include <string.h>

void pn_request_pool_lock(pn_request_pool_t* pool)
{
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != pool && NULL != pool->lock
        && NULL != pool->platform && NULL != pool->platform->lock_acquire) {
        pool->platform->lock_acquire(pool->platform, pool->lock);
    }
}

void pn_request_pool_unlock(pn_request_pool_t* pool)
{
    if (PUBNUB_CFG_THREAD_SAFETY && NULL != pool && NULL != pool->lock
        && NULL != pool->platform && NULL != pool->platform->lock_release) {
        pool->platform->lock_release(pool->platform, pool->lock);
    }
}

pubnub_res_t pn_request_pool_init(pn_request_pool_t*           pool,
                                  uint16_t                     capacity,
                                  pubnub_allocator_provider_t* allocator,
                                  pubnub_platform_provider_t*  platform,
                                  pubnub_lock_t*               lock,
                                  pubnub_logger_provider_t*    logger)
{
    uint16_t      i;
    pn_request_t* slots;

    if (NULL == pool || NULL == allocator || NULL == allocator->alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == capacity) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    slots = (pn_request_t*)PN_ALLOC(
        allocator, (size_t)capacity * sizeof(pn_request_t), 0);
    if (NULL == slots) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    for (i = 0; i < capacity; i++) {
        pn_request_init(&slots[i], i);
    }

    pool->slots        = slots;
    pool->capacity     = capacity;
    pool->in_use_count = 0;
    pool->allocator    = allocator;
    pool->platform     = platform;
    pool->lock         = lock;
    pool->logger       = logger;

    return PUBNUB_OK;
}

void pn_request_pool_deinit(pn_request_pool_t* pool)
{
    if (NULL == pool) {
        return;
    }
    if (NULL != pool->slots && NULL != pool->allocator) {
        uint16_t i;
        for (i = 0; i < pool->capacity; i++) {
            pn_request_t* slot = &pool->slots[i];
#if PUBNUB_CFG_ASSERT_POOL_CLEAN
            if (!pn_request_is_idle(slot)) {
                PUBNUB_LOG(pool->logger,
                           PUBNUB_LOG_LEVEL_WARN,
                           "unreleased slot %u at context destroy "
                           "(feature=%u) — pubnub_future_release was "
                           "not called",
                           (unsigned)i,
                           (unsigned)slot->feature_id);
            }
#endif
            if (NULL != slot->feature_state && NULL != slot->feature_state_cleanup) {
                slot->feature_state_cleanup(slot->feature_state, pool->allocator);
            }
            /* Mirror pn_request_pool_release: a slot may be sitting
             * in a terminal state with a parsed-body cache when the
             * context is torn down. */
            if (NULL != slot->parsed_body_tree && NULL != slot->parsed_body_owner
                && NULL != slot->parsed_body_owner->value_destroy) {
                slot->parsed_body_owner->value_destroy(slot->parsed_body_owner,
                                                       slot->parsed_body_tree);
                slot->parsed_body_tree  = NULL;
                slot->parsed_body_owner = NULL;
            }
        }
        if (NULL != pool->allocator->free) {
            PN_FREE(pool->allocator, pool->slots);
        }
    }

    /* The pool does NOT destroy the mutex - it is borrowed from the
     * context which manages its lifecycle. */

    pool->slots        = NULL;
    pool->capacity     = 0;
    pool->in_use_count = 0;
    pool->allocator    = NULL;
    pool->platform     = NULL;
    pool->lock         = NULL;
    pool->logger       = NULL;
}

pubnub_res_t pn_request_pool_acquire(pn_request_pool_t* pool,
                                     pubnub_context_t*  ctx_for_future,
                                     pubnub_future_t*   out_future)
{
    uint16_t     i;
    pubnub_res_t rc;

    if (NULL == pool || NULL == out_future) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* No internal lock - callers serialize externally via the
     * context mutex (pn_ctx_lock / pn_request_pool_lock). This
     * avoids deadlock with non-recursive mutexes when the caller
     * already holds the context lock around a larger critical
     * section (acquire + populate + dispatch). */

    for (i = 0; i < pool->capacity; i++) {
        if (!pn_request_is_idle(&pool->slots[i])) {
            continue;
        }

        rc = pn_request_enqueue(&pool->slots[i]);
        if (PUBNUB_OK != rc) {
            return rc;
        }

        pool->in_use_count++;
        out_future->ctx        = ctx_for_future;
        out_future->slot_id    = i;
        out_future->generation = pool->slots[i].generation;
        out_future->status     = PUBNUB_IN_PROGRESS;

        return PUBNUB_OK;
    }

    /* Pool exhausted — callers route through pn_dispatch_or_enqueue()
     * which handles pending-queue fallback at the client layer. */
    return PUBNUB_ERR_QUEUE_FULL;
}

void pn_request_pool_release(pn_request_pool_t* pool, uint16_t slot_id)
{
    pn_request_t* slot;

    if (NULL == pool || NULL == pool->slots || slot_id >= pool->capacity) {
        return;
    }

    /* No internal lock - callers serialize externally (see acquire). */

    slot = &pool->slots[slot_id];
    if (pn_request_is_idle(slot)) {
        return;
    }

    PUBNUB_LOG(pool->logger,
               PUBNUB_LOG_LEVEL_TRACE,
               "slot %u → IDLE: feature=%u",
               (unsigned)slot_id,
               (unsigned)slot->feature_id);

    /* Release feature-owned parsed result cache before the memset
     * in pn_request_reset() obliterates the pointers. */
    if (NULL != slot->feature_state && NULL != slot->feature_state_cleanup) {
        slot->feature_state_cleanup(slot->feature_state, pool->allocator);
    }
    slot->feature_state         = NULL;
    slot->feature_state_cleanup = NULL;

    /* Release the slot-level lazy-parse tree before reset wipes the
     * pointers. The owning provider is captured at parse time so the
     * destructor stays paired with the constructor across mismatched
     * default/custom serialization providers. */
    if (NULL != slot->parsed_body_tree && NULL != slot->parsed_body_owner
        && NULL != slot->parsed_body_owner->value_destroy) {
        slot->parsed_body_owner->value_destroy(slot->parsed_body_owner,
                                               slot->parsed_body_tree);
    }
    slot->parsed_body_tree      = NULL;
    slot->parsed_body_owner     = NULL;
    slot->parsed_body_attempted = 0;
    slot->svc_error_kind        = 0;
    slot->svc_error_classified  = 0;

    /* pn_request_reset() zeroes every field except slot_id (which it
     * captures and restores), so the slot comes back out IDLE with
     * its pool index intact. */
    pn_request_reset(slot);
    if (pool->in_use_count > 0) {
        pool->in_use_count--;
    }
}

pn_request_t* pn_request_pool_get(pn_request_pool_t* pool, uint16_t slot_id)
{
    if (NULL == pool || NULL == pool->slots || slot_id >= pool->capacity) {
        return NULL;
    }

    return &pool->slots[slot_id];
}

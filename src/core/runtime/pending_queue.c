/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pending_queue_internal.h"

#include <string.h>

pubnub_res_t pn_pending_queue_init(pn_pending_queue_t*          queue,
                                   uint16_t                     capacity,
                                   pubnub_allocator_provider_t* allocator)
{
    if (NULL == queue || NULL == allocator || NULL == allocator->alloc) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == capacity) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pn_pending_entry_t* entries = (pn_pending_entry_t*)PN_ALLOC(
        allocator, (size_t)capacity * sizeof(pn_pending_entry_t), 0);
    if (NULL == entries) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memset(entries, 0, (size_t)capacity * sizeof(pn_pending_entry_t));

    queue->entries   = entries;
    queue->capacity  = capacity;
    queue->head      = 0;
    queue->tail      = 0;
    queue->count     = 0;
    queue->allocator = allocator;

    return PUBNUB_OK;
}

void pn_pending_queue_deinit(pn_pending_queue_t* queue)
{
    if (NULL == queue) {
        return;
    }
    if (NULL != queue->entries && NULL != queue->allocator
        && NULL != queue->allocator->free) {
        PN_FREE(queue->allocator, queue->entries);
    }
    queue->entries   = NULL;
    queue->capacity  = 0;
    queue->head      = 0;
    queue->tail      = 0;
    queue->count     = 0;
    queue->allocator = NULL;
}

pubnub_res_t pn_pending_queue_enqueue(pn_pending_queue_t*       queue,
                                      const pn_pending_entry_t* entry)
{
    if (NULL == queue || NULL == entry || NULL == queue->entries) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (queue->count >= queue->capacity) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    queue->entries[queue->tail]          = *entry;
    queue->entries[queue->tail].occupied = 1;
    pn_http_request_relocate_scratch_ptrs(
        &queue->entries[queue->tail].http_request, &entry->http_request);
    queue->tail = (uint16_t)((queue->tail + 1) % queue->capacity);
    queue->count++;

    return PUBNUB_OK;
}

pubnub_res_t pn_pending_queue_dequeue(pn_pending_queue_t* queue,
                                      pn_pending_entry_t* out_entry)
{
    if (NULL == queue || NULL == out_entry || NULL == queue->entries) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == queue->count) {
        return PUBNUB_IN_PROGRESS;
    }

    /* Advance past cancelled head entries; count was already decremented by
     * cancel_at, so do NOT decrement here (count tracks occupied only). */
    while (queue->count > 0 && !queue->entries[queue->head].occupied) {
        queue->head = (uint16_t)((queue->head + 1) % queue->capacity);
    }

    if (0 == queue->count) {
        return PUBNUB_IN_PROGRESS;
    }

    *out_entry = queue->entries[queue->head];
    pn_http_request_relocate_scratch_ptrs(
        &out_entry->http_request, &queue->entries[queue->head].http_request);
    memset(&queue->entries[queue->head], 0, sizeof(pn_pending_entry_t));
    queue->head = (uint16_t)((queue->head + 1) % queue->capacity);
    queue->count--;

    return PUBNUB_OK;
}

uint16_t pn_pending_queue_count(const pn_pending_queue_t* queue)
{
    if (NULL == queue) {
        return 0;
    }
    return queue->count;
}

int pn_pending_queue_is_full(const pn_pending_queue_t* queue)
{
    if (NULL == queue) {
        return 1;
    }
    return queue->count >= queue->capacity;
}

void pn_pending_cancel_data_run(pn_pending_cancel_data_t* data)
{
    if (NULL == data) {
        return;
    }
    if (NULL != data->feature_state_cleanup && NULL != data->feature_state) {
        data->feature_state_cleanup(data->feature_state, data->allocator);
    }
    if (NULL != data->async_cb) {
        data->async_cb(data->async_cb_future,
                       PUBNUB_ERR_CANCELLED,
                       data->async_cb_user_data);
    }
}

pubnub_res_t pn_pending_queue_cancel_at(pn_pending_queue_t*       queue,
                                        uint16_t                  index,
                                        pn_pending_cancel_data_t* out_data)
{
    if (NULL == queue || NULL == queue->entries) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (index >= queue->count) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Convert logical index (from head) to physical index. */
    uint16_t phys = (uint16_t)((queue->head + index) % queue->capacity);

    pn_pending_entry_t* entry = &queue->entries[phys];
    if (!entry->occupied) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL != out_data) {
        /* Extract callbacks for caller to invoke outside the lock. */
        out_data->feature_state         = entry->feature_state;
        out_data->feature_state_cleanup = entry->feature_state_cleanup;
        out_data->allocator             = queue->allocator;
        out_data->async_cb              = entry->async_cb;
        out_data->async_cb_user_data    = entry->async_cb_user_data;
        /* async_cb_future must be populated by the caller — the queue
         * has no context pointer to reconstruct it. */
    } else {
        /* Legacy path: fire cleanup inline (for callers that cannot
         * reconstruct the future). */
        if (NULL != entry->feature_state && NULL != entry->feature_state_cleanup) {
            entry->feature_state_cleanup(entry->feature_state, queue->allocator);
        }
    }

    memset(entry, 0, sizeof(*entry));
    queue->count--;
    return PUBNUB_OK;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/* Include-time instantiation of the event-engine ring-buffer queue.
 *
 * Define these macros before including this file:
 *   PN_EEQ_QUEUE_T    — the queue struct type
 *   PN_EEQ_EVENT_T    — the event element type
 *   PN_EEQ_CAPACITY   — compile-time queue capacity macro
 *   PN_EEQ_INIT       — name for the init function
 *   PN_EEQ_PUSH       — name for the push function
 *   PN_EEQ_POP        — name for the pop function
 *   PN_EEQ_HAS_EVENTS — name for the has_events function
 *   PN_EEQ_CLEAR      — name for the clear function
 *
 * Undefine all macros after including.
 * Do NOT add include guards — this file is designed for multiple inclusion.
 */

#include "pubnub/pubnub_compat.h"

#include <string.h>

PUBNUB_STATIC_ASSERT(
    PN_EEQ_CAPACITY <= 255U,
    "head/tail/count are uint8_t — capacity exceeds addressable range");

void PN_EEQ_INIT(PN_EEQ_QUEUE_T* q)
{
    if (NULL == q) {
        return;
    }
    memset(q, 0, sizeof(*q));
}

int PN_EEQ_PUSH(PN_EEQ_QUEUE_T* q, const PN_EEQ_EVENT_T* event)
{
    if (NULL == q || NULL == event) {
        return 0;
    }
    if (q->count >= PN_EEQ_CAPACITY) {
        return 0;
    }

    q->events[q->tail] = *event;
    q->tail            = (uint8_t)((q->tail + 1) % PN_EEQ_CAPACITY);
    q->count++;
    return 1;
}

int PN_EEQ_POP(PN_EEQ_QUEUE_T* q, PN_EEQ_EVENT_T* out)
{
    if (NULL == q || NULL == out) {
        return 0;
    }
    if (0 == q->count) {
        return 0;
    }

    *out    = q->events[q->head];
    q->head = (uint8_t)((q->head + 1) % PN_EEQ_CAPACITY);
    q->count--;
    return 1;
}

int PN_EEQ_HAS_EVENTS(const PN_EEQ_QUEUE_T* q)
{
    if (NULL == q) {
        return 0;
    }
    return q->count > 0 ? 1 : 0;
}

void PN_EEQ_CLEAR(PN_EEQ_QUEUE_T* q)
{
    if (NULL == q) {
        return;
    }
    q->head  = 0;
    q->tail  = 0;
    q->count = 0;
}

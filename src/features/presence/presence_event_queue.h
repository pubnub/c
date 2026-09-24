/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_EVENT_QUEUE_H
#define PN_PRESENCE_EVENT_QUEUE_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_event_queue.h requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "presence_internal.h"

#include "pubnub/pubnub_compat.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Maximum events queued between ticks of the presence event engine.
 *
 * Defaults to 8: 5 main-thread API entry points (joined, left, left_all,
 * disconnect, reconnect) + 1 heartbeat completion + 1 timer event + 1
 * headroom. Override via -DPUBNUB_CFG_PRESENCE_EVENT_QUEUE_SIZE=N.
 */
#ifndef PUBNUB_CFG_PRESENCE_EVENT_QUEUE_SIZE
#define PUBNUB_CFG_PRESENCE_EVENT_QUEUE_SIZE 8
#endif
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_PRESENCE_EVENT_QUEUE_SIZE <= 255,
                     "presence event queue capacity exceeds uint8_t range");

/**
 * @brief Fixed-capacity ring buffer of presence event engine events.
 *
 * Events are enqueued by heartbeat completion callbacks and timer
 * expiry handlers, then drained by the feature tick that feeds them
 * into the state machine one at a time.
 *
 * The queue is NOT thread-safe internally; the caller must hold the
 * per-context mutex when accessing it.
 */
typedef struct pn_presence_event_queue {
    /** Ring buffer storage (inline, no heap). */
    pn_presence_ee_event_t events[PUBNUB_CFG_PRESENCE_EVENT_QUEUE_SIZE];
    /** Read index (next event to dequeue). */
    uint8_t head;
    /** Write index (next free slot). */
    uint8_t tail;
    /** Number of events currently enqueued. */
    uint8_t count;
} pn_presence_event_queue_t;

/**
 * @brief Initialize (zero) the event queue.
 *
 * @param q Queue to initialize (non-NULL).
 */
void pn_presence_event_queue_init(pn_presence_event_queue_t* q);

/**
 * @brief Push an event into the ring buffer.
 *
 * @param q     Queue (non-NULL).
 * @param event Event to enqueue (copied).
 * @return 1 on success, 0 when the queue is full (event dropped).
 */
int pn_presence_event_queue_push(pn_presence_event_queue_t*    q,
                                 const pn_presence_ee_event_t* event);

/**
 * @brief Pop the oldest event from the ring buffer.
 *
 * @param q   Queue (non-NULL).
 * @param out Populated with the dequeued event on success.
 * @return 1 on success, 0 when the queue is empty.
 */
int pn_presence_event_queue_pop(pn_presence_event_queue_t* q,
                                pn_presence_ee_event_t*    out);

/**
 * @brief Query whether the queue has pending events.
 *
 * @param q Queue (non-NULL).
 * @return 1 if non-empty, 0 if empty.
 */
int pn_presence_event_queue_has_events(const pn_presence_event_queue_t* q);

/**
 * @brief Discard all enqueued events.
 *
 * @param q Queue (non-NULL).
 */
void pn_presence_event_queue_clear(pn_presence_event_queue_t* q);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PRESENCE_EVENT_QUEUE_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PUBNUB_IT_BUS_H
#define PUBNUB_IT_BUS_H

#include "pubnub/features/subscribe_types.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Opaque subscribe event ring buffer for integration tests. */
typedef struct it_bus it_bus_t;

/**
 * @brief Allocate and initialise a new bus.
 *
 * @return New bus instance, or NULL on allocation failure.
 */
it_bus_t* it_bus_create(void);

/**
 * @brief Release all resources held by @p bus.
 *
 * @param bus Bus to destroy (NULL-safe).
 */
void it_bus_destroy(it_bus_t* bus);

/**
 * @brief Push a received subscribe event onto the message ring.
 *
 * All string-view fields are deep-copied into slot-owned storage so
 * the event survives beyond the listener callback. JSON tree pointers
 * (payload, user_metadata) are set to NULL in the copy — they alias
 * SDK-internal parsed nodes that are valid only for the callback
 * duration and cannot be deep-copied without the serialization vtable.
 * If the ring is full the incoming event is silently dropped; the
 * oldest pending event is preserved.
 *
 * @param bus Bus to push onto (must not be NULL).
 * @param ev  Event to copy (must not be NULL).
 */
void it_bus_push_message(it_bus_t* bus, const pubnub_subscribe_event_t* ev);

/**
 * @brief Push a status change onto the status ring.
 *
 * If the ring is full the incoming status is silently dropped.
 *
 * @param bus    Bus to push onto (must not be NULL).
 * @param status Status category to record.
 */
void it_bus_push_status(it_bus_t* bus, pubnub_subscribe_status_t status);

/**
 * @brief Wait up to @p timeout_ms ms for the next message event.
 *
 * On success @p out is populated. String-view pointers in @p out
 * alias bus-internal slot buffers and remain valid until the slot is
 * overwritten by a subsequent push (at most IT_BUS_RING_SIZE pushes
 * later).
 *
 * @note The string view fields in @p out alias the ring slot's internal
 *       buffers. They remain valid until the slot is overwritten — which
 *       happens after @c IT_BUS_RING_SIZE (32) further push_message calls.
 *       In tests that call it_bus_wait_message twice in sequence, consume
 *       and copy any needed fields from the first result BEFORE calling
 *       wait again.
 *
 * @param bus        Bus to read from (must not be NULL).
 * @param timeout_ms Maximum wait time in milliseconds.
 * @param out        Receives the event on success (must not be NULL).
 * @retval 1 Message received; @p out is populated.
 * @retval 0 Timeout elapsed before a message arrived.
 */
int it_bus_wait_message(it_bus_t*                 bus,
                        unsigned int              timeout_ms,
                        pubnub_subscribe_event_t* out);

/**
 * @brief Wait up to @p timeout_ms ms for a specific status category.
 *
 * Non-matching status events that arrive before the expected category
 * are consumed and discarded.
 *
 * @param bus        Bus to read from (must not be NULL).
 * @param timeout_ms Maximum wait time in milliseconds.
 * @param expected   Status category to wait for.
 * @retval 1 Expected status received.
 * @retval 0 Timeout elapsed before the expected status arrived.
 */
int it_bus_wait_status(it_bus_t*                 bus,
                       unsigned int              timeout_ms,
                       pubnub_subscribe_status_t expected);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_IT_BUS_H */

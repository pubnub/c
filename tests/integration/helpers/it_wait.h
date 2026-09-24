/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#ifndef PUBNUB_IT_WAIT_H
#define PUBNUB_IT_WAIT_H

/** Delay before reading history after publish (milliseconds). */
#define IT_DELAY_HISTORY_MS 2500u
/** Delay before reading message actions after publish (milliseconds). */
#define IT_DELAY_MESSAGE_ACTION_MS 2000u
/** Delay before reading after message-action removal (milliseconds). */
#define IT_DELAY_MESSAGE_ACTION_REMOVE_MS 4000u
/** Delay after channel-group mutations before re-querying (milliseconds). */
#define IT_DELAY_CHANNEL_GROUP_MS 1000u
/** Delay after App Context (Objects) writes before read queries.
 *  PubNub Objects uses eventual consistency; newly written data may not
 *  be visible to read replicas for up to a second after the write returns. */
#define IT_DELAY_APP_CONTEXT_WRITE_MS 1500u
/** Push-notification channel registration propagates slower than channel-
 *  group membership. CI consistently shows 4s is insufficient -- the
 *  read replica can take up to ~6s to reflect the registration. */
#define IT_DELAY_PUSH_MS 8000u
/** Delay after file upload before download — S3 write propagation. */
#define IT_DELAY_FILE_PROPAGATION_MS 1500u
/** Maximum time to wait for a presence event (milliseconds). */
#define IT_PRESENCE_WAIT_MAX_MS 30000u
/** Poll interval when waiting for a presence event (milliseconds). */
#define IT_PRESENCE_WAIT_POLL_MS 500u
/** Maximum time to wait for a subscribe connection (milliseconds). */
#define IT_SUBSCRIBE_CONNECT_MAX_MS 10000u
/** Maximum time to wait for a subscribed message to arrive (milliseconds). */
#define IT_SUBSCRIBE_MESSAGE_MAX_MS 20000u

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Sleep for @p ms milliseconds.
 *
 * Wraps POSIX @c nanosleep and retries automatically on @c EINTR so
 * the full requested delay is always served.
 *
 * @param ms Duration in milliseconds.
 */
void pn_test_sleep_ms(unsigned int ms);

/**
 * @brief Poll @p condition_fn every @p poll_ms milliseconds until the
 * condition is met or the deadline expires.
 *
 * @param condition_fn Predicate called with @p arg on every poll cycle.
 *                     Return non-zero to signal that the condition is met.
 * @param arg          Opaque argument forwarded to @p condition_fn unchanged.
 * @param max_ms       Total wait budget in milliseconds.
 * @param poll_ms      Interval between predicate calls in milliseconds.
 * @retval 1 Condition became true within @p max_ms.
 * @retval 0 Timed out before condition became true.
 */
int pn_test_wait_until(int (*condition_fn)(void* arg),
                       void*        arg,
                       unsigned int max_ms,
                       unsigned int poll_ms);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_IT_WAIT_H */

/** Delay after CONNECTED before publishing — ensures the receive long-poll
 *  request is on the wire before the message is published. Prevents the
 *  re-handshake race on CI cold-start where a brief connection delay causes
 *  the long-poll to fail just as the message arrives. */
#define IT_DELAY_RECEIVE_STABILIZE_MS 200u

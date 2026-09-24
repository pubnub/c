/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PUBNUB_IT_CLEANUP_H
#define PUBNUB_IT_CLEANUP_H

#include "pubnub/types_fwd.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Cleanup operation kind.
 *
 * Each enumerator identifies the PubNub API called to undo a side
 * effect created by a test. @c it_cleanup_run processes entries in
 * LIFO order, logging but never asserting on failure.
 */
typedef enum it_cleanup_kind {
    /** Delete all messages from a channel's history. */
    IT_CLEANUP_DELETE_MESSAGES,
    /** Delete a specific file by ID from a channel. */
    IT_CLEANUP_DELETE_FILE,
    /** List and delete all files in a channel (first page only). */
    IT_CLEANUP_LIST_DELETE_FILES,
    /** Delete an entire channel group. */
    IT_CLEANUP_REMOVE_CHANNEL_GROUP,
    /** Remove UUID App Context metadata. */
    IT_CLEANUP_REMOVE_UUID_METADATA,
    /** Remove channel App Context metadata. */
    IT_CLEANUP_REMOVE_CHANNEL_METADATA,
    /** Remove a UUID from a channel's member list. */
    IT_CLEANUP_REMOVE_MEMBERS,
    /** Remove a channel from a UUID's membership list. */
    IT_CLEANUP_REMOVE_MEMBERSHIPS,
    /** Remove a device from all push notification registrations. */
    IT_CLEANUP_REMOVE_PUSH_DEVICE,
} it_cleanup_kind_t;

/**
 * @brief Single cleanup action descriptor.
 *
 * Fields @c a and @c b carry operation-specific string arguments,
 * NUL-terminated, truncated to 127 characters on registration.
 * Semantics per kind:
 *  - DELETE_MESSAGES:      a=channel
 *  - DELETE_FILE:          a=channel, b=file_id
 *  - LIST_DELETE_FILES:    a=channel
 *  - REMOVE_CHANNEL_GROUP: a=group
 *  - REMOVE_UUID_METADATA: a=uuid
 *  - REMOVE_CHANNEL_METADATA: a=channel
 *  - REMOVE_MEMBERS:       a=channel, b=uuid
 *  - REMOVE_MEMBERSHIPS:   a=uuid, b=channel_id
 *  - REMOVE_PUSH_DEVICE:   a=device_token, b=gateway ("apns2" or "fcm")
 */
typedef struct it_cleanup_entry {
    /** Operation kind discriminator. */
    it_cleanup_kind_t kind;
    /** Primary argument (NUL-terminated). */
    char a[128];
    /** Secondary argument (NUL-terminated). */
    char b[128];
} it_cleanup_entry_t;

/**
 * @brief LIFO registry of cleanup actions for a test.
 *
 * Initialize with @c {0} before use. Call @c it_cleanup_add during
 * the test body and @c it_cleanup_run in teardown.
 */
typedef struct it_cleanup {
    /** Registered actions (up to 64). */
    it_cleanup_entry_t entries[64];
    /** Number of registered actions. */
    int count;
} it_cleanup_t;

/**
 * @brief Register a cleanup action.
 *
 * Appends a new entry to @p cl. When @p cl is full (64 entries) the
 * call is silently dropped. @p a and @p b are copied and truncated to
 * 127 characters; either may be @c NULL (stored as empty string).
 *
 * @param cl   Cleanup registry (non-NULL, borrowed).
 * @param kind Operation to perform during teardown.
 * @param a    Primary argument (may be @c NULL).
 * @param b    Secondary argument (may be @c NULL).
 */
void it_cleanup_add(it_cleanup_t*     cl,
                    it_cleanup_kind_t kind,
                    const char*       a,
                    const char*       b);

/**
 * @brief Execute all registered cleanup actions in LIFO order.
 *
 * Calls @c pubnub_await on each operation. Failures are reported via
 * @c print_message but never cause an assertion. Resets @p cl->count
 * to zero after all entries are processed.
 *
 * @param cl   Cleanup registry (non-NULL, borrowed).
 * @param ctx  PubNub context used for all cleanup calls (borrowed).
 */
void it_cleanup_run(it_cleanup_t* cl, pubnub_context_t* ctx);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_IT_CLEANUP_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_SUBSCRIBE_MANAGER_INTERNAL_H
#define PN_SUBSCRIBE_MANAGER_INTERNAL_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_manager_internal.h requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "subscribe_event_queue.h"
#include "subscribe_internal.h"
#include "subscribe_wire_internal.h"
#include "pubnub/error.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport.h"
#include "pubnub/pubnub_compat.h"
#include "pubnub/types_fwd.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Maximum subscriptions per subscription set.
 *
 * Defaults to PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS so each set can
 * reference up to the configured channel limit. Override via
 * -DPUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET=N if a different cap is
 * needed.
 */
#ifndef PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET
#define PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
#endif

/**
 * @brief Entity type for a subscription entry.
 *
 * Determines how the entity appears on the wire: channels and
 * metadata entities go in the URL path; channel groups go in the
 * "channel-group" query parameter. Metadata entities never receive
 * the `-pnpres` presence suffix.
 */
typedef enum pn_subscribe_entity_type {
    /** Regular channel. */
    PN_ENTITY_CHANNEL = 0,
    /** Channel group (resolved server-side). */
    PN_ENTITY_CHANNEL_GROUP = 1,
    /** Channel metadata entity (App Context). */
    PN_ENTITY_CHANNEL_METADATA = 2,
    /** User metadata entity (App Context). */
    PN_ENTITY_USER_METADATA = 3
} pn_subscribe_entity_type_t;

/**
 * @brief Single subscription entry in the channel registry.
 *
 * Each entry represents one logical entity (channel or channel group)
 * and tracks whether presence events are also subscribed. Entries are
 * reference-counted so multiple subscription-sets may share one entry.
 */
typedef struct pn_subscription_entry {
    /** Allocator-owned, NUL-terminated entity name. NULL when slot is free. */
    char* name;
    /** String length of name (excludes NUL). */
    uint16_t name_len;
    /** Entity type (channel or channel group). */
    pn_subscribe_entity_type_t entity_type;
    /** 1 = also subscribe to presence channel (<name>-pnpres). */
    uint8_t with_presence;
    /** Non-zero when this slot is occupied. */
    uint8_t occupied;
    /** Reference count (number of subscription-sets referencing this). */
    uint16_t ref_count;
    /** Number of subscriptions with subscribed=1 referencing this entry.
     *  Only entries with active_count > 0 appear on the wire. */
    uint16_t active_count;
} pn_subscription_entry_t;

/**
 * @brief Internal subscription set slot data.
 *
 * Stores the actual entry indices for a subscription set. One slot
 * exists per active set in the manager's fixed-capacity array.
 */
typedef struct pn_subscription_set_data {
    /** Indices into the manager's entries[] array. */
    uint16_t entry_indices[PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET];
    /** Number of valid entries in entry_indices[]. */
    uint16_t count;
    /** 1 = set slot is occupied. */
    uint8_t active;
} pn_subscription_set_data_t;

/**
 * @brief Opaque subscription set handle (heap-allocated).
 *
 * Wraps a back-pointer to the owning context and an index into the
 * manager's sets[] array. Analogous to how pn_subscription_t wraps
 * { ctx, entry_index, subscribed }.
 */
struct pubnub_subscription_set {
    /** Owning context (borrowed). */
    pubnub_context_t* ctx;
    /** Index into the manager's sets[] array. */
    uint16_t set_index;
    /** 1 = set has been activated (contributed to channel set). */
    uint8_t subscribed;
};

/** Internal alias so existing src/ code compiles unchanged. */
typedef struct pubnub_subscription_set pn_subscription_set_t;

/**
 * @brief Single listener registration entry with typed callbacks.
 *
 * Each callback is dispatched only for its matching message type. The
 * on_status callback receives subscribe lifecycle events. All fields
 * mirror the public pubnub_subscribe_listener_t structure.
 *
 * Listeners support optional binding to a specific subscription entry
 * or subscription set for filtered event delivery:
 *  - bound_entry_index = UINT16_MAX AND bound_set_index = UINT16_MAX:
 *    Global listener, receives all events.
 *  - bound_entry_index != UINT16_MAX: per-subscription listener,
 *    receives only events matching that entry.
 *  - bound_set_index != UINT16_MAX: per-set listener, receives events
 *    whose source entry is a member of the referenced set.
 */
typedef struct pn_subscribe_listener {
    /** Status change callback (may be NULL). */
    pubnub_subscribe_status_cb_t on_status;
    /** Regular message callback (may be NULL). */
    pubnub_subscribe_message_cb_t on_message;
    /** Signal callback (may be NULL). */
    pubnub_subscribe_signal_cb_t on_signal;
    /** Presence event callback (may be NULL). */
    pubnub_subscribe_presence_cb_t on_presence;
    /** Message action callback (may be NULL). */
    pubnub_subscribe_message_action_cb_t on_message_action;
    /** App Context callback (may be NULL). */
    pubnub_subscribe_app_context_cb_t on_app_context;
    /** File event callback (may be NULL). */
    pubnub_subscribe_file_cb_t on_file;
    /** Opaque user data forwarded to all callbacks. */
    void* user_data;
    /** Bound subscription entry index (UINT16_MAX = not bound). */
    uint16_t bound_entry_index;
    /** Bound subscription set index (UINT16_MAX = not bound). */
    uint16_t bound_set_index;
    /** Non-zero when this listener slot is occupied. */
    uint8_t active;
    /** Non-zero when removal is deferred until the current emit cycle
     *  completes. Set under the context lock; cleared by the post-emit
     *  sweep. While set, the emit loop skips this slot. Atomic because
     *  the emit loop reads it outside the lock. */
    PUBNUB_ATOMIC_UINT8 pending_remove;
} pn_subscribe_listener_t;

/**
 * @brief Opaque handle returned when registering a listener.
 *
 * Used to remove the listener later. Values 0..N-1 are valid slot
 * indices; UINT16_MAX indicates an invalid/exhausted handle.
 */
typedef uint16_t pn_listener_handle_t;

/** Sentinel for an invalid listener handle. */
#define PN_LISTENER_HANDLE_INVALID UINT16_MAX

/**
 * @brief Internal entity handle.
 *
 * Each handle represents one subscribable entity (channel, channel
 * group, or metadata object). It carries the owning context pointer
 * and the index into the manager's channel registry.
 */
struct pubnub_entity {
    /** Owning context (borrowed). */
    pubnub_context_t* ctx;
    /** Index into the manager's entries[] array. */
    uint16_t entry_index;
};

/** Internal alias so existing src/ code compiles unchanged. */
typedef struct pubnub_entity pn_entity_t;

/**
 * @brief Internal subscription handle.
 *
 * Each handle represents one logical subscription (one channel or
 * channel group). It carries the owning context pointer and the index
 * into the manager's channel registry so it can be subscribed/
 * unsubscribed independently.
 */
struct pubnub_subscription {
    /** Owning context (borrowed). */
    pubnub_context_t* ctx;
    /** Index into the manager's entries[] array. */
    uint16_t entry_index;
    /** 1 = currently contributing to the active channel set. */
    uint8_t subscribed;
};

/** Internal alias so existing src/ code compiles unchanged. */
typedef struct pubnub_subscription pn_subscription_t;

/**
 * @brief Subscribe manager: per-context feature state for subscribe.
 *
 * Owns the channel registry, subscription sets, listener list, event
 * engine state, and the current subscribe cursor. Allocated as the
 * per-feature state in the feature registry.
 */
typedef struct pn_subscribe_manager {
    /** Channel / channel-group registry (flat array). */
    pn_subscription_entry_t entries[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    /** Number of occupied entries. */
    uint16_t channel_count;

    /** Subscription sets (fixed capacity). */
    pn_subscription_set_data_t sets[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    /** Number of active sets. */
    uint16_t set_count;

    /** Listener registry. */
    pn_subscribe_listener_t listeners[PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS];
    /** Number of active listeners. */
    uint16_t listener_count;

    /** Current event engine state. */
    pn_subscribe_ee_state_t ee_state;

    /** Public-facing connection state (updated on EE transitions). */
    pubnub_subscribe_connection_state_t connection_state;

    /** Current subscribe cursor (updated after each response). */
    pn_subscribe_cursor_t cursor;

    /**
     * Non-zero when the caller supplied a restore timetoken via
     * pubnub_subscribe_restore() that has not yet been merged with a
     * handshake region.  When set, apply_response_cursor() keeps the
     * existing timetoken in cursor and only replaces the region with
     * the one returned by the handshake response.
     *
     * Cleared on entry to PN_SUBSCRIBE_STATE_UNSUBSCRIBED so that a
     * stale restore timetoken from a previous session is not injected
     * into a subsequent fresh subscription.
     */
    uint8_t restore_cursor_valid;

    /** Event queue for buffering EE events between ticks. */
    pn_subscribe_event_queue_t event_queue;

    /** Slot ID of the currently in-flight subscribe request.
     *  PUBNUB_SLOT_ID_INVALID when no request is active. */
    uint16_t active_slot_id;

    /** Detached transport handle from a prior long-poll whose cancel was
     *  deferred to the next re-dispatch. Used only in background-thread
     *  mode, where the successor send runs on the bg thread after the
     *  dispatch call returns: cancelling the old handle immediately would
     *  match the still-current socket generation and tear down the
     *  keep-alive connection. Holding it until the next re-dispatch — by
     *  which point the successor send has bumped the generation — makes
     *  the cancel a stale no-op (socket keep-alive preserved) while still
     *  freeing the transport's per-request buffers (curl rx_buf) one cycle
     *  later. NULL when nothing is pending. */
    pubnub_transport_handle_t* prev_reap_handle;

    /** Pool slot deferred with prev_reap_handle so generation stays intact
     *  until the transport cancel runs. PUBNUB_SLOT_ID_INVALID when empty. */
    uint16_t prev_reap_slot_id;

    /** 1 = context is being destroyed; callbacks must no-op. */
    uint8_t draining;

    /**
     * Non-zero while an emit function is iterating the listener
     * array and invoking callbacks. When set, pubnub_remove_listener
     * defers removal by setting pending_remove on the slot instead
     * of clearing it immediately. The post-emit sweep clears deferred
     * slots under the context lock.
     *
     * There is NO guarantee that callbacks have stopped when
     * pubnub_remove_listener returns — callers must not free
     * user_data until the context is destroyed or they otherwise
     * know no more callbacks will fire.
     *
     * Invariant: only one thread calls emit functions at a time,
     * enforced by poll_active guard in pn_process_tick. If this
     * changes, convert to a saturating atomic counter.
     */
    PUBNUB_ATOMIC_UINT8 invoke_pending;

    /** Live subscription handles (registered on create, cleared on
     *  destroy). Enables the pubnub_subscriptions() introspection
     *  accessor to return the same handles the caller created. */
    pn_subscription_t* tracked_subs[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    /** Number of entries in tracked_subs[] that are non-NULL. */
    uint16_t tracked_sub_count;

    /** Live subscription set handles (registered on create, cleared
     *  on destroy). Enables pubnub_subscription_sets(). */
    pn_subscription_set_t* tracked_sets[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    /** Number of entries in tracked_sets[] that are non-NULL. */
    uint16_t tracked_set_count;

    /** Monotonically increasing generation counter. Incremented on
     *  every subscription set mutation (subscribe/unsubscribe/restore).
     *  Carried in SUBSCRIPTION_CHANGED / SUBSCRIPTION_RESTORED events
     *  so the EE loop can discard stale events superseded by a later
     *  mutation before the queue was drained. */
    uint32_t subscription_generation;

    /** Owning context (borrowed, for provider access). */
    pubnub_context_t* ctx;
} pn_subscribe_manager_t;

/* Compile-time guard: catch unexpected size regressions on 32-bit
 * embedded targets. */
#if !defined(__LP64__) && !defined(_WIN64) && !defined(__x86_64__)
PUBNUB_STATIC_ASSERT(sizeof(pn_subscribe_manager_t) <= 4096,
                     "pn_subscribe_manager_t exceeds embedded memory budget");
#endif

/**
 * @brief Retrieve the subscribe manager from a context.
 *
 * Uses the feature registry to look up the per-context subscribe
 * state. Returns NULL when subscribe is not registered on @p ctx.
 *
 * @param ctx Context (borrowed, may be NULL).
 * @return Manager pointer (borrowed), or NULL.
 */
pn_subscribe_manager_t* pn_subscribe_manager_from_ctx(const pubnub_context_t* ctx);

/**
 * @brief Allocate and register the subscribe manager for a context.
 *
 * Called during feature initialization. Allocates the manager struct
 * via the context's allocator and registers it in the feature
 * registry.
 *
 * The caller is responsible for registering the returned manager in
 * the feature registry via pn_feature_register() with cleanup =
 * pn_subscribe_manager_cleanup.
 *
 * @param ctx   Context (non-NULL, initialized). Stored as back-pointer.
 * @param alloc Allocator for the manager struct.
 * @return Allocated manager on success, or NULL on allocation failure.
 */
pn_subscribe_manager_t* pn_subscribe_manager_create(pubnub_context_t* ctx,
                                                    pubnub_allocator_provider_t* alloc);

/**
 * @brief Add a subscription entry to the channel registry.
 *
 * If an entry with the same name and entity_type already exists, its
 * reference count is incremented. Otherwise a new slot is allocated.
 *
 * @note On arena allocators that do not support per-allocation free
 *       (bulk-free-only), channel names are reclaimed only on context
 *       destroy. Repeated subscribe/unsubscribe to different channel
 *       names will consume arena space without reclaim. Arena-backed
 *       contexts should treat subscription sets as configure-once, or
 *       use an allocator that supports tracked free.
 *
 * @param mgr           Manager (non-NULL).
 * @param name          Entity name (need not be NUL-terminated).
 * @param name_len      Number of bytes in name.
 * @param entity_type   Channel or channel-group.
 * @param with_presence 1 to also subscribe to presence.
 * @return Index into entries[] on success, or UINT16_MAX on capacity.
 */
uint16_t pn_subscription_acquire(pn_subscribe_manager_t*    mgr,
                                 const char*                name,
                                 uint16_t                   name_len,
                                 pn_subscribe_entity_type_t entity_type,
                                 uint8_t                    with_presence);

/**
 * @brief Release a reference to a subscription entry.
 *
 * Decrements the reference count. If it reaches zero, the entry slot
 * is freed and channel_count is decremented.
 *
 * @param mgr   Manager (non-NULL).
 * @param index Slot index returned by pn_subscription_acquire().
 */
void pn_subscription_release(pn_subscribe_manager_t* mgr, uint16_t index);

/**
 * @brief Create a new empty subscription set.
 *
 * @param mgr Manager (non-NULL).
 * @return Index into sets[] on success, or UINT16_MAX on capacity.
 */
uint16_t pn_subscription_set_create(pn_subscribe_manager_t* mgr);

/**
 * @brief Add a subscription entry to a subscription set.
 *
 * Calls pn_subscription_acquire() internally and appends the index
 * to the set's entry_indices[].
 *
 * @param mgr           Manager (non-NULL).
 * @param set_index     Set index returned by pn_subscription_set_create().
 * @param name          NUL-terminated entity name.
 * @param name_len      Length of name (excludes NUL).
 * @param entity_type   Channel or channel-group.
 * @param with_presence 1 to also subscribe to presence.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_subscription_set_add(pn_subscribe_manager_t*    mgr,
                                     uint16_t                   set_index,
                                     const char*                name,
                                     uint16_t                   name_len,
                                     pn_subscribe_entity_type_t entity_type,
                                     uint8_t                    with_presence);

/**
 * @brief Remove and destroy a subscription set.
 *
 * Releases all subscription entries in the set and marks the set slot
 * as inactive.
 *
 * @param mgr       Manager (non-NULL).
 * @param set_index Set index.
 */
void pn_subscription_set_destroy(pn_subscribe_manager_t* mgr, uint16_t set_index);

/**
 * @brief Register a typed listener (global — receives all events).
 *
 * Copies the callback pointers and user_data from @p listener into
 * an internal slot. The caller retains ownership of the listener
 * struct itself (only the contents are copied).
 *
 * @param mgr      Manager (non-NULL).
 * @param listener Listener with typed callbacks (borrowed, copied).
 * @return Listener handle, or PN_LISTENER_HANDLE_INVALID when full.
 */
pn_listener_handle_t
pn_subscribe_listener_add(pn_subscribe_manager_t*            mgr,
                          const pubnub_subscribe_listener_t* listener);

/**
 * @brief Register a listener bound to a specific subscription entry.
 *
 * The listener only receives message events whose source entry index
 * matches @p entry_index. Status events are always delivered.
 *
 * @param mgr         Manager (non-NULL).
 * @param listener    Listener with typed callbacks (borrowed, copied).
 * @param entry_index Registry entry index to bind to.
 * @return Listener handle, or PN_LISTENER_HANDLE_INVALID when full.
 */
pn_listener_handle_t
pn_subscribe_listener_add_bound(pn_subscribe_manager_t*            mgr,
                                const pubnub_subscribe_listener_t* listener,
                                uint16_t                           entry_index);

/**
 * @brief Register a listener bound to a subscription set.
 *
 * The listener receives message events only from entries that are
 * members of the set at @p set_index. Status events are always
 * delivered.
 *
 * @param mgr       Manager (non-NULL).
 * @param listener  Listener with typed callbacks (borrowed, copied).
 * @param set_index Subscription set index to bind to.
 * @return Listener handle, or PN_LISTENER_HANDLE_INVALID when full.
 */
pn_listener_handle_t
pn_subscribe_listener_add_to_set(pn_subscribe_manager_t*            mgr,
                                 const pubnub_subscribe_listener_t* listener,
                                 uint16_t                           set_index);

/**
 * @brief Remove a previously registered listener.
 *
 * @param mgr    Manager (non-NULL).
 * @param handle Handle returned by pn_subscribe_listener_add().
 */
void pn_subscribe_listener_remove(pn_subscribe_manager_t* mgr,
                                  pn_listener_handle_t    handle);

/**
 * @brief Emit a status event to all registered listeners.
 *
 * Builds a public pubnub_subscribe_status_event_t on the stack from
 * the effect's fields and invokes every active listener's on_status
 * callback.
 *
 * @param mgr    Manager (non-NULL).
 * @param effect EMIT_STATUS effect carrying status, reason, and HTTP code.
 */
void pn_subscribe_emit_status(pn_subscribe_manager_t*         mgr,
                              const pn_subscribe_ee_effect_t* effect);

/**
 * @brief Emit a message to the matching typed listener callback.
 *
 * Invokes the callback matching the message type (on_message,
 * on_signal, on_presence, on_message_action, on_app_context, on_file).
 * The event is already in public form inside the dispatch entry.
 *
 * @param mgr   Manager (non-NULL).
 * @param entry Dispatch entry (borrowed, valid for call duration).
 */
void pn_subscribe_emit_message(pn_subscribe_manager_t*              mgr,
                               const pn_subscribe_dispatch_entry_t* entry);

/**
 * @brief Build the comma-separated channel string for the wire.
 *
 * Iterates all occupied entries of type PN_ENTITY_CHANNEL and writes
 * their names (plus -pnpres variants when with_presence is set) into
 * @p buf. Returns the number of bytes written (excluding NUL).
 *
 * @param mgr     Manager (non-NULL).
 * @param buf     Output buffer (NUL-terminated on success).
 * @param buf_len Buffer capacity in bytes.
 * @return Bytes written (excluding NUL), or 0 on overflow/empty.
 */
size_t pn_subscribe_build_channel_string(const pn_subscribe_manager_t* mgr,
                                         char*                         buf,
                                         size_t                        buf_len);

/**
 * @brief Build the comma-separated channel-group string for the wire.
 *
 * Same as pn_subscribe_build_channel_string() but filters entries of
 * type PN_ENTITY_CHANNEL_GROUP.
 *
 * @param mgr     Manager (non-NULL).
 * @param buf     Output buffer (NUL-terminated on success).
 * @param buf_len Buffer capacity in bytes.
 * @return Bytes written (excluding NUL), or 0 on overflow/empty.
 */
size_t pn_subscribe_build_channel_group_string(const pn_subscribe_manager_t* mgr,
                                               char*  buf,
                                               size_t buf_len);

/**
 * @brief Build a dynamically-allocated channel string for the wire.
 *
 * Two-pass: first computes total length, then allocates and writes.
 * Active channel entries (plus -pnpres variants) are concatenated
 * with comma separators.
 *
 * @param mgr   Manager (non-NULL).
 * @param alloc Allocator for the output string (borrowed).
 * @return NUL-terminated, allocator-owned string on success. NULL on
 *         allocation failure or when no channels are active.
 */
char* pn_subscribe_build_channel_string_alloc(const pn_subscribe_manager_t* mgr,
                                              pubnub_allocator_provider_t* alloc);

/**
 * @brief Build a dynamically-allocated channel-group string for the wire.
 *
 * Same as pn_subscribe_build_channel_string_alloc() but filters
 * entries of type PN_ENTITY_CHANNEL_GROUP.
 *
 * @param mgr   Manager (non-NULL).
 * @param alloc Allocator for the output string (borrowed).
 * @return NUL-terminated, allocator-owned string on success. NULL on
 *         allocation failure or when no channel-groups are active.
 */
char* pn_subscribe_build_channel_group_string_alloc(const pn_subscribe_manager_t* mgr,
                                                    pubnub_allocator_provider_t* alloc);

/**
 * @brief Build a dynamically-allocated heartbeat channel string (no
 *        -pnpres).
 *
 * Same two-pass approach as pn_subscribe_build_channel_string_alloc()
 * but never appends the -pnpres virtual channel suffix. Intended for
 * presence heartbeat/leave where only real channel names are expected.
 *
 * @param mgr   Manager (non-NULL).
 * @param alloc Allocator for the output string (borrowed).
 * @return NUL-terminated, allocator-owned string on success. NULL on
 *         allocation failure or when no channels are active.
 */
char* pn_subscribe_build_heartbeat_channel_string_alloc(
    const pn_subscribe_manager_t* mgr,
    pubnub_allocator_provider_t*  alloc);

/**
 * @brief Build a dynamically-allocated heartbeat group string (no
 *        -pnpres).
 *
 * Same two-pass approach as
 * pn_subscribe_build_channel_group_string_alloc() but never appends
 * the -pnpres virtual channel suffix. Intended for presence
 * heartbeat/leave where only real group names are expected.
 *
 * @param mgr   Manager (non-NULL).
 * @param alloc Allocator for the output string (borrowed).
 * @return NUL-terminated, allocator-owned string on success. NULL on
 *         allocation failure or when no channel-groups are active.
 */
char* pn_subscribe_build_heartbeat_group_string_alloc(
    const pn_subscribe_manager_t* mgr,
    pubnub_allocator_provider_t*  alloc);

/**
 * @brief Query whether the subscription registry is empty.
 *
 * @param mgr Manager (non-NULL).
 * @return 1 if no entries are occupied, 0 otherwise.
 */
int pn_subscribe_subscriptions_empty(const pn_subscribe_manager_t* mgr);

/**
 * @brief Check whether an entry is a member of a subscription set.
 *
 * @param mgr         Manager (non-NULL).
 * @param set_index   Set index to check.
 * @param entry_index Entry index to search for in the set.
 * @return 1 if the entry is a member, 0 otherwise.
 */
int pn_subscription_set_contains(const pn_subscribe_manager_t* mgr,
                                 uint16_t                      set_index,
                                 uint16_t                      entry_index);

/**
 * @brief Remove an entry from a subscription set by entry_index.
 *
 * Scans the set's entry_indices[] for a match. If found, shifts
 * remaining elements down (memmove), decrements count, and releases
 * the ref_count via pn_subscription_release.
 *
 * @param mgr         Manager (non-NULL).
 * @param set_index   Set index.
 * @param entry_index Entry to remove.
 * @return 1 if found and removed, 0 if not found.
 */
int pn_subscription_set_remove_entry(pn_subscribe_manager_t* mgr,
                                     uint16_t                set_index,
                                     uint16_t                entry_index);

/**
 * @brief Resolve a channel name to its entry index in the registry.
 *
 * Strips the `-pnpres` suffix before lookup. Returns UINT16_MAX
 * when the channel name cannot be matched to any occupied entry.
 *
 * @param mgr         Manager (non-NULL).
 * @param channel_ptr Channel name string.
 * @param channel_len Length in bytes.
 * @return Entry index on success, UINT16_MAX on not found.
 */
uint16_t pn_subscribe_resolve_entry(const pn_subscribe_manager_t* mgr,
                                    const char*                   channel_ptr,
                                    size_t                        channel_len);

/**
 * @brief Feature cleanup callback for the feature registry.
 *
 * Conforms to pn_feature_cleanup_fn_t. Frees the manager struct.
 *
 * @param state Manager pointer (cast to void*).
 * @param alloc Allocator for deallocation.
 */
void pn_subscribe_manager_cleanup(void* state, pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_SUBSCRIBE_MANAGER_INTERNAL_H */

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

/* Fallback for non-CMake builds that define only the channel cap: default
 * the independent subscribe caps to it. Inert for CMake builds. */
#if !defined(PUBNUB_CFG_MAX_SUBSCRIPTIONS) \
    && defined(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS)
#define PUBNUB_CFG_MAX_SUBSCRIPTIONS PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
#endif
#if !defined(PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) \
    && defined(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS)
#define PUBNUB_CFG_MAX_SUBSCRIPTION_SETS PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
#endif
#if !defined(PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) \
    && defined(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS)
#define PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
#endif

/* Each cap must fit uint16_t slot indices (UINT16_MAX is the "none"
 * sentinel); a set holds no more members than there are handles. */
PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS >= 1
        && PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS <= 65535,
    "PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS out of range [1,65535]");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_SUBSCRIPTIONS >= 1
                         && PUBNUB_CFG_MAX_SUBSCRIPTIONS <= 65535,
                     "PUBNUB_CFG_MAX_SUBSCRIPTIONS out of range [1,65535]");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_SUBSCRIPTION_SETS >= 1
                         && PUBNUB_CFG_MAX_SUBSCRIPTION_SETS <= 65535,
                     "PUBNUB_CFG_MAX_SUBSCRIPTION_SETS out of range [1,65535]");
PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET >= 1
        && PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET <= 65535,
    "PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET out of range [1,65535]");
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET
                         <= PUBNUB_CFG_MAX_SUBSCRIPTIONS,
                     "PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET must be <= "
                     "PUBNUB_CFG_MAX_SUBSCRIPTIONS");

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
    /** Cache of (presence_contributors > 0); 1 emits `<name>-pnpres`. Sole
     *  writer: pn_subscription_entry_presence_adjust(). */
    uint8_t with_presence;
    /** Non-zero when this slot is occupied. */
    uint8_t occupied;
    /** Reference count (number of subscription-sets referencing this). */
    uint16_t ref_count;
    /** Number of subscriptions with subscribed=1 referencing this entry.
     *  Only entries with active_count > 0 appear on the wire. */
    uint16_t active_count;
    /** Distinct presence sources (presence-requesting standalone handles and
     *  sets with such a member); with_presence caches (this > 0). */
    uint16_t presence_contributors;
} pn_subscription_entry_t;

/**
 * @brief Internal subscription set slot data.
 *
 * Holds member handles by tracked_subs[] slot index, taking one reference on
 * each. A member resolves to tracked_subs[member_slot]->entry_index; the set
 * contributes one active-count share per distinct entry while subscribed.
 */
typedef struct pn_subscription_set_data {
    /** Member handle slot indices into the manager's tracked_subs[] table. */
    uint16_t member_slots[PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET];
    /** Number of valid entries in member_slots[]. */
    uint16_t count;
    /** 1 = set slot is occupied. */
    uint8_t active;
    /** 1 = set is subscribed. Mirrors the public handle's subscribed flag;
     *  per-set listeners deliver events only while this is 1. */
    uint8_t subscribed;
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
 * Binding filters delivery:
 *  - both bound_* = UINT16_MAX: global listener, receives all events.
 *  - bound_slot_index set: per-handle listener; delivers while that handle is
 *    subscribed, or while at least one subscribed set contains it, and its
 *    entry name matches. Binds to the slot, not the shared entry, so it
 *    survives an unsubscribe/subscribe cycle.
 *  - bound_set_index set: per-set listener; delivers for the set's members
 *    only while the set is subscribed.
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
    /** Bound handle slot into tracked_subs[], or UINT16_MAX when not bound
     *  (both bound_* at UINT16_MAX means a global listener). */
    uint16_t bound_slot_index;
    /** Bound set index, or UINT16_MAX when not bound. */
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
    /** Own index into the manager's tracked_subs[] slot table, or
     *  UINT16_MAX when not tracked. */
    uint16_t slot_index;
    /** Reference count: creator holds one, each owning set one more. Handle
     *  and its registry-entry reference freed at 0; saturated adds refused. */
    uint16_t ref_count;
    /** 1 = this handle's own share contributes to the active channel set.
     *  Cleared on destroy even while the handle lives on in a set. */
    uint8_t subscribed;
    /** 1 = handle requested presence (`<name>-pnpres`). Immutable after
     *  creation; always 0 for metadata entities. */
    uint8_t with_presence;
    /** Number of currently-subscribed sets that contain this handle. A
     *  per-handle listener fires while `subscribed` is set OR this count is
     *  non-zero, so a member of a subscribed set receives events even when its
     *  own handle was never directly subscribed. Maintained under the context
     *  lock alongside set membership/subscribe state. Saturates at UINT16_MAX;
     *  never decremented below 0. */
    uint16_t subscribed_set_refs;
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
    pn_subscription_set_data_t sets[PUBNUB_CFG_MAX_SUBSCRIPTION_SETS];
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

    /** Consecutive malformed response batches; reset on any clean parse.
     *  At a ceiling, a RECEIVE_FAILURE event breaks the stale-cursor loop.
     *  Poll-thread only. */
    uint8_t consecutive_malformed;

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

    /** Stable slot table of live handles: a handle keeps its slot for life
     *  (freed slots become NULL holes, never compacted) so sets can
     *  reference members by slot index. Backs pubnub_subscriptions(). */
    pn_subscription_t* tracked_subs[PUBNUB_CFG_MAX_SUBSCRIPTIONS];
    /** Number of non-NULL (occupied) slots in tracked_subs[]. */
    uint16_t tracked_sub_count;

    /** Live subscription set handles (registered on create, cleared
     *  on destroy). Enables pubnub_subscription_sets(). */
    pn_subscription_set_t* tracked_sets[PUBNUB_CFG_MAX_SUBSCRIPTION_SETS];
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

/* Compile-time guard: catch size regressions on 32-bit embedded targets.
 * ILP32 worst case (full profile) is ~3.3 KB, under the 4 KB budget. */
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
 * @brief Report whether the entity table has no room for a new entity.
 *
 * True only when no entry matches @p name + @p entity_type and no free
 * slot remains, i.e. a failed pn_subscription_acquire() was caused by
 * PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS rather than allocation failure or
 * reference-count saturation. The caller must hold the context lock.
 *
 * @param mgr         Manager (NULL yields 0).
 * @param name        Entity name (need not be NUL-terminated).
 * @param name_len    Number of bytes in name.
 * @param entity_type Channel or channel-group.
 * @retval 0 A matching entry or a free slot exists (or inputs invalid).
 * @retval 1 The entity table is exhausted for this entity.
 */
uint8_t pn_subscription_entity_table_full(const pn_subscribe_manager_t* mgr,
                                          const char*                   name,
                                          uint16_t name_len,
                                          pn_subscribe_entity_type_t entity_type);

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
 * @brief Remove and destroy a subscription set.
 *
 * Drops the set's reference on every member handle (freeing any handle
 * whose last reference this was) and marks the set slot as inactive. Does
 * not touch active_count or emit presence — the caller must settle the
 * set's wire shares before calling this.
 *
 * @param mgr       Manager (non-NULL).
 * @param set_index Set index.
 */
void pn_subscription_set_destroy(pn_subscribe_manager_t* mgr, uint16_t set_index);

/**
 * @brief Register a subscription handle in the stable slot table.
 *
 * Assigns a free slot and records it on @c sub->slot_index. The caller
 * must hold the context lock.
 *
 * @param mgr Manager (non-NULL).
 * @param sub Subscription handle to track (non-NULL).
 * @return Assigned slot index, or UINT16_MAX when the table is full.
 */
uint16_t pn_track_subscription(pn_subscribe_manager_t* mgr, pn_subscription_t* sub);

/**
 * @brief Remove a subscription handle from the stable slot table.
 *
 * Clears the handle's slot (leaving a NULL hole) when it still owns that
 * slot. The caller must hold the context lock.
 *
 * @param mgr Manager (non-NULL).
 * @param sub Subscription handle to untrack (non-NULL).
 */
void pn_untrack_subscription(pn_subscribe_manager_t* mgr, pn_subscription_t* sub);

/**
 * @brief Drop one reference on a subscription handle.
 *
 * At zero, releases the handle's registry-entry reference, untracks its
 * slot, and frees the handle. The caller must hold the context lock; the
 * free runs under the lock (allocator free is O(1), non-blocking).
 *
 * @param mgr Manager (non-NULL).
 * @param sub Subscription handle (may be NULL — no-op).
 */
void pn_subscription_handle_unref(pn_subscribe_manager_t* mgr,
                                  pn_subscription_t*      sub);

/**
 * @brief Add a subscription handle as a member of a set.
 *
 * Appends the handle's slot to the set and takes one reference on the
 * handle. Membership is deduplicated by handle: adding a handle already
 * in the set is a no-op. Does not touch active_count. The caller must
 * hold the context lock.
 *
 * @param mgr       Manager (non-NULL).
 * @param set_index Set index.
 * @param sub       Member subscription handle (non-NULL, already tracked).
 * @retval 1  Added as a new member.
 * @retval 0  Already a member (no-op).
 * @retval -1 Set is full or the handle's reference count is saturated.
 */
int pn_subscription_set_add_member(pn_subscribe_manager_t* mgr,
                                   uint16_t                set_index,
                                   pn_subscription_t*      sub);

/**
 * @brief Remove a member handle slot from a set.
 *
 * Removes the member at the matching slot. Does not drop the handle
 * reference — the caller unrefs separately after settling active_count.
 * The caller must hold the context lock.
 *
 * @param mgr         Manager (non-NULL).
 * @param set_index   Set index.
 * @param member_slot Handle slot to remove.
 * @retval 1 Removed.
 * @retval 0 Not a member.
 */
int pn_subscription_set_remove_member_slot(pn_subscribe_manager_t* mgr,
                                           uint16_t                set_index,
                                           uint16_t                member_slot);

/**
 * @brief Count members of a set that resolve to a given registry entry.
 *
 * @param mgr         Manager (non-NULL).
 * @param set_index   Set index.
 * @param entry_index Registry entry to match.
 * @return Number of member handles whose entry_index equals @p entry_index.
 */
uint16_t pn_subscription_set_member_entry_count(const pn_subscribe_manager_t* mgr,
                                                uint16_t set_index,
                                                uint16_t entry_index);

/**
 * @brief Count presence-requesting members of a set that resolve to an entry.
 *
 * Like pn_subscription_set_member_entry_count() but counts only member
 * handles whose own @c with_presence flag is set. Used to decide when a
 * subscribed set gains or loses its single presence share for an entry.
 *
 * @param mgr         Manager (non-NULL).
 * @param set_index   Set index.
 * @param entry_index Registry entry to match.
 * @return Number of presence-requesting member handles resolving to the entry.
 */
uint16_t pn_subscription_set_member_entry_presence_count(const pn_subscribe_manager_t* mgr,
                                                         uint16_t set_index,
                                                         uint16_t entry_index);

/**
 * @brief Adjust an entry's presence-contributor count and refresh its cache.
 *
 * Increments (positive) or decrements (!positive) the entry's
 * presence_contributors, clamping at 0 and UINT16_MAX, then recomputes the
 * derived @c with_presence cache as (presence_contributors > 0). This is the
 * ONLY writer of @c with_presence. The caller must hold the context lock.
 *
 * @param mgr         Manager (non-NULL).
 * @param entry_index Registry entry to adjust.
 * @param positive    Non-zero to add a presence share, 0 to drop one.
 * @retval 1 The derived @c with_presence cache flipped (0->1 or 1->0).
 * @retval 0 No cache change (counter saturated, entry invalid, or the flip
 *           threshold was not crossed).
 */
int pn_subscription_entry_presence_adjust(pn_subscribe_manager_t* mgr,
                                          uint16_t                entry_index,
                                          int                     positive);

/**
 * @brief Collect the distinct registry entries referenced by a set's
 *        members.
 *
 * @param mgr       Manager (non-NULL).
 * @param set_index Set index.
 * @param out       Caller buffer receiving distinct entry indices.
 * @param out_cap   Capacity of @p out.
 * @return Number of distinct entries written (<= out_cap).
 */
uint16_t pn_subscription_set_distinct_entries(const pn_subscribe_manager_t* mgr,
                                              uint16_t  set_index,
                                              uint16_t* out,
                                              uint16_t  out_cap);

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
 * @brief Register a listener bound to a specific subscription handle.
 *
 * The listener receives message events only while the handle at
 * @p slot_index is subscribed and its entry name matches the event.
 * Status events are never delivered to a bound listener.
 *
 * @param mgr        Manager (non-NULL).
 * @param listener   Listener with typed callbacks (borrowed, copied).
 * @param slot_index Handle slot (index into tracked_subs[]) to bind to.
 * @return Listener handle, or PN_LISTENER_HANDLE_INVALID when full or when
 *         no handle occupies @p slot_index.
 */
pn_listener_handle_t
pn_subscribe_listener_add_bound(pn_subscribe_manager_t*            mgr,
                                const pubnub_subscribe_listener_t* listener,
                                uint16_t                           slot_index);

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
 * @brief Detach every per-subscription listener bound to a handle slot.
 *
 * Removes all listeners whose @c bound_slot_index equals @p slot_index via
 * the deferred-removal path of pn_subscribe_listener_remove(), so it is safe
 * to call from within a listener callback. The caller must hold the context
 * lock.
 *
 * @param mgr        Manager (non-NULL).
 * @param slot_index Handle slot whose listeners are detached.
 */
void pn_subscribe_listener_remove_for_slot(pn_subscribe_manager_t* mgr,
                                           uint16_t                slot_index);

/**
 * @brief Detach every per-set listener bound to a subscription set.
 *
 * Removes all listeners whose @c bound_set_index equals @p set_index via the
 * deferred-removal path of pn_subscribe_listener_remove(), so it is safe to
 * call from within a listener callback. The caller must hold the context
 * lock.
 *
 * @param mgr       Manager (non-NULL).
 * @param set_index Set whose listeners are detached.
 */
void pn_subscribe_listener_remove_for_set(pn_subscribe_manager_t* mgr,
                                          uint16_t                set_index);

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
 *
 * @param mgr   Manager (non-NULL).
 * @param event Event (borrowed, valid for call duration).
 */
void pn_subscribe_emit_message(pn_subscribe_manager_t*         mgr,
                               const pubnub_subscribe_event_t* event);

/**
 * @brief Build the comma-separated channel string for the wire.
 *
 * Iterates active path-eligible entries and writes their unique names
 * (plus -pnpres variants when with_presence is set) into @p buf.
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
 * @brief Check whether any member of a set resolves to a given entry.
 *
 * Scans the set's member handle slots and matches on the entry each
 * member resolves to (tracked_subs[slot]->entry_index).
 *
 * @param mgr         Manager (non-NULL).
 * @param set_index   Set index to check.
 * @param entry_index Entry index to search for among the set's members.
 * @return 1 if a member resolves to the entry, 0 otherwise.
 */
int pn_subscription_set_contains(const pn_subscribe_manager_t* mgr,
                                 uint16_t                      set_index,
                                 uint16_t                      entry_index);

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

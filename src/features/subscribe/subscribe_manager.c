/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "subscribe_manager_internal.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_manager.c requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "pubnub/capabilities.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport.h"
#include "core/core_internal.h"
#include "core/pn_feature_registry.h"
#include "core/pn_lock.h"
#include "core/pn_string.h"
#include "core/runtime/pipeline_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

pn_subscribe_manager_t* pn_subscribe_manager_from_ctx(const pubnub_context_t* ctx)
{
    if (NULL == ctx) {
        return NULL;
    }
    return (pn_subscribe_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_SUBSCRIBE);
}

static void cancel_active_slot(pn_subscribe_manager_t* mgr)
{
    pn_request_pool_t* pool = pn_context_request_pool(mgr->ctx);
    if (NULL == pool) {
        return;
    }
    const uint16_t cap = pn_context_pool_capacity(mgr->ctx);
    if (mgr->active_slot_id < cap) {
        pn_request_t* slot = pn_request_pool_get(pool, mgr->active_slot_id);
        if (NULL != slot && !pn_request_is_terminal(slot)
            && !pn_request_is_idle(slot)) {
            pn_request_abort(mgr->ctx,
                             mgr->active_slot_id,
                             PN_GENERATION_ANY,
                             PUBNUB_ERR_CANCELLED,
                             1);
        }
        if (NULL != slot && pn_request_is_terminal(slot)) {
            pn_request_pool_lock(pool);
            pn_request_pool_release(pool, mgr->active_slot_id);
            pn_request_pool_unlock(pool);
        }
    } else {
        /* Pending-range slot: cancel in the pending queue.
         * Suppress async callback to avoid re-entry into the
         * manager that is being destroyed. */
        pn_pending_queue_t* queue = pn_context_pending_queue(mgr->ctx);
        if (NULL != queue) {
            uint16_t pending_idx = (uint16_t)(mgr->active_slot_id - cap);
            uint16_t logical =
                (uint16_t)((pending_idx - queue->head + queue->capacity)
                           % queue->capacity);
            pn_pending_cancel_data_t cancel_data = {0};
            cancel_data.async_cb_future.ctx      = mgr->ctx;
            cancel_data.async_cb_future.slot_id  = mgr->active_slot_id;
            cancel_data.async_cb_future.status   = PUBNUB_IN_PROGRESS;
            pn_request_pool_lock(pool);
            (void)pn_pending_queue_cancel_at(queue, logical, &cancel_data);
            pn_request_pool_unlock(pool);
            cancel_data.async_cb           = NULL;
            cancel_data.async_cb_user_data = NULL;
            pn_pending_cancel_data_run(&cancel_data);
        }
    }
}

void pn_subscribe_manager_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    pn_subscribe_manager_t* mgr;
    uint16_t                i;

    if (NULL == state || NULL == alloc) {
        return;
    }

    mgr           = (pn_subscribe_manager_t*)state;
    mgr->draining = 1;

    if (PUBNUB_SLOT_ID_INVALID != mgr->active_slot_id) {
        cancel_active_slot(mgr);
        mgr->active_slot_id = PUBNUB_SLOT_ID_INVALID;
    }

    /* Cancel a background-thread deferred handle before the pipeline is torn
     * down, so the transport still frees its per-request buffers. Cancel first
     * (generation intact → retry frees the inner handle), then release the
     * parked slot. */
    if (NULL != mgr->prev_reap_handle
        || PUBNUB_SLOT_ID_INVALID != mgr->prev_reap_slot_id) {
        pubnub_transport_provider_t* head =
            pn_context_pipeline_chain_head(mgr->ctx);
        if (NULL != mgr->prev_reap_handle && NULL != head && NULL != head->cancel) {
            head->cancel(head, mgr->prev_reap_handle);
        }
        if (PUBNUB_SLOT_ID_INVALID != mgr->prev_reap_slot_id) {
            pn_request_pool_t* pool = pn_context_request_pool(mgr->ctx);
            const uint16_t     cap  = pn_context_pool_capacity(mgr->ctx);
            if (NULL != pool && mgr->prev_reap_slot_id < cap) {
                pn_request_pool_lock(pool);
                pn_request_pool_release(pool, mgr->prev_reap_slot_id);
                pn_request_pool_unlock(pool);
            }
        }
        mgr->prev_reap_handle  = NULL;
        mgr->prev_reap_slot_id = PUBNUB_SLOT_ID_INVALID;
    }

    /* Every live handle is tracked here, so freeing both arrays releases all
     * handle memory exactly once; refcount bookkeeping is skipped as the whole
     * manager is being discarded. */
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS; ++i) {
        if (NULL != mgr->tracked_sets[i]) {
            PN_FREE(alloc, mgr->tracked_sets[i]);
            mgr->tracked_sets[i] = NULL;
        }
    }
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS; ++i) {
        if (NULL != mgr->tracked_subs[i]) {
            PN_FREE(alloc, mgr->tracked_subs[i]);
            mgr->tracked_subs[i] = NULL;
        }
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        pn_strfree(mgr->entries[i].name, alloc);
    }

    PN_FREE(alloc, state);
}

pn_subscribe_manager_t* pn_subscribe_manager_create(pubnub_context_t* ctx,
                                                    pubnub_allocator_provider_t* alloc)
{
    pn_subscribe_manager_t* mgr;

    if (NULL == ctx || NULL == alloc) {
        return NULL;
    }

    mgr = (pn_subscribe_manager_t*)PN_ALLOC(
        alloc, sizeof(pn_subscribe_manager_t), sizeof(void*));
    if (NULL == mgr) {
        return NULL;
    }

    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx               = ctx;
    mgr->ee_state          = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
    mgr->active_slot_id    = PUBNUB_SLOT_ID_INVALID;
    mgr->prev_reap_slot_id = PUBNUB_SLOT_ID_INVALID;

    pn_subscribe_event_queue_init(&mgr->event_queue);

    return mgr;
}

/**
 * @brief Find an existing entry matching name + type, or return
 *        UINT16_MAX if not found.
 */
static uint16_t pn_find_entry(const pn_subscribe_manager_t* mgr,
                              const char*                   name,
                              uint16_t                      name_len,
                              pn_subscribe_entity_type_t    entity_type)
{
    uint16_t i;
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (mgr->entries[i].entity_type != entity_type) {
            continue;
        }
        if (mgr->entries[i].name_len != name_len) {
            continue;
        }
        if (0 == memcmp(mgr->entries[i].name, name, name_len)) {
            return i;
        }
    }
    return UINT16_MAX;
}

/**
 * @brief Find first free slot in entries[].
 */
static uint16_t pn_find_free_entry(const pn_subscribe_manager_t* mgr)
{
    uint16_t i;
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            return i;
        }
    }
    return UINT16_MAX;
}

uint8_t pn_subscription_entity_table_full(const pn_subscribe_manager_t* mgr,
                                          const char*                   name,
                                          uint16_t name_len,
                                          pn_subscribe_entity_type_t entity_type)
{
    if (NULL == mgr || NULL == name || 0 == name_len) {
        return 0;
    }
    if (UINT16_MAX != pn_find_entry(mgr, name, name_len, entity_type)) {
        return 0;
    }
    return (UINT16_MAX == pn_find_free_entry(mgr)) ? 1 : 0;
}

uint16_t pn_subscription_acquire(pn_subscribe_manager_t*    mgr,
                                 const char*                name,
                                 uint16_t                   name_len,
                                 pn_subscribe_entity_type_t entity_type,
                                 uint8_t                    with_presence)
{
    uint16_t                     idx;
    pubnub_allocator_provider_t* alloc;
    char*                        dup;

    if (NULL == mgr || NULL == name || 0 == name_len) {
        return UINT16_MAX;
    }

    /* with_presence is a derived cache maintained elsewhere, not set here. */
    (void)with_presence;

    /* Look for existing entry with same name and type. */
    idx = pn_find_entry(mgr, name, name_len, entity_type);
    if (UINT16_MAX != idx) {
        if (UINT16_MAX == mgr->entries[idx].ref_count) {
            return UINT16_MAX; /* saturated — cannot add more refs */
        }
        mgr->entries[idx].ref_count++;
        return idx;
    }

    /* Allocate a new slot. */
    idx = pn_find_free_entry(mgr);
    if (UINT16_MAX == idx) {
        return UINT16_MAX;
    }

    /* Duplicate exactly name_len bytes (does not require NUL-termination).
     * The allocator call is O(1) and non-blocking, safe under lock. */
    alloc = pn_context_allocator(mgr->ctx);
    dup   = pn_strndup(name, name_len, alloc);
    if (NULL == dup) {
        return UINT16_MAX;
    }

    mgr->entries[idx].name                  = dup;
    mgr->entries[idx].name_len              = name_len;
    mgr->entries[idx].entity_type           = entity_type;
    mgr->entries[idx].with_presence         = 0; /* derived cache */
    mgr->entries[idx].occupied              = 1;
    mgr->entries[idx].ref_count             = 1;
    mgr->entries[idx].active_count          = 0;
    mgr->entries[idx].presence_contributors = 0;
    mgr->channel_count++;

    return idx;
}

void pn_subscription_release(pn_subscribe_manager_t* mgr, uint16_t index)
{
    if (NULL == mgr) {
        return;
    }
    if (index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return;
    }
    if (0 == mgr->entries[index].occupied) {
        return;
    }
    if (0 == mgr->entries[index].ref_count) {
        return; /* already zero — guard against double-release */
    }

    mgr->entries[index].ref_count--;
    if (0 == mgr->entries[index].ref_count) {
        pn_strfree(mgr->entries[index].name, pn_context_allocator(mgr->ctx));
        mgr->entries[index].name                  = NULL;
        mgr->entries[index].name_len              = 0;
        mgr->entries[index].occupied              = 0;
        mgr->entries[index].with_presence         = 0;
        mgr->entries[index].presence_contributors = 0;
        mgr->channel_count--;
    }
}

uint16_t pn_subscription_set_create(pn_subscribe_manager_t* mgr)
{
    uint16_t i;

    if (NULL == mgr) {
        return UINT16_MAX;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS; ++i) {
        if (0 == mgr->sets[i].active) {
            memset(&mgr->sets[i], 0, sizeof(mgr->sets[i]));
            mgr->sets[i].active = 1;
            mgr->set_count++;
            return i;
        }
    }
    return UINT16_MAX;
}

void pn_subscription_set_destroy(pn_subscribe_manager_t* mgr, uint16_t set_index)
{
    pn_subscription_set_data_t* set;
    uint16_t                    i;

    if (NULL == mgr) {
        return;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return;
    }

    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return;
    }

    /* Drop the set's reference on each member; a member at its last
     * reference is freed here (releasing its registry-entry reference). When
     * the set was subscribed, each member also loses this set's delivery
     * share, so decrement its subscribed-set counter before the unref (which
     * may free a surviving member held by another set). */
    for (i = 0; i < set->count; ++i) {
        uint16_t slot = set->member_slots[i];
        if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
            pn_subscription_t* member = mgr->tracked_subs[slot];
            if (set->subscribed && NULL != member
                && member->subscribed_set_refs > 0) {
                member->subscribed_set_refs--;
            }
            pn_subscription_handle_unref(mgr, member);
        }
    }

    set->active     = 0;
    set->count      = 0;
    set->subscribed = 0;
    mgr->set_count--;
}

uint16_t pn_track_subscription(pn_subscribe_manager_t* mgr, pn_subscription_t* sub)
{
    uint16_t i;

    if (NULL == mgr || NULL == sub) {
        return UINT16_MAX;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS; ++i) {
        if (NULL == mgr->tracked_subs[i]) {
            mgr->tracked_subs[i] = sub;
            sub->slot_index      = i;
            mgr->tracked_sub_count++;
            return i;
        }
    }
    return UINT16_MAX;
}

void pn_untrack_subscription(pn_subscribe_manager_t* mgr, pn_subscription_t* sub)
{
    if (NULL == mgr || NULL == sub) {
        return;
    }
    if (sub->slot_index >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        return;
    }
    if (mgr->tracked_subs[sub->slot_index] != sub) {
        return;
    }
    mgr->tracked_subs[sub->slot_index] = NULL;
    sub->slot_index                    = UINT16_MAX;
    if (mgr->tracked_sub_count > 0) {
        mgr->tracked_sub_count--;
    }
}

void pn_subscription_handle_unref(pn_subscribe_manager_t* mgr, pn_subscription_t* sub)
{
    if (NULL == sub) {
        return;
    }
    if (sub->ref_count > 0) {
        sub->ref_count--;
    }
    if (0 != sub->ref_count) {
        return;
    }

    if (NULL != mgr) {
        pn_subscription_release(mgr, sub->entry_index);
        pn_untrack_subscription(mgr, sub);
    }

    if (NULL != mgr && NULL != mgr->ctx) {
        pubnub_allocator_provider_t* alloc = pn_context_allocator(mgr->ctx);
        if (NULL != alloc) {
            PN_FREE(alloc, sub);
        }
    }
}

int pn_subscription_set_add_member(pn_subscribe_manager_t* mgr,
                                   uint16_t                set_index,
                                   pn_subscription_t*      sub)
{
    pn_subscription_set_data_t* set;
    uint16_t                    i;

    if (NULL == mgr || NULL == sub) {
        return -1;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return -1;
    }
    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return -1;
    }
    if (sub->slot_index >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        return -1;
    }

    /* Deduplicate by handle: adding the same handle twice is a no-op. */
    for (i = 0; i < set->count; ++i) {
        if (set->member_slots[i] == sub->slot_index) {
            return 0;
        }
    }

    if (set->count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
        return -1;
    }
    if (UINT16_MAX == sub->ref_count) {
        return -1; /* saturated — cannot add another membership */
    }
    /* Joining a subscribed set grants the member an immediate delivery share;
     * refuse the add if its counter would overflow (keeps it consistent with
     * ref_count, which saturates first in practice). */
    if (set->subscribed && UINT16_MAX == sub->subscribed_set_refs) {
        return -1;
    }

    set->member_slots[set->count] = sub->slot_index;
    set->count++;
    sub->ref_count++;
    if (set->subscribed) {
        sub->subscribed_set_refs++;
    }
    return 1;
}

int pn_subscription_set_remove_member_slot(pn_subscribe_manager_t* mgr,
                                           uint16_t                set_index,
                                           uint16_t                member_slot)
{
    pn_subscription_set_data_t* set;
    uint16_t                    i;

    if (NULL == mgr || set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return 0;
    }
    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count; ++i) {
        if (set->member_slots[i] == member_slot) {
            /* Leaving a subscribed set drops the member's delivery share. */
            if (set->subscribed && member_slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
                pn_subscription_t* member = mgr->tracked_subs[member_slot];
                if (NULL != member && member->subscribed_set_refs > 0) {
                    member->subscribed_set_refs--;
                }
            }
            if (i < set->count - 1) {
                memmove(&set->member_slots[i],
                        &set->member_slots[i + 1],
                        (size_t)(set->count - 1 - i) * sizeof(uint16_t));
            }
            set->count--;
            return 1;
        }
    }
    return 0;
}

uint16_t pn_subscription_set_member_entry_count(const pn_subscribe_manager_t* mgr,
                                                uint16_t set_index,
                                                uint16_t entry_index)
{
    const pn_subscription_set_data_t* set;
    uint16_t                          i;
    uint16_t                          n = 0;

    if (NULL == mgr || set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return 0;
    }
    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count; ++i) {
        uint16_t slot = set->member_slots[i];
        if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS && NULL != mgr->tracked_subs[slot]
            && mgr->tracked_subs[slot]->entry_index == entry_index) {
            n++;
        }
    }
    return n;
}

uint16_t pn_subscription_set_member_entry_presence_count(const pn_subscribe_manager_t* mgr,
                                                         uint16_t set_index,
                                                         uint16_t entry_index)
{
    const pn_subscription_set_data_t* set;
    uint16_t                          i;
    uint16_t                          n = 0;

    if (NULL == mgr || set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return 0;
    }
    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count; ++i) {
        uint16_t slot = set->member_slots[i];
        if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS && NULL != mgr->tracked_subs[slot]
            && mgr->tracked_subs[slot]->entry_index == entry_index
            && 0 != mgr->tracked_subs[slot]->with_presence) {
            n++;
        }
    }
    return n;
}

int pn_subscription_entry_presence_adjust(pn_subscribe_manager_t* mgr,
                                          uint16_t                entry_index,
                                          int                     positive)
{
    pn_subscription_entry_t* e;
    uint8_t                  before;

    if (NULL == mgr || entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return 0;
    }
    e = &mgr->entries[entry_index];
    if (0 == e->occupied) {
        return 0;
    }

    before = e->with_presence;
    if (positive) {
        if (e->presence_contributors < UINT16_MAX) {
            e->presence_contributors++;
        }
    } else if (e->presence_contributors > 0) {
        e->presence_contributors--;
    }
    e->with_presence = (e->presence_contributors > 0) ? 1 : 0;
    return (before != e->with_presence) ? 1 : 0;
}

uint16_t pn_subscription_set_distinct_entries(const pn_subscribe_manager_t* mgr,
                                              uint16_t  set_index,
                                              uint16_t* out,
                                              uint16_t  out_cap)
{
    const pn_subscription_set_data_t* set;
    uint16_t                          i;
    uint16_t                          j;
    uint16_t                          n = 0;

    if (NULL == mgr || NULL == out || 0 == out_cap) {
        return 0;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return 0;
    }
    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count && n < out_cap; ++i) {
        uint16_t slot = set->member_slots[i];
        uint16_t ei;
        uint8_t  seen = 0;
        if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS
            || NULL == mgr->tracked_subs[slot]) {
            continue;
        }
        ei = mgr->tracked_subs[slot]->entry_index;
        for (j = 0; j < n; ++j) {
            if (out[j] == ei) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            out[n++] = ei;
        }
    }
    return n;
}

/**
 * @brief Internal helper to populate a listener slot from public struct.
 */
static void pn_fill_listener_slot(pn_subscribe_listener_t*           slot,
                                  const pubnub_subscribe_listener_t* listener,
                                  uint16_t                           bound_slot,
                                  uint16_t                           bound_set)
{
    slot->on_status         = listener->on_status;
    slot->on_message        = listener->on_message;
    slot->on_signal         = listener->on_signal;
    slot->on_presence       = listener->on_presence;
    slot->on_message_action = listener->on_message_action;
    slot->on_app_context    = listener->on_app_context;
    slot->on_file           = listener->on_file;
    slot->user_data         = listener->user_data;
    slot->bound_slot_index  = bound_slot;
    slot->bound_set_index   = bound_set;
    slot->active            = 1;
    PUBNUB_ATOMIC_STORE_U8(&slot->pending_remove, 0);
}

pn_listener_handle_t pn_subscribe_listener_add(pn_subscribe_manager_t* mgr,
                                               const pubnub_subscribe_listener_t* listener)
{
    uint16_t i;

    if (NULL == mgr || NULL == listener) {
        return PN_LISTENER_HANDLE_INVALID;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 == mgr->listeners[i].active) {
            pn_fill_listener_slot(
                &mgr->listeners[i], listener, UINT16_MAX, UINT16_MAX);
            mgr->listener_count++;
            return (pn_listener_handle_t)i;
        }
    }
    return PN_LISTENER_HANDLE_INVALID;
}

pn_listener_handle_t
pn_subscribe_listener_add_bound(pn_subscribe_manager_t*            mgr,
                                const pubnub_subscribe_listener_t* listener,
                                uint16_t                           slot_index)
{
    uint16_t i;

    if (NULL == mgr || NULL == listener) {
        return PN_LISTENER_HANDLE_INVALID;
    }
    if (slot_index >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        return PN_LISTENER_HANDLE_INVALID;
    }
    if (NULL == mgr->tracked_subs[slot_index]) {
        return PN_LISTENER_HANDLE_INVALID;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 == mgr->listeners[i].active) {
            pn_fill_listener_slot(
                &mgr->listeners[i], listener, slot_index, UINT16_MAX);
            mgr->listener_count++;
            return (pn_listener_handle_t)i;
        }
    }
    return PN_LISTENER_HANDLE_INVALID;
}

pn_listener_handle_t
pn_subscribe_listener_add_to_set(pn_subscribe_manager_t*            mgr,
                                 const pubnub_subscribe_listener_t* listener,
                                 uint16_t                           set_index)
{
    uint16_t i;

    if (NULL == mgr || NULL == listener) {
        return PN_LISTENER_HANDLE_INVALID;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return PN_LISTENER_HANDLE_INVALID;
    }
    if (0 == mgr->sets[set_index].active) {
        return PN_LISTENER_HANDLE_INVALID;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 == mgr->listeners[i].active) {
            pn_fill_listener_slot(&mgr->listeners[i], listener, UINT16_MAX, set_index);
            mgr->listener_count++;
            return (pn_listener_handle_t)i;
        }
    }
    return PN_LISTENER_HANDLE_INVALID;
}

void pn_subscribe_listener_remove(pn_subscribe_manager_t* mgr,
                                  pn_listener_handle_t    handle)
{
    if (NULL == mgr) {
        return;
    }
    if (handle >= PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS) {
        return;
    }
    if (0 == mgr->listeners[handle].active) {
        return;
    }

    if (PUBNUB_ATOMIC_LOAD_U8(&mgr->invoke_pending)) {
        /* Emit cycle in progress — defer removal. active stays 1 so
         * add won't reuse the slot; the post-emit sweep memsets it. */
        PUBNUB_ATOMIC_STORE_U8(&mgr->listeners[handle].pending_remove, 1);
    } else {
        mgr->listeners[handle].active = 0;
        if (mgr->listener_count > 0) {
            mgr->listener_count--;
        }
        memset(&mgr->listeners[handle], 0, sizeof(mgr->listeners[handle]));
    }
}

void pn_subscribe_listener_remove_for_slot(pn_subscribe_manager_t* mgr,
                                           uint16_t                slot_index)
{
    uint16_t i;

    if (NULL == mgr || slot_index >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        return;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 != mgr->listeners[i].active
            && UINT16_MAX == mgr->listeners[i].bound_set_index
            && slot_index == mgr->listeners[i].bound_slot_index) {
            pn_subscribe_listener_remove(mgr, (pn_listener_handle_t)i);
        }
    }
}

void pn_subscribe_listener_remove_for_set(pn_subscribe_manager_t* mgr,
                                          uint16_t                set_index)
{
    uint16_t i;

    if (NULL == mgr || set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 != mgr->listeners[i].active
            && set_index == mgr->listeners[i].bound_set_index) {
            pn_subscribe_listener_remove(mgr, (pn_listener_handle_t)i);
        }
    }
}

/**
 * @brief Clear listener slots marked for deferred removal.
 *
 * @param mgr Manager (non-NULL).
 *
 * @warning Caller must hold the context lock.
 */
static void pn_listener_sweep_pending_locked(pn_subscribe_manager_t* mgr)
{
    uint16_t i;
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (PUBNUB_ATOMIC_LOAD_U8(&mgr->listeners[i].pending_remove)) {
            /* active=0 must precede memset — emit loop reads active
             * without lock on the next cycle. */
            mgr->listeners[i].active = 0;
            if (mgr->listener_count > 0) {
                mgr->listener_count--;
            }
            memset(&mgr->listeners[i], 0, sizeof(mgr->listeners[i]));
        }
    }
}

/**
 * @brief Convert internal status enum to public status enum.
 *
 * The two enums have identical value ordering by design, so this is
 * a direct cast. Kept as a named function for type safety and
 * auditability.
 */
static pubnub_subscribe_status_t pn_to_public_status(pn_subscribe_ee_status_t internal)
{
    switch (internal) {
    case PN_SUB_EE_STATUS_CONNECTED: return PUBNUB_SUBSCRIBE_STATUS_CONNECTED;
    case PN_SUB_EE_STATUS_DISCONNECTED:
        return PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED;
    case PN_SUB_EE_STATUS_DISCONNECTED_UNEXPECTEDLY:
        return PUBNUB_SUBSCRIBE_STATUS_DISCONNECTED_UNEXPECTEDLY;
    case PN_SUB_EE_STATUS_CONNECTION_ERROR:
        return PUBNUB_SUBSCRIBE_STATUS_CONNECTION_ERROR;
    case PN_SUB_EE_STATUS_SUBSCRIPTION_CHANGED:
        return PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED;
    default: return PUBNUB_SUBSCRIBE_STATUS_CONNECTION_ERROR;
    }
}

void pn_subscribe_emit_status(pn_subscribe_manager_t*         mgr,
                              const pn_subscribe_ee_effect_t* effect)
{
    uint16_t                        i;
    pubnub_subscribe_status_event_t evt      = {0};
    pubnub_platform_provider_t*     platform = NULL;
    void*                           lock_mem = NULL;
    pubnub_allocator_provider_t*    alloc    = NULL;
    char*                           ch_str   = NULL;
    char*                           gr_str   = NULL;

    if (NULL == mgr || NULL == effect) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock_mem = pn_context_mutex_mem(mgr->ctx);
    alloc    = pn_context_allocator(mgr->ctx);

    evt.status           = pn_to_public_status(effect->status);
    evt.reason           = effect->reason;
    evt.http_status_code = effect->http_status_code;

    if (PUBNUB_SUBSCRIBE_STATUS_CONNECTED == evt.status
        || PUBNUB_SUBSCRIBE_STATUS_SUBSCRIPTION_CHANGED == evt.status) {
        /* Two-pass measure-then-write over entries[] — must be atomic
         * w.r.t. concurrent subscription mutations (use-after-free). */
        pn_ctx_lock(platform, lock_mem);
        ch_str = pn_subscribe_build_channel_string_alloc(mgr, alloc);
        gr_str = pn_subscribe_build_channel_group_string_alloc(mgr, alloc);
        pn_ctx_unlock(platform, lock_mem);
        if (NULL != ch_str) {
            evt.channels.ptr = ch_str;
            evt.channels.len = strlen(ch_str);
        }
        if (NULL != gr_str) {
            evt.groups.ptr = gr_str;
            evt.groups.len = strlen(gr_str);
        }
    }

    PUBNUB_ATOMIC_STORE_U8(&mgr->invoke_pending, 1);

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 == mgr->listeners[i].active
            || PUBNUB_ATOMIC_LOAD_U8(&mgr->listeners[i].pending_remove)) {
            continue;
        }
        /* Status events dispatch to context-level listeners only. */
        if (UINT16_MAX != mgr->listeners[i].bound_slot_index
            || UINT16_MAX != mgr->listeners[i].bound_set_index) {
            continue;
        }
        if (NULL == mgr->listeners[i].on_status) {
            continue;
        }
        mgr->listeners[i].on_status(&evt, mgr->listeners[i].user_data);
    }

    /* Free allocator-backed strings after all callbacks complete
     * (views in evt are no longer needed). */
    if (NULL != ch_str) {
        PN_FREE(alloc, ch_str);
    }
    if (NULL != gr_str) {
        PN_FREE(alloc, gr_str);
    }

    /* Sweep deferred removals under lock before clearing invoke_pending so
     * the remove-side never races with the memset. */
    pn_ctx_lock(platform, lock_mem);
    pn_listener_sweep_pending_locked(mgr);
    pn_ctx_unlock(platform, lock_mem);

    PUBNUB_ATOMIC_STORE_U8(&mgr->invoke_pending, 0);
}

static int pn_entity_is_metadata(pn_subscribe_entity_type_t etype);

/**
 * @brief Exact name equality: equal length then byte compare.
 *
 * @param name      Entry-name bytes (need not be NUL-terminated).
 * @param name_len  Length of @p name.
 * @param other     Candidate bytes; may be NULL when @p other_len is 0.
 * @param other_len Length of @p other.
 * @retval 1 The two spans are byte-for-byte equal.
 * @retval 0 Otherwise.
 */
static int pn_name_equals(const char* name,
                          size_t      name_len,
                          const char* other,
                          size_t      other_len)
{
    return (name_len == other_len && 0 == memcmp(name, other, name_len)) ? 1 : 0;
}

/**
 * @brief Whether a `<prefix>.*` channel-wildcard name matches a concrete
 *        base channel.
 *
 * @param name     Entry name bytes (need not be NUL-terminated); may be NULL.
 * @param name_len Length of @p name.
 * @param base     Concrete base channel bytes; may be NULL.
 * @param base_len Length of @p base.
 * @retval 1 @p name is `<prefix>.*` and @p base extends @p prefix.
 * @retval 0 Otherwise.
 */
static int pn_wildcard_prefix_match(const char* name,
                                    size_t      name_len,
                                    const char* base,
                                    size_t      base_len)
{
    size_t prefix_len;

    if (NULL == name || NULL == base || name_len < 2) {
        return 0;
    }
    if ('*' != name[name_len - 1] || '.' != name[name_len - 2]) {
        return 0;
    }
    prefix_len = name_len - 1; /* keep the trailing dot, drop the star */
    if (base_len <= prefix_len) {
        return 0;
    }
    return (0 == memcmp(name, base, prefix_len)) ? 1 : 0;
}

/**
 * @brief Test whether a registry entry should receive an event.
 *
 * @param name          Entry-name bytes (need not be NUL-terminated).
 * @param name_len      Length of @p name.
 * @param etype         Entity type of the entry (channel, group, metadata).
 * @param with_presence Non-zero when the entry opted into presence events.
 * @param event         Event under consideration (borrowed, non-NULL).
 * @param sub_base_len  Length of @p event->subscription with any `-pnpres`
 *                      suffix already removed.
 * @retval 1 The entry matches the event's channel or subscription.
 * @retval 0 Otherwise.
 */
static int pn_entry_matches_event(const char*                     name,
                                  uint16_t                        name_len,
                                  pn_subscribe_entity_type_t      etype,
                                  uint8_t                         with_presence,
                                  const pubnub_subscribe_event_t* event,
                                  size_t                          sub_base_len)
{
    const char* ch   = event->channel.ptr;
    size_t      chl  = event->channel.len;
    const char* sub  = event->subscription.ptr;
    size_t      subl = event->subscription.len;

    if (PUBNUB_SUBSCRIBE_PRESENCE != event->type) {
        if (pn_name_equals(name, name_len, ch, chl)) {
            return 1;
        }
        if (pn_name_equals(name, name_len, sub, subl)) {
            return 1;
        }
        if (PN_ENTITY_CHANNEL == etype
            && pn_wildcard_prefix_match(name, name_len, ch, chl)) {
            return 1;
        }
        return 0;
    }

    if (pn_entity_is_metadata(etype)) {
        return 0;
    }

    if (pn_pnpres_has_suffix(name, name_len)) {
        size_t base = (size_t)name_len - PN_PNPRES_SUFFIX_LEN;
        /* A `<prefix>.*-pnpres` entity matches concrete presence channels
         * under its prefix (suffix removed), regardless of the flag. */
        if (PN_ENTITY_CHANNEL == etype
            && pn_wildcard_prefix_match(name, base, ch, chl)) {
            return 1;
        }
        if (pn_name_equals(name, base, ch, chl)) {
            return 1;
        }
        if (pn_name_equals(name, base, sub, sub_base_len)) {
            return 1;
        }
        return 0;
    }

    if (0 == with_presence) {
        return 0;
    }
    if (PN_ENTITY_CHANNEL == etype
        && pn_wildcard_prefix_match(name, name_len, ch, chl)) {
        return 1;
    }
    if (pn_name_equals(name, name_len, ch, chl)) {
        return 1;
    }
    if (pn_name_equals(name, name_len, sub, sub_base_len)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Check whether a listener should receive an event.
 *
 * Matches by entity name. A per-set listener fires only while its set is
 * subscribed. A per-handle listener fires while its handle is subscribed OR
 * while at least one subscribed set contains it, so a member of a subscribed
 * set delivers events even without a direct subscribe. Returns one boolean
 * per listener.
 *
 * @param mgr          Manager (non-NULL).
 * @param listener     Listener slot to test (borrowed, non-NULL).
 * @param event        Event under consideration (borrowed, non-NULL).
 * @param sub_base_len Length of @p event->subscription without `-pnpres`.
 * @retval 1 The listener should receive @p event.
 * @retval 0 Otherwise.
 * @warning Caller must hold the context lock.
 */
static int pn_listener_matches_locked(const pn_subscribe_manager_t*   mgr,
                                      const pn_subscribe_listener_t*  listener,
                                      const pubnub_subscribe_event_t* event,
                                      size_t sub_base_len)
{
    /* Global listener: no binding — fires for everything. */
    if (UINT16_MAX == listener->bound_slot_index
        && UINT16_MAX == listener->bound_set_index) {
        return 1;
    }

    /* Per-subscription: a stale/NULL slot matches nothing. The handle delivers
     * when directly subscribed or while a subscribed set still contains it;
     * otherwise match the handle's entry name. */
    if (UINT16_MAX != listener->bound_slot_index) {
        uint16_t                 slot = listener->bound_slot_index;
        const pn_subscription_t* sub;
        uint16_t                 ei;
        if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
            return 0;
        }
        sub = mgr->tracked_subs[slot];
        if (NULL == sub || (0 == sub->subscribed && 0 == sub->subscribed_set_refs)) {
            return 0;
        }
        ei = sub->entry_index;
        if (ei >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
            || 0 == mgr->entries[ei].occupied) {
            return 0;
        }
        /* Presence gating uses the handle's own flag, not the shared entry
         * cache. */
        return pn_entry_matches_event(mgr->entries[ei].name,
                                      mgr->entries[ei].name_len,
                                      mgr->entries[ei].entity_type,
                                      sub->with_presence,
                                      event,
                                      sub_base_len);
    }

    /* Per-set: gate on the set's subscribed state, then match any member
     * entry name — the set's state governs, not the member handle's. */
    if (UINT16_MAX != listener->bound_set_index) {
        const pn_subscription_set_data_t* set;
        uint16_t                          si = listener->bound_set_index;
        uint16_t                          j;
        if (si >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS || 0 == mgr->sets[si].active) {
            return 0;
        }
        set = &mgr->sets[si];
        if (0 == set->subscribed) {
            return 0;
        }
        for (j = 0; j < set->count; ++j) {
            uint16_t slot = set->member_slots[j];
            uint16_t ei;
            if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS
                || NULL == mgr->tracked_subs[slot]) {
                continue;
            }
            ei = mgr->tracked_subs[slot]->entry_index;
            if (ei >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
                || 0 == mgr->entries[ei].occupied) {
                continue;
            }
            /* Presence gating uses each member handle's own flag, so a set
             * may route presence for one member of an entry but not another. */
            if (pn_entry_matches_event(mgr->entries[ei].name,
                                       mgr->entries[ei].name_len,
                                       mgr->entries[ei].entity_type,
                                       mgr->tracked_subs[slot]->with_presence,
                                       event,
                                       sub_base_len)) {
                return 1;
            }
        }
        return 0;
    }

    return 0;
}

/**
 * @brief Dispatch a typed callback to the listener based on type.
 */
static void pn_dispatch_typed(const pn_subscribe_listener_t*  listener,
                              pubnub_subscribe_message_type_t type,
                              const pubnub_subscribe_event_t* event)
{
    switch (type) {
    case PUBNUB_SUBSCRIBE_MESSAGE:
        if (NULL != listener->on_message) {
            listener->on_message(event, listener->user_data);
        }
        break;
    case PUBNUB_SUBSCRIBE_SIGNAL:
        if (NULL != listener->on_signal) {
            listener->on_signal(event, listener->user_data);
        }
        break;
    case PUBNUB_SUBSCRIBE_APP_CONTEXT:
        if (NULL != listener->on_app_context) {
            listener->on_app_context(event, listener->user_data);
        }
        break;
    case PUBNUB_SUBSCRIBE_MESSAGE_ACTION:
        if (NULL != listener->on_message_action) {
            listener->on_message_action(event, listener->user_data);
        }
        break;
    case PUBNUB_SUBSCRIBE_FILE:
        if (NULL != listener->on_file) {
            listener->on_file(event, listener->user_data);
        }
        break;
    case PUBNUB_SUBSCRIBE_PRESENCE:
        if (NULL != listener->on_presence) {
            listener->on_presence(event, listener->user_data);
        }
        break;
    default: break;
    }
}

void pn_subscribe_emit_message(pn_subscribe_manager_t*         mgr,
                               const pubnub_subscribe_event_t* event)
{
    pubnub_platform_provider_t* platform = NULL;
    void*                       lock_mem = NULL;
    size_t                      sub_base_len;
    uint8_t  should_dispatch[PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS];
    uint16_t i;

    if (NULL == mgr || NULL == event) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock_mem = pn_context_mutex_mem(mgr->ctx);
    sub_base_len =
        pn_pnpres_base_len(event->subscription.ptr, event->subscription.len);

    PUBNUB_ATOMIC_STORE_U8(&mgr->invoke_pending, 1);

    pn_ctx_lock(platform, lock_mem);
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        should_dispatch[i] =
            (0 != mgr->listeners[i].active
             && 0 == PUBNUB_ATOMIC_LOAD_U8(&mgr->listeners[i].pending_remove)
             && pn_listener_matches_locked(
                 mgr, &mgr->listeners[i], event, sub_base_len))
                ? (uint8_t)1
                : (uint8_t)0;
    }
    pn_ctx_unlock(platform, lock_mem);

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 == should_dispatch[i]) {
            continue;
        }
        if (PUBNUB_ATOMIC_LOAD_U8(&mgr->listeners[i].pending_remove)) {
            continue;
        }
        pn_dispatch_typed(&mgr->listeners[i], event->type, event);
    }

    /* Sweep deferred removals under lock before clearing invoke_pending
     * so the remove-side never races with the memset. */
    pn_ctx_lock(platform, lock_mem);
    pn_listener_sweep_pending_locked(mgr);
    pn_ctx_unlock(platform, lock_mem);

    PUBNUB_ATOMIC_STORE_U8(&mgr->invoke_pending, 0);
}

/**
 * @brief Check whether an entity type is a metadata type (never gets
 *        presence suffix).
 */
static int pn_entity_is_metadata(pn_subscribe_entity_type_t etype)
{
    return (PN_ENTITY_CHANNEL_METADATA == etype || PN_ENTITY_USER_METADATA == etype)
             ? 1
             : 0;
}

/**
 * @brief Check whether an entity type belongs in the URL path.
 *
 * Channels, channel metadata, and user metadata all go in the path;
 * only channel groups go in the query parameter.
 */
static int pn_entity_in_path(pn_subscribe_entity_type_t etype)
{
    return (PN_ENTITY_CHANNEL_GROUP != etype) ? 1 : 0;
}

/**
 * @brief Check whether an entity type is a channel group.
 */
static int pn_entity_is_channel_group(pn_subscribe_entity_type_t etype)
{
    return (PN_ENTITY_CHANNEL_GROUP == etype) ? 1 : 0;
}

/**
 * @brief Whether an entry contributes a `-pnpres` presence token to the
 *        subscribe wire string.
 *
 * @param e Subscription entry to inspect (borrowed, non-NULL).
 * @retval 1 The entry emits a presence token (non-metadata, presence
 *           requested, and its own name is not already `-pnpres`-suffixed).
 * @retval 0 Otherwise.
 */
static int pn_entry_emits_presence_token(const pn_subscription_entry_t* e)
{
    if (pn_entity_is_metadata(e->entity_type)) {
        return 0;
    }
    if (0 == e->with_presence) {
        return 0;
    }
    if (pn_pnpres_has_suffix(e->name, e->name_len)) {
        return 0;
    }
    return 1;
}

/**
 * @brief Compare two logical wire tokens (name plus optional `-pnpres`)
 *        for byte equality without materializing the suffixed string.
 *
 * @param a      First token name bytes (need not be NUL-terminated).
 * @param a_len  Length of @p a (base name, excluding any suffix).
 * @param a_pres Non-zero to treat @p a as `<a>-pnpres`.
 * @param b      Second token name bytes (need not be NUL-terminated).
 * @param b_len  Length of @p b (base name, excluding any suffix).
 * @param b_pres Non-zero to treat @p b as `<b>-pnpres`.
 * @retval 1 The two logical tokens are byte-for-byte equal.
 * @retval 0 Otherwise.
 */
static int pn_token_byte_eq(const char* a,
                            size_t      a_len,
                            int         a_pres,
                            const char* b,
                            size_t      b_len,
                            int         b_pres)
{
    size_t a_full = a_len + (a_pres ? PN_PNPRES_SUFFIX_LEN : 0);
    size_t b_full = b_len + (b_pres ? PN_PNPRES_SUFFIX_LEN : 0);
    size_t k;

    if (a_full != b_full) {
        return 0;
    }
    for (k = 0; k < a_full; ++k) {
        const char ca = (char)((k < a_len) ? a[k] : PN_PNPRES_SUFFIX[k - a_len]);
        const char cb = (char)((k < b_len) ? b[k] : PN_PNPRES_SUFFIX[k - b_len]);
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Whether an earlier active entry passing @p filter already
 *        emitted the given token (dedup helper for the wire writer).
 *
 * @param mgr                  Manager (non-NULL).
 * @param index                Upper bound (exclusive) of entries to scan.
 * @param filter               Entity-type predicate selecting eligible
 *                             entries.
 * @param with_presence_tokens Also compare the earlier entries' `-pnpres`
 *                             variants when they qualify.
 * @param exclude_pnpres_named When set, entries whose own name ends in
 *                             `-pnpres` are skipped entirely (heartbeat/leave
 *                             strings must not carry presence channels).
 * @param tok_name             Candidate token name bytes.
 * @param tok_len              Length of @p tok_name (base name).
 * @param tok_pres             Non-zero to treat the candidate as
 *                             `<tok_name>-pnpres`.
 * @retval 1 An earlier eligible entry already emitted the same token.
 * @retval 0 Otherwise.
 */
static int pn_token_seen_earlier(const pn_subscribe_manager_t* mgr,
                                 uint16_t                      index,
                                 int (*filter)(pn_subscribe_entity_type_t),
                                 int         with_presence_tokens,
                                 int         exclude_pnpres_named,
                                 const char* tok_name,
                                 size_t      tok_len,
                                 int         tok_pres)
{
    uint16_t j;

    for (j = 0; j < index; ++j) {
        const pn_subscription_entry_t* e = &mgr->entries[j];
        if (0 == e->occupied || 0 == e->active_count) {
            continue;
        }
        if (!filter(e->entity_type)) {
            continue;
        }
        if (exclude_pnpres_named && pn_pnpres_has_suffix(e->name, e->name_len)) {
            continue;
        }
        if (pn_token_byte_eq(e->name, e->name_len, 0, tok_name, tok_len, tok_pres)) {
            return 1;
        }
        if (with_presence_tokens && pn_entry_emits_presence_token(e)
            && pn_token_byte_eq(e->name, e->name_len, 1, tok_name, tok_len, tok_pres)) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Emit the comma-separated wire tokens for active entries.
 *
 * @param mgr    Manager (non-NULL).
 * @param filter Entity-type predicate selecting eligible entries.
 * @param with_presence_tokens Append `-pnpres` variants for qualifying
 *        entries (subscribe path = 1; heartbeat/leave = 0).
 * @param exclude_pnpres_named Skip entries whose own name is already
 *        `-pnpres`-suffixed (heartbeat/leave = 1; subscribe path = 0).
 * @param buf Output buffer, or NULL to measure only.
 * @param buf_len Capacity of @p buf; ignored when @p buf is NULL.
 * @return Content length (excluding NUL). In write mode returns 0 on
 *         overflow after NUL-terminating at the last valid offset.
 */
static size_t pn_emit_entity_tokens(const pn_subscribe_manager_t* mgr,
                                    int (*filter)(pn_subscribe_entity_type_t),
                                    int    with_presence_tokens,
                                    int    exclude_pnpres_named,
                                    char*  buf,
                                    size_t buf_len)
{
    size_t   offset = 0;
    int      first  = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        const pn_subscription_entry_t* e = &mgr->entries[i];
        size_t                         comma;
        if (0 == e->occupied || 0 == e->active_count) {
            continue;
        }
        if (!filter(e->entity_type)) {
            continue;
        }
        if (exclude_pnpres_named && pn_pnpres_has_suffix(e->name, e->name_len)) {
            continue;
        }

        if (!pn_token_seen_earlier(mgr,
                                   i,
                                   filter,
                                   with_presence_tokens,
                                   exclude_pnpres_named,
                                   e->name,
                                   e->name_len,
                                   0)) {
            comma = first ? 0 : 1;
            if (NULL != buf && offset + comma + e->name_len >= buf_len) {
                buf[offset] = '\0';
                return 0;
            }
            if (NULL != buf) {
                if (!first) {
                    buf[offset] = ',';
                }
                memcpy(buf + offset + comma, e->name, e->name_len);
            }
            offset += comma + e->name_len;
            first = 0;
        }

        if (with_presence_tokens && pn_entry_emits_presence_token(e)
            && !pn_token_seen_earlier(mgr,
                                      i,
                                      filter,
                                      with_presence_tokens,
                                      exclude_pnpres_named,
                                      e->name,
                                      e->name_len,
                                      1)) {
            size_t need;
            comma = first ? 0 : 1;
            need  = comma + e->name_len + PN_PNPRES_SUFFIX_LEN;
            if (NULL != buf && offset + need >= buf_len) {
                buf[offset] = '\0';
                return 0;
            }
            if (NULL != buf) {
                if (!first) {
                    buf[offset] = ',';
                }
                memcpy(buf + offset + comma, e->name, e->name_len);
                memcpy(/* NOLINT(bugprone-not-null-terminated-result) */
                       buf + offset + comma + e->name_len,
                       PN_PNPRES_SUFFIX,
                       PN_PNPRES_SUFFIX_LEN);
            }
            offset += need;
            first = 0;
        }
    }

    if (NULL != buf) {
        buf[offset] = '\0';
    }
    return offset;
}

size_t pn_subscribe_build_channel_string(const pn_subscribe_manager_t* mgr,
                                         char*                         buf,
                                         size_t                        buf_len)
{
    if (NULL == mgr || NULL == buf || 0 == buf_len) {
        return 0;
    }
    return pn_emit_entity_tokens(mgr, pn_entity_in_path, 1, 0, buf, buf_len);
}

size_t pn_subscribe_build_channel_group_string(const pn_subscribe_manager_t* mgr,
                                               char*  buf,
                                               size_t buf_len)
{
    if (NULL == mgr || NULL == buf || 0 == buf_len) {
        return 0;
    }
    return pn_emit_entity_tokens(mgr, pn_entity_is_channel_group, 1, 0, buf, buf_len);
}

/**
 * @brief Allocate and build a wire string for entries matching a filter.
 *
 * Two-pass over @ref pn_emit_entity_tokens: measure, allocate, write.
 *
 * @param mgr    Manager (non-NULL).
 * @param alloc  Allocator for the returned buffer (non-NULL).
 * @param filter Entity-type predicate selecting eligible entries.
 * @param with_presence_tokens Append `-pnpres` variants for qualifying
 *                             entries (subscribe path = 1; heartbeat/leave = 0).
 * @param exclude_pnpres_named Skip entries whose own name is already
 *                             `-pnpres`-suffixed (heartbeat/leave = 1;
 *                             subscribe path = 0).
 * @return NUL-terminated buffer owned by the caller, or NULL when there
 *         are no matching entries or allocation fails.
 */
static char* pn_build_entity_string_alloc(const pn_subscribe_manager_t* mgr,
                                          pubnub_allocator_provider_t*  alloc,
                                          int (*filter)(pn_subscribe_entity_type_t),
                                          int with_presence_tokens,
                                          int exclude_pnpres_named)
{
    size_t needed;
    char*  buf;

    if (NULL == mgr || NULL == alloc) {
        return NULL;
    }

    needed = pn_emit_entity_tokens(
        mgr, filter, with_presence_tokens, exclude_pnpres_named, NULL, 0);
    if (0 == needed) {
        return NULL;
    }

    buf = (char*)PN_ALLOC(alloc, needed + 1, 1);
    if (NULL == buf) {
        return NULL;
    }

    pn_emit_entity_tokens(
        mgr, filter, with_presence_tokens, exclude_pnpres_named, buf, needed + 1);
    return buf;
}

char* pn_subscribe_build_channel_string_alloc(const pn_subscribe_manager_t* mgr,
                                              pubnub_allocator_provider_t* alloc)
{
    return pn_build_entity_string_alloc(mgr, alloc, pn_entity_in_path, 1, 0);
}

char* pn_subscribe_build_channel_group_string_alloc(const pn_subscribe_manager_t* mgr,
                                                    pubnub_allocator_provider_t* alloc)
{
    return pn_build_entity_string_alloc(mgr, alloc, pn_entity_is_channel_group, 1, 0);
}

char* pn_subscribe_build_heartbeat_channel_string_alloc(
    const pn_subscribe_manager_t* mgr,
    pubnub_allocator_provider_t*  alloc)
{
    return pn_build_entity_string_alloc(mgr, alloc, pn_entity_in_path, 0, 1);
}

char* pn_subscribe_build_heartbeat_group_string_alloc(
    const pn_subscribe_manager_t* mgr,
    pubnub_allocator_provider_t*  alloc)
{
    return pn_build_entity_string_alloc(mgr, alloc, pn_entity_is_channel_group, 0, 1);
}

int pn_subscribe_subscriptions_empty(const pn_subscribe_manager_t* mgr)
{
    uint16_t i;

    if (NULL == mgr) {
        return 1;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (mgr->entries[i].occupied && mgr->entries[i].active_count > 0) {
            return 0;
        }
    }
    return 1;
}

int pn_subscription_set_contains(const pn_subscribe_manager_t* mgr,
                                 uint16_t                      set_index,
                                 uint16_t                      entry_index)
{
    const pn_subscription_set_data_t* set;
    uint16_t                          i;

    if (NULL == mgr) {
        return 0;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        return 0;
    }

    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count; ++i) {
        uint16_t slot = set->member_slots[i];
        if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS && NULL != mgr->tracked_subs[slot]
            && mgr->tracked_subs[slot]->entry_index == entry_index) {
            return 1;
        }
    }
    return 0;
}

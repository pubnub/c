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

/** Presence channel suffix appended when with_presence is set. */
#define PN_PNPRES_SUFFIX     "-pnpres"
#define PN_PNPRES_SUFFIX_LEN ((size_t)7)

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

    /* Look for existing entry with same name and type. */
    idx = pn_find_entry(mgr, name, name_len, entity_type);
    if (UINT16_MAX != idx) {
        if (UINT16_MAX == mgr->entries[idx].ref_count) {
            return UINT16_MAX; /* saturated — cannot add more refs */
        }
        mgr->entries[idx].ref_count++;
        /* Upgrade to presence if newly requested. */
        if (with_presence && 0 == mgr->entries[idx].with_presence) {
            mgr->entries[idx].with_presence = 1;
        }
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

    mgr->entries[idx].name          = dup;
    mgr->entries[idx].name_len      = name_len;
    mgr->entries[idx].entity_type   = entity_type;
    mgr->entries[idx].with_presence = with_presence;
    mgr->entries[idx].occupied      = 1;
    mgr->entries[idx].ref_count     = 1;
    mgr->entries[idx].active_count  = 0;
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
        mgr->entries[index].name     = NULL;
        mgr->entries[index].name_len = 0;
        mgr->entries[index].occupied = 0;
        mgr->channel_count--;
    }
}

uint16_t pn_subscription_set_create(pn_subscribe_manager_t* mgr)
{
    uint16_t i;

    if (NULL == mgr) {
        return UINT16_MAX;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->sets[i].active) {
            memset(&mgr->sets[i], 0, sizeof(mgr->sets[i]));
            mgr->sets[i].active = 1;
            mgr->set_count++;
            return i;
        }
    }
    return UINT16_MAX;
}

pubnub_res_t pn_subscription_set_add(pn_subscribe_manager_t*    mgr,
                                     uint16_t                   set_index,
                                     const char*                name,
                                     uint16_t                   name_len,
                                     pn_subscribe_entity_type_t entity_type,
                                     uint8_t                    with_presence)
{
    pn_subscription_set_data_t* set;
    uint16_t                    entry_idx;

    if (NULL == mgr) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (set->count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    entry_idx =
        pn_subscription_acquire(mgr, name, name_len, entity_type, with_presence);
    if (UINT16_MAX == entry_idx) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    /* Deduplicate: if entry_idx is already in the set, release the
     * extra ref we just acquired and return OK (no-op). */
    if (pn_subscription_set_contains(mgr, set_index, entry_idx)) {
        pn_subscription_release(mgr, entry_idx);
        return PUBNUB_OK;
    }

    set->entry_indices[set->count] = entry_idx;
    set->count++;
    return PUBNUB_OK;
}

void pn_subscription_set_destroy(pn_subscribe_manager_t* mgr, uint16_t set_index)
{
    pn_subscription_set_data_t* set;
    uint16_t                    i;

    if (NULL == mgr) {
        return;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return;
    }

    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return;
    }

    /* Release all referenced entries. */
    for (i = 0; i < set->count; ++i) {
        pn_subscription_release(mgr, set->entry_indices[i]);
    }

    set->active = 0;
    set->count  = 0;
    mgr->set_count--;
}

/**
 * @brief Internal helper to populate a listener slot from public struct.
 */
static void pn_fill_listener_slot(pn_subscribe_listener_t*           slot,
                                  const pubnub_subscribe_listener_t* listener,
                                  uint16_t bound_entry,
                                  uint16_t bound_set)
{
    slot->on_status         = listener->on_status;
    slot->on_message        = listener->on_message;
    slot->on_signal         = listener->on_signal;
    slot->on_presence       = listener->on_presence;
    slot->on_message_action = listener->on_message_action;
    slot->on_app_context    = listener->on_app_context;
    slot->on_file           = listener->on_file;
    slot->user_data         = listener->user_data;
    slot->bound_entry_index = bound_entry;
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
                                uint16_t                           entry_index)
{
    uint16_t i;

    if (NULL == mgr || NULL == listener) {
        return PN_LISTENER_HANDLE_INVALID;
    }
    if (entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return PN_LISTENER_HANDLE_INVALID;
    }
    if (0 == mgr->entries[entry_index].occupied) {
        return PN_LISTENER_HANDLE_INVALID;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        if (0 == mgr->listeners[i].active) {
            pn_fill_listener_slot(
                &mgr->listeners[i], listener, entry_index, UINT16_MAX);
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
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
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

/**
 * @brief Clear listener slots marked for deferred removal.
 *
 * Caller must hold the context lock. Only invoked from emit functions
 * after the callback iteration loop, before clearing invoke_pending.
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
        if (UINT16_MAX != mgr->listeners[i].bound_entry_index
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

    /* Sweep deferred removals under lock before clearing
     * invoke_pending so the remove-side never races with the
     * memset. */
    pn_ctx_lock(platform, lock_mem);
    pn_listener_sweep_pending_locked(mgr);
    pn_ctx_unlock(platform, lock_mem);

    PUBNUB_ATOMIC_STORE_U8(&mgr->invoke_pending, 0);
}

/**
 * @brief Check whether a listener should receive an event based on
 *        its binding and the event's source entry index.
 *
 * Global listeners (no binding) always receive all events.
 * Bound-to-entry listeners fire only when the entry matches.
 * Bound-to-set listeners fire when the entry is a set member.
 */
static int pn_listener_matches(const pn_subscribe_manager_t*  mgr,
                               const pn_subscribe_listener_t* listener,
                               uint16_t                       event_entry_index)
{
    /* Global listener: no binding — fires for everything. */
    if (UINT16_MAX == listener->bound_entry_index
        && UINT16_MAX == listener->bound_set_index) {
        return 1;
    }

    /* Per-subscription listener: direct entry match. */
    if (UINT16_MAX != listener->bound_entry_index) {
        return (listener->bound_entry_index == event_entry_index) ? 1 : 0;
    }

    /* Per-set listener: check set membership. */
    if (UINT16_MAX != listener->bound_set_index) {
        if (UINT16_MAX == event_entry_index) {
            return 0;
        }
        return pn_subscription_set_contains(
            mgr, listener->bound_set_index, event_entry_index);
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

void pn_subscribe_emit_message(pn_subscribe_manager_t*              mgr,
                               const pn_subscribe_dispatch_entry_t* entry)
{
    pubnub_platform_provider_t* platform = NULL;
    void*                       lock_mem = NULL;

    if (NULL == mgr || NULL == entry) {
        return;
    }

    platform = pn_context_platform(mgr->ctx);
    lock_mem = pn_context_mutex_mem(mgr->ctx);

    PUBNUB_ATOMIC_STORE_U8(&mgr->invoke_pending, 1);

    {
        uint16_t event_entry_index = entry->entry_index;
        uint16_t i;
        if (UINT16_MAX == event_entry_index && NULL != entry->event.channel.ptr
            && entry->event.channel.len > 0) {
            event_entry_index = pn_subscribe_resolve_entry(
                mgr, entry->event.channel.ptr, entry->event.channel.len);
        }
        /* Fallback: resolve by "b" (subscription match) field for
         * channel-group and wildcard subscriptions where the "c"
         * field is the individual channel, not the subscribed
         * entity. */
        if (UINT16_MAX == event_entry_index && NULL != entry->event.subscription.ptr
            && entry->event.subscription.len > 0) {
            event_entry_index = pn_subscribe_resolve_entry(
                mgr, entry->event.subscription.ptr, entry->event.subscription.len);
        }

        for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
            if (0 == mgr->listeners[i].active
                || PUBNUB_ATOMIC_LOAD_U8(&mgr->listeners[i].pending_remove)) {
                continue;
            }
            if (!pn_listener_matches(mgr, &mgr->listeners[i], event_entry_index)) {
                continue;
            }
            pn_dispatch_typed(&mgr->listeners[i], entry->event.type, &entry->event);
        }
    }

    /* Sweep deferred removals under lock before clearing
     * invoke_pending so the remove-side never races with the
     * memset. */
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
 * @brief Append an entity name (and optionally its -pnpres variant)
 *        to a comma-separated output buffer.
 *
 * Metadata entities never receive the `-pnpres` suffix regardless
 * of the `with_presence` flag.
 *
 * @return New offset on success, or 0 on overflow.
 */
static size_t pn_append_entity(const pn_subscription_entry_t* entry,
                               char*                          buf,
                               size_t                         buf_len,
                               size_t                         offset,
                               int                            first)
{
    size_t needed;
    size_t comma_len = first ? 0 : 1;

    /* Write bare name. */
    needed = comma_len + entry->name_len;
    if (offset + needed >= buf_len) {
        return 0;
    }

    if (!first) {
        buf[offset++] = ',';
    }
    memcpy(buf + offset, entry->name, entry->name_len);
    offset += entry->name_len;

    /* Write -pnpres variant if presence is requested and entity
     * supports it (metadata entities never get presence). */
    if (entry->with_presence && !pn_entity_is_metadata(entry->entity_type)) {
        /* ",<name>-pnpres" */
        needed = (size_t)1 + entry->name_len + PN_PNPRES_SUFFIX_LEN;
        if (offset + needed >= buf_len) {
            return 0;
        }
        buf[offset++] = ',';
        memcpy(buf + offset, entry->name, entry->name_len);
        offset += entry->name_len;
        memcpy(buf + offset, /* NOLINT(bugprone-not-null-terminated-result) */
               PN_PNPRES_SUFFIX,
               PN_PNPRES_SUFFIX_LEN);
        offset += PN_PNPRES_SUFFIX_LEN;
    }

    return offset;
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

size_t pn_subscribe_build_channel_string(const pn_subscribe_manager_t* mgr,
                                         char*                         buf,
                                         size_t                        buf_len)
{
    size_t   offset = 0;
    int      first  = 1;
    uint16_t i;

    if (NULL == mgr || NULL == buf || 0 == buf_len) {
        return 0;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        size_t new_offset;
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!pn_entity_in_path(mgr->entries[i].entity_type)) {
            continue;
        }
        new_offset =
            pn_append_entity(&mgr->entries[i], buf, buf_len, offset, first);
        if (0 == new_offset && !first) {
            /* Overflow: truncate at last valid position. */
            buf[offset] = '\0';
            return 0;
        }
        if (0 == new_offset && first) {
            /* First entry overflows the buffer entirely. */
            buf[0] = '\0';
            return 0;
        }
        offset = new_offset;
        first  = 0;
    }

    buf[offset] = '\0';
    return offset;
}

size_t pn_subscribe_build_channel_group_string(const pn_subscribe_manager_t* mgr,
                                               char*  buf,
                                               size_t buf_len)
{
    size_t   offset = 0;
    int      first  = 1;
    uint16_t i;

    if (NULL == mgr || NULL == buf || 0 == buf_len) {
        return 0;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        size_t new_offset;
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (PN_ENTITY_CHANNEL_GROUP != mgr->entries[i].entity_type) {
            continue;
        }
        new_offset =
            pn_append_entity(&mgr->entries[i], buf, buf_len, offset, first);
        if (0 == new_offset && !first) {
            buf[offset] = '\0';
            return 0;
        }
        if (0 == new_offset && first) {
            buf[0] = '\0';
            return 0;
        }
        offset = new_offset;
        first  = 0;
    }

    buf[offset] = '\0';
    return offset;
}

/**
 * @brief Compute the total serialized length of active entries matching
 *        a filter predicate (including commas and -pnpres variants).
 *
 * Two-pass helper: call once to get the needed size, allocate, then
 * call the write pass.
 */
static size_t pn_compute_entity_string_len(const pn_subscribe_manager_t* mgr,
                                           int (*filter)(pn_subscribe_entity_type_t))
{
    size_t   total = 0;
    int      first = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!filter(mgr->entries[i].entity_type)) {
            continue;
        }

        if (!first) {
            total += 1; /* comma */
        }
        total += mgr->entries[i].name_len;
        first = 0;

        if (mgr->entries[i].with_presence
            && !pn_entity_is_metadata(mgr->entries[i].entity_type)) {
            /* ",<name>-pnpres" */
            total += 1 + mgr->entries[i].name_len + PN_PNPRES_SUFFIX_LEN;
        }
    }

    return total;
}

/**
 * @brief Write active entries matching a filter into a pre-sized buffer.
 *
 * The buffer must have at least the size returned by
 * pn_compute_entity_string_len() + 1 (NUL) bytes available.
 */
static void pn_write_entity_string(const pn_subscribe_manager_t* mgr,
                                   int (*filter)(pn_subscribe_entity_type_t),
                                   char* buf)
{
    size_t   offset = 0;
    int      first  = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!filter(mgr->entries[i].entity_type)) {
            continue;
        }

        if (!first) {
            buf[offset++] = ',';
        }
        memcpy(buf + offset, mgr->entries[i].name, mgr->entries[i].name_len);
        offset += mgr->entries[i].name_len;
        first = 0;

        if (mgr->entries[i].with_presence
            && !pn_entity_is_metadata(mgr->entries[i].entity_type)) {
            buf[offset++] = ',';
            memcpy(buf + offset, mgr->entries[i].name, mgr->entries[i].name_len);
            offset += mgr->entries[i].name_len;
            memcpy(buf + offset, PN_PNPRES_SUFFIX, PN_PNPRES_SUFFIX_LEN);
            offset += PN_PNPRES_SUFFIX_LEN;
        }
    }

    buf[offset] = '\0';
}

/**
 * @brief Compute total length of heartbeat channel names (no -pnpres).
 *
 * Counts only path-eligible entries (channels, metadata), skipping
 * channel groups. Never includes the -pnpres suffix regardless of
 * the with_presence flag. Used for presence heartbeat/leave calls.
 */
static size_t pn_compute_heartbeat_channel_string_len(const pn_subscribe_manager_t* mgr)
{
    size_t   total = 0;
    int      first = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!pn_entity_in_path(mgr->entries[i].entity_type)) {
            continue;
        }

        if (!first) {
            total += 1; /* comma */
        }
        total += mgr->entries[i].name_len;
        first = 0;
    }

    return total;
}

/**
 * @brief Compute total length of heartbeat group names (no -pnpres).
 *
 * Counts only channel-group entries. Never includes the -pnpres
 * suffix regardless of the with_presence flag. Used for presence
 * heartbeat/leave calls.
 */
static size_t pn_compute_heartbeat_group_string_len(const pn_subscribe_manager_t* mgr)
{
    size_t   total = 0;
    int      first = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!pn_entity_is_channel_group(mgr->entries[i].entity_type)) {
            continue;
        }

        if (!first) {
            total += 1; /* comma */
        }
        total += mgr->entries[i].name_len;
        first = 0;
    }

    return total;
}

/**
 * @brief Write heartbeat channel names (no -pnpres) into a pre-sized
 *        buffer.
 *
 * The buffer must have at least the size returned by
 * pn_compute_heartbeat_channel_string_len() + 1 (NUL) bytes.
 */
static void pn_write_heartbeat_channel_string(const pn_subscribe_manager_t* mgr,
                                              char*                         buf)
{
    size_t   offset = 0;
    int      first  = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!pn_entity_in_path(mgr->entries[i].entity_type)) {
            continue;
        }

        if (!first) {
            buf[offset++] = ',';
        }
        memcpy(buf + offset, mgr->entries[i].name, mgr->entries[i].name_len);
        offset += mgr->entries[i].name_len;
        first = 0;
    }

    buf[offset] = '\0';
}

/**
 * @brief Write heartbeat group names (no -pnpres) into a pre-sized
 *        buffer.
 *
 * The buffer must have at least the size returned by
 * pn_compute_heartbeat_group_string_len() + 1 (NUL) bytes.
 */
static void pn_write_heartbeat_group_string(const pn_subscribe_manager_t* mgr,
                                            char*                         buf)
{
    size_t   offset = 0;
    int      first  = 1;
    uint16_t i;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if (0 == mgr->entries[i].active_count) {
            continue;
        }
        if (!pn_entity_is_channel_group(mgr->entries[i].entity_type)) {
            continue;
        }

        if (!first) {
            buf[offset++] = ',';
        }
        memcpy(buf + offset, mgr->entries[i].name, mgr->entries[i].name_len);
        offset += mgr->entries[i].name_len;
        first = 0;
    }

    buf[offset] = '\0';
}

char* pn_subscribe_build_channel_string_alloc(const pn_subscribe_manager_t* mgr,
                                              pubnub_allocator_provider_t* alloc)
{
    size_t needed;
    char*  buf;

    if (NULL == mgr || NULL == alloc) {
        return NULL;
    }

    needed = pn_compute_entity_string_len(mgr, pn_entity_in_path);
    if (0 == needed) {
        return NULL;
    }

    buf = (char*)PN_ALLOC(alloc, needed + 1, 1);
    if (NULL == buf) {
        return NULL;
    }

    pn_write_entity_string(mgr, pn_entity_in_path, buf);
    return buf;
}

char* pn_subscribe_build_channel_group_string_alloc(const pn_subscribe_manager_t* mgr,
                                                    pubnub_allocator_provider_t* alloc)
{
    size_t needed;
    char*  buf;

    if (NULL == mgr || NULL == alloc) {
        return NULL;
    }

    needed = pn_compute_entity_string_len(mgr, pn_entity_is_channel_group);
    if (0 == needed) {
        return NULL;
    }

    buf = (char*)PN_ALLOC(alloc, needed + 1, 1);
    if (NULL == buf) {
        return NULL;
    }

    pn_write_entity_string(mgr, pn_entity_is_channel_group, buf);
    return buf;
}

char* pn_subscribe_build_heartbeat_channel_string_alloc(
    const pn_subscribe_manager_t* mgr,
    pubnub_allocator_provider_t*  alloc)
{
    size_t needed;
    char*  buf;

    if (NULL == mgr || NULL == alloc) {
        return NULL;
    }

    needed = pn_compute_heartbeat_channel_string_len(mgr);
    if (0 == needed) {
        return NULL;
    }

    buf = (char*)PN_ALLOC(alloc, needed + 1, 1);
    if (NULL == buf) {
        return NULL;
    }

    pn_write_heartbeat_channel_string(mgr, buf);
    return buf;
}

char* pn_subscribe_build_heartbeat_group_string_alloc(
    const pn_subscribe_manager_t* mgr,
    pubnub_allocator_provider_t*  alloc)
{
    size_t needed;
    char*  buf;

    if (NULL == mgr || NULL == alloc) {
        return NULL;
    }

    needed = pn_compute_heartbeat_group_string_len(mgr);
    if (0 == needed) {
        return NULL;
    }

    buf = (char*)PN_ALLOC(alloc, needed + 1, 1);
    if (NULL == buf) {
        return NULL;
    }

    pn_write_heartbeat_group_string(mgr, buf);
    return buf;
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
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return 0;
    }

    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count; ++i) {
        if (set->entry_indices[i] == entry_index) {
            return 1;
        }
    }
    return 0;
}

int pn_subscription_set_remove_entry(pn_subscribe_manager_t* mgr,
                                     uint16_t                set_index,
                                     uint16_t                entry_index)
{
    pn_subscription_set_data_t* set;
    uint16_t                    i;

    if (NULL == mgr) {
        return 0;
    }
    if (set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        return 0;
    }

    set = &mgr->sets[set_index];
    if (0 == set->active) {
        return 0;
    }

    for (i = 0; i < set->count; ++i) {
        if (set->entry_indices[i] == entry_index) {
            /* Shift remaining elements down. */
            if (i < set->count - 1) {
                memmove(&set->entry_indices[i],
                        &set->entry_indices[i + 1],
                        (size_t)(set->count - 1 - i) * sizeof(uint16_t));
            }
            set->count--;

            /* Release the reference held by this set. */
            pn_subscription_release(mgr, entry_index);
            return 1;
        }
    }
    return 0;
}

uint16_t pn_subscribe_resolve_entry(const pn_subscribe_manager_t* mgr,
                                    const char*                   channel_ptr,
                                    size_t                        channel_len)
{
    uint16_t i;
    size_t   name_len = channel_len;

    if (NULL == mgr || NULL == channel_ptr || 0 == channel_len) {
        return UINT16_MAX;
    }

    /* Strip -pnpres suffix if present. */
    if (channel_len > 7 && 0 == memcmp(channel_ptr + channel_len - 7, "-pnpres", 7)) {
        name_len = channel_len - 7;
    }

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (0 == mgr->entries[i].occupied) {
            continue;
        }
        if ((size_t)mgr->entries[i].name_len != name_len) {
            continue;
        }
        if (0 == memcmp(mgr->entries[i].name, channel_ptr, name_len)) {
            return i;
        }
    }
    return UINT16_MAX;
}

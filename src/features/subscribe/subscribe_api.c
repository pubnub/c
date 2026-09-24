/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/features/subscribe.h"

#if !PUBNUB_ENABLE_SUBSCRIBE
#error "subscribe_api.c requires PUBNUB_ENABLE_SUBSCRIBE=ON - this " \
    "translation unit has no meaning without the subscribe feature."
#endif

#include "subscribe_effects.h"
#include "subscribe_event_queue.h"
#include "subscribe_manager_internal.h"

#include "core/core_internal.h"
#include "core/pn_feature_registry.h"
#include "core/pn_lock.h"

#include "pubnub/capabilities.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"

#if PUBNUB_ENABLE_PRESENCE
#include "features/presence/presence_api.h"
#endif

#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <string.h>

/**
 * @brief Notify presence that the active channel set has changed
 *        (channels added).
 *
 * Delegates to the presence API layer which handles lazy-allocation
 * of the presence manager and observer registration.
 */
static void pn_notify_presence_joined(pubnub_context_t*       ctx,
                                      pn_subscribe_manager_t* mgr)
{
#if PUBNUB_ENABLE_PRESENCE
    if (NULL == ctx || NULL == mgr) {
        return;
    }

    pubnub_allocator_provider_t* alloc = pn_context_allocator(ctx);
    if (NULL == alloc) {
        return;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);
    char*                       ch_str   = NULL;
    char*                       gr_str   = NULL;

    /* Two-pass measure-then-write over entries[] — must be atomic
     * w.r.t. concurrent subscription mutations (use-after-free). */
    pn_ctx_lock(platform, lock);
    ch_str = pn_subscribe_build_heartbeat_channel_string_alloc(mgr, alloc);
    gr_str = pn_subscribe_build_heartbeat_group_string_alloc(mgr, alloc);
    pn_ctx_unlock(platform, lock);

    if (NULL == ch_str && NULL == gr_str) {
        return;
    }

    pn_presence_api_joined(ctx, ch_str, gr_str);

    if (NULL != ch_str) {
        PN_FREE(alloc, ch_str);
    }
    if (NULL != gr_str) {
        PN_FREE(alloc, gr_str);
    }
#else
    (void)ctx;
    (void)mgr;
#endif
}

/**
 * @brief Notify presence that channels were removed.
 */
static void pn_notify_presence_left(pubnub_context_t*       ctx,
                                    pn_subscribe_manager_t* mgr,
                                    const char*             removed_channels,
                                    const char*             removed_groups,
                                    uint8_t                 subscriptions_empty)
{
#if PUBNUB_ENABLE_PRESENCE
    if (NULL == ctx || NULL == mgr) {
        return;
    }

    if (subscriptions_empty) {
        pn_presence_api_left_all(ctx);
    } else {
        pubnub_allocator_provider_t* alloc = pn_context_allocator(ctx);
        if (NULL == alloc) {
            pn_presence_api_left_all(ctx);
            return;
        }

        pubnub_platform_provider_t* platform = pn_context_platform(ctx);
        pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);
        char*                       ch_str   = NULL;
        char*                       gr_str   = NULL;

        /* Two-pass measure-then-write over entries[] — must be atomic
         * w.r.t. concurrent subscription mutations (use-after-free). */
        pn_ctx_lock(platform, lock);
        ch_str = pn_subscribe_build_heartbeat_channel_string_alloc(mgr, alloc);
        gr_str = pn_subscribe_build_heartbeat_group_string_alloc(mgr, alloc);
        pn_ctx_unlock(platform, lock);

        if (NULL == ch_str && NULL == gr_str) {
            pn_presence_api_left_all(ctx);
            return;
        }

        pn_presence_api_left(
            ctx, ch_str, gr_str, removed_channels, removed_groups, subscriptions_empty);

        if (NULL != ch_str) {
            PN_FREE(alloc, ch_str);
        }
        if (NULL != gr_str) {
            PN_FREE(alloc, gr_str);
        }
    }
#else
    (void)ctx;
    (void)mgr;
    (void)removed_channels;
    (void)removed_groups;
    (void)subscriptions_empty;
#endif
}

/**
 * @brief Notify presence of disconnect.
 */
static void pn_notify_presence_disconnect(pubnub_context_t* ctx)
{
#if PUBNUB_ENABLE_PRESENCE
    pn_presence_api_disconnect(ctx);
#else
    (void)ctx;
#endif
}

/**
 * @brief Notify presence of reconnect.
 */
static void pn_notify_presence_reconnect(pubnub_context_t* ctx)
{
#if PUBNUB_ENABLE_PRESENCE
    pn_presence_api_reconnect(ctx);
#else
    (void)ctx;
#endif
}

#if PUBNUB_CFG_NO_HEAP
/**
 * @brief Append a channel/group name to a comma-separated buffer.
 *
 * @param buf      Destination buffer.
 * @param buf_size Total capacity of buf.
 * @param pos      Current write position (updated on success).
 * @param name     Name to append.
 * @param name_len Length of name (bytes).
 * @return 0 on success, 1 when the name did not fit (truncation).
 */
static int pn_removed_buf_append(char*       buf,
                                 size_t      buf_size,
                                 size_t*     pos,
                                 const char* name,
                                 uint16_t    name_len)
{
    size_t need = *pos + (*pos > 0 ? 1 : 0) + name_len;
    if (need >= buf_size) {
        return 1;
    }
    if (*pos > 0) {
        buf[(*pos)++] = ',';
    }
    memcpy(buf + *pos, name, name_len);
    *pos += name_len;
    buf[*pos] = '\0';
    return 0;
}

/**
 * @brief Record removed entry into channel/group buffers.
 *
 * Dispatches to the appropriate buffer based on entity type.
 *
 * @return 0 on success, 1 when the entry name was truncated.
 */
static int pn_record_removed_entry(pn_subscription_entry_t* entry,
                                   char*                    removed_ch,
                                   size_t                   ch_size,
                                   size_t*                  ch_pos,
                                   char*                    removed_gr,
                                   size_t                   gr_size,
                                   size_t*                  gr_pos)
{
    if (PN_ENTITY_CHANNEL_GROUP == entry->entity_type) {
        return pn_removed_buf_append(
            removed_gr, gr_size, gr_pos, entry->name, entry->name_len);
    }
    return pn_removed_buf_append(
        removed_ch, ch_size, ch_pos, entry->name, entry->name_len);
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if !PUBNUB_CFG_NO_HEAP
/**
 * @brief Heap-allocate a comma-separated string of removed entries.
 *
 * Two-pass: first measures total length, then allocates and writes.
 * Filters entries by entity_type so channels and groups can be
 * collected separately.
 *
 * @param entries     Entry array (the subscribe manager entries[]).
 * @param indices     Array of entry indices to include.
 * @param index_count Number of elements in indices[].
 * @param filter_type Entity type to include (others skipped).
 * @param alloc       Allocator for the result string.
 * @return Heap-allocated NUL-terminated string, or NULL if empty or
 *         allocation failed. Caller must free via alloc->free().
 */
static char* pn_build_removed_string_alloc(const pn_subscription_entry_t* entries,
                                           const uint16_t* indices,
                                           uint16_t        index_count,
                                           pn_subscribe_entity_type_t filter_type,
                                           pubnub_allocator_provider_t* alloc)
{
    if (NULL == entries || NULL == alloc || 0 == index_count) {
        return NULL;
    }

    /* Pass 1: measure total length. */
    size_t   total  = 0;
    uint16_t ncomma = 0;
    uint16_t i;
    for (i = 0; i < index_count; ++i) {
        uint16_t idx = indices[i];
        if (idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
            continue;
        }
        if (!entries[idx].occupied) {
            continue;
        }
        if (entries[idx].entity_type != filter_type) {
            continue;
        }
        if (0 == entries[idx].active_count) {
            total += entries[idx].name_len;
            ncomma++;
        }
    }

    if (0 == ncomma) {
        return NULL;
    }

    /* commas between entries + NUL */
    total += (size_t)(ncomma - 1) + 1;

    char* buf = (char*)PN_ALLOC(alloc, total, 1);
    if (NULL == buf) {
        return NULL;
    }

    /* Pass 2: write comma-separated names. */
    size_t pos = 0;
    for (i = 0; i < index_count; ++i) {
        uint16_t idx = indices[i];
        if (idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
            continue;
        }
        if (!entries[idx].occupied) {
            continue;
        }
        if (entries[idx].entity_type != filter_type) {
            continue;
        }
        if (0 == entries[idx].active_count) {
            if (pos > 0) {
                buf[pos++] = ',';
            }
            memcpy(buf + pos, entries[idx].name, entries[idx].name_len);
            pos += entries[idx].name_len;
        }
    }
    buf[pos] = '\0';

    return buf;
}

/**
 * @brief Heap-allocate a single-entry "removed" string.
 *
 * For sites that remove exactly one subscription and know the name
 * at the call site.
 *
 * @param name     Entry name (not NUL-terminated).
 * @param name_len Length of name.
 * @param alloc    Allocator for the result string.
 * @return Heap-allocated NUL-terminated copy, or NULL on failure.
 */
static char* pn_build_single_removed_alloc(const char* name,
                                           uint16_t    name_len,
                                           pubnub_allocator_provider_t* alloc)
{
    if (NULL == name || 0 == name_len || NULL == alloc) {
        return NULL;
    }

    char* buf = (char*)PN_ALLOC(alloc, (size_t)name_len + 1, 1);
    if (NULL == buf) {
        return NULL;
    }
    memcpy(buf, name, name_len);
    buf[name_len] = '\0';
    return buf;
}
#endif /* !PUBNUB_CFG_NO_HEAP */

#if PUBNUB_CFG_NO_HEAP
/**
 * @brief Capture a single deactivated entry into the appropriate removal
 *        buffer based on entity type (no-heap path).
 *
 * @param entry      Deactivated subscription entry.
 * @param removed_ch Channel removal buffer.
 * @param ch_size    Channel buffer capacity.
 * @param removed_gr Group removal buffer.
 * @param gr_size    Group buffer capacity.
 * @return 0 on success, 1 when the name did not fit (truncation).
 */
static int pn_capture_removed_single(const pn_subscription_entry_t* entry,
                                     char*                          removed_ch,
                                     size_t                         ch_size,
                                     char*                          removed_gr,
                                     size_t                         gr_size)
{
    int    is_group = (PN_ENTITY_CHANNEL_GROUP == entry->entity_type);
    char*  dst      = is_group ? removed_gr : removed_ch;
    size_t capacity = is_group ? gr_size : ch_size;

    if (entry->name_len < capacity) {
        memcpy(dst, entry->name, entry->name_len);
        dst[entry->name_len] = '\0';
        return 0;
    }
    return 1;
}
#else  /* !PUBNUB_CFG_NO_HEAP */
/**
 * @brief Heap-allocate a single-entry removal string and store it in the
 *        appropriate out-pointer based on entity type (hosted path).
 *
 * @param entry      Deactivated subscription entry.
 * @param alloc      Allocator (non-NULL).
 * @param out_ch     Receives allocated string when entry is a channel.
 * @param out_gr     Receives allocated string when entry is a group.
 */
static void pn_alloc_removed_single(const pn_subscription_entry_t* entry,
                                    pubnub_allocator_provider_t*   alloc,
                                    char**                         out_ch,
                                    char**                         out_gr)
{
    if (PN_ENTITY_CHANNEL_GROUP == entry->entity_type) {
        *out_gr =
            pn_build_single_removed_alloc(entry->name, entry->name_len, alloc);
    } else {
        *out_ch =
            pn_build_single_removed_alloc(entry->name, entry->name_len, alloc);
    }
}
#endif /* PUBNUB_CFG_NO_HEAP */

#if PUBNUB_CFG_NO_HEAP && PUBNUB_ENABLE_PRESENCE
PUBNUB_STATIC_ASSERT(PUBNUB_CFG_HTTP_SCRATCH_SIZE >= 256,
                     "HTTP scratch too small for presence leave lists");
#endif

/**
 * @brief Lazy-allocate the subscribe manager for a context.
 *
 * If the manager is not yet created, allocates it and registers it
 * in the feature registry. Returns the manager on success, NULL on
 * allocation failure.
 *
 * @pre Caller MUST hold the context lock during the call.
 */
static pn_subscribe_manager_t* pn_ensure_subscribe_manager(pubnub_context_t* ctx)
{
    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL != mgr) {
        return mgr;
    }

    const pubnub_config_t* config = pn_context_config(ctx);
    if (NULL == config || NULL == config->allocator) {
        return NULL;
    }

    mgr = pn_subscribe_manager_create(ctx, config->allocator);
    if (NULL == mgr) {
        return NULL;
    }

    pn_context_set_feature_state(
        ctx, PUBNUB_FEATURE_SUBSCRIBE, mgr, pn_subscribe_manager_cleanup);
    pn_context_set_feature_tick(
        ctx, PUBNUB_FEATURE_SUBSCRIBE, pn_subscribe_feature_tick);

    return mgr;
}

/**
 * @brief Internal factory for entity handles.
 *
 * Validates inputs, lazy-allocates the manager, acquires a registry
 * entry, and allocates the entity handle.
 */
static pubnub_entity_t pn_entity_create(pubnub_context_t*          ctx,
                                        const char*                name,
                                        pn_subscribe_entity_type_t entity_type)
{
    pn_subscribe_manager_t*      mgr;
    pubnub_allocator_provider_t* alloc;
    pn_entity_t*                 entity;
    uint16_t                     entry_idx;
    uint16_t                     name_len;

    if (NULL == name) {
        return NULL;
    }

    const pubnub_config_t* cfg = NULL;
    if (PUBNUB_OK != pn_validate_ctx(ctx, &cfg)) {
        return NULL;
    }
    (void)cfg;

    const size_t raw_len = strlen(name);
    if (0 == raw_len || raw_len > UINT16_MAX) {
        return NULL;
    }
    name_len = (uint16_t)raw_len;

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    /* Metadata entities never get presence suffix. */
    const uint8_t with_presence = 0;

    entry_idx =
        pn_subscription_acquire(mgr, name, name_len, entity_type, with_presence);
    if (UINT16_MAX == entry_idx) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    const pubnub_config_t* config = pn_context_config(ctx);
    alloc                         = config->allocator;
    entity = (pn_entity_t*)PN_ALLOC(alloc, sizeof(pn_entity_t), sizeof(void*));
    if (NULL == entity) {
        pn_subscription_release(mgr, entry_idx);
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    entity->ctx         = ctx;
    entity->entry_index = entry_idx;

    pn_ctx_unlock(platform, lock);

    return entity;
}

pubnub_entity_t pubnub_channel(pubnub_context_t* ctx, const char* name)
{
    return pn_entity_create(ctx, name, PN_ENTITY_CHANNEL);
}

pubnub_entity_t pubnub_channel_group(pubnub_context_t* ctx, const char* name)
{
    return pn_entity_create(ctx, name, PN_ENTITY_CHANNEL_GROUP);
}

pubnub_entity_t pubnub_channel_metadata(pubnub_context_t* ctx, const char* id)
{
    return pn_entity_create(ctx, id, PN_ENTITY_CHANNEL_METADATA);
}

pubnub_entity_t pubnub_user_metadata(pubnub_context_t* ctx, const char* id)
{
    return pn_entity_create(ctx, id, PN_ENTITY_USER_METADATA);
}

void pubnub_entity_destroy(pubnub_entity_t entity)
{
    pn_subscribe_manager_t* mgr;

    if (NULL == entity) {
        return;
    }

    pubnub_context_t*           ctx      = entity->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);
    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL != mgr) {
        pn_subscription_release(mgr, entity->entry_index);
    }
    pn_ctx_unlock(platform, lock);

    const pubnub_config_t* config = pn_context_config(ctx);
    if (NULL != config && NULL != config->allocator) {
        PN_FREE(config->allocator, entity);
    }
}

const char* pubnub_entity_name(pubnub_entity_t entity)
{
    pn_subscribe_manager_t* mgr;
    const char*             result = NULL;

    if (NULL == entity) {
        return NULL;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(entity->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(entity->ctx);

    pn_ctx_lock(platform, lock);
    mgr = pn_subscribe_manager_from_ctx(entity->ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }
    if (entity->entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }
    if (0 == mgr->entries[entity->entry_index].occupied) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    /* The name buffer is stable for the entry's lifetime. */
    result = mgr->entries[entity->entry_index].name;
    pn_ctx_unlock(platform, lock);

    return result;
}

pubnub_subscribe_entity_type_t pubnub_entity_type(pubnub_entity_t entity)
{
    pn_subscribe_manager_t*        mgr;
    pubnub_subscribe_entity_type_t result = PUBNUB_SUBSCRIBE_CHANNEL;

    if (NULL == entity) {
        return PUBNUB_SUBSCRIBE_CHANNEL;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(entity->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(entity->ctx);

    pn_ctx_lock(platform, lock);
    mgr = pn_subscribe_manager_from_ctx(entity->ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIBE_CHANNEL;
    }
    if (entity->entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIBE_CHANNEL;
    }
    if (0 == mgr->entries[entity->entry_index].occupied) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIBE_CHANNEL;
    }

    switch (mgr->entries[entity->entry_index].entity_type) {
    case PN_ENTITY_CHANNEL_GROUP:
        result = PUBNUB_SUBSCRIBE_CHANNEL_GROUP;
        break;
    case PN_ENTITY_CHANNEL_METADATA:
        result = PUBNUB_SUBSCRIBE_CHANNEL_METADATA;
        break;
    case PN_ENTITY_USER_METADATA:
        result = PUBNUB_SUBSCRIBE_USER_METADATA;
        break;
    default: result = PUBNUB_SUBSCRIBE_CHANNEL; break;
    }
    pn_ctx_unlock(platform, lock);

    return result;
}

pubnub_subscription_t pubnub_subscription_create(pubnub_entity_t entity,
                                                 const pubnub_subscription_opts_t* opts)
{
    pn_subscribe_manager_t*      mgr;
    pubnub_allocator_provider_t* alloc;
    pn_subscription_t*           sub;
    uint16_t                     entry_idx;

    if (NULL == entity) {
        return NULL;
    }

    pubnub_context_t*           ctx      = entity->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    /* Acquire a new ref on the same registry entry so the
     * subscription holds its own independent reference. */
    if (entity->entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }
    if (0 == mgr->entries[entity->entry_index].occupied) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }
    if (UINT16_MAX == mgr->entries[entity->entry_index].ref_count) {
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    mgr->entries[entity->entry_index].ref_count++;
    entry_idx = entity->entry_index;

    /* Guard: tracking array must have room before we commit. */
    if (mgr->tracked_sub_count >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_subscription_release(mgr, entry_idx);
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    /* Apply with_presence from opts (only for non-metadata entities). */
    if (NULL != opts && opts->with_presence) {
        pn_subscribe_entity_type_t etype = mgr->entries[entry_idx].entity_type;
        if (PN_ENTITY_CHANNEL == etype || PN_ENTITY_CHANNEL_GROUP == etype) {
            mgr->entries[entry_idx].with_presence = 1;
        }
    }

    /* Allocate the subscription handle. */
    const pubnub_config_t* config = pn_context_config(ctx);
    alloc                         = config->allocator;
    sub                           = (pn_subscription_t*)PN_ALLOC(
        alloc, sizeof(pn_subscription_t), sizeof(void*));
    if (NULL == sub) {
        pn_subscription_release(mgr, entry_idx);
        pn_ctx_unlock(platform, lock);
        return NULL;
    }

    sub->ctx         = ctx;
    sub->entry_index = entry_idx;
    sub->subscribed  = 0;

    /* Register in the tracking array for introspection accessors. */
    if (mgr->tracked_sub_count < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        mgr->tracked_subs[mgr->tracked_sub_count] = sub;
        mgr->tracked_sub_count++;
    }

    pn_ctx_unlock(platform, lock);

    return sub;
}

/**
 * @brief Remove a subscription handle from the manager's tracking
 *        array.
 *
 * Caller must hold the context lock.
 */
static void pn_untrack_subscription_locked(pn_subscribe_manager_t* mgr,
                                           pn_subscription_t*      sub)
{
    uint16_t i;
    for (i = 0; i < mgr->tracked_sub_count; ++i) {
        if (mgr->tracked_subs[i] == sub) {
            mgr->tracked_sub_count--;
            mgr->tracked_subs[i] = mgr->tracked_subs[mgr->tracked_sub_count];
            mgr->tracked_subs[mgr->tracked_sub_count] = NULL;
            return;
        }
    }
}

void pubnub_subscription_destroy(pubnub_subscription_t sub)
{
    pn_subscribe_manager_t* mgr;
    pubnub_context_t*       ctx;
    uint8_t                 need_presence_left  = 0;
    uint8_t                 subscriptions_empty = 0;

#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    uint8_t truncated                                = 0;
#else
    char*                        removed_ch = NULL;
    char*                        removed_gr = NULL;
    pubnub_allocator_provider_t* alloc      = NULL;
#endif

    if (NULL == sub) {
        return;
    }

    ctx = sub->ctx;

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);

    if (NULL != mgr) {
        /* If subscribed, deactivate first to drive the EE. */
        if (sub->subscribed) {
            sub->subscribed = 0;
            mgr->entries[sub->entry_index].active_count--;

            if (0 == mgr->entries[sub->entry_index].active_count) {
                /* Copy before release (which may free the entry). */
#if PUBNUB_CFG_NO_HEAP
                truncated |= (uint8_t)pn_capture_removed_single(
                    &mgr->entries[sub->entry_index],
                    removed_ch,
                    sizeof(removed_ch),
                    removed_gr,
                    sizeof(removed_gr));
#else
                alloc = pn_context_allocator(ctx);
                if (NULL != alloc) {
                    pn_alloc_removed_single(&mgr->entries[sub->entry_index],
                                            alloc,
                                            &removed_ch,
                                            &removed_gr);
                }
#endif
            }

            subscriptions_empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);

            /* Enqueue SUBSCRIPTION_CHANGED to reflect the removal. */
            pn_subscribe_ee_event_t event;
            memset(&event, 0, sizeof(event));
            event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
            event.subscriptions_empty = subscriptions_empty;
            mgr->subscription_generation++;
            event.generation = mgr->subscription_generation;
            pn_subscribe_event_queue_push(&mgr->event_queue, &event);

            need_presence_left = 1;
        }

        /* Always release the registry ref (taken at create time). */
        pn_subscription_release(mgr, sub->entry_index);

        /* Remove from introspection tracking array. */
        pn_untrack_subscription_locked(mgr, sub);
    }

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Presence notification outside the lock (may do I/O). */
    if (need_presence_left) {
#if PUBNUB_CFG_NO_HEAP
        if (truncated) {
            PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                            PUBNUB_LOG_LEVEL_WARNING,
                            "Presence leave list truncated; some channels "
                            "may show stale occupancy until heartbeat "
                            "timeout");
        }
#endif
        pn_notify_presence_left(ctx, mgr, removed_ch, removed_gr, subscriptions_empty);
#if !PUBNUB_CFG_NO_HEAP
        if (NULL != removed_ch && NULL != alloc) {
            PN_FREE(alloc, removed_ch);
        }
        if (NULL != removed_gr && NULL != alloc) {
            PN_FREE(alloc, removed_gr);
        }
#endif
    }

    /* Free the handle. */
    const pubnub_config_t* config = pn_context_config(ctx);
    if (NULL != config && NULL != config->allocator) {
        PN_FREE(config->allocator, sub);
    }
}

pubnub_res_t pubnub_subscription_subscribe(pubnub_subscription_t sub)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;
    pubnub_context_t*       ctx;

    if (NULL == sub) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    ctx = sub->ctx;

    PUBNUB_LOG_TEXT(
        pn_context_logger(ctx), PUBNUB_LOG_LEVEL_DEBUG, "Subscription subscribe");

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    if (sub->subscribed) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK; /* Already active — no-op. */
    }

    sub->subscribed = 1;
    mgr->entries[sub->entry_index].active_count++;

    /* Feed SUBSCRIPTION_CHANGED into the event engine. */
    memset(&event, 0, sizeof(event));
    event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
    event.subscriptions_empty = 0; /* We just subscribed something. */
    mgr->subscription_generation++;
    event.generation = mgr->subscription_generation;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    (void)pn_context_start_bg_thread(ctx);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE — channels were added (outside lock). */
    pn_notify_presence_joined(ctx, mgr);

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscription_unsubscribe(pubnub_subscription_t sub)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;
    pubnub_context_t*       ctx;
    uint8_t                 empty;

#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    uint8_t truncated                                = 0;
#else
    char*                        removed_ch = NULL;
    char*                        removed_gr = NULL;
    pubnub_allocator_provider_t* alloc      = NULL;
#endif

    if (NULL == sub) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    ctx = sub->ctx;

    PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                    PUBNUB_LOG_LEVEL_DEBUG,
                    "Subscription unsubscribe");

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    if (!sub->subscribed) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK;
    }

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    sub->subscribed = 0;
    mgr->entries[sub->entry_index].active_count--;

    /* Copy name while still holding the lock (entry remains valid here
     * since the subscription handle still holds a ref, but copy for
     * safety under concurrent access patterns). */
    if (0 == mgr->entries[sub->entry_index].active_count) {
#if PUBNUB_CFG_NO_HEAP
        truncated |=
            (uint8_t)pn_capture_removed_single(&mgr->entries[sub->entry_index],
                                               removed_ch,
                                               sizeof(removed_ch),
                                               removed_gr,
                                               sizeof(removed_gr));
#else
        alloc = pn_context_allocator(ctx);
        if (NULL != alloc) {
            pn_alloc_removed_single(
                &mgr->entries[sub->entry_index], alloc, &removed_ch, &removed_gr);
        }
#endif
    }

    empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);

    memset(&event, 0, sizeof(event));
    event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
    event.subscriptions_empty = empty;
    mgr->subscription_generation++;
    event.generation = mgr->subscription_generation;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE — channels were removed (outside lock). */
#if PUBNUB_CFG_NO_HEAP
    if (truncated) {
        PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                        PUBNUB_LOG_LEVEL_WARNING,
                        "Presence leave list truncated; some channels "
                        "may show stale occupancy until heartbeat "
                        "timeout");
    }
#endif
    pn_notify_presence_left(ctx, mgr, removed_ch, removed_gr, empty);
#if !PUBNUB_CFG_NO_HEAP
    if (NULL != removed_ch && NULL != alloc) {
        PN_FREE(alloc, removed_ch);
    }
    if (NULL != removed_gr && NULL != alloc) {
        PN_FREE(alloc, removed_gr);
    }
#endif

    return PUBNUB_OK;
}

pubnub_listener_handle_t pubnub_add_listener(pubnub_context_t* ctx,
                                             const pubnub_subscribe_listener_t* listener)
{
    pn_subscribe_manager_t*  mgr;
    pubnub_listener_handle_t result = PUBNUB_LISTENER_HANDLE_INVALID;

    if (NULL == ctx || NULL == listener) {
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pn_listener_handle_t handle = pn_subscribe_listener_add(mgr, listener);
    if (PN_LISTENER_HANDLE_INVALID != handle) {
        result = (pubnub_listener_handle_t)handle;
    }

    pn_ctx_unlock(platform, lock);

    return result;
}

void pubnub_remove_listener(pubnub_context_t* ctx, pubnub_listener_handle_t handle)
{
    pn_subscribe_manager_t*     mgr;
    pn_listener_handle_t        h;
    pubnub_platform_provider_t* platform;
    void*                       lock_mem;

    if (NULL == ctx) {
        return;
    }
    if (PUBNUB_LISTENER_HANDLE_INVALID == handle) {
        return;
    }

    h        = (pn_listener_handle_t)handle;
    platform = pn_context_platform(ctx);
    lock_mem = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock_mem);
    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL != mgr) {
        pn_subscribe_listener_remove(mgr, h);
    }
    pn_ctx_unlock(platform, lock_mem);
}

pubnub_listener_handle_t
pubnub_subscription_add_listener(pubnub_subscription_t              sub,
                                 const pubnub_subscribe_listener_t* listener)
{
    pn_subscribe_manager_t*  mgr;
    pubnub_listener_handle_t result = PUBNUB_LISTENER_HANDLE_INVALID;

    if (NULL == sub || NULL == listener) {
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(sub->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(sub->ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(sub->ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pn_listener_handle_t handle =
        pn_subscribe_listener_add_bound(mgr, listener, sub->entry_index);
    if (PN_LISTENER_HANDLE_INVALID != handle) {
        result = (pubnub_listener_handle_t)handle;
    }

    pn_ctx_unlock(platform, lock);

    return result;
}

void pubnub_subscription_remove_listener(pubnub_subscription_t    sub,
                                         pubnub_listener_handle_t handle)
{
    pn_subscribe_manager_t*     mgr;
    pn_listener_handle_t        h;
    pubnub_platform_provider_t* platform;
    void*                       lock_mem;

    if (NULL == sub) {
        return;
    }
    if (PUBNUB_LISTENER_HANDLE_INVALID == handle) {
        return;
    }

    h        = (pn_listener_handle_t)handle;
    platform = pn_context_platform(sub->ctx);
    lock_mem = pn_context_mutex_mem(sub->ctx);

    pn_ctx_lock(platform, lock_mem);
    mgr = pn_subscribe_manager_from_ctx(sub->ctx);
    if (NULL != mgr) {
        pn_subscribe_listener_remove(mgr, h);
    }
    pn_ctx_unlock(platform, lock_mem);
}

pubnub_subscription_set_t pubnub_subscription_set_create(pubnub_context_t* ctx)
{
    pn_subscribe_manager_t*      mgr;
    pubnub_allocator_provider_t* alloc;
    pn_subscription_set_t*       handle;

    if (NULL == ctx) {
        return PUBNUB_SUBSCRIPTION_SET_INVALID;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_SET_INVALID;
    }

    uint16_t idx = pn_subscription_set_create(mgr);
    if (UINT16_MAX == idx) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_SET_INVALID;
    }

    /* Guard: tracking array must have room before we commit. */
    if (mgr->tracked_set_count >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_subscription_set_destroy(mgr, idx);
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_SET_INVALID;
    }

    const pubnub_config_t* config = pn_context_config(ctx);
    alloc                         = config->allocator;
    handle                        = (pn_subscription_set_t*)PN_ALLOC(
        alloc, sizeof(pn_subscription_set_t), sizeof(void*));
    if (NULL == handle) {
        pn_subscription_set_destroy(mgr, idx);
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_SET_INVALID;
    }

    handle->ctx        = ctx;
    handle->set_index  = idx;
    handle->subscribed = 0;

    /* Register in the tracking array for introspection accessors. */
    if (mgr->tracked_set_count < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        mgr->tracked_sets[mgr->tracked_set_count] = handle;
        mgr->tracked_set_count++;
    }

    pn_ctx_unlock(platform, lock);

    return handle;
}

/**
 * @brief Remove a subscription set handle from the manager's tracking
 *        array.
 *
 * Caller must hold the context lock.
 */
static void pn_untrack_subscription_set_locked(pn_subscribe_manager_t* mgr,
                                               pn_subscription_set_t*  set)
{
    uint16_t i;
    for (i = 0; i < mgr->tracked_set_count; ++i) {
        if (mgr->tracked_sets[i] == set) {
            mgr->tracked_set_count--;
            mgr->tracked_sets[i] = mgr->tracked_sets[mgr->tracked_set_count];
            mgr->tracked_sets[mgr->tracked_set_count] = NULL;
            return;
        }
    }
}

pubnub_res_t pubnub_subscription_set_add_subscription(pubnub_subscription_set_t set,
                                                      pubnub_subscription_t sub)
{
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* s;
    uint16_t                    entry_idx;
    uint8_t                     need_activate = 0;

    if (NULL == set || NULL == sub) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Both must belong to the same context. */
    if (set->ctx != sub->ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_context_t*           ctx      = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    s = &mgr->sets[set->set_index];
    if (0 == s->active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    entry_idx = sub->entry_index;
    if (entry_idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == mgr->entries[entry_idx].occupied) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Deduplicate: if entry_index is already in the set, no-op. */
    if (pn_subscription_set_contains(mgr, set->set_index, entry_idx)) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK;
    }

    if (s->count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_QUEUE_FULL;
    }
    if (UINT16_MAX == mgr->entries[entry_idx].ref_count) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_QUEUE_FULL;
    }

    /* Acquire a new reference for the set. */
    mgr->entries[entry_idx].ref_count++;
    s->entry_indices[s->count] = entry_idx;
    s->count++;

    /* Auto-activate: if the set is already subscribed, increment
     * active_count for the newly added entry. */
    if (set->subscribed) {
        mgr->entries[entry_idx].active_count++;
        need_activate = 1;

        pn_subscribe_ee_event_t event;
        memset(&event, 0, sizeof(event));
        event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
        event.subscriptions_empty = 0;
        mgr->subscription_generation++;
        event.generation = mgr->subscription_generation;
        pn_subscribe_event_queue_push(&mgr->event_queue, &event);
    }

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Presence notification outside the lock (may do I/O). */
    if (need_activate) {
        pn_notify_presence_joined(ctx, mgr);
    }

    return PUBNUB_OK;
}

pubnub_res_t
pubnub_subscription_set_add_subscription_set(pubnub_subscription_set_t target,
                                             pubnub_subscription_set_t other)
{
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* ts;
    pn_subscription_set_data_t* os;
    uint16_t                    i;
    uint8_t                     need_activate = 0;

    if (NULL == target || NULL == other) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (target->ctx != other->ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (target == other) {
        return PUBNUB_OK; /* Self-merge is a no-op. */
    }

    pubnub_context_t*           ctx      = target->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    if (target->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    ts = &mgr->sets[target->set_index];
    if (0 == ts->active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (other->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    os = &mgr->sets[other->set_index];
    if (0 == os->active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Merge each entry from other into target, deduplicating. */
    for (i = 0; i < os->count; ++i) {
        uint16_t entry_idx = os->entry_indices[i];

        /* Skip if already present in the target set. */
        if (pn_subscription_set_contains(mgr, target->set_index, entry_idx)) {
            continue;
        }

        if (ts->count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
            pn_ctx_unlock(platform, lock);
            return PUBNUB_ERR_QUEUE_FULL;
        }
        if (entry_idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
            continue;
        }
        if (0 == mgr->entries[entry_idx].occupied) {
            continue;
        }
        if (UINT16_MAX == mgr->entries[entry_idx].ref_count) {
            continue;
        }

        /* Acquire a new reference for the target set. */
        mgr->entries[entry_idx].ref_count++;
        ts->entry_indices[ts->count] = entry_idx;
        ts->count++;

        /* Auto-activate if target set is already subscribed. */
        if (target->subscribed) {
            mgr->entries[entry_idx].active_count++;
            need_activate = 1;
        }
    }

    /* Emit a single SUBSCRIPTION_CHANGED if we activated entries. */
    if (need_activate) {
        pn_subscribe_ee_event_t event;
        memset(&event, 0, sizeof(event));
        event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
        event.subscriptions_empty = 0;
        mgr->subscription_generation++;
        event.generation = mgr->subscription_generation;
        pn_subscribe_event_queue_push(&mgr->event_queue, &event);
    }

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Presence notification outside the lock (may do I/O). */
    if (need_activate) {
        pn_notify_presence_joined(ctx, mgr);
    }

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscription_set_remove_subscription(pubnub_subscription_set_t set,
                                                         pubnub_subscription_t sub)
{
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* s;
    uint16_t                    entry_idx;
    uint8_t                     need_presence_left  = 0;
    uint8_t                     subscriptions_empty = 0;

    if (NULL == set || NULL == sub) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (set->ctx != sub->ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_context_t*           ctx      = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    s = &mgr->sets[set->set_index];
    if (0 == s->active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    entry_idx = sub->entry_index;
    if (entry_idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == mgr->entries[entry_idx].occupied) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* If the set is subscribed, this entry was contributing to the
     * active channel set. Decrement active_count BEFORE calling
     * remove_entry (which calls pn_subscription_release and may
     * free the entry slot if this set held the last ref). */
#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    uint8_t truncated                                = 0;
#else
    char*                        removed_ch = NULL;
    char*                        removed_gr = NULL;
    pubnub_allocator_provider_t* alloc      = NULL;
#endif

    if (set->subscribed && mgr->entries[entry_idx].occupied
        && mgr->entries[entry_idx].active_count > 0) {
        mgr->entries[entry_idx].active_count--;
        need_presence_left = 1;

        /* Copy name BEFORE remove_entry (which may free it). */
        if (0 == mgr->entries[entry_idx].active_count) {
#if PUBNUB_CFG_NO_HEAP
            truncated |=
                (uint8_t)pn_capture_removed_single(&mgr->entries[entry_idx],
                                                   removed_ch,
                                                   sizeof(removed_ch),
                                                   removed_gr,
                                                   sizeof(removed_gr));
#else
            alloc = pn_context_allocator(ctx);
            if (NULL != alloc) {
                pn_alloc_removed_single(
                    &mgr->entries[entry_idx], alloc, &removed_ch, &removed_gr);
            }
#endif
        }
    }

    /* Attempt removal — returns 0 if entry was not in the set. */
    if (!pn_subscription_set_remove_entry(mgr, set->set_index, entry_idx)) {
        /* Undo active_count decrement if removal failed. */
        if (need_presence_left && mgr->entries[entry_idx].occupied) {
            mgr->entries[entry_idx].active_count++;
        }
#if !PUBNUB_CFG_NO_HEAP
        if (NULL != removed_ch && NULL != alloc) {
            PN_FREE(alloc, removed_ch);
        }
        if (NULL != removed_gr && NULL != alloc) {
            PN_FREE(alloc, removed_gr);
        }
#endif
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (need_presence_left) {
        subscriptions_empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);

        pn_subscribe_ee_event_t event;
        memset(&event, 0, sizeof(event));
        event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
        event.subscriptions_empty = subscriptions_empty;
        mgr->subscription_generation++;
        event.generation = mgr->subscription_generation;
        pn_subscribe_event_queue_push(&mgr->event_queue, &event);
    }

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Presence notification outside the lock (may do I/O). */
    if (need_presence_left) {
#if PUBNUB_CFG_NO_HEAP
        if (truncated) {
            PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                            PUBNUB_LOG_LEVEL_WARNING,
                            "Presence leave list truncated; some channels "
                            "may show stale occupancy until heartbeat "
                            "timeout");
        }
#endif
        pn_notify_presence_left(ctx, mgr, removed_ch, removed_gr, subscriptions_empty);
#if !PUBNUB_CFG_NO_HEAP
        if (NULL != removed_ch && NULL != alloc) {
            PN_FREE(alloc, removed_ch);
        }
        if (NULL != removed_gr && NULL != alloc) {
            PN_FREE(alloc, removed_gr);
        }
#endif
    }

    return PUBNUB_OK;
}

pubnub_res_t
pubnub_subscription_set_remove_subscription_set(pubnub_subscription_set_t target,
                                                pubnub_subscription_set_t other)
{
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* ts;
    pn_subscription_set_data_t* os;
    uint16_t                    i;
    uint8_t                     need_presence_left  = 0;
    uint8_t                     subscriptions_empty = 0;

    if (NULL == target || NULL == other || target->ctx != other->ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (target == other) {
        return PUBNUB_OK;
    }

    pubnub_context_t*           ctx      = target->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr || target->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
        || other->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return (NULL == mgr) ? PUBNUB_ERR_NOT_INITIALIZED
                             : PUBNUB_ERR_INVALID_ARGUMENT;
    }
    ts = &mgr->sets[target->set_index];
    os = &mgr->sets[other->set_index];
    if (0 == ts->active || 0 == os->active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Cache other's count — we are only modifying target. */
    uint16_t other_count = os->count;

#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    size_t  ch_pos                                   = 0;
    size_t  gr_pos                                   = 0;
    uint8_t truncated                                = 0;
#else
    pubnub_allocator_provider_t* alloc = pn_context_allocator(ctx);
    /* Two-pass: first pass decrements + removes; second pass builds
     * strings. We track which indices became inactive. */
    uint16_t removed_indices[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    uint16_t removed_count = 0;
#endif

    for (i = 0; i < other_count; ++i) {
        uint16_t entry_idx = os->entry_indices[i];

        if (entry_idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
            continue;
        }

        /* Decrement active_count BEFORE remove_entry (which may free
         * the entry slot via pn_subscription_release if this set
         * held the last ref). */
        uint8_t was_active = 0;
        if (target->subscribed && mgr->entries[entry_idx].occupied
            && mgr->entries[entry_idx].active_count > 0) {
            mgr->entries[entry_idx].active_count--;
            was_active = 1;
        }

#if PUBNUB_CFG_NO_HEAP
        /* Capture name BEFORE remove_entry may free the entry. */
        if (was_active && 0 == mgr->entries[entry_idx].active_count) {
            truncated |= (uint8_t)pn_record_removed_entry(&mgr->entries[entry_idx],
                                                          removed_ch,
                                                          sizeof(removed_ch),
                                                          &ch_pos,
                                                          removed_gr,
                                                          sizeof(removed_gr),
                                                          &gr_pos);
        }
#else
        if (was_active && 0 == mgr->entries[entry_idx].active_count) {
            if (removed_count < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
                removed_indices[removed_count++] = entry_idx;
            }
        }
#endif

        /* remove_entry has no side effects on failure (entry not in
         * set means pn_subscription_release was never called). */
        if (!pn_subscription_set_remove_entry(mgr, target->set_index, entry_idx)) {
            /* Undo: entry was not in the target set. */
            if (was_active && mgr->entries[entry_idx].occupied) {
                mgr->entries[entry_idx].active_count++;
            }
#if PUBNUB_CFG_NO_HEAP
            /* Cannot un-record — leave the captured name in buffer.
             * Presence will send a harmless extra leave for this entry. */
#else
            if (removed_count > 0) {
                removed_count--;
            }
#endif
            continue;
        }

        if (was_active) {
            need_presence_left = 1;
        }
    }

    /* Emit a single SUBSCRIPTION_CHANGED if we deactivated entries. */
    if (need_presence_left) {
        subscriptions_empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);

        pn_subscribe_ee_event_t event;
        memset(&event, 0, sizeof(event));
        event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
        event.subscriptions_empty = subscriptions_empty;
        mgr->subscription_generation++;
        event.generation = mgr->subscription_generation;
        pn_subscribe_event_queue_push(&mgr->event_queue, &event);
    }

#if !PUBNUB_CFG_NO_HEAP
    /* Build heap strings while entries still valid (we captured
     * indices before remove, but active_count is already 0). The
     * two-pass helper checks occupied + active_count == 0. NOTE: for
     * entries whose last ref was held by the target set, remove_entry
     * freed them (occupied=0). The helper skips those — harmless
     * because presence for a fully-released entry is irrelevant. */
    char* heap_ch = NULL;
    char* heap_gr = NULL;
    if (need_presence_left && NULL != alloc && removed_count > 0) {
        heap_ch = pn_build_removed_string_alloc(
            mgr->entries, removed_indices, removed_count, PN_ENTITY_CHANNEL, alloc);
        heap_gr = pn_build_removed_string_alloc(mgr->entries,
                                                removed_indices,
                                                removed_count,
                                                PN_ENTITY_CHANNEL_GROUP,
                                                alloc);
    }
#endif

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Presence notification outside the lock (may do I/O). */
    if (need_presence_left) {
#if PUBNUB_CFG_NO_HEAP
        if (truncated) {
            PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                            PUBNUB_LOG_LEVEL_WARNING,
                            "Presence leave list truncated; some channels "
                            "may show stale occupancy until heartbeat "
                            "timeout");
        }
        pn_notify_presence_left(ctx, mgr, removed_ch, removed_gr, subscriptions_empty);
#else
        pn_notify_presence_left(ctx, mgr, heap_ch, heap_gr, subscriptions_empty);
        if (NULL != heap_ch) {
            PN_FREE(alloc, heap_ch);
        }
        if (NULL != heap_gr) {
            PN_FREE(alloc, heap_gr);
        }
#endif
    }

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscription_set_subscribe(pubnub_subscription_set_t set)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;

    if (NULL == set) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_context_t*           ctx      = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == mgr->sets[set->set_index].active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (set->subscribed) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK; /* Already active — no-op. */
    }

    set->subscribed = 1;

    /* Activate all entries in the set. */
    pn_subscription_set_data_t* s = &mgr->sets[set->set_index];
    uint16_t                    i;
    for (i = 0; i < s->count; ++i) {
        uint16_t idx = s->entry_indices[i];
        if (idx < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS && mgr->entries[idx].occupied) {
            mgr->entries[idx].active_count++;
        }
    }

    /* Feed SUBSCRIPTION_CHANGED into the event engine. */
    memset(&event, 0, sizeof(event));
    event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
    event.subscriptions_empty = 0;
    mgr->subscription_generation++;
    event.generation = mgr->subscription_generation;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    (void)pn_context_start_bg_thread(ctx);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE (outside lock). */
    pn_notify_presence_joined(ctx, mgr);

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscription_set_unsubscribe(pubnub_subscription_set_t set)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;
    uint8_t                 empty;

    if (NULL == set) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_context_t*           ctx      = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == mgr->sets[set->set_index].active) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (!set->subscribed) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK; /* Already inactive — no-op. */
    }

    set->subscribed = 0;

    /* Deactivate all entries in the set. */
    pn_subscription_set_data_t* s = &mgr->sets[set->set_index];
    uint16_t                    i;

#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    size_t  ch_pos                                   = 0;
    size_t  gr_pos                                   = 0;
    uint8_t truncated                                = 0;
#endif

    for (i = 0; i < s->count; ++i) {
        uint16_t idx = s->entry_indices[i];
        if (idx < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS && mgr->entries[idx].occupied
            && mgr->entries[idx].active_count > 0) {
            mgr->entries[idx].active_count--;

#if PUBNUB_CFG_NO_HEAP
            if (0 == mgr->entries[idx].active_count) {
                truncated |= (uint8_t)pn_record_removed_entry(&mgr->entries[idx],
                                                              removed_ch,
                                                              sizeof(removed_ch),
                                                              &ch_pos,
                                                              removed_gr,
                                                              sizeof(removed_gr),
                                                              &gr_pos);
            }
#endif
        }
    }

#if !PUBNUB_CFG_NO_HEAP
    /* Build heap strings — entries remain valid (no remove_entry). */
    pubnub_allocator_provider_t* alloc   = pn_context_allocator(ctx);
    char*                        heap_ch = NULL;
    char*                        heap_gr = NULL;
    if (NULL != alloc) {
        heap_ch = pn_build_removed_string_alloc(
            mgr->entries, s->entry_indices, s->count, PN_ENTITY_CHANNEL, alloc);
        heap_gr = pn_build_removed_string_alloc(
            mgr->entries, s->entry_indices, s->count, PN_ENTITY_CHANNEL_GROUP, alloc);
    }
#endif

    empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);

    memset(&event, 0, sizeof(event));
    event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
    event.subscriptions_empty = empty;
    mgr->subscription_generation++;
    event.generation = mgr->subscription_generation;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE (outside lock). */
#if PUBNUB_CFG_NO_HEAP
    if (truncated) {
        PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                        PUBNUB_LOG_LEVEL_WARNING,
                        "Presence leave list truncated; some channels "
                        "may show stale occupancy until heartbeat "
                        "timeout");
    }
    pn_notify_presence_left(ctx, mgr, removed_ch, removed_gr, empty);
#else
    pn_notify_presence_left(ctx, mgr, heap_ch, heap_gr, empty);
    if (NULL != heap_ch && NULL != alloc) {
        PN_FREE(alloc, heap_ch);
    }
    if (NULL != heap_gr && NULL != alloc) {
        PN_FREE(alloc, heap_gr);
    }
#endif

    return PUBNUB_OK;
}

void pubnub_subscription_set_destroy(pubnub_subscription_set_t set)
{
    pn_subscribe_manager_t* mgr;
    uint8_t                 need_presence_left  = 0;
    uint8_t                 subscriptions_empty = 0;

    if (NULL == set) {
        return;
    }

    pubnub_context_t*           ctx      = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return;
    }

    /* Unsubscribe first if the set was subscribed. */
    if (set->subscribed) {
        pn_subscription_set_data_t* s = &mgr->sets[set->set_index];
        uint16_t                    i;
        int                         had_active = 0;

#if PUBNUB_CFG_NO_HEAP
        char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
        char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
        size_t  ch_pos                                   = 0;
        size_t  gr_pos                                   = 0;
        uint8_t truncated                                = 0;
#endif

        for (i = 0; i < s->count; ++i) {
            uint16_t idx = s->entry_indices[i];
            if (idx < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS && mgr->entries[idx].occupied
                && mgr->entries[idx].active_count > 0) {
                mgr->entries[idx].active_count--;
                had_active = 1;

#if PUBNUB_CFG_NO_HEAP
                if (0 == mgr->entries[idx].active_count) {
                    truncated |=
                        (uint8_t)pn_record_removed_entry(&mgr->entries[idx],
                                                         removed_ch,
                                                         sizeof(removed_ch),
                                                         &ch_pos,
                                                         removed_gr,
                                                         sizeof(removed_gr),
                                                         &gr_pos);
                }
#endif
            }
        }

#if !PUBNUB_CFG_NO_HEAP
        /* Build heap strings while entries valid (before set_destroy
         * which releases refs and may free entries). */
        pubnub_allocator_provider_t* alloc   = pn_context_allocator(ctx);
        char*                        heap_ch = NULL;
        char*                        heap_gr = NULL;
        if (had_active && NULL != alloc) {
            heap_ch = pn_build_removed_string_alloc(
                mgr->entries, s->entry_indices, s->count, PN_ENTITY_CHANNEL, alloc);
            heap_gr = pn_build_removed_string_alloc(mgr->entries,
                                                    s->entry_indices,
                                                    s->count,
                                                    PN_ENTITY_CHANNEL_GROUP,
                                                    alloc);
        }
#endif

        if (had_active) {
            subscriptions_empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);
            pn_subscribe_ee_event_t event;
            memset(&event, 0, sizeof(event));
            event.type                = PN_SUB_EVENT_SUBSCRIPTION_CHANGED;
            event.subscriptions_empty = subscriptions_empty;
            mgr->subscription_generation++;
            event.generation = mgr->subscription_generation;
            pn_subscribe_event_queue_push(&mgr->event_queue, &event);
            need_presence_left = 1;
        }

        set->subscribed = 0;

        pn_untrack_subscription_set_locked(mgr, set);
        pn_subscription_set_destroy(mgr, set->set_index);

        pn_ctx_unlock(platform, lock);
        pn_context_wake_bg_thread(ctx);

        /* Presence notification outside the lock (may do I/O). */
        if (need_presence_left) {
#if PUBNUB_CFG_NO_HEAP
            if (truncated) {
                PUBNUB_LOG_TEXT(
                    pn_context_logger(ctx),
                    PUBNUB_LOG_LEVEL_WARNING,
                    "Presence leave list truncated; some channels "
                    "may show stale occupancy until heartbeat timeout");
            }
            pn_notify_presence_left(
                ctx, mgr, removed_ch, removed_gr, subscriptions_empty);
#else
            pn_notify_presence_left(ctx, mgr, heap_ch, heap_gr, subscriptions_empty);
            if (NULL != heap_ch && NULL != alloc) {
                PN_FREE(alloc, heap_ch);
            }
            if (NULL != heap_gr && NULL != alloc) {
                PN_FREE(alloc, heap_gr);
            }
#endif
        }
#if !PUBNUB_CFG_NO_HEAP
        else {
            /* No presence left needed — still free heap strings. */
            if (NULL != heap_ch && NULL != alloc) {
                PN_FREE(alloc, heap_ch);
            }
            if (NULL != heap_gr && NULL != alloc) {
                PN_FREE(alloc, heap_gr);
            }
        }
#endif
    } else {
        /* Not subscribed — just destroy the set. */
        pn_untrack_subscription_set_locked(mgr, set);
        pn_subscription_set_destroy(mgr, set->set_index);
        pn_ctx_unlock(platform, lock);
    }

    /* Free the handle. */
    const pubnub_config_t* config = pn_context_config(ctx);
    if (NULL != config && NULL != config->allocator) {
        PN_FREE(config->allocator, set);
    }
}

pubnub_listener_handle_t
pubnub_subscription_set_add_listener(pubnub_subscription_set_t set,
                                     const pubnub_subscribe_listener_t* listener)
{
    pn_subscribe_manager_t*  mgr;
    pubnub_listener_handle_t result = PUBNUB_LISTENER_HANDLE_INVALID;

    if (NULL == set || NULL == listener) {
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(set->ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(set->ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(set->ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pn_listener_handle_t handle =
        pn_subscribe_listener_add_to_set(mgr, listener, set->set_index);
    if (PN_LISTENER_HANDLE_INVALID != handle) {
        result = (pubnub_listener_handle_t)handle;
    }

    pn_ctx_unlock(platform, lock);

    return result;
}

void pubnub_subscription_set_remove_listener(pubnub_subscription_set_t set,
                                             pubnub_listener_handle_t  handle)
{
    pn_subscribe_manager_t*     mgr;
    pn_listener_handle_t        h;
    pubnub_platform_provider_t* platform;
    void*                       lock_mem;

    if (NULL == set) {
        return;
    }
    if (PUBNUB_LISTENER_HANDLE_INVALID == handle) {
        return;
    }

    h        = (pn_listener_handle_t)handle;
    platform = pn_context_platform(set->ctx);
    lock_mem = pn_context_mutex_mem(set->ctx);

    pn_ctx_lock(platform, lock_mem);
    mgr = pn_subscribe_manager_from_ctx(set->ctx);
    if (NULL != mgr) {
        pn_subscribe_listener_remove(mgr, h);
    }

    pn_ctx_unlock(platform, lock_mem);
}

pubnub_res_t pubnub_subscribe_disconnect(pubnub_context_t* ctx)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;

    if (NULL == ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    memset(&event, 0, sizeof(event));
    event.type = PN_SUB_EVENT_DISCONNECT;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE (outside lock). */
    pn_notify_presence_disconnect(ctx);

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscribe_reconnect(pubnub_context_t* ctx)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;

    if (NULL == ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    memset(&event, 0, sizeof(event));
    event.type = PN_SUB_EVENT_RECONNECT;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE (outside lock). */
    pn_notify_presence_reconnect(ctx);

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscribe_restore(pubnub_context_t*  ctx,
                                      pubnub_timetoken_t timetoken)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;

    if (NULL == ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_ERR_NOT_INITIALIZED;
    }

    if (NULL != timetoken.ptr && 0 < timetoken.len) {
        size_t len = timetoken.len;
        if (len >= sizeof(mgr->cursor.timetoken)) {
            len = sizeof(mgr->cursor.timetoken) - 1;
        }
        memcpy(mgr->cursor.timetoken, timetoken.ptr, len);
        mgr->cursor.timetoken[len] = '\0';
        mgr->cursor.timetoken_len  = (uint8_t)len;
        /* Mark that the handshake should keep this timetoken and only
         * adopt the region from the server's handshake response. */
        mgr->restore_cursor_valid = 1;
    }

    memset(&event, 0, sizeof(event));
    event.type                = PN_SUB_EVENT_SUBSCRIPTION_RESTORED;
    event.subscriptions_empty = (uint8_t)pn_subscribe_subscriptions_empty(mgr);
    mgr->subscription_generation++;
    event.generation = mgr->subscription_generation;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE (outside lock). */
    pn_notify_presence_reconnect(ctx);

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscribe_unsubscribe_all(pubnub_context_t* ctx)
{
    pn_subscribe_manager_t* mgr;
    pn_subscribe_ee_event_t event;

    if (NULL == ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_OK;
    }

    memset(&event, 0, sizeof(event));
    event.type                = PN_SUB_EVENT_UNSUBSCRIBE_ALL;
    event.subscriptions_empty = 1;
    pn_subscribe_event_queue_push(&mgr->event_queue, &event);

    pn_ctx_unlock(platform, lock);
    pn_context_wake_bg_thread(ctx);

    /* Bridge to presence EE — all channels removed (outside lock).
     * Pass NULL for removed strings — pn_presence_left_all handles
     * the full leave set internally. */
    pn_notify_presence_left(ctx, mgr, NULL, NULL, 1);

    return PUBNUB_OK;
}

pubnub_res_t pubnub_subscriptions(pubnub_context_t*      ctx,
                                  pubnub_subscription_t* out,
                                  size_t                 max_count,
                                  size_t*                out_count)
{
    pn_subscribe_manager_t* mgr;
    size_t                  count = 0;
    uint16_t                i;
    pubnub_res_t            rc = PUBNUB_OK;

    if (NULL == ctx || NULL == out) {
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_OK;
    }

    for (i = 0; i < mgr->tracked_sub_count; ++i) {
        if (NULL == mgr->tracked_subs[i]) {
            continue;
        }
        if (!mgr->tracked_subs[i]->subscribed) {
            continue;
        }
        if (count < max_count) {
            out[count] = mgr->tracked_subs[i];
        } else {
            rc = PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        count++;
    }

    pn_ctx_unlock(platform, lock);

    if (NULL != out_count) {
        *out_count = count;
    }

    return rc;
}

pubnub_res_t pubnub_subscription_sets(pubnub_context_t*          ctx,
                                      pubnub_subscription_set_t* out,
                                      size_t                     max_count,
                                      size_t*                    out_count)
{
    pn_subscribe_manager_t* mgr;
    size_t                  count = 0;
    uint16_t                i;
    pubnub_res_t            rc = PUBNUB_OK;

    if (NULL == ctx || NULL == out) {
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_OK;
    }

    for (i = 0; i < mgr->tracked_set_count; ++i) {
        if (NULL == mgr->tracked_sets[i]) {
            continue;
        }
        if (!mgr->tracked_sets[i]->subscribed) {
            continue;
        }
        if (count < max_count) {
            out[count] = mgr->tracked_sets[i];
        } else {
            rc = PUBNUB_ERR_BUFFER_TOO_SMALL;
        }
        count++;
    }

    pn_ctx_unlock(platform, lock);

    if (NULL != out_count) {
        *out_count = count;
    }

    return rc;
}

pubnub_res_t pubnub_subscription_set_subscriptions(pubnub_subscription_set_t set,
                                                   pubnub_subscription_t* out,
                                                   size_t  max_count,
                                                   size_t* out_count)
{
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* s;
    size_t                      count = 0;
    uint16_t                    i;
    uint16_t                    j;
    pubnub_res_t                rc = PUBNUB_OK;

    if (NULL == set || NULL == out) {
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_context_t*           ctx      = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_OK;
    }

    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    s = &mgr->sets[set->set_index];
    if (0 == s->active) {
        pn_ctx_unlock(platform, lock);
        if (NULL != out_count) {
            *out_count = 0;
        }
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* For each entry in the set, find tracked subscription handles
     * that reference that entry. Return all matches regardless of
     * the individual subscription's subscribed flag, because the set
     * manages subscription state at the set level. */
    for (i = 0; i < s->count; ++i) {
        uint16_t entry_idx = s->entry_indices[i];
        for (j = 0; j < mgr->tracked_sub_count; ++j) {
            if (NULL == mgr->tracked_subs[j]) {
                continue;
            }
            if (mgr->tracked_subs[j]->entry_index != entry_idx) {
                continue;
            }
            if (count < max_count) {
                out[count] = mgr->tracked_subs[j];
            } else {
                rc = PUBNUB_ERR_BUFFER_TOO_SMALL;
            }
            count++;
        }
    }

    pn_ctx_unlock(platform, lock);

    if (NULL != out_count) {
        *out_count = count;
    }

    return rc;
}

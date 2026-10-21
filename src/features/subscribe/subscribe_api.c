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

typedef enum pn_sub_limit {
    PN_SUB_LIMIT_ENTITIES,
    PN_SUB_LIMIT_SUBSCRIPTIONS,
    PN_SUB_LIMIT_SETS,
    PN_SUB_LIMIT_SET_MEMBERS,
    PN_SUB_LIMIT_LISTENERS
} pn_sub_limit_t;

/**
 * @brief Log which compile-time capacity limit rejected a registration.
 *
 * Call only after the context lock is released: the logger provider is
 * another subsystem and must not run under the lock. Logs at WARNING
 * because the failure is returned to the application.
 */
static void pn_log_capacity_limit(pubnub_context_t* ctx, pn_sub_limit_t limit)
{
#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
    switch (limit) {
    case PN_SUB_LIMIT_ENTITIES:
        PN_LOG_WARN(ctx,
                    "subscribe entity limit reached "
                    "(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS=%u); raise it at "
                    "build time",
                    (unsigned)PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS);
        break;
    case PN_SUB_LIMIT_SUBSCRIPTIONS:
        PN_LOG_WARN(ctx,
                    "subscription handle limit reached "
                    "(PUBNUB_CFG_MAX_SUBSCRIPTIONS=%u); raise it at build "
                    "time",
                    (unsigned)PUBNUB_CFG_MAX_SUBSCRIPTIONS);
        break;
    case PN_SUB_LIMIT_SETS:
        PN_LOG_WARN(ctx,
                    "subscription set limit reached "
                    "(PUBNUB_CFG_MAX_SUBSCRIPTION_SETS=%u); raise it at "
                    "build time",
                    (unsigned)PUBNUB_CFG_MAX_SUBSCRIPTION_SETS);
        break;
    case PN_SUB_LIMIT_SET_MEMBERS:
        PN_LOG_WARN(ctx,
                    "subscription set member limit reached "
                    "(PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET=%u); raise it "
                    "at build time",
                    (unsigned)PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET);
        break;
    case PN_SUB_LIMIT_LISTENERS:
        PN_LOG_WARN(ctx,
                    "subscribe listener limit reached "
                    "(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS=%u); raise it at "
                    "build time",
                    (unsigned)PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
        break;
    default: break;
    }
#else
    (void)ctx;
    (void)limit;
#endif
}

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
 * @brief Record removed entry into channel/group buffers by entity type.
 *
 * Presence-only entities (`*-pnpres`) are skipped: they never appear in
 * heartbeat/leave lists.
 *
 * @param entry      Deactivated subscription entry (borrowed, non-NULL).
 * @param removed_ch Channel removal buffer.
 * @param ch_size    Channel buffer capacity.
 * @param ch_pos     In/out write offset into @p removed_ch.
 * @param removed_gr Group removal buffer.
 * @param gr_size    Group buffer capacity.
 * @param gr_pos     In/out write offset into @p removed_gr.
 * @retval 0 Recorded (or skipped presence-only entity).
 * @retval 1 The entry name did not fit (truncation).
 */
static int pn_record_removed_entry(pn_subscription_entry_t* entry,
                                   char*                    removed_ch,
                                   size_t                   ch_size,
                                   size_t*                  ch_pos,
                                   char*                    removed_gr,
                                   size_t                   gr_size,
                                   size_t*                  gr_pos)
{
    /* Presence-only entities never appear in heartbeat/leave lists. */
    if (pn_pnpres_has_suffix(entry->name, entry->name_len)) {
        return 0;
    }
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
        if (pn_pnpres_has_suffix(entries[idx].name, entries[idx].name_len)) {
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
        if (pn_pnpres_has_suffix(entries[idx].name, entries[idx].name_len)) {
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

    /* Presence-only entities (`*-pnpres`) never appear in leave lists. */
    if (pn_pnpres_has_suffix(entry->name, entry->name_len)) {
        return 0;
    }
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
    /* Presence-only entities (`*-pnpres`) never appear in leave lists. */
    if (pn_pnpres_has_suffix(entry->name, entry->name_len)) {
        return;
    }
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
        uint8_t table_full = 0;
#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0
        /* The scan only feeds the log line; skip it when logging is off. */
        table_full =
            pn_subscription_entity_table_full(mgr, name, name_len, entity_type);
#endif
        pn_ctx_unlock(platform, lock);
        if (table_full) {
            pn_log_capacity_limit(ctx, PN_SUB_LIMIT_ENTITIES);
        }
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
        return PUBNUB_SUBSCRIPTION_INVALID;
    }

    pubnub_context_t*           ctx      = entity->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_INVALID;
    }

    /* Acquire a new ref on the same registry entry so the
     * subscription holds its own independent reference. */
    if (entity->entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_INVALID;
    }
    if (0 == mgr->entries[entity->entry_index].occupied) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_INVALID;
    }
    if (UINT16_MAX == mgr->entries[entity->entry_index].ref_count) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_SUBSCRIPTION_INVALID;
    }

    mgr->entries[entity->entry_index].ref_count++;
    entry_idx = entity->entry_index;

    /* Guard: tracking array must have room before we commit. */
    if (mgr->tracked_sub_count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        pn_subscription_release(mgr, entry_idx);
        pn_ctx_unlock(platform, lock);
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_SUBSCRIPTIONS);
        return PUBNUB_SUBSCRIPTION_INVALID;
    }

    /* Presence is a per-handle property (not the shared entry); metadata
     * entities ignore it. */
    uint8_t sub_with_presence = 0;
    if (NULL != opts && opts->with_presence) {
        pn_subscribe_entity_type_t etype = mgr->entries[entry_idx].entity_type;
        if (PN_ENTITY_CHANNEL == etype || PN_ENTITY_CHANNEL_GROUP == etype) {
            sub_with_presence = 1;
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
        return PUBNUB_SUBSCRIPTION_INVALID;
    }

    sub->ctx                 = ctx;
    sub->entry_index         = entry_idx;
    sub->slot_index          = UINT16_MAX;
    sub->ref_count           = 1; /* creator's reference */
    sub->subscribed          = 0;
    sub->with_presence       = sub_with_presence;
    sub->subscribed_set_refs = 0;

    /* Register in the stable slot table for introspection and set membership. */
    if (UINT16_MAX == pn_track_subscription(mgr, sub)) {
        PN_FREE(alloc, sub);
        pn_subscription_release(mgr, entry_idx);
        pn_ctx_unlock(platform, lock);
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_SUBSCRIPTIONS);
        return PUBNUB_SUBSCRIPTION_INVALID;
    }

    pn_ctx_unlock(platform, lock);

    return sub;
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
            if (sub->with_presence) {
                (void)pn_subscription_entry_presence_adjust(mgr, sub->entry_index, 0);
            }

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

        /* Detach listeners before the ref drops so a destroyed handle stops
         * firing even if a set keeps it alive; read the slot before the unref
         * below may free the handle. Deferred-removal safe inside a callback. */
        if (sub->slot_index < PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
            pn_subscribe_listener_remove_for_slot(mgr, sub->slot_index);
        }

        /* Drop the caller's reference; the handle is freed only when the last
         * reference drops. A handle still held by a set stays alive. */
        pn_subscription_handle_unref(mgr, sub);
    } else {
        /* Manager already torn down — free the caller's handle directly. */
        const pubnub_config_t* config = pn_context_config(ctx);
        if (NULL != config && NULL != config->allocator) {
            PN_FREE(config->allocator, sub);
        }
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
    if (sub->with_presence) {
        (void)pn_subscription_entry_presence_adjust(mgr, sub->entry_index, 1);
    }

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
    if (sub->with_presence) {
        (void)pn_subscription_entry_presence_adjust(mgr, sub->entry_index, 0);
    }

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
    pubnub_listener_handle_t result    = PUBNUB_LISTENER_HANDLE_INVALID;
    uint8_t                  limit_hit = 0;

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
    } else if (mgr->listener_count >= PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS) {
        limit_hit = 1;
    }

    pn_ctx_unlock(platform, lock);
    if (limit_hit) {
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_LISTENERS);
    }

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
    pubnub_listener_handle_t result    = PUBNUB_LISTENER_HANDLE_INVALID;
    uint8_t                  limit_hit = 0;
    pubnub_context_t*        ctx;

    if (NULL == sub || NULL == listener) {
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    ctx                                  = sub->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pn_listener_handle_t handle =
        pn_subscribe_listener_add_bound(mgr, listener, sub->slot_index);
    if (PN_LISTENER_HANDLE_INVALID != handle) {
        result = (pubnub_listener_handle_t)handle;
    } else if (sub->slot_index < PUBNUB_CFG_MAX_SUBSCRIPTIONS
               && NULL != mgr->tracked_subs[sub->slot_index]
               && mgr->listener_count >= PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS) {
        /* The binding check precedes the table scan in the callee, so a
         * stale handle fails without being a capacity problem. */
        limit_hit = 1;
    }

    pn_ctx_unlock(platform, lock);
    if (limit_hit) {
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_LISTENERS);
    }

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
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_SETS);
        return PUBNUB_SUBSCRIPTION_SET_INVALID;
    }

    /* Guard: tracking array must have room before we commit. */
    if (mgr->tracked_set_count >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
        pn_subscription_set_destroy(mgr, idx);
        pn_ctx_unlock(platform, lock);
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_SETS);
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
    if (mgr->tracked_set_count < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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
    uint8_t                     presence_flip = 0;

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

    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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

    {
        /* Capture prior members so a second member of the same entry does not
         * add a second active share. */
        uint16_t prior_members =
            pn_subscription_set_member_entry_count(mgr, set->set_index, entry_idx);
        uint16_t prior_presence = pn_subscription_set_member_entry_presence_count(
            mgr, set->set_index, entry_idx);
        int added = pn_subscription_set_add_member(mgr, set->set_index, sub);
        if (0 == added) {
            /* Same handle already a member — no-op. */
            pn_ctx_unlock(platform, lock);
            return PUBNUB_OK;
        }
        if (added < 0) {
            /* -1 also covers reference saturation and stale handles; only
             * an exhausted member table is a configured-limit failure. */
            const uint8_t member_limit =
                (s->count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET
                 && sub->slot_index < PUBNUB_CFG_MAX_SUBSCRIPTIONS)
                    ? 1
                    : 0;
            pn_ctx_unlock(platform, lock);
            if (member_limit) {
                pn_log_capacity_limit(ctx, PN_SUB_LIMIT_SET_MEMBERS);
                return PUBNUB_ERR_LIMIT_REACHED;
            }
            return PUBNUB_ERR_QUEUE_FULL;
        }

        /* Auto-activate: if the set is already subscribed and this is the
         * first member resolving to the entry, contribute one active share. */
        if (set->subscribed && 0 == prior_members) {
            mgr->entries[entry_idx].active_count++;
            need_activate = 1;
        }

        /* Raise the entry's presence share when this presence-requesting
         * member is its first; the flip restarts the long-poll. */
        if (set->subscribed && sub->with_presence && 0 == prior_presence) {
            if (pn_subscription_entry_presence_adjust(mgr, entry_idx, 1)) {
                presence_flip = 1;
            }
        }
    }

    if (need_activate || presence_flip) {
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

/**
 * @brief All-or-nothing capacity/reference pre-check for a set merge.
 *
 * Verifies before any mutation that every new source handle has ref-count
 * headroom and the member count stays within the per-set cap. Caller must
 * hold the context lock.
 *
 * @param mgr Manager (non-NULL).
 * @param ts  Target set data (non-NULL).
 * @param os  Source set data (non-NULL).
 * @param out_member_limit Set to 1 when the failure is the per-set member cap
 *        (left untouched otherwise; non-NULL, caller zero-initializes).
 * @return PUBNUB_OK when the whole merge fits, PUBNUB_ERR_LIMIT_REACHED
 *         for the member cap, PUBNUB_ERR_QUEUE_FULL for reference saturation.
 */
static pubnub_res_t pn_set_merge_precheck_locked(const pn_subscribe_manager_t* mgr,
                                                 const pn_subscription_set_data_t* ts,
                                                 const pn_subscription_set_data_t* os,
                                                 uint8_t* out_member_limit)
{
    uint16_t new_members = 0;
    uint16_t i;

    for (i = 0; i < os->count; ++i) {
        uint16_t                 slot = os->member_slots[i];
        const pn_subscription_t* sub;
        uint16_t                 j;
        uint8_t                  already = 0;

        if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS
            || NULL == mgr->tracked_subs[slot]) {
            continue;
        }
        sub = mgr->tracked_subs[slot];
        if (sub->entry_index >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
            || 0 == mgr->entries[sub->entry_index].occupied) {
            continue;
        }

        for (j = 0; j < ts->count; ++j) {
            if (ts->member_slots[j] == slot) {
                already = 1;
                break;
            }
        }
        if (already) {
            continue; /* already a target member — adds no new membership */
        }

        if (UINT16_MAX == sub->ref_count) {
            return PUBNUB_ERR_QUEUE_FULL;
        }
        new_members++;
    }

    if ((uint32_t)ts->count + new_members > PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
        *out_member_limit = 1;
        return PUBNUB_ERR_LIMIT_REACHED;
    }

    return PUBNUB_OK;
}

/**
 * @brief Resolve and validate the target and source set slots of a merge.
 *
 * @param ctx    Owning context (non-NULL).
 * @param target Target set handle (non-NULL).
 * @param other  Source set handle (non-NULL).
 * @param out_mgr Receives the subscribe manager on success.
 * @param out_ts  Receives the target set data on success.
 * @param out_os  Receives the source set data on success.
 * @return PUBNUB_OK, PUBNUB_ERR_NOT_INITIALIZED when the subscribe manager is
 *         absent, or PUBNUB_ERR_INVALID_ARGUMENT for a stale or inactive set.
 * @note Caller must hold the context lock. Outputs are valid only on PUBNUB_OK.
 */
static pubnub_res_t pn_set_merge_resolve_locked(pubnub_context_t* ctx,
                                                pubnub_subscription_set_t target,
                                                pubnub_subscription_set_t other,
                                                pn_subscribe_manager_t** out_mgr,
                                                pn_subscription_set_data_t** out_ts,
                                                pn_subscription_set_data_t** out_os)
{
    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);

    if (NULL == mgr) {
        return PUBNUB_ERR_NOT_INITIALIZED;
    }
    if (target->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS
        || 0 == mgr->sets[target->set_index].active) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (other->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS
        || 0 == mgr->sets[other->set_index].active) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_mgr = mgr;
    *out_ts  = &mgr->sets[target->set_index];
    *out_os  = &mgr->sets[other->set_index];
    return PUBNUB_OK;
}

/**
 * @brief Copy every live member handle of a source set into the target set.
 *
 * Members are deduplicated by handle; a handle resolving to an entry the
 * target already covers adds no second active share. Callers must run the
 * capacity pre-check first so no add below can fail on capacity.
 *
 * @param mgr    Manager (non-NULL).
 * @param target Target set handle (non-NULL).
 * @param os     Source set data (non-NULL).
 * @param out_need_activate Set to 1 when an entry gained an active share.
 * @param out_presence_flip Set to 1 when an entry's wire presence flipped on.
 * @return PUBNUB_OK, or PUBNUB_ERR_QUEUE_FULL when a member add is rejected.
 * @note Caller must hold the context lock. Outputs are only ever raised to 1;
 *       the caller zero-initializes them.
 */
static pubnub_res_t pn_set_merge_members_locked(pn_subscribe_manager_t* mgr,
                                                pubnub_subscription_set_t target,
                                                const pn_subscription_set_data_t* os,
                                                uint8_t* out_need_activate,
                                                uint8_t* out_presence_flip)
{
    uint16_t i;

    for (i = 0; i < os->count; ++i) {
        uint16_t           slot = os->member_slots[i];
        pn_subscription_t* sub;
        uint16_t           entry_idx;
        uint16_t           prior_members;
        uint16_t           prior_presence;
        int                added;

        if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS
            || NULL == mgr->tracked_subs[slot]) {
            continue;
        }
        sub       = mgr->tracked_subs[slot];
        entry_idx = sub->entry_index;
        if (entry_idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
            || 0 == mgr->entries[entry_idx].occupied) {
            continue;
        }

        prior_members = pn_subscription_set_member_entry_count(
            mgr, target->set_index, entry_idx);
        prior_presence = pn_subscription_set_member_entry_presence_count(
            mgr, target->set_index, entry_idx);
        added = pn_subscription_set_add_member(mgr, target->set_index, sub);
        if (0 == added) {
            continue; /* same handle already a target member */
        }
        if (added < 0) {
            return PUBNUB_ERR_QUEUE_FULL;
        }

        if (target->subscribed && 0 == prior_members) {
            mgr->entries[entry_idx].active_count++;
            *out_need_activate = 1;
        }

        /* Target gains one presence share when this incoming presence member
         * is the first presence source resolving to the entry. */
        if (target->subscribed && sub->with_presence && 0 == prior_presence) {
            if (pn_subscription_entry_presence_adjust(mgr, entry_idx, 1)) {
                *out_presence_flip = 1;
            }
        }
    }

    return PUBNUB_OK;
}

pubnub_res_t
pubnub_subscription_set_add_subscription_set(pubnub_subscription_set_t target,
                                             pubnub_subscription_set_t other)
{
    pn_subscribe_manager_t*     mgr = NULL;
    pn_subscription_set_data_t* ts  = NULL;
    pn_subscription_set_data_t* os  = NULL;
    pubnub_res_t                res;
    uint8_t                     member_limit  = 0;
    uint8_t                     need_activate = 0;
    uint8_t                     presence_flip = 0;

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

    res = pn_set_merge_resolve_locked(ctx, target, other, &mgr, &ts, &os);
    if (PUBNUB_OK != res) {
        pn_ctx_unlock(platform, lock);
        return res;
    }

    /* All-or-nothing pre-check: verify the merge fits before mutating so the
     * member copy cannot fail midway; on failure the target is left untouched. */
    res = pn_set_merge_precheck_locked(mgr, ts, os, &member_limit);
    if (PUBNUB_OK != res) {
        pn_ctx_unlock(platform, lock);
        if (member_limit) {
            pn_log_capacity_limit(ctx, PN_SUB_LIMIT_SET_MEMBERS);
        }
        return res;
    }

    res = pn_set_merge_members_locked(mgr, target, os, &need_activate, &presence_flip);
    if (PUBNUB_OK != res) {
        pn_ctx_unlock(platform, lock);
        return res;
    }

    /* Emit one SUBSCRIPTION_CHANGED if any entry was activated or had its
     * -pnpres membership changed. */
    if (need_activate || presence_flip) {
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

    /* Presence notification outside the lock (may do I/O). A presence-only
     * flip changes only the -pnpres channel, so it drives no join. */
    if (need_activate) {
        pn_notify_presence_joined(ctx, mgr);
    }

    return PUBNUB_OK;
}

/** @brief Drop a set's -pnpres share for an entry when its last subscribed
 *         presence member leaves.
 *
 *  @param mgr            Subscribe manager.
 *  @param entry_idx      Entry the departing handle resolves to.
 *  @param sub            Departing member handle.
 *  @param set_subscribed Non-zero when the owning set is on the wire.
 *  @param prior_presence Member presence count for the entry, captured before
 *                        removal.
 *  @return 1 when the entry's derived wire-presence cache flipped off,
 *          0 otherwise.
 *  @note Caller must hold the context lock. Call before the handle unref so the
 *        entry is still occupied.
 */
static uint8_t pn_set_member_drop_presence_locked(pn_subscribe_manager_t* mgr,
                                                  uint16_t entry_idx,
                                                  const pn_subscription_t* sub,
                                                  uint8_t  set_subscribed,
                                                  uint16_t prior_presence)
{
    if (set_subscribed && sub->with_presence && 1 == prior_presence
        && mgr->entries[entry_idx].occupied) {
        return (uint8_t)pn_subscription_entry_presence_adjust(mgr, entry_idx, 0);
    }
    return 0;
}

pubnub_res_t pubnub_subscription_set_remove_subscription(pubnub_subscription_set_t set,
                                                         pubnub_subscription_t sub)
{
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* s;
    uint16_t                    entry_idx;
    uint8_t                     need_presence_left  = 0;
    uint8_t                     presence_flip       = 0;
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

    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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

#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    uint8_t truncated                                = 0;
#else
    char*                        removed_ch = NULL;
    char*                        removed_gr = NULL;
    pubnub_allocator_provider_t* alloc      = NULL;
#endif

    {
        /* Capture before removal so the set's active share drops only when
         * the entry's last member leaves. */
        uint16_t prior_members =
            pn_subscription_set_member_entry_count(mgr, set->set_index, entry_idx);
        uint16_t prior_presence = pn_subscription_set_member_entry_presence_count(
            mgr, set->set_index, entry_idx);

        /* Returns 0 when this handle is not a member of the set. */
        if (!pn_subscription_set_remove_member_slot(
                mgr, set->set_index, sub->slot_index)) {
            pn_ctx_unlock(platform, lock);
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }

        /* Adjust before the handle unref below so the entry is still occupied. */
        presence_flip = pn_set_member_drop_presence_locked(
            mgr, entry_idx, sub, set->subscribed, prior_presence);

        if (set->subscribed && 1 == prior_members && mgr->entries[entry_idx].occupied
            && mgr->entries[entry_idx].active_count > 0) {
            mgr->entries[entry_idx].active_count--;
            need_presence_left = 1;

            /* Copy name BEFORE handle unref (which may free the entry). */
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

        /* Drop the set's reference on the member handle. */
        pn_subscription_handle_unref(mgr, sub);
    }

    if (need_presence_left || presence_flip) {
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

    /* Presence notification outside the lock (may do I/O). A presence-only
     * flip changes only the -pnpres channel, so it drives no leave. */
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
    uint8_t                     presence_flip       = 0;
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
    if (NULL == mgr || target->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS
        || other->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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
    /* Registry entry indices (not handle slots) that became inactive. */
    uint16_t removed_indices[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    uint16_t removed_count = 0;
#endif

    for (i = 0; i < other_count; ++i) {
        uint16_t           slot = os->member_slots[i];
        pn_subscription_t* sub;
        uint16_t           entry_idx;
        uint16_t           prior_members;
        uint16_t           prior_presence;
        uint8_t            was_active = 0;

        if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS
            || NULL == mgr->tracked_subs[slot]) {
            continue;
        }
        sub       = mgr->tracked_subs[slot];
        entry_idx = sub->entry_index;
        if (entry_idx >= PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
            continue;
        }

        /* Capture before removal so target's active share drops only when its
         * last member for the entry leaves. */
        prior_members = pn_subscription_set_member_entry_count(
            mgr, target->set_index, entry_idx);
        prior_presence = pn_subscription_set_member_entry_presence_count(
            mgr, target->set_index, entry_idx);
        if (!pn_subscription_set_remove_member_slot(
                mgr, target->set_index, sub->slot_index)) {
            continue; /* this handle is not a member of target */
        }

        /* Adjust before the handle unref below so the entry is still occupied. */
        presence_flip |= pn_set_member_drop_presence_locked(
            mgr, entry_idx, sub, target->subscribed, prior_presence);

        if (target->subscribed && 1 == prior_members && mgr->entries[entry_idx].occupied
            && mgr->entries[entry_idx].active_count > 0) {
            mgr->entries[entry_idx].active_count--;
            was_active = 1;

            /* Capture name BEFORE handle unref (which may free the entry). */
            if (0 == mgr->entries[entry_idx].active_count) {
#if PUBNUB_CFG_NO_HEAP
                truncated |=
                    (uint8_t)pn_record_removed_entry(&mgr->entries[entry_idx],
                                                     removed_ch,
                                                     sizeof(removed_ch),
                                                     &ch_pos,
                                                     removed_gr,
                                                     sizeof(removed_gr),
                                                     &gr_pos);
#else
                if (removed_count < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS) {
                    removed_indices[removed_count++] = entry_idx;
                }
#endif
            }
        }

        /* other keeps its own reference, so a shared handle is not freed here. */
        pn_subscription_handle_unref(mgr, sub);

        if (was_active) {
            need_presence_left = 1;
        }
    }

    /* Emit one SUBSCRIPTION_CHANGED if any entry was deactivated or had its
     * -pnpres membership changed. */
    if (need_presence_left || presence_flip) {
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
    /* Build heap strings while entries are still valid: every handle here is
     * a member of other, so the entry stays occupied (active_count 0). */
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
    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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

    set->subscribed                      = 1;
    mgr->sets[set->set_index].subscribed = 1;

    /* Grant every member handle a delivery share so its per-handle listeners
     * fire while this set is subscribed. One share per member (handles are
     * deduplicated in the set); saturate rather than wrap on the unreachable
     * overflow (ref_count saturates first at membership time). */
    {
        const pn_subscription_set_data_t* sd = &mgr->sets[set->set_index];
        uint16_t                          m;
        for (m = 0; m < sd->count; ++m) {
            uint16_t slot = sd->member_slots[m];
            if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS
                && NULL != mgr->tracked_subs[slot]
                && UINT16_MAX != mgr->tracked_subs[slot]->subscribed_set_refs) {
                mgr->tracked_subs[slot]->subscribed_set_refs++;
            }
        }
    }

    /* Activate each distinct entry once: the set contributes one active share
     * even when several member handles resolve to the same entry. */
    {
        /* Distinct registry entry indices. */
        uint16_t distinct[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
        uint16_t dn;
        uint16_t i;
        dn = pn_subscription_set_distinct_entries(
            mgr, set->set_index, distinct, PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS);
        for (i = 0; i < dn; ++i) {
            uint16_t idx = distinct[i];
            if (idx < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
                && mgr->entries[idx].occupied) {
                mgr->entries[idx].active_count++;
                /* One presence share per entry with a presence-requesting
                 * member. */
                if (pn_subscription_set_member_entry_presence_count(
                        mgr, set->set_index, idx)
                    > 0) {
                    (void)pn_subscription_entry_presence_adjust(mgr, idx, 1);
                }
            }
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
    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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

    set->subscribed                      = 0;
    mgr->sets[set->set_index].subscribed = 0;

    /* Revoke each member's delivery share granted at subscribe time. */
    {
        const pn_subscription_set_data_t* sd = &mgr->sets[set->set_index];
        uint16_t                          m;
        for (m = 0; m < sd->count; ++m) {
            uint16_t slot = sd->member_slots[m];
            if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS
                && NULL != mgr->tracked_subs[slot]
                && mgr->tracked_subs[slot]->subscribed_set_refs > 0) {
                mgr->tracked_subs[slot]->subscribed_set_refs--;
            }
        }
    }

    /* Deactivate each distinct entry once; distinct[] holds registry entry
     * indices. */
    uint16_t distinct[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
    uint16_t dn;
    uint16_t i;

#if PUBNUB_CFG_NO_HEAP
    char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
    size_t  ch_pos                                   = 0;
    size_t  gr_pos                                   = 0;
    uint8_t truncated                                = 0;
#endif

    dn = pn_subscription_set_distinct_entries(
        mgr, set->set_index, distinct, PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS);
    for (i = 0; i < dn; ++i) {
        uint16_t idx = distinct[i];
        if (idx < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS && mgr->entries[idx].occupied
            && mgr->entries[idx].active_count > 0) {
            mgr->entries[idx].active_count--;

            /* Drop the set's presence share for each entry it contributed to. */
            if (pn_subscription_set_member_entry_presence_count(
                    mgr, set->set_index, idx)
                > 0) {
                (void)pn_subscription_entry_presence_adjust(mgr, idx, 0);
            }

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
    /* Build heap strings over the distinct entries (still valid — no
     * handle unref here). */
    pubnub_allocator_provider_t* alloc   = pn_context_allocator(ctx);
    char*                        heap_ch = NULL;
    char*                        heap_gr = NULL;
    if (NULL != alloc) {
        heap_ch = pn_build_removed_string_alloc(
            mgr->entries, distinct, dn, PN_ENTITY_CHANNEL, alloc);
        heap_gr = pn_build_removed_string_alloc(
            mgr->entries, distinct, dn, PN_ENTITY_CHANNEL_GROUP, alloc);
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
        /* distinct[] holds registry entry indices. */
        uint16_t distinct[PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS];
        uint16_t dn;
        uint16_t i;
        int      had_active = 0;

#if PUBNUB_CFG_NO_HEAP
        char    removed_ch[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
        char    removed_gr[PUBNUB_CFG_HTTP_SCRATCH_SIZE] = {0};
        size_t  ch_pos                                   = 0;
        size_t  gr_pos                                   = 0;
        uint8_t truncated                                = 0;
#endif

        /* Capture distinct entries BEFORE set_destroy drops member handle
         * references (which may free handles and release entries). */
        dn = pn_subscription_set_distinct_entries(
            mgr, set->set_index, distinct, PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS);
        for (i = 0; i < dn; ++i) {
            uint16_t idx = distinct[i];
            if (idx < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS && mgr->entries[idx].occupied
                && mgr->entries[idx].active_count > 0) {
                mgr->entries[idx].active_count--;
                had_active = 1;

                /* Drop the set's presence share for each entry it contributed
                 * to, before member handles are freed. */
                if (pn_subscription_set_member_entry_presence_count(
                        mgr, set->set_index, idx)
                    > 0) {
                    (void)pn_subscription_entry_presence_adjust(mgr, idx, 0);
                }

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
        /* Build heap strings while entries valid (before set_destroy). */
        pubnub_allocator_provider_t* alloc   = pn_context_allocator(ctx);
        char*                        heap_ch = NULL;
        char*                        heap_gr = NULL;
        if (had_active && NULL != alloc) {
            heap_ch = pn_build_removed_string_alloc(
                mgr->entries, distinct, dn, PN_ENTITY_CHANNEL, alloc);
            heap_gr = pn_build_removed_string_alloc(
                mgr->entries, distinct, dn, PN_ENTITY_CHANNEL_GROUP, alloc);
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

        /* Detach per-set listeners before the set slot is freed/reusable.
         * Deferred-removal safe when called from inside a callback. */
        pn_subscribe_listener_remove_for_set(mgr, set->set_index);
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
        /* Not subscribed — just destroy the set. Detach per-set listeners
         * before the set slot is freed/reusable. */
        pn_subscribe_listener_remove_for_set(mgr, set->set_index);
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
    pubnub_listener_handle_t result    = PUBNUB_LISTENER_HANDLE_INVALID;
    uint8_t                  limit_hit = 0;
    pubnub_context_t*        ctx;

    if (NULL == set || NULL == listener) {
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    ctx                                  = set->ctx;
    pubnub_platform_provider_t* platform = pn_context_platform(ctx);
    pubnub_lock_t*              lock     = pn_context_mutex_mem(ctx);

    pn_ctx_lock(platform, lock);

    mgr = pn_ensure_subscribe_manager(ctx);
    if (NULL == mgr) {
        pn_ctx_unlock(platform, lock);
        return PUBNUB_LISTENER_HANDLE_INVALID;
    }

    pn_listener_handle_t handle =
        pn_subscribe_listener_add_to_set(mgr, listener, set->set_index);
    if (PN_LISTENER_HANDLE_INVALID != handle) {
        result = (pubnub_listener_handle_t)handle;
    } else if (set->set_index < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS
               && 0 != mgr->sets[set->set_index].active
               && mgr->listener_count >= PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS) {
        /* An out-of-range or inactive set fails before the table scan. */
        limit_hit = 1;
    }

    pn_ctx_unlock(platform, lock);
    if (limit_hit) {
        pn_log_capacity_limit(ctx, PN_SUB_LIMIT_LISTENERS);
    }

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

    /* tracked_subs is a slot table with NULL holes; iterate full capacity. */
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS; ++i) {
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

    if (set->set_index >= PUBNUB_CFG_MAX_SUBSCRIPTION_SETS) {
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

    /* Return the set's real member handles (one per member slot). The
     * handles are borrowed; do NOT pass them to pubnub_subscription_destroy. */
    for (i = 0; i < s->count; ++i) {
        uint16_t              slot = s->member_slots[i];
        pubnub_subscription_t sub;
        if (slot >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
            continue;
        }
        sub = mgr->tracked_subs[slot];
        if (NULL == sub) {
            continue;
        }
        if (count < max_count) {
            out[count] = sub;
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

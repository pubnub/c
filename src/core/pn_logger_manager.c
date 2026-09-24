/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_logger_manager.h"

#include <stdint.h>
#include <string.h>

/** Union covering every concrete entry type for stack-local copy. */
typedef union {
    pubnub_log_entry_t              base;
    pubnub_log_entry_text_t         text;
    pubnub_log_entry_object_t       object;
    pubnub_log_entry_error_t        error;
    pubnub_log_entry_net_request_t  req;
    pubnub_log_entry_net_response_t resp;
} pn_mgr_entry_copy_t;

static size_t pn_mgr_entry_size_(pubnub_log_entry_type_t type)
{
    switch (type) {
    case PUBNUB_LOG_ENTRY_TEXT: return sizeof(pubnub_log_entry_text_t);
    case PUBNUB_LOG_ENTRY_OBJECT: return sizeof(pubnub_log_entry_object_t);
    case PUBNUB_LOG_ENTRY_ERROR: return sizeof(pubnub_log_entry_error_t);
    case PUBNUB_LOG_ENTRY_NET_REQ:
        return sizeof(pubnub_log_entry_net_request_t);
    case PUBNUB_LOG_ENTRY_NET_RESP:
        return sizeof(pubnub_log_entry_net_response_t);
    default: return sizeof(pubnub_log_entry_t);
    }
}

/** Format a 32-bit value as 8 lowercase hex digits. */
static void pn_mgr_hash_context_id_(uint32_t addr, char out[9])
{
    static const char hex[] = "0123456789abcdef";
    int               i;

    for (i = 7; i >= 0; --i) {
        out[i] = hex[addr & 0x0FU];
        addr >>= 4;
    }
    out[8] = '\0';
}

static void pn_mgr_log_(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    pn_logger_manager_t*      mgr = (pn_logger_manager_t*)self;
    pn_mgr_entry_copy_t       copy;
    pubnub_logger_provider_t* snap[PUBNUB_CFG_MAX_LOGGERS];
    int                       snap_count;
    int                       i;

    /* Level filtering — reject entries below threshold. */
    if (PUBNUB_LOG_LEVEL_NONE == mgr->min_level) {
        return;
    }
    if (PUBNUB_LOG_LEVEL_ALL != mgr->min_level
        && (unsigned int)entry->level < (unsigned int)mgr->min_level) {
        return;
    }
    if (0 == PUBNUB_ATOMIC_LOAD_U8(&mgr->count)) {
        return;
    }

    /* Stack-local enriched copy (before lock). */
    memset(&copy, 0, sizeof(copy));
    (void)memcpy(&copy, entry, pn_mgr_entry_size_(entry->type));

    copy.base.context_id    = mgr->context_id;
    copy.base.minimum_level = mgr->min_level;
    copy.base.timestamp_ms  = 0U;
    if (NULL != mgr->platform) {
        if (NULL != mgr->platform->wall_clock_ms) {
            copy.base.timestamp_ms = mgr->platform->wall_clock_ms(mgr->platform);
        }
        if (0U == copy.base.timestamp_ms && NULL != mgr->platform->monotonic_ms) {
            copy.base.timestamp_ms = mgr->platform->monotonic_ms(mgr->platform);
        }
    }

    /* Lock-free fan-out: this path may already run under the context lock
     * (dispatch logs under it), so locking here would self-deadlock. The
     * count release/acquire pair orders it against add/remove; callbacks run
     * from the stack snapshot, touching no manager state. */
    snap_count = (int)PUBNUB_ATOMIC_LOAD_U8(&mgr->count);
    for (i = 0; i < snap_count; ++i) {
        snap[i] = mgr->children[i];
    }

    for (i = 0; i < snap_count; ++i) {
        if (NULL != snap[i] && NULL != snap[i]->log) {
            snap[i]->log(snap[i], &copy.base);
        }
    }
}

static void pn_mgr_set_level_(struct pubnub_logger_provider* self,
                              pubnub_log_level_t             min_level)
{
    pn_logger_manager_t* mgr = (pn_logger_manager_t*)self;
    int                  i;
    int                  n;

    mgr->min_level = min_level;

    /* Called under the per-context lock, so the count is stable; the
     * acquire-load keeps the read consistent with the mutators' publication. */
    n = (int)PUBNUB_ATOMIC_LOAD_U8(&mgr->count);
    for (i = 0; i < n; ++i) {
        pubnub_logger_provider_t* child = mgr->children[i];
        if (NULL != child && NULL != child->set_level) {
            child->set_level(child, min_level);
        }
    }
}

void pn_logger_manager_init(pn_logger_manager_t* mgr)
{
    if (NULL == mgr) {
        return;
    }

    memset(mgr, 0, sizeof(*mgr));
    mgr->base.log       = pn_mgr_log_;
    mgr->base.set_level = pn_mgr_set_level_;
    mgr->min_level      = PUBNUB_LOG_LEVEL_TRACE;

    (void)memcpy(mgr->context_id, "00000000", 9);
}

void pn_logger_manager_wire(pn_logger_manager_t*        mgr,
                            pubnub_platform_provider_t* platform)
{
    if (NULL == mgr) {
        return;
    }

    mgr->platform = platform;
    pn_mgr_hash_context_id_((uint32_t)(uintptr_t)mgr, mgr->context_id);
}

pubnub_res_t pn_logger_manager_add(pn_logger_manager_t*      mgr,
                                   pubnub_logger_provider_t* child)
{
    int n;

    if (NULL == mgr || NULL == child) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    n = (int)PUBNUB_ATOMIC_LOAD_U8(&mgr->count);
    if (n >= PUBNUB_CFG_MAX_LOGGERS) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    /* Publish the pointer BEFORE the count: the lock-free reader in
     * pn_mgr_log_ that observes the incremented count is then guaranteed to
     * see the fully-written children[n] slot (release/acquire pair). */
    mgr->children[n] = child;
    PUBNUB_ATOMIC_STORE_U8(&mgr->count, (uint8_t)(n + 1));

    if (NULL != child->set_level) {
        child->set_level(child, mgr->min_level);
    }

    return PUBNUB_OK;
}

pubnub_res_t pn_logger_manager_remove(pn_logger_manager_t*      mgr,
                                      pubnub_logger_provider_t* child)
{
    int i;
    int n;

    if (NULL == mgr || NULL == child) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    n = (int)PUBNUB_ATOMIC_LOAD_U8(&mgr->count);
    for (i = 0; i < n; ++i) {
        if (mgr->children[i] == child) {
            /* Compact in place, then publish the decremented count LAST. A
             * concurrent lock-free reader that still holds the old count
             * reads only already-valid pointers (or the NULLed tail) — never
             * an uninitialised slot. */
            int j;
            for (j = i; j < n - 1; ++j) {
                mgr->children[j] = mgr->children[j + 1];
            }
            mgr->children[n - 1] = NULL;
            PUBNUB_ATOMIC_STORE_U8(&mgr->count, (uint8_t)(n - 1));
            return PUBNUB_OK;
        }
    }

    return PUBNUB_ERR_INVALID_ARGUMENT;
}

void pn_logger_manager_wire_lock(pn_logger_manager_t* mgr, pubnub_lock_t* lock)
{
    if (NULL == mgr) {
        return;
    }
    mgr->lock = lock;
}

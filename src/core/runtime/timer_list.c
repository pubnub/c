/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file timer_list.c
 * @brief Centralized timer scheduler implementation.
 *
 * Uses a linear scan over a fixed-capacity array. This is optimal
 * for small lists (typical: <= 16 timers per context). If profiling
 * shows this is a bottleneck with large timer counts, replace with a
 * min-heap without changing the public API.
 */

#include "timer_list_internal.h"

#include <string.h>

void pn_timer_list_init(pn_timer_list_t*  list,
                        pn_timer_entry_t* entries,
                        unsigned int      capacity)
{
    if (NULL == list || NULL == entries) {
        return;
    }
    list->entries  = entries;
    list->capacity = capacity;
    list->count    = 0;
    memset(entries, 0, sizeof(pn_timer_entry_t) * capacity);
}

static pn_timer_entry_t* pn_timer_list_find_free(pn_timer_list_t* list)
{
    for (unsigned int i = 0; i < list->capacity; i++) {
        if (!list->entries[i].active) {
            return &list->entries[i];
        }
    }
    return NULL;
}

pn_timer_handle_t pn_timer_list_add(pn_timer_list_t*            list,
                                    pubnub_milliseconds_t       delay_ms,
                                    pn_timer_cb_t               cb,
                                    void*                       cb_data,
                                    pubnub_platform_provider_t* platform)
{
    if (NULL == list || NULL == platform || NULL == cb) {
        return NULL;
    }

    pn_timer_entry_t* entry = pn_timer_list_find_free(list);
    if (NULL == entry) {
        return NULL;
    }

    entry->deadline = pn_timer_start(delay_ms, platform);
    entry->cb       = cb;
    entry->cb_data  = cb_data;
    entry->active   = 1;
    list->count++;
    return (pn_timer_handle_t)entry;
}

void pn_timer_list_remove(pn_timer_list_t* list, pn_timer_handle_t handle)
{
    if (NULL == list || NULL == handle || 0 == list->count) {
        return;
    }

    pn_timer_entry_t* entry = (pn_timer_entry_t*)handle;
    if (entry->active) {
        entry->active  = 0;
        entry->cb      = NULL;
        entry->cb_data = NULL;
        memset(&entry->deadline, 0, sizeof(entry->deadline));
        list->count--;
    }
}

int pn_timer_list_fire_expired(pn_timer_list_t*            list,
                               pubnub_platform_provider_t* platform)
{
    if (NULL == list || NULL == platform || 0 == list->count) {
        return 0;
    }

    int fired = 0;
    for (unsigned int i = 0; i < list->capacity; i++) {
        pn_timer_entry_t* entry = &list->entries[i];
        if (!entry->active) {
            continue;
        }
        if (pn_timer_is_expired(entry->deadline, platform)) {
            /* Capture callback before deactivating - the callback
             * may call pn_timer_list_add() to re-arm this slot. */
            pn_timer_cb_t cb      = entry->cb;
            void*         cb_data = entry->cb_data;

            entry->active  = 0;
            entry->cb      = NULL;
            entry->cb_data = NULL;
            memset(&entry->deadline, 0, sizeof(entry->deadline));
            list->count--;

            cb(cb_data);
            fired++;
        }
    }
    return fired;
}

pubnub_milliseconds_t pn_timer_list_ms_until_next(const pn_timer_list_t* list,
                                                  pubnub_platform_provider_t* platform)
{
    if (NULL == list || NULL == platform || 0 == list->count) {
        return PN_TIMER_LIST_NO_ACTIVE_TIMERS;
    }

    pubnub_milliseconds_t min_remaining = PN_TIMER_LIST_NO_ACTIVE_TIMERS;
    for (unsigned int i = 0; i < list->capacity; i++) {
        const pn_timer_entry_t* entry = &list->entries[i];
        if (!entry->active) {
            continue;
        }
        pubnub_milliseconds_t remaining =
            pn_timer_remaining_ms(entry->deadline, platform);
        if (remaining < min_remaining) {
            min_remaining = remaining;
        }
        if (0 == min_remaining) {
            break; /* Can't get lower than 0. */
        }
    }
    return min_remaining;
}

unsigned int pn_timer_list_count(const pn_timer_list_t* list)
{
    if (NULL == list) {
        return 0;
    }
    return list->count;
}

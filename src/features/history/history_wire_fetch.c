/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "history_internal.h"

#if !PUBNUB_ENABLE_HISTORY
#error "history_wire_fetch.c requires PUBNUB_ENABLE_HISTORY=ON"
#endif

#include "pubnub/providers/serialization.h"

#include <stddef.h>
#include <string.h>

/** Extract the next-page cursor from "more"."start" if present. */
static pubnub_timetoken_t
pn_history_extract_next_cursor(pubnub_serialization_provider_t* serial,
                               const pubnub_json_value_t*       root)
{
    pubnub_timetoken_t cursor = {0};

    const pubnub_json_value_t* more_obj = serial->object_get(root, "more", 4);
    if (NULL == more_obj || PUBNUB_JSON_OBJECT != serial->value_type(more_obj)) {
        return cursor;
    }

    const pubnub_json_value_t* start_val = serial->object_get(more_obj, "start", 5);
    if (NULL == start_val || PUBNUB_JSON_STRING != serial->value_type(start_val)) {
        return cursor;
    }

    size_t      len = 0;
    const char* ptr = serial->value_as_string(start_val, &len);
    if (NULL != ptr && 0 < len) {
        cursor.ptr = ptr;
        cursor.len = len;
    }
    return cursor;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_parse_fetch(pubnub_serialization_provider_t* serial,
                                    const pubnub_json_value_t*       tree,
                                    pubnub_allocator_provider_t*     allocator,
                                    pn_history_fetch_parsed_t*       out)
{
    if (NULL == serial || NULL == tree || NULL == allocator || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->object_size || NULL == serial->array_size
        || NULL == serial->object_iter_init || NULL == serial->object_iter_next
        || NULL == serial->value_as_string) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    if (PUBNUB_JSON_OBJECT != serial->value_type(tree)) {
        return PUBNUB_ERR_SERIALIZATION;
    }

    /* Navigate to "channels" object. */
    const pubnub_json_value_t* channels_obj =
        serial->object_get(tree, "channels", 8);
    if (NULL == channels_obj
        || PUBNUB_JSON_OBJECT != serial->value_type(channels_obj)) {
        /* Valid response but no channels object — return empty. */
        out->channel_entries     = NULL;
        out->channel_count       = 0;
        out->next_cursor.ptr     = NULL;
        out->next_cursor.len     = 0;
        out->decrypted_msg_tree  = NULL;
        out->cached_channel_idx  = SIZE_MAX;
        out->cached_message_idx  = SIZE_MAX;
        out->allocator           = allocator;
        out->serial              = serial;
        out->decrypted_file_tree = NULL;
        return PUBNUB_OK;
    }

    const size_t ch_count = serial->object_size(channels_obj);
    if (0 == ch_count) {
        out->channel_entries     = NULL;
        out->channel_count       = 0;
        out->next_cursor.ptr     = NULL;
        out->next_cursor.len     = 0;
        out->decrypted_msg_tree  = NULL;
        out->cached_channel_idx  = SIZE_MAX;
        out->cached_message_idx  = SIZE_MAX;
        out->allocator           = allocator;
        out->serial              = serial;
        out->decrypted_file_tree = NULL;
        return PUBNUB_OK;
    }

    if (ch_count > SIZE_MAX / sizeof(pn_history_fetch_channel_entry_t)) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    const size_t alloc_size = ch_count * sizeof(pn_history_fetch_channel_entry_t);
    pn_history_fetch_channel_entry_t* entries =
        (pn_history_fetch_channel_entry_t*)PN_ALLOC(allocator, alloc_size, 0);
    if (NULL == entries) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memset(entries, 0, alloc_size);

    /* Walk channels object with iterator. */
    pubnub_json_iter_t iter;
    uint32_t           idx = 0;

    if (0 == serial->object_iter_init(channels_obj, &iter)) {
        /* Empty or not an object — shouldn't happen after size check. */
        PN_FREE(allocator, entries);
        out->channel_entries     = NULL;
        out->channel_count       = 0;
        out->next_cursor.ptr     = NULL;
        out->next_cursor.len     = 0;
        out->decrypted_msg_tree  = NULL;
        out->cached_channel_idx  = SIZE_MAX;
        out->cached_message_idx  = SIZE_MAX;
        out->allocator           = allocator;
        out->serial              = serial;
        out->decrypted_file_tree = NULL;
        return PUBNUB_OK;
    }

    const char*          key     = NULL;
    size_t               key_len = 0;
    pubnub_json_value_t* value   = NULL;

    while (serial->object_iter_next(&iter, &key, &key_len, &value)) {
        if (idx >= (uint32_t)ch_count) {
            break;
        }
        entries[idx].name.ptr = key;
        entries[idx].name.len = key_len;

        if (NULL != value && PUBNUB_JSON_ARRAY == serial->value_type(value)) {
            entries[idx].messages_array = value;
            entries[idx].message_count  = (uint32_t)serial->array_size(value);
        } else {
            entries[idx].messages_array = NULL;
            entries[idx].message_count  = 0;
        }
        ++idx;
    }

    out->channel_entries     = entries;
    out->channel_count       = idx;
    out->next_cursor.ptr     = NULL;
    out->next_cursor.len     = 0;
    out->decrypted_msg_tree  = NULL;
    out->cached_channel_idx  = SIZE_MAX;
    out->cached_message_idx  = SIZE_MAX;
    out->allocator           = allocator;
    out->serial              = serial;
    out->decrypted_file_tree = NULL;

    out->next_cursor = pn_history_extract_next_cursor(serial, tree);

    return PUBNUB_OK;
}

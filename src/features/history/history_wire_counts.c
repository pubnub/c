/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "history_internal.h"

#if !PUBNUB_ENABLE_HISTORY
#error "history_wire_counts.c requires PUBNUB_ENABLE_HISTORY=ON"
#endif

#include "pubnub/providers/serialization.h"

#include <stddef.h>
#include <string.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_res_t pn_history_parse_counts(pubnub_serialization_provider_t* serial,
                                     const pubnub_json_value_t*       tree,
                                     pubnub_allocator_provider_t*     allocator,
                                     pn_history_counts_parsed_t*      out)
{
    if (NULL == serial || NULL == tree || NULL == allocator || NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->object_size || NULL == serial->value_as_int
        || NULL == serial->object_iter_init || NULL == serial->object_iter_next) {
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
        out->channel_entries = NULL;
        out->channel_count   = 0;
        return PUBNUB_OK;
    }

    const size_t ch_count = serial->object_size(channels_obj);
    if (0 == ch_count) {
        out->channel_entries = NULL;
        out->channel_count   = 0;
        return PUBNUB_OK;
    }

    if (ch_count > SIZE_MAX / sizeof(pn_history_counts_channel_entry_t)) {
        return PUBNUB_ERR_SERIALIZATION;
    }
    const size_t alloc_size = ch_count * sizeof(pn_history_counts_channel_entry_t);
    pn_history_counts_channel_entry_t* entries =
        (pn_history_counts_channel_entry_t*)PN_ALLOC(allocator, alloc_size, 0);
    if (NULL == entries) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    memset(entries, 0, alloc_size);

    /* Walk channels object and extract integer counts. */
    pubnub_json_iter_t iter;
    uint32_t           idx = 0;

    if (0 == serial->object_iter_init(channels_obj, &iter)) {
        PN_FREE(allocator, entries);
        out->channel_entries = NULL;
        out->channel_count   = 0;
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
        entries[idx].count    = 0;

        if (NULL != value && PUBNUB_JSON_INT == serial->value_type(value)) {
            int int_val = 0;
            if (PUBNUB_OK == serial->value_as_int(value, &int_val) && int_val >= 0) {
                entries[idx].count = (uint32_t)int_val;
            }
        }
        ++idx;
    }

    out->channel_entries = entries;
    out->channel_count   = idx;
    return PUBNUB_OK;
}

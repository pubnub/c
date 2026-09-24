/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_buf_serialize.h"

pubnub_res_t pn_buf_serialize_grow(pubnub_allocator_provider_t*     alloc,
                                   pubnub_serialization_provider_t* serial,
                                   const pubnub_json_value_t*       value,
                                   pubnub_buffer_t*                 buf)
{
    int          i;
    size_t       written = 0;
    size_t       new_cap;
    pubnub_res_t rc;

    if (NULL == serial || NULL == serial->serialize || NULL == buf
        || NULL == buf->data || 0 == buf->cap) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    rc = serial->serialize(serial, value, buf->data, buf->cap, &written);

    for (i = 0; PUBNUB_ERR_BUFFER_TOO_SMALL == rc && i < 16; ++i) {
        if (NULL == alloc || NULL == alloc->buf_grow) {
            break;
        }
        new_cap = buf->cap * 2;
        if (0 != PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE
            && new_cap > PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE) {
            break;
        }
        if (0 != alloc->buf_grow(alloc, buf, new_cap)) {
            break;
        }
        rc = serial->serialize(serial, value, buf->data, buf->cap, &written);
    }

    if (PUBNUB_OK == rc) {
        buf->len = written;
    }
    return rc;
}

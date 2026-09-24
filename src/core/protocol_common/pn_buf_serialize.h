/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Helpers for serializing JSON values into growable buffers.
 *
 * Used by wire/protocol code across serializing features (publish,
 * signal, presence, app_context). Lives alongside pn_url_encode in
 * protocol_common because the consumer profile is identical.
 */

#ifndef PN_BUF_SERIALIZE_H
#define PN_BUF_SERIALIZE_H

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Ensure a buffer has at least @p needed bytes of capacity.
 *
 * When the buffer already has sufficient capacity this is a no-op.
 * Otherwise calls @c buf_grow on the allocator. On embedded profiles
 * where @c buf_grow is NULL, this always returns failure for any
 * capacity shortfall.
 *
 * @param alloc  Allocator provider (borrowed). May be NULL.
 * @param buf    Buffer to grow (borrowed).
 * @param needed Minimum required capacity in bytes.
 * @return 0 on success (capacity >= needed), non-zero on failure.
 */
static inline int pn_buf_ensure_cap(pubnub_allocator_provider_t* alloc,
                                    pubnub_buffer_t*             buf,
                                    size_t                       needed)
{
    if (needed <= buf->cap) {
        return 0;
    }
    if (0 != PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE
        && needed > PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE) {
        return -1;
    }
    if (NULL == alloc || NULL == alloc->buf_grow) {
        return -1;
    }
    return alloc->buf_grow(alloc, buf, needed);
}

/**
 * @brief Serialize a JSON value tree into a buffer, growing on demand.
 *
 * Calls @c serial->serialize and, when the buffer is too small,
 * attempts to double it via @c alloc->buf_grow. Stops immediately
 * when growth fails (no further retries on OOM). On success,
 * @c buf->len is set to the number of bytes written.
 *
 * On embedded profiles where @c buf_grow is NULL the first
 * BUFFER_TOO_SMALL error is final.
 *
 * @param alloc  Allocator for buffer growth (borrowed).
 * @param serial Serialization provider (borrowed).
 * @param value  JSON value tree to serialize (borrowed).
 * @param buf    Buffer to write into; @c buf->len updated on success.
 * @return @c PUBNUB_OK on success, @c PUBNUB_ERR_BUFFER_TOO_SMALL
 *         when the buffer cannot be grown, or another error from the
 *         serialization provider.
 */
pubnub_res_t pn_buf_serialize_grow(pubnub_allocator_provider_t*     alloc,
                                   pubnub_serialization_provider_t* serial,
                                   const pubnub_json_value_t*       value,
                                   pubnub_buffer_t*                 buf);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_BUF_SERIALIZE_H */

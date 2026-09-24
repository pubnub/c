/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_PRESENCE_WIRE_INTERNAL_H
#define PN_PRESENCE_WIRE_INTERNAL_H

#include "pubnub/config.h"

#if !PUBNUB_ENABLE_PRESENCE
#error "presence_wire_internal.h requires PUBNUB_ENABLE_PRESENCE=ON - this " \
    "translation unit has no meaning without the presence feature."
#endif

#include "pubnub/error.h"
#include "pubnub/providers/transport_types.h"

#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Inputs required to build a presence HTTP request.
 *
 * All pointers are borrowed and must remain valid until the request
 * is dispatched to the transport.
 */
typedef struct pn_presence_wire_inputs {
    /** Subscribe key (NUL-terminated, required). */
    const char* subscribe_key;
    /** Comma-separated channel names (required). */
    const char* channels;
    /** Comma-separated channel group names, or NULL. */
    const char* channel_groups;
    /** Presence timeout in seconds (heartbeat query param). */
    uint32_t heartbeat_sec;
    /** Per-request timeout in milliseconds. */
    uint32_t timeout_ms;
} pn_presence_wire_inputs_t;

/**
 * @brief Build a presence heartbeat HTTP request.
 *
 * Path: /v2/presence/sub-key/{sub_key}/channel/{channels}/heartbeat
 * Query: heartbeat={timeout_sec}, channel-group={groups} (if any)
 *
 * @param request HTTP request descriptor to populate (caller-owned,
 *                should be zero-initialized before call).
 * @param inputs  Wire inputs describing channels and configuration.
 * @return PUBNUB_OK on success, PUBNUB_ERR_INVALID_ARGUMENT if
 *         required inputs are NULL, PUBNUB_ERR_BUFFER_TOO_SMALL if
 *         query params exceed the request's capacity.
 */
pubnub_res_t pn_presence_build_heartbeat(pubnub_http_request_t* request,
                                         const pn_presence_wire_inputs_t* inputs);

/**
 * @brief Build a presence leave HTTP request.
 *
 * Path: /v2/presence/sub-key/{sub_key}/channel/{channels}/leave
 * Query: channel-group={groups} (if any)
 *
 * @param request HTTP request descriptor to populate.
 * @param inputs  Wire inputs describing channels and configuration.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_presence_build_leave(pubnub_http_request_t*           request,
                                     const pn_presence_wire_inputs_t* inputs);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PRESENCE_WIRE_INTERNAL_H */

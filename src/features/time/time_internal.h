/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TIME_INTERNAL_H
#define PN_TIME_INTERNAL_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_TIME

#include "core/runtime/request_internal.h"
#include "pubnub/error.h"
#include "pubnub/features/time.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Per-request state for @ref pubnub_time.
 *
 * Holds an owned copy of the timetoken digit string, captured at
 * completion while the response body is still valid (see
 * @ref pn_time_capture_timetoken). The result accessor returns a view
 * into this owned storage, so the timetoken never aliases the transport
 * rx buffer — which the socket transport's Connection: close path can
 * reclaim before the accessor runs.
 *
 * Released via @ref pn_time_feature_state_cleanup. @c tt is inline
 * storage, so cleanup needs no extra free.
 */
typedef struct pn_time_state {
    /** Owned, NUL-terminated copy of the timetoken digits. Sized for a
     *  20-digit uint64 timetoken plus NUL, with headroom. */
    char tt[24];
    /** Number of digits copied into @ref tt (0 = not captured/invalid). */
    uint8_t tt_len;
} pn_time_state_t;

/**
 * @brief Build the REST time path into @p request's path_segments.
 *
 * Path layout: `/time/0`
 *
 * @param request Populated with path segments on success.
 * @return @c PUBNUB_OK on success, or an error code if path_segments
 *         capacity is exceeded.
 */
pubnub_res_t pn_time_build_path(pubnub_http_request_t* request);

/**
 * @brief Minimal response validator probe for the time endpoint.
 *
 * Scans the raw body to confirm the response is a JSON array with a
 * numeric first element (the timetoken string). No allocation.
 *
 * @param body        Response body bytes (borrowed).
 * @param body_len    Response body length in bytes.
 * @param http_status HTTP status code.
 * @return @c PUBNUB_OK on logical success; a server-class error on
 *         logical failure or malformed body.
 */
pubnub_res_t pn_time_response_validator(const uint8_t* body,
                                        size_t         body_len,
                                        int            http_status);

/**
 * @brief Extract the timetoken from a raw time response body.
 *
 * Expected shape: `[<timetoken>]`. The returned view aliases the body
 * buffer.
 *
 * @param body      Response body bytes (borrowed); must remain valid
 *                  while the view is used.
 * @param body_len  Response body length in bytes.
 * @param out_token Receives the timetoken view; zero-initialized on
 *                  failure.
 * @return @c PUBNUB_OK on success, or @c PUBNUB_ERR_SERIALIZATION on
 *         malformed body.
 */
pubnub_res_t pn_time_parse_response(const uint8_t*      body,
                                    size_t              body_len,
                                    pubnub_timetoken_t* out_token);

/**
 * @brief Capture the timetoken digits into feature-owned storage.
 *
 * Completion capture hook (@ref pn_response_capture_fn_t) for the time
 * feature. Invoked on the poll thread while the response body is still
 * valid, before the transport rx buffer can be reclaimed. Locates the
 * digit substring via @ref pn_time_parse_response and copies it (bounded)
 * into the slot's @ref pn_time_state_t, so @ref pubnub_time_result_timetoken
 * can return a stable view independent of the transport buffer.
 *
 * @param slot Completed request slot (borrowed); reads @c http_response
 *             and resolves the time feature state. A NULL @p slot or a
 *             mismatched feature is tolerated as a no-op.
 */
void pn_time_capture_timetoken(pn_request_t* slot);

/**
 * @brief Cleanup for the time slot's feature_state.
 *
 * @param state The @ref pn_time_state_t pointer.
 * @param alloc Allocator for deallocation.
 */
void pn_time_feature_state_cleanup(void* state, pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_TIME */

#endif /* PN_TIME_INTERNAL_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file service_error_internal.h
 * @brief Internal classifier for the public service_error API.
 *
 * Not installed. The internal kind enum lives here so it never
 * leaks into installed headers; the folded public surface in
 * @c include/pubnub/service_error.h is the only contract callers
 * see.
 */

#ifndef PN_SERVICE_ERROR_INTERNAL_H
#define PN_SERVICE_ERROR_INTERNAL_H

#include "pubnub/providers/serialization.h"
#include "runtime/request_internal.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Internal taxonomy of server error envelope shapes.
 *
 * Cached on the slot as uint8_t. NOT part of any public ABI.
 * Probe order matters: History before boolean-flag (see values).
 */
typedef enum pn_service_error_kind {
    /** No classification has run yet (cache sentinel). */
    PN_SVC_ERR_KIND_UNKNOWN = 0,

    /** Array publish/signal envelope: `[0, "msg", ...]`. */
    PN_SVC_ERR_KIND_ARRAY_PUBLISH = 1,

    /** Push management string envelope: `{"error": "msg"}`. */
    PN_SVC_ERR_KIND_OBJ_PUSH_STRING = 2,

    /** History flat envelope: `{"status", "error_message", ...}`. */
    PN_SVC_ERR_KIND_OBJ_HISTORY_FLAT = 3,

    /** PAM-style nested envelope:
     *  `{"status", "error": {"message", "source", "details"?}}`. */
    PN_SVC_ERR_KIND_OBJ_PAM_DETAILS = 4,

    /** Boolean-error-flag envelope:
     *  `{"status", "message", "error": bool, "service"?}`. */
    PN_SVC_ERR_KIND_OBJ_BOOL_ERROR_FLAG = 5,

    /** Generic object harvest - catch-all for object bodies that
     *  matched none of the more specific shapes. */
    PN_SVC_ERR_KIND_OBJ_GENERIC_HARVEST = 6,

    /** Raw text - parse failed or root is a string. The classifier
     *  surfaces the raw response bytes as @c message. */
    PN_SVC_ERR_KIND_RAW_TEXT = 7,

    /** Body is a successful (non-error) response shape. */
    PN_SVC_ERR_KIND_NONE = 8
} pn_service_error_kind_t;

/**
 * @brief Classify the slot's response body (idempotent, cached).
 *
 * @param req    Slot to classify (borrowed).
 * @param serial Serialization provider (borrowed).
 * @return Cached classification (UNKNOWN only when req is NULL/not terminal).
 */
pn_service_error_kind_t
pn_request_get_service_error_kind(pn_request_t*                    req,
                                  pubnub_serialization_provider_t* serial);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_SERVICE_ERROR_INTERNAL_H */

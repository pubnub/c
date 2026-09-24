/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file service_error.c
 * @brief Classifier and accessors for the folded service-error API.
 *
 * The classifier walks the slot's lazily-parsed JSON tree (or raw
 * RX buffer when the parse failed) and assigns one of the
 * @ref pn_service_error_kind_t variants. Subsequent accessor calls
 * read the cached variant and project the requested fields into
 * the public folded shape.
 */

#include "pubnub/service_error.h"

#include "core_internal.h"
#include "pubnub/pubnub_compat.h"
#include "runtime/request_internal.h"
#include "runtime/request_pool_internal.h"
#include "service_error_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Convenience: read a JSON string-typed field from an object
 *        at @p key, or `{NULL, 0}` when absent / not a string.
 */
static pubnub_string_view_t object_string_field(pubnub_serialization_provider_t* serial,
                                                const pubnub_json_value_t* obj,
                                                const char*                key,
                                                size_t key_len)
{
    pubnub_string_view_t empty = {NULL, 0};
    if (NULL == serial || NULL == obj || NULL == serial->object_get
        || NULL == serial->value_type || NULL == serial->value_as_string) {
        return empty;
    }
    pubnub_json_value_t* node = serial->object_get(obj, key, key_len);
    if (NULL == node) {
        return empty;
    }
    if (PUBNUB_JSON_STRING != serial->value_type(node)) {
        return empty;
    }
    size_t      len = 0;
    const char* p   = serial->value_as_string(node, &len);
    if (NULL == p) {
        return empty;
    }
    return (pubnub_string_view_t){p, len};
}

/** Read a JSON int-typed field into int32_t. */
static int read_int32_field(pubnub_serialization_provider_t* serial,
                            const pubnub_json_value_t*       obj,
                            const char*                      key,
                            size_t                           key_len,
                            int32_t*                         out)
{
    if (NULL == serial || NULL == obj || NULL == serial->object_get
        || NULL == serial->value_as_int) {
        return 0;
    }
    pubnub_json_value_t* node = serial->object_get(obj, key, key_len);
    if (NULL == node) {
        return 0;
    }
    int v = 0;
    if (PUBNUB_OK != serial->value_as_int(node, &v)) {
        return 0;
    }
    *out = (int32_t)v;
    return 1;
}

/**
 * @brief Probe variant 1: array-form publish/signal failure.
 *
 * Recognises `[0, "msg", ...]` shapes with 2 or 3 elements where
 * the first integer is 0 (PubNub's failure marker) and the second
 * element is a string.
 */
static int matches_array_publish(pubnub_serialization_provider_t* serial,
                                 const pubnub_json_value_t*       root)
{
    if (NULL == serial->value_type || NULL == serial->array_size
        || NULL == serial->array_get || NULL == serial->value_as_int) {
        return 0;
    }
    if (PUBNUB_JSON_ARRAY != serial->value_type(root)) {
        return 0;
    }
    const size_t n = serial->array_size(root);
    if (2 != n && 3 != n) {
        return 0;
    }
    const pubnub_json_value_t* first = serial->array_get(root, 0);
    if (NULL == first) {
        return 0;
    }
    if (PUBNUB_JSON_INT != serial->value_type(first)) {
        return 0;
    }
    int status = 0;
    if (PUBNUB_OK != serial->value_as_int(first, &status)) {
        return 0;
    }
    /* status == 1 is a successful publish (`[1, "Sent", "<tt>"]`).
     * Only failures match this kind. */
    if (0 != status) {
        return 0;
    }
    const pubnub_json_value_t* second = serial->array_get(root, 1);
    if (NULL == second) {
        return 0;
    }
    return PUBNUB_JSON_STRING == serial->value_type(second);
}

/**
 * @brief Probe variant 2: push-management string envelope.
 *
 * `{"error": "msg"}` - the @c error key carries a STRING, not a
 * boolean and not a nested object.
 */
static int matches_push_string(pubnub_serialization_provider_t* serial,
                               const pubnub_json_value_t*       root)
{
    if (NULL == serial->value_type || NULL == serial->object_get) {
        return 0;
    }
    if (PUBNUB_JSON_OBJECT != serial->value_type(root)) {
        return 0;
    }
    pubnub_json_value_t* err = serial->object_get(root, "error", 5);
    if (NULL == err) {
        return 0;
    }
    return PUBNUB_JSON_STRING == serial->value_type(err);
}

/**
 * @brief Probe variant 3: history flat envelope.
 *
 * Distinguishing trait: presence of @c error_message at the top
 * level. The @c error key, when present, is boolean - but History
 * carries BOTH keys, which is why the probe order in the dispatcher
 * runs History before the boolean-flag variant.
 */
static int matches_history_flat(pubnub_serialization_provider_t* serial,
                                const pubnub_json_value_t*       root)
{
    if (NULL == serial->value_type || NULL == serial->object_get) {
        return 0;
    }
    if (PUBNUB_JSON_OBJECT != serial->value_type(root)) {
        return 0;
    }
    return NULL != serial->object_get(root, "error_message", 13);
}

/**
 * @brief Probe variant 4: PAM-style nested error envelope.
 *
 * `{"error": {"message": "...", ...}}` - the @c error key carries
 * an OBJECT that has a @c message field.
 */
static int matches_pam_details(pubnub_serialization_provider_t* serial,
                               const pubnub_json_value_t*       root)
{
    if (NULL == serial->value_type || NULL == serial->object_get) {
        return 0;
    }
    if (PUBNUB_JSON_OBJECT != serial->value_type(root)) {
        return 0;
    }
    pubnub_json_value_t* err = serial->object_get(root, "error", 5);
    if (NULL == err) {
        return 0;
    }
    if (PUBNUB_JSON_OBJECT != serial->value_type(err)) {
        return 0;
    }
    return NULL != serial->object_get(err, "message", 7);
}

/**
 * @brief Probe variant 5: boolean error flag.
 *
 * `{"error": true, "message": "..."}` - the @c error key is a
 * boolean (true), and the body has a top-level @c message string.
 */
static int matches_bool_error_flag(pubnub_serialization_provider_t* serial,
                                   const pubnub_json_value_t*       root)
{
    if (NULL == serial->value_type || NULL == serial->object_get
        || NULL == serial->value_as_bool) {
        return 0;
    }
    if (PUBNUB_JSON_OBJECT != serial->value_type(root)) {
        return 0;
    }
    pubnub_json_value_t* err = serial->object_get(root, "error", 5);
    if (NULL == err || PUBNUB_JSON_BOOL != serial->value_type(err)) {
        return 0;
    }
    int truthy = 0;
    if (PUBNUB_OK != serial->value_as_bool(err, &truthy) || 0 == truthy) {
        return 0;
    }
    return NULL != serial->object_get(root, "message", 7);
}

/**
 * @brief Walk the parsed tree and assign a kind.
 *
 * Probe order is significant - see the @ref pn_service_error_kind_t
 * documentation. Always ends with @c GENERIC_HARVEST for object
 * bodies that match none of the specific shapes; @c NONE only when
 * the body looks like a successful response.
 */
static pn_service_error_kind_t classify_tree(pubnub_serialization_provider_t* serial,
                                             const pubnub_json_value_t* root)
{
    if (NULL == serial || NULL == root || NULL == serial->value_type) {
        return PN_SVC_ERR_KIND_RAW_TEXT;
    }

    /* String-rooted JSON ("foo") falls back to raw-text handling so
     * the message view aliases the parsed bytes uniformly. */
    if (PUBNUB_JSON_STRING == serial->value_type(root)) {
        return PN_SVC_ERR_KIND_RAW_TEXT;
    }

    if (matches_array_publish(serial, root)) {
        return PN_SVC_ERR_KIND_ARRAY_PUBLISH;
    }
    if (PUBNUB_JSON_ARRAY == serial->value_type(root)) {
        /* A successful array body (`[1, "Sent", "<tt>"]`) is not an
         * error variant; flag it explicitly so the caller can treat
         * it as "no error to report". */
        return PN_SVC_ERR_KIND_NONE;
    }
    if (matches_push_string(serial, root)) {
        return PN_SVC_ERR_KIND_OBJ_PUSH_STRING;
    }
    if (matches_history_flat(serial, root)) {
        return PN_SVC_ERR_KIND_OBJ_HISTORY_FLAT;
    }
    if (matches_pam_details(serial, root)) {
        return PN_SVC_ERR_KIND_OBJ_PAM_DETAILS;
    }
    if (matches_bool_error_flag(serial, root)) {
        return PN_SVC_ERR_KIND_OBJ_BOOL_ERROR_FLAG;
    }
    if (PUBNUB_JSON_OBJECT == serial->value_type(root)) {
        return PN_SVC_ERR_KIND_OBJ_GENERIC_HARVEST;
    }
    return PN_SVC_ERR_KIND_RAW_TEXT;
}

pn_service_error_kind_t
pn_request_get_service_error_kind(pn_request_t*                    req,
                                  pubnub_serialization_provider_t* serial)
{
    if (NULL == req) {
        return PN_SVC_ERR_KIND_UNKNOWN;
    }

    /* Lock-free cache: classification runs outside any SDK lock because
     * serialization vtable calls cannot be made while holding a lock
     * (lock-discipline rule). The acquire-load / release-store pair
     * ensures the svc_error_kind write is visible before the flag. */
    if (PUBNUB_ATOMIC_LOAD_U8(&req->svc_error_classified)) {
        return (pn_service_error_kind_t)req->svc_error_kind;
    }

    pubnub_json_value_t*    tree = pn_request_get_parsed_body(req, serial);
    pn_service_error_kind_t k =
        (NULL == tree) ? PN_SVC_ERR_KIND_RAW_TEXT : classify_tree(serial, tree);

    req->svc_error_kind = (uint8_t)k;
    PUBNUB_ATOMIC_STORE_U8(&req->svc_error_classified, 1);
    return k;
}

/**
 * @brief Default @c status from the response, used when the body
 *        does not embed one. Mirrors @c http_response.status_code.
 */
static uint16_t default_status(const pn_request_t* slot)
{
    if (PUBNUB_HTTP_COMPLETE != slot->http_response.completion) {
        return 0;
    }
    int sc = slot->http_response.status_code;
    if (sc < 0) {
        return 0;
    }
    if (sc > 0xFFFF) {
        sc = 0xFFFF;
    }
    return (uint16_t)sc;
}

/**
 * @brief Read the body's own status field when present (variants 3,
 *        4, 5, 6 carry one); fall back to HTTP status otherwise.
 */
static uint16_t status_from_body(pubnub_serialization_provider_t* serial,
                                 const pubnub_json_value_t*       root,
                                 const pn_request_t*              slot)
{
    int32_t s = 0;
    if (read_int32_field(serial, root, "status", 6, &s) && s > 0 && s <= 0xFFFF) {
        return (uint16_t)s;
    }
    return default_status(slot);
}

/**
 * @brief Project a kind onto the folded public envelope.
 */
static void fold_envelope(pubnub_serialization_provider_t* serial,
                          const pn_request_t*              slot,
                          pn_service_error_kind_t          kind,
                          const pubnub_json_value_t*       root,
                          pubnub_service_error_t*          out)
{
    /* Initialise to the safe-default shape; per-variant overrides
     * below mutate only the fields they apply to. */
    out->status     = default_status(slot);
    out->error_flag = 0;
    out->_pad       = 0;
    out->code       = 0;
    out->service    = (pubnub_string_view_t){NULL, 0};
    out->message    = (pubnub_string_view_t){NULL, 0};
    out->source     = (pubnub_string_view_t){NULL, 0};

    switch (kind) {
    case PN_SVC_ERR_KIND_ARRAY_PUBLISH: {
        const pubnub_json_value_t* second = serial->array_get(root, 1);
        if (NULL != second && PUBNUB_JSON_STRING == serial->value_type(second)) {
            size_t      n = 0;
            const char* p = serial->value_as_string(second, &n);
            if (NULL != p) {
                out->message = (pubnub_string_view_t){p, n};
            }
        }
        out->error_flag = 1;
        break;
    }
    case PN_SVC_ERR_KIND_OBJ_PUSH_STRING: {
        out->message    = object_string_field(serial, root, "error", 5);
        out->error_flag = 1;
        out->status     = status_from_body(serial, root, slot);
        break;
    }
    case PN_SVC_ERR_KIND_OBJ_HISTORY_FLAT: {
        out->message = object_string_field(serial, root, "error_message", 13);
        out->status  = status_from_body(serial, root, slot);
        /* History sets `error: bool` separately; reflect it. */
        pubnub_json_value_t* err = serial->object_get(root, "error", 5);
        if (NULL != err && PUBNUB_JSON_BOOL == serial->value_type(err)
            && NULL != serial->value_as_bool) {
            int truthy = 0;
            if (PUBNUB_OK == serial->value_as_bool(err, &truthy)) {
                out->error_flag = (uint8_t)(truthy ? 1 : 0);
            }
        }
        break;
    }
    case PN_SVC_ERR_KIND_OBJ_PAM_DETAILS: {
        pubnub_json_value_t* err = serial->object_get(root, "error", 5);
        if (NULL != err) {
            out->message = object_string_field(serial, err, "message", 7);
            out->source  = object_string_field(serial, err, "source", 6);
            /* Files-style numeric subcode, when the variant
             * carries one. */
            int32_t code = 0;
            if (read_int32_field(serial, err, "code", 4, &code)) {
                out->code = code;
            }
        }
        out->service    = object_string_field(serial, root, "service", 7);
        out->status     = status_from_body(serial, root, slot);
        out->error_flag = 1;
        break;
    }
    case PN_SVC_ERR_KIND_OBJ_BOOL_ERROR_FLAG: {
        out->message = object_string_field(serial, root, "message", 7);
        out->service = object_string_field(serial, root, "service", 7);
        out->status  = status_from_body(serial, root, slot);
        pubnub_json_value_t* err = serial->object_get(root, "error", 5);
        if (NULL != err && NULL != serial->value_as_bool) {
            int truthy = 0;
            if (PUBNUB_OK == serial->value_as_bool(err, &truthy)) {
                out->error_flag = (uint8_t)(truthy ? 1 : 0);
            }
        }
        break;
    }
    case PN_SVC_ERR_KIND_OBJ_GENERIC_HARVEST: {
        out->message = object_string_field(serial, root, "message", 7);
        out->service = object_string_field(serial, root, "service", 7);
        out->status  = status_from_body(serial, root, slot);
        /* No declared error flag in the generic harvest path;
         * leave it 0. Callers needing a verdict consult `status`
         * directly. */
        break;
    }
    case PN_SVC_ERR_KIND_RAW_TEXT: {
        /* Parse failure: alias the raw RX buffer directly. The
         * buffer's lifetime ends at the same boundary as the
         * parsed tree (slot release), so the view stays valid
         * for the same window as every other variant. */
        if (NULL != slot->http_response.body && 0 != slot->http_response.body_len) {
            out->message =
                (pubnub_string_view_t){(const char*)slot->http_response.body,
                                       slot->http_response.body_len};
        }
        /* Status: 0 when the transport never observed HTTP framing;
         * the HTTP code otherwise. The body text is the diagnostic
         * regardless. */
        out->error_flag = (0 == out->status) ? 0 : 1;
        break;
    }
    case PN_SVC_ERR_KIND_NONE:
    case PN_SVC_ERR_KIND_UNKNOWN:
    default: {
        /* Successful body / not-yet-classified: leave the
         * defaults. error_flag stays 0; message stays empty. */
        break;
    }
    }
}

pubnub_res_t pubnub_response_service_error(pubnub_future_t         future,
                                           pubnub_service_error_t* out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    /* Safe default before any lookup, so a non-OK return still leaves
     * the caller with a zero-initialised envelope. */
    memset(out, 0, sizeof(*out));

    if (NULL == future.ctx) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        /* Future is invalid OR not yet terminal; the second case
         * mirrors the IN_PROGRESS contract of pubnub_future_status. */
        pn_request_pool_t* pool = pn_context_request_pool(future.ctx);
        if (NULL != pool) {
            pn_request_t* maybe = pn_request_pool_get(pool, future.slot_id);
            if (NULL != maybe && future.generation == maybe->generation
                && !pn_request_is_ready(maybe)) {
                return PUBNUB_IN_PROGRESS;
            }
        }
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);

    pn_service_error_kind_t kind = pn_request_get_service_error_kind(slot, serial);

    /* Classifier returned RAW_TEXT and no body bytes? Genuinely
     * nothing recoverable (transport never observed HTTP framing
     * AND no diagnostic bytes either). */
    if (PN_SVC_ERR_KIND_RAW_TEXT == kind
        && (NULL == slot->http_response.body || 0 == slot->http_response.body_len)) {
        return PUBNUB_ERR_TRANSPORT;
    }

    fold_envelope(serial, slot, kind, slot->parsed_body_tree, out);
    return PUBNUB_OK;
}

/**
 * @brief Resolve the slot's classified kind + parsed tree pair.
 *
 * Used by both iterator helpers. Returns NULL tree when the slot
 * is not classified or the variant does not surface iterable
 * structures.
 */
static const pubnub_json_value_t*
locate_kind_and_tree(pubnub_future_t                   future,
                     pn_service_error_kind_t*          out_kind,
                     pubnub_serialization_provider_t** out_serial)
{
    *out_kind   = PN_SVC_ERR_KIND_UNKNOWN;
    *out_serial = NULL;

    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return NULL;
    }
    pubnub_serialization_provider_t* serial = pn_context_serialization(future.ctx);
    *out_serial = serial;

    pn_service_error_kind_t kind = pn_request_get_service_error_kind(slot, serial);
    *out_kind = kind;

    return slot->parsed_body_tree;
}

size_t pubnub_service_error_detail_count(pubnub_future_t future)
{
    pn_service_error_kind_t          kind   = PN_SVC_ERR_KIND_UNKNOWN;
    pubnub_serialization_provider_t* serial = NULL;
    const pubnub_json_value_t* root = locate_kind_and_tree(future, &kind, &serial);
    if (NULL == root || NULL == serial || PN_SVC_ERR_KIND_OBJ_PAM_DETAILS != kind) {
        return 0;
    }
    if (NULL == serial->object_get || NULL == serial->value_type
        || NULL == serial->array_size) {
        return 0;
    }
    pubnub_json_value_t* err = serial->object_get(root, "error", 5);
    if (NULL == err) {
        return 0;
    }
    pubnub_json_value_t* details = serial->object_get(err, "details", 7);
    if (NULL == details || PUBNUB_JSON_ARRAY != serial->value_type(details)) {
        return 0;
    }
    return serial->array_size(details);
}

pubnub_res_t pubnub_service_error_detail_at(pubnub_future_t future,
                                            size_t          index,
                                            pubnub_service_error_detail_t* out)
{
    if (NULL == out) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->message  = (pubnub_string_view_t){NULL, 0};
    out->location = (pubnub_string_view_t){NULL, 0};

    pn_service_error_kind_t          kind   = PN_SVC_ERR_KIND_UNKNOWN;
    pubnub_serialization_provider_t* serial = NULL;
    const pubnub_json_value_t* root = locate_kind_and_tree(future, &kind, &serial);
    if (NULL == root || NULL == serial || PN_SVC_ERR_KIND_OBJ_PAM_DETAILS != kind) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == serial->object_get || NULL == serial->value_type
        || NULL == serial->array_get || NULL == serial->array_size) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_json_value_t* err = serial->object_get(root, "error", 5);
    if (NULL == err) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    pubnub_json_value_t* details = serial->object_get(err, "details", 7);
    if (NULL == details || PUBNUB_JSON_ARRAY != serial->value_type(details)
        || index >= serial->array_size(details)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_json_value_t* entry = serial->array_get(details, index);
    if (NULL == entry || PUBNUB_JSON_OBJECT != serial->value_type(entry)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    out->message  = object_string_field(serial, entry, "message", 7);
    out->location = object_string_field(serial, entry, "location", 8);
    return PUBNUB_OK;
}

/**
 * @brief Locate the channels container for the variants that carry
 *        one. Variant 3 (history) reports per-channel objects under
 *        a top-level @c channels object; variant 5 (subscribe
 *        forbidden) reports a string array under
 *        @c payload.channels.
 *
 * Returns the iterable container (object or array) plus a flag
 * indicating which one. NULL when the variant has no channels.
 */
static const pubnub_json_value_t* locate_channels(pubnub_serialization_provider_t* serial,
                                                  pn_service_error_kind_t kind,
                                                  const pubnub_json_value_t* root,
                                                  int* out_is_array)
{
    *out_is_array = 0;
    if (NULL == serial || NULL == root || NULL == serial->object_get
        || NULL == serial->value_type) {
        return NULL;
    }
    if (PN_SVC_ERR_KIND_OBJ_HISTORY_FLAT == kind) {
        pubnub_json_value_t* ch = serial->object_get(root, "channels", 8);
        if (NULL == ch || PUBNUB_JSON_OBJECT != serial->value_type(ch)) {
            return NULL;
        }
        return ch;
    }
    if (PN_SVC_ERR_KIND_OBJ_BOOL_ERROR_FLAG == kind) {
        pubnub_json_value_t* payload = serial->object_get(root, "payload", 7);
        if (NULL == payload || PUBNUB_JSON_OBJECT != serial->value_type(payload)) {
            return NULL;
        }
        pubnub_json_value_t* ch = serial->object_get(payload, "channels", 8);
        if (NULL == ch || PUBNUB_JSON_ARRAY != serial->value_type(ch)) {
            return NULL;
        }
        *out_is_array = 1;
        return ch;
    }
    return NULL;
}

size_t pubnub_service_error_channel_count(pubnub_future_t future)
{
    pn_service_error_kind_t          kind   = PN_SVC_ERR_KIND_UNKNOWN;
    pubnub_serialization_provider_t* serial = NULL;
    const pubnub_json_value_t* root = locate_kind_and_tree(future, &kind, &serial);
    if (NULL == root || NULL == serial) {
        return 0;
    }
    int is_array = 0;
    const pubnub_json_value_t* ch = locate_channels(serial, kind, root, &is_array);
    if (NULL == ch) {
        return 0;
    }
    if (is_array) {
        return (NULL != serial->array_size) ? serial->array_size(ch) : 0;
    }
    return (NULL != serial->object_size) ? serial->object_size(ch) : 0;
}

pubnub_string_view_t pubnub_service_error_channel_at(pubnub_future_t future,
                                                     size_t          index)
{
    pubnub_string_view_t empty = {NULL, 0};

    pn_service_error_kind_t          kind   = PN_SVC_ERR_KIND_UNKNOWN;
    pubnub_serialization_provider_t* serial = NULL;
    const pubnub_json_value_t* root = locate_kind_and_tree(future, &kind, &serial);
    if (NULL == root || NULL == serial) {
        return empty;
    }
    int is_array = 0;
    const pubnub_json_value_t* ch = locate_channels(serial, kind, root, &is_array);
    if (NULL == ch) {
        return empty;
    }

    if (is_array) {
        if (NULL == serial->array_get || NULL == serial->array_size
            || NULL == serial->value_type || NULL == serial->value_as_string
            || index >= serial->array_size(ch)) {
            return empty;
        }
        pubnub_json_value_t* entry = serial->array_get(ch, index);
        if (NULL == entry || PUBNUB_JSON_STRING != serial->value_type(entry)) {
            return empty;
        }
        size_t      n = 0;
        const char* p = serial->value_as_string(entry, &n);
        if (NULL == p) {
            return empty;
        }
        return (pubnub_string_view_t){p, n};
    }

    /* History per-channel report: keys of the @c channels object
     * are the channel names. Walk the iterator to the requested
     * index. */
    if (NULL == serial->object_iter_init || NULL == serial->object_iter_next
        || NULL == serial->object_size || index >= serial->object_size(ch)) {
        return empty;
    }
    pubnub_json_iter_t it;
    if (!serial->object_iter_init(ch, &it)) {
        return empty;
    }
    size_t               pos     = 0;
    const char*          key     = NULL;
    size_t               key_len = 0;
    pubnub_json_value_t* val     = NULL;
    while (serial->object_iter_next(&it, &key, &key_len, &val)) {
        if (pos == index && NULL != key) {
            return (pubnub_string_view_t){key, key_len};
        }
        pos++;
    }
    return empty;
}

/* Pin the public envelope size so future field additions trip a
 * compile-time gate. Two layouts are intentional: 56 bytes when
 * pointers are 8 bytes (LP64 / LLP64), 32 bytes when pointers are 4
 * bytes (ILP32). Any other value is an unintentional ABI change. */
PUBNUB_STATIC_ASSERT(sizeof(pubnub_service_error_t) == 56
                         || sizeof(pubnub_service_error_t) == 32,
                     "pubnub_service_error_t size unexpectedly changed");

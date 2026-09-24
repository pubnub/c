/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file response.c
 * @brief Core-level response accessors.
 *
 * Status code and raw body access stay here; error-message
 * extraction is delegated to the folded service_error layer.
 */

#include "pubnub/response.h"

#include "core_internal.h"
#include "pubnub/service_error.h"
#include "runtime/request_internal.h"
#include "runtime/request_pool_internal.h"

#include <stddef.h>
#include <stdint.h>

int pubnub_response_status_code(pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return 0;
    }
    if (PUBNUB_HTTP_COMPLETE != slot->http_response.completion) {
        return 0;
    }
    return slot->http_response.status_code;
}

pubnub_string_view_t pubnub_response_body(pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return (pubnub_string_view_t){NULL, 0};
    }
    if (PUBNUB_HTTP_COMPLETE != slot->http_response.completion) {
        return (pubnub_string_view_t){NULL, 0};
    }
    if (NULL == slot->http_response.body || 0 == slot->http_response.body_len) {
        return (pubnub_string_view_t){NULL, 0};
    }
    return (pubnub_string_view_t){(const char*)slot->http_response.body,
                                  slot->http_response.body_len};
}

pubnub_string_view_t pubnub_response_error_message(pubnub_future_t future)
{
    pubnub_service_error_t err;
    if (PUBNUB_OK != pubnub_response_service_error(future, &err)) {
        return (pubnub_string_view_t){NULL, 0};
    }
    return err.message;
}

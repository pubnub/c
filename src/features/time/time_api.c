/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "time_internal.h"

#if !PUBNUB_ENABLE_TIME
#error "time_api.c requires PUBNUB_ENABLE_TIME=ON - this translation unit " \
    "has no meaning without the time feature. Check the CMake feature "  \
    "gating in src/features/CMakeLists.txt; the file must not appear in " \
    "the build when the flag is off."
#endif

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "pubnub/client.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Owned timetoken storage must stay within the small feature-state budget;
 * the accessor returns a view into it, so it must not grow unbounded. */
PUBNUB_STATIC_ASSERT(sizeof(pn_time_state_t) <= 32,
                     "pn_time_state_t exceeds the small feature-state budget");

pubnub_future_t pubnub_time(pubnub_context_t* ctx)
{
    pn_feature_prep_t prep;
    pubnub_res_t      rc = pn_feature_prepare(ctx,
                                         (uint8_t)PUBNUB_FEATURE_TIME,
                                         sizeof(pn_time_state_t),
                                         pn_time_feature_state_cleanup,
                                         pn_time_response_validator,
                                         PUBNUB_HTTP_GET,
                                         0,
                                         &prep);
    if (PUBNUB_OK != rc) {
        return pn_failed_future(rc);
    }

    /* Capture the timetoken digits at completion, in the body-valid
     * window. A dedicated hook (not on_complete) is used because
     * pubnub_async overwrites on_complete and would silently clobber a
     * capture installed there, re-opening the use-after-free. */
    prep.entry->response_capture = pn_time_capture_timetoken;

    rc = pn_time_build_path(&prep.entry->http_request);
    if (PUBNUB_OK != rc) {
        pn_feature_prep_release(ctx, &prep);
        PN_LOG_ERROR_ENTRY(ctx, (int)rc, pubnub_res_str(rc), NULL);
        return pn_failed_future(rc);
    }

    PUBNUB_LOG_TEXT(pn_context_logger(ctx),
                    PUBNUB_LOG_LEVEL_DEBUG,
                    "Time request dispatched");

    return pn_dispatch_or_enqueue(ctx, prep.entry);
}

void pn_time_capture_timetoken(pn_request_t* slot)
{
    pubnub_timetoken_t view = {0};
    pn_time_state_t*   s;
    size_t             n;

    if (NULL == slot) {
        return;
    }

    s = (pn_time_state_t*)pn_request_feature_state_for(slot, PUBNUB_FEATURE_TIME);
    if (NULL == s) {
        return;
    }

    if (PUBNUB_OK
        != pn_time_parse_response(
            slot->http_response.body, slot->http_response.body_len, &view)) {
        s->tt_len = 0;
        return;
    }

    n = view.len;
    if (n > sizeof(s->tt) - 1) {
        /* A token that cannot fit is treated as absent rather than
         * truncated: a truncated token would read as a valid-but-wrong
         * value. Realistic uint64 timetokens are <= 20 digits, so this
         * only guards adversarial/malformed bodies. */
        s->tt_len = 0;
        return;
    }
    if (n > 0 && NULL != view.ptr) {
        memcpy(s->tt, view.ptr, n);
    }
    s->tt[n]  = '\0';
    s->tt_len = (uint8_t)n;
}

pubnub_timetoken_t pubnub_time_result_timetoken(pubnub_future_t future)
{
    pn_request_t* slot = pn_ready_slot_for_future(future);
    if (NULL == slot) {
        return (pubnub_timetoken_t){NULL, 0};
    }

    pn_time_state_t* s =
        (pn_time_state_t*)pn_request_feature_state_for(slot, PUBNUB_FEATURE_TIME);
    if (NULL == s || 0 == s->tt_len) {
        return (pubnub_timetoken_t){NULL, 0};
    }

    return (pubnub_timetoken_t){s->tt, s->tt_len};
}

void pn_time_feature_state_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    if (NULL == state || NULL == alloc) {
        return;
    }
    if (NULL != alloc->free) {
        PN_FREE(alloc, state);
    }
}

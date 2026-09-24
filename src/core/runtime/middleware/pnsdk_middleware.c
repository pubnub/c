/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pnsdk_middleware.c
 * @brief Middleware that appends `pnsdk=PubNub-C-core/<version>` to every request.
 *
 * The SDK identifier value is baked in at build time via
 * PUBNUB_SDK_IDENTIFIER (see config.h). There is no runtime
 * configuration for it - the format is canonical and shared by
 * every build of this SDK.
 */

#include "middleware_internal.h"

#include "core/pn_format.h"
#include "pubnub/config.h"

/** Stack buffer size for the combined pnsdk value. */
#define PN_PNSDK_MAX_LEN 128

static pubnub_transport_handle_t* pnsdk_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    if (NULL == self || NULL == response) {
        return NULL;
    }
    pn_middleware_pnsdk_t* mw = (pn_middleware_pnsdk_t*)self;
    if (NULL == mw->next) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Skip decoration for external requests (e.g., S3 uploads). */
    if (request->external) {
        return mw->next->send(mw->next, request, response);
    }

    const char* base =
        (NULL != mw->pnsdk_override && '\0' != mw->pnsdk_override[0])
            ? mw->pnsdk_override
            : PUBNUB_SDK_IDENTIFIER;
    const char* value = base;
    char        buf[PN_PNSDK_MAX_LEN];

    if (NULL != mw->suffix && '\0' != mw->suffix[0]) {
        pn_snprintf(buf, sizeof(buf), "%s %s", base, mw->suffix);
        value = buf;
    }

    if (PUBNUB_OK
        != pn_request_add_query_param(request, "pnsdk", value, PN_ENCODE_FULL)) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    return mw->next->send(mw->next, request, response);
}

static int pnsdk_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    if (NULL == self) {
        return -1;
    }
    pn_middleware_pnsdk_t* mw = (pn_middleware_pnsdk_t*)self;
    if (NULL == mw->next) {
        return -1;
    }
    return mw->next->poll(mw->next, timeout_ms);
}

static void pnsdk_cancel(pubnub_transport_provider_t* self,
                         pubnub_transport_handle_t*   transport_handle)
{
    if (NULL == self) {
        return;
    }
    pn_middleware_pnsdk_t* mw = (pn_middleware_pnsdk_t*)self;
    if (NULL == mw->next) {
        return;
    }
    mw->next->cancel(mw->next, transport_handle);
}

void pn_middleware_pnsdk_init(pn_middleware_pnsdk_t*       mw,
                              const char*                  pnsdk_override,
                              const char*                  suffix,
                              pubnub_transport_provider_t* next)
{
    if (NULL == mw || NULL == next) {
        return;
    }

    mw->base.send      = pnsdk_send;
    mw->base.poll      = pnsdk_poll;
    mw->base.cancel    = pnsdk_cancel;
    mw->base.init      = NULL;
    mw->base.deinit    = NULL;
    mw->next           = next;
    mw->suffix         = suffix;
    mw->pnsdk_override = pnsdk_override;
}

pubnub_transport_provider_t*
pn_middleware_pnsdk_create(const char*                  pnsdk_override,
                           const char*                  suffix,
                           pubnub_transport_provider_t* next,
                           pubnub_allocator_provider_t* allocator)
{
    if (NULL == allocator || NULL == allocator->alloc || NULL == next) {
        return NULL;
    }

    pn_middleware_pnsdk_t* mw =
        (pn_middleware_pnsdk_t*)PN_ALLOC(allocator, sizeof(*mw), 0);
    if (NULL == mw) {
        return NULL;
    }
    pn_middleware_pnsdk_init(mw, pnsdk_override, suffix, next);

    return (pubnub_transport_provider_t*)mw;
}

void pn_middleware_pnsdk_destroy(pubnub_transport_provider_t* mw,
                                 pubnub_allocator_provider_t* allocator)
{
    if (NULL == mw) {
        return;
    }
    if (NULL == allocator || NULL == allocator->free) {
        return;
    }
    PN_FREE(allocator, mw);
}

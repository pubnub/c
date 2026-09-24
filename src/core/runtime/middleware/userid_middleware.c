/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file userid_middleware.c
 * @brief Middleware that appends `uuid=<user_id>` to every request.
 *
 * The user_id is a pointer-to-pointer so that runtime changes via
 * pubnub_set_user_id() are visible without re-initializing the
 * middleware - matches the pattern already used by auth.
 */

#include "middleware_internal.h"

static pubnub_transport_handle_t* userid_send(pubnub_transport_provider_t* self,
                                              pubnub_http_request_t*  request,
                                              pubnub_http_response_t* response)
{
    if (NULL == self || NULL == response) {
        return NULL;
    }
    pn_middleware_user_id_t* mw = (pn_middleware_user_id_t*)self;
    if (NULL == mw->next) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Skip decoration for external requests (e.g., S3 uploads). */
    if (request->external) {
        return mw->next->send(mw->next, request, response);
    }

    if (NULL == mw->user_id || NULL == *mw->user_id) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    if (PUBNUB_OK
        != pn_request_add_query_param(request, "uuid", *mw->user_id, PN_ENCODE_FULL)) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    return mw->next->send(mw->next, request, response);
}

static int userid_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    if (NULL == self) {
        return -1;
    }
    pn_middleware_user_id_t* mw = (pn_middleware_user_id_t*)self;
    if (NULL == mw->next) {
        return -1;
    }
    return mw->next->poll(mw->next, timeout_ms);
}

static void userid_cancel(pubnub_transport_provider_t* self,
                          pubnub_transport_handle_t*   transport_handle)
{
    if (NULL == self) {
        return;
    }
    pn_middleware_user_id_t* mw = (pn_middleware_user_id_t*)self;
    if (NULL == mw->next) {
        return;
    }
    mw->next->cancel(mw->next, transport_handle);
}

void pn_middleware_userid_init(pn_middleware_user_id_t*     mw,
                               const char* const*           user_id,
                               pubnub_transport_provider_t* next)
{
    if (NULL == mw || NULL == next || NULL == user_id) {
        return;
    }

    mw->base.send   = userid_send;
    mw->base.poll   = userid_poll;
    mw->base.cancel = userid_cancel;
    mw->base.init   = NULL;
    mw->base.deinit = NULL;
    mw->next        = next;
    mw->user_id     = user_id;
}

pubnub_transport_provider_t*
pn_middleware_userid_create(const char* const*           user_id,
                            pubnub_transport_provider_t* next,
                            pubnub_allocator_provider_t* allocator)
{
    if (NULL == allocator || NULL == allocator->alloc || NULL == next
        || NULL == user_id) {
        return NULL;
    }

    pn_middleware_user_id_t* mw =
        (pn_middleware_user_id_t*)PN_ALLOC(allocator, sizeof(*mw), 0);
    if (NULL == mw) {
        return NULL;
    }
    pn_middleware_userid_init(mw, user_id, next);

    return (pubnub_transport_provider_t*)mw;
}

void pn_middleware_userid_destroy(pubnub_transport_provider_t* mw,
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

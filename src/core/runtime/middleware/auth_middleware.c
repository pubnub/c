/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file auth_middleware.c
 * @brief Middleware that appends `auth=<token>` when an auth token is set.
 *
 * The auth_token is a pointer-to-pointer so that runtime changes via
 * pubnub_set_auth_token() are visible without re-initializing the
 * middleware.
 */

#include "middleware_internal.h"

#include "core/protocol_common/pn_url_encode.h"

#include <string.h>

static pubnub_transport_handle_t* auth_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    if (NULL == self || NULL == response) {
        return NULL;
    }
    pn_middleware_auth_t* mw = (pn_middleware_auth_t*)self;
    if (NULL == mw->next) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Skip decoration for external requests (e.g., S3 uploads). */
    if (request->external) {
        return mw->next->send(mw->next, request, response);
    }

    /* No token configured — passthrough. */
    if (NULL == mw->auth_token || NULL == *mw->auth_token) {
        return mw->next->send(mw->next, request, response);
    }

    const char* tok = *mw->auth_token;

    /* strcmp, not pointer compare: a new token may land at the same address
     * as the freed old one (ABA), making pointer identity miss the change. */
    if (NULL == mw->cached_raw_str || 0 != strcmp(tok, mw->cached_raw_str)) {
        const size_t tok_len  = strlen(tok);
        char*        raw_copy = (char*)PN_ALLOC(mw->allocator, tok_len + 1, 0);
        char*        encoded  = NULL;

        /* Allocate the new raw copy before freeing the old cache, so a
         * failed allocation leaves the old (stale but safe) cached values
         * intact for the next call. */
        if (NULL == raw_copy) {
            response->completion = PUBNUB_HTTP_ERROR;
            return NULL;
        }
        memcpy(raw_copy, tok, tok_len + 1);

        if (NULL != mw->cached_encoded) {
            PN_FREE(mw->allocator, mw->cached_encoded);
            mw->cached_encoded = NULL;
        }
        if (NULL != mw->cached_raw_str) {
            PN_FREE(mw->allocator, mw->cached_raw_str);
            mw->cached_raw_str = NULL;
        }

        /* PAM tokens can exceed 10KB (grows with granted resources),
         * so scratch buffer (typically 128-512B) is not sufficient. */
        encoded = pn_url_encode_alloc_n(
            (const uint8_t*)tok, tok_len, mw->allocator, PN_ENCODE_FULL);
        if (NULL == encoded) {
            PN_FREE(mw->allocator, raw_copy);
            response->completion = PUBNUB_HTTP_ERROR;
            return NULL;
        }

        /* Publish the raw copy only after the encoded value is in
         * place, so a failed encode never leaves a content match with
         * a NULL cached_encoded (which would skip re-encode next call). */
        mw->cached_raw_str = raw_copy;
        mw->cached_encoded = encoded;
    }

    pubnub_string_view_t val = {mw->cached_encoded, strlen(mw->cached_encoded)};
    if (PUBNUB_OK != pn_request_add_query_param_view(request, "auth", val)) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Security: log only that auth is attached, never the token value. */
    PUBNUB_LOG_TEXT(mw->logger, PUBNUB_LOG_LEVEL_TRACE, "Auth token attached");

    return mw->next->send(mw->next, request, response);
}

static int auth_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    if (NULL == self) {
        return -1;
    }
    pn_middleware_auth_t* mw = (pn_middleware_auth_t*)self;
    if (NULL == mw->next) {
        return -1;
    }
    return mw->next->poll(mw->next, timeout_ms);
}

static void auth_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   transport_handle)
{
    if (NULL == self) {
        return;
    }
    pn_middleware_auth_t* mw = (pn_middleware_auth_t*)self;
    if (NULL == mw->next) {
        return;
    }
    mw->next->cancel(mw->next, transport_handle);
}

void pn_middleware_auth_init(pn_middleware_auth_t*        mw,
                             const char* const*           auth_token,
                             pubnub_transport_provider_t* next,
                             pubnub_allocator_provider_t* allocator)
{
    if (NULL == mw || NULL == next || NULL == allocator) {
        return;
    }

    mw->base.send      = auth_send;
    mw->base.poll      = auth_poll;
    mw->base.cancel    = auth_cancel;
    mw->base.init      = NULL;
    mw->base.deinit    = NULL;
    mw->next           = next;
    mw->auth_token     = auth_token;
    mw->allocator      = allocator;
    mw->logger         = NULL;
    mw->cached_raw_str = NULL;
    mw->cached_encoded = NULL;
}

pubnub_transport_provider_t*
pn_middleware_auth_create(const char* const*           auth_token,
                          pubnub_transport_provider_t* next,
                          pubnub_allocator_provider_t* allocator,
                          pubnub_logger_provider_t*    logger)
{
    if (NULL == allocator || NULL == allocator->alloc || NULL == allocator->free
        || NULL == next) {
        return NULL;
    }

    pn_middleware_auth_t* mw =
        (pn_middleware_auth_t*)PN_ALLOC(allocator, sizeof(*mw), 0);
    if (NULL == mw) {
        return NULL;
    }
    pn_middleware_auth_init(mw, auth_token, next, allocator);
    mw->logger = logger;

    return (pubnub_transport_provider_t*)mw;
}

void pn_middleware_auth_deinit(pn_middleware_auth_t* mw)
{
    if (NULL == mw || NULL == mw->allocator) {
        return;
    }
    if (NULL != mw->cached_encoded) {
        PN_FREE(mw->allocator, mw->cached_encoded);
        mw->cached_encoded = NULL;
    }
    if (NULL != mw->cached_raw_str) {
        PN_FREE(mw->allocator, mw->cached_raw_str);
        mw->cached_raw_str = NULL;
    }
}

void pn_middleware_auth_destroy(pubnub_transport_provider_t* mw,
                                pubnub_allocator_provider_t* allocator)
{
    if (NULL == mw) {
        return;
    }
    if (NULL == allocator || NULL == allocator->free) {
        return;
    }

    pn_middleware_auth_deinit((pn_middleware_auth_t*)mw);
    PN_FREE(allocator, mw);
}

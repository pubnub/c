/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pipeline.c
 * @brief Request pipeline orchestrator.
 *
 * The low-level pn_pipeline_init() just stores a pre-built chain;
 * it is decoupled from every middleware type. A convenience helper,
 * pn_pipeline_prepare_pubnub_middlewares(), creates the SDK's canonical
 * middleware chain and delegates to pn_pipeline_init(). Features call
 * only pn_request_dispatch(); they never see the middleware types.
 *
 * Dispatch order (outermost to innermost):
 *   auth -> pnsdk -> userid -> [retry] -> [signature] -> [compression] -> transport
 *
 * Construction order is the reverse: compression wraps transport first,
 * then each subsequent layer wraps the previous head.
 */

#include "pipeline_internal.h"

#include "middleware/middleware_internal.h"
#include "middleware/compression_middleware/pn_middleware_compression.h"
#include "pubnub/pubnub_compat.h"

#include <string.h>

/** @brief Number of built-in middleware layers the canonical chain
 *         creates. Used to size local arrays exactly and to validate
 *         at compile time that the configured cap is sufficient. */
#define PN_PIPELINE_BUILTIN_LAYER_COUNT \
    (3 + PUBNUB_ENABLE_PAM + PUBNUB_ENABLE_RETRY + PUBNUB_ENABLE_REQUEST_COMPRESSION)

PUBNUB_STATIC_ASSERT(PN_PIPELINE_BUILTIN_LAYER_COUNT
                         <= PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES,
                     "builtin middleware count exceeds pipeline capacity");

pubnub_res_t pn_pipeline_init(pn_pipeline_t*                      pipeline,
                              pubnub_transport_provider_t*        chain_head,
                              pubnub_transport_provider_t* const* layers,
                              const pn_middleware_destroy_fn_t*   destroys,
                              unsigned int                        layer_count,
                              pubnub_allocator_provider_t*        allocator)
{
    if (NULL == pipeline) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == chain_head) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == layers) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == destroys) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == allocator) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (0 == layer_count || layer_count > PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    for (unsigned int i = 0; i < layer_count; i++) {
        if (NULL == layers[i] || NULL == destroys[i]) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
    }

    memset(pipeline, 0, sizeof(*pipeline));
    pipeline->allocator  = allocator;
    pipeline->chain_head = chain_head;
    for (unsigned int i = 0; i < layer_count; i++) {
        pipeline->owned[i].layer   = layers[i];
        pipeline->owned[i].destroy = destroys[i];
    }
    pipeline->owned_count = layer_count;

    return PUBNUB_OK;
}

void pn_pipeline_deinit(pn_pipeline_t* pipeline)
{
    if (NULL == pipeline) {
        return;
    }

    /* Free in reverse construction order (outermost first). Each
     * layer is released through its own _destroy() so teardown is
     * symmetric with _create() and future type-specific cleanup
     * hooks land in the right place. */
    for (unsigned int i = pipeline->owned_count; i > 0; i--) {
        pn_owned_middleware_t* owned = &pipeline->owned[i - 1];
        if (NULL != owned->layer && NULL != owned->destroy) {
            owned->destroy(owned->layer, pipeline->allocator);
        }
        owned->layer   = NULL;
        owned->destroy = NULL;
    }
    pipeline->owned_count = 0;
    pipeline->chain_head  = NULL;
    pipeline->allocator   = NULL;
    pipeline->logger      = NULL;
}

pubnub_res_t pn_request_dispatch(pn_pipeline_t*              pipeline,
                                 pn_request_t*               req,
                                 pubnub_platform_provider_t* platform)
{
    if (NULL == pipeline) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == req) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (PN_REQUEST_PENDING != req->state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == pipeline->chain_head) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    /* Propagate the pipeline's logger to the request slot so that
     * success/failure/cancel transitions can emit log entries. */
    req->logger = pipeline->logger;

    pubnub_transport_handle_t* handle = pipeline->chain_head->send(
        pipeline->chain_head, &req->http_request, &req->http_response);

    if (NULL == handle) {
        /* Chain or transport rejected the request immediately.
         * Middlewares that short-circuit already set
         * http_response.completion = PUBNUB_HTTP_ERROR before
         * returning NULL per the transport contract.
         *
         * The request is still PENDING; drive it through IN_FLIGHT
         * briefly so PN_REQUEST_ON_FAILURE()'s precondition is met
         * (IN_FLIGHT is the only source state for failure). This
         * keeps the state machine invariants intact. */
        pubnub_res_t err = req->http_response.transport_error;
        if (PUBNUB_OK == err) {
            err = PUBNUB_ERR_TRANSPORT;
        }
        req->state = PN_REQUEST_IN_FLIGHT;
        PN_REQUEST_ON_FAILURE(req, err);

        return err;
    }

    pubnub_res_t rc = pn_request_accept_handle(req, handle);
    if (NULL != platform && PUBNUB_OK == rc && 0 != req->http_request.timeout_ms) {
        req->deadline = pn_timer_start(
            (pubnub_milliseconds_t)req->http_request.timeout_ms, platform);
    }
    return rc;
}

/**
 * @brief Release every non-NULL entry of @p layers via the matching
 *        @p destroys teardown.
 *
 * Used by pn_pipeline_prepare_pubnub_middlewares() to roll back a
 * partially built chain when any subsequent _create() fails.
 */
static void destroy_layers(pubnub_transport_provider_t* const* layers,
                           const pn_middleware_destroy_fn_t*   destroys,
                           unsigned int                        count,
                           pubnub_allocator_provider_t*        allocator)
{
    for (unsigned int i = 0; i < count; i++) {
        if (NULL != layers[i] && NULL != destroys[i]) {
            destroys[i](layers[i], allocator);
        }
    }
}

pubnub_res_t pn_pipeline_prepare_pubnub_middlewares(pn_pipeline_t* pipeline,
                                                    const pn_pipeline_prepare_opts_t* opts)
{
    if (NULL == pipeline || NULL == opts) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == opts->user_id || NULL == opts->allocator || NULL == opts->transport) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    pubnub_allocator_provider_t* allocator = opts->allocator;

    /* Build inside-out: compression is innermost (wraps transport).
     * Signature wraps compression — in call order signature.send fires
     * BEFORE compression.send, so HMAC is computed over the original
     * uncompressed body (matching JS/Kotlin SDK behaviour). Compression
     * then compresses the body before it reaches the wire. Retry wraps
     * both, so each re-dispatch gets a fresh HMAC over the uncompressed
     * body. Then userid, pnsdk, and auth (outermost). */
    pubnub_transport_provider_t* layers[PN_PIPELINE_BUILTIN_LAYER_COUNT] = {NULL};
    pn_middleware_destroy_fn_t destroys[PN_PIPELINE_BUILTIN_LAYER_COUNT] = {NULL};
    unsigned int count = 0;

    /* The "head" of the sub-chain built so far — used as `next` for
     * the next outer layer. Starts at the raw transport. */
    pubnub_transport_provider_t* inner = opts->transport;

    /* Layer 0 (conditional): compression (innermost, wraps transport).
     * Per-request gating via request->compress_body; features that
     * do not set it get transparent passthrough. */
    if (PUBNUB_ENABLE_REQUEST_COMPRESSION) {
        layers[count] =
            pn_middleware_compression_create(inner, allocator, opts->logger);
        if (NULL == layers[count]) {
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        destroys[count] = pn_middleware_compression_destroy;
        inner           = layers[count];
        count++;
    }

    /* Layer 1 (conditional): signature wraps [compression | transport]. */
    if (PUBNUB_ENABLE_PAM && NULL != opts->secret_key && NULL != *opts->secret_key) {
        layers[count] = pn_middleware_signature_create(opts->publish_key,
                                                       opts->secret_key,
                                                       opts->crypto,
                                                       inner,
                                                       allocator,
                                                       opts->platform,
                                                       opts->logger);
        if (NULL == layers[count]) {
            destroy_layers(layers, destroys, count, allocator);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        destroys[count] = pn_middleware_signature_destroy;
        inner           = layers[count];
        count++;
    }

    /* Layer 2 (conditional): retry wraps [signature | compression | transport]. */
    if (PUBNUB_ENABLE_RETRY && NULL != opts->retry_config
        && PUBNUB_RETRY_NONE != opts->retry_config->policy) {
        layers[count] = pn_middleware_retry_create(
            opts->retry_config, opts->platform, inner, allocator, opts->logger);
        if (NULL == layers[count]) {
            destroy_layers(layers, destroys, count, allocator);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        destroys[count] = pn_middleware_retry_destroy;
        inner           = layers[count];
        count++;
    }

    /* Layer N: userid wraps [retry | signature]. */
    layers[count] = pn_middleware_userid_create(opts->user_id, inner, allocator);
    if (NULL == layers[count]) {
        destroy_layers(layers, destroys, count, allocator);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    destroys[count] = pn_middleware_userid_destroy;
    inner           = layers[count];
    count++;

    /* Layer N+1: pnsdk wraps userid. */
    layers[count] = pn_middleware_pnsdk_create(
        opts->pnsdk_override, opts->pnsdk_suffix, inner, allocator);
    if (NULL == layers[count]) {
        destroy_layers(layers, destroys, count, allocator);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    destroys[count] = pn_middleware_pnsdk_destroy;
    inner           = layers[count];
    count++;

    /* Layer N+2: auth wraps pnsdk (outermost). */
    layers[count] =
        pn_middleware_auth_create(opts->auth_token, inner, allocator, opts->logger);
    if (NULL == layers[count]) {
        destroy_layers(layers, destroys, count, allocator);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    destroys[count] = pn_middleware_auth_destroy;
    count++;

    pubnub_res_t rc = pn_pipeline_init(pipeline,
                                       /*chain_head=*/layers[count - 1],
                                       layers,
                                       destroys,
                                       count,
                                       allocator);
    if (PUBNUB_OK != rc) {
        destroy_layers(layers, destroys, count, allocator);
        return rc;
    }

    pipeline->logger = opts->logger;

    return PUBNUB_OK;
}

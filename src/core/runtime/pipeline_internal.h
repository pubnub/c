/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pipeline_internal.h
 * @brief Request-pipeline orchestrator.
 *
 * Owns the middleware chain wrapping the transport provider.
 * Dispatch order (outermost to innermost):
 *   auth -> pnsdk -> userid -> [retry] -> [signature] -> [compression] -> transport
 *
 * Compression is innermost (wraps transport). Signature wraps
 * compression — in call order signature fires before compression,
 * so HMAC covers the uncompressed body (matching JS/Kotlin SDK
 * behaviour). Retry sits before signature so re-dispatches get a
 * fresh HMAC over the uncompressed body and re-compress. Signature, compression, and
 * retry are optional layers controlled by compile-time toggles
 * and runtime configuration.
 */

#ifndef PN_PIPELINE_INTERNAL_H
#define PN_PIPELINE_INTERNAL_H

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport.h"
#include "request_internal.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** @brief Teardown function for an owned middleware layer. */
typedef void (*pn_middleware_destroy_fn_t)(pubnub_transport_provider_t* mw,
                                           pubnub_allocator_provider_t* allocator);

/**
 * @brief A single middleware layer owned by the pipeline.
 */
typedef struct pn_owned_middleware {
    /** Owned middleware instance. */
    pubnub_transport_provider_t* layer;
    /** Type-specific teardown. */
    pn_middleware_destroy_fn_t destroy;
} pn_owned_middleware_t;

/** @brief Request pipeline - owns the middleware chain opaquely. */
typedef struct pn_pipeline {
    /** Outermost middleware in the chain (borrowed into @c owned). */
    pubnub_transport_provider_t* chain_head;

    /** Allocator used to construct the chain (borrowed). */
    pubnub_allocator_provider_t* allocator;

    /** Logger for network diagnostics (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;

    /** Middleware instances owned by this pipeline, in construction
     *  order (innermost first, outermost last). */
    pn_owned_middleware_t owned[PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES];

    /** Number of entries populated in @c owned. */
    unsigned int owned_count;
} pn_pipeline_t;

/**
 * @brief Initialize the pipeline from a pre-built middleware chain.
 *
 * Takes ownership of @p layers on success (freed in reverse during
 * pn_pipeline_deinit). On error the pipeline is left zeroed.
 *
 * @param pipeline    Pipeline to initialize (caller-owned).
 * @param chain_head  Outermost middleware (must appear in @p layers).
 * @param layers      Middleware layers, innermost first (each non-NULL).
 * @param destroys    Parallel teardown functions (each non-NULL).
 * @param layer_count Entries in layers/destroys.
 * @param allocator   Passed to destroys during teardown (borrowed).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_pipeline_init(pn_pipeline_t*                      pipeline,
                              pubnub_transport_provider_t*        chain_head,
                              pubnub_transport_provider_t* const* layers,
                              const pn_middleware_destroy_fn_t*   destroys,
                              unsigned int                        layer_count,
                              pubnub_allocator_provider_t*        allocator);

/**
 * @brief Options for building the canonical middleware chain.
 *
 * Passed by const-pointer to @ref pn_pipeline_prepare_pubnub_middlewares.
 * All pointer fields are borrowed and must outlive the pipeline.
 */
typedef struct pn_pipeline_prepare_opts {
    /** Pointer-to-pointer: current user ID (non-NULL). */
    const char* const* user_id;
    /** Pointer-to-pointer: current auth token (NULL disables auth). */
    const char* const* auth_token;
    /** SDK suffix string (may be NULL). */
    const char* pnsdk_suffix;
    /** Override for the base SDK identifier (may be NULL). */
    const char* pnsdk_override;
    /** Publisher key for PAMv3 signing (may be NULL). */
    const char* publish_key;
    /** Pointer-to-pointer: secret key (NULL disables signing). */
    const char* const* secret_key;
    /** Crypto provider for HMAC-SHA256 (may be NULL). */
    pubnub_crypto_provider_t* crypto;
    /** Allocator (must outlive pipeline). */
    pubnub_allocator_provider_t* allocator;
    /** Platform for PAMv3 timestamp (may be NULL). */
    pubnub_platform_provider_t* platform;
    /** Innermost transport (must outlive pipeline). */
    pubnub_transport_provider_t* transport;
    /** Retry configuration (may be NULL). */
    const pubnub_retry_configuration_t* retry_config;
    /** Logger for network diagnostics (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;
} pn_pipeline_prepare_opts_t;

/**
 * @brief Build the canonical middleware chain and initialize the pipeline.
 *
 * Wraps the transport from @p opts with auth, pnsdk, userid, [retry],
 * [signature], and [compression] middlewares. Rolls back on allocation
 * failure.
 *
 * @param pipeline Pipeline to initialize (caller-owned).
 * @param opts     Configuration for the chain (borrowed, non-NULL).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t
pn_pipeline_prepare_pubnub_middlewares(pn_pipeline_t* pipeline,
                                       const pn_pipeline_prepare_opts_t* opts);

/**
 * @brief Tear down the pipeline, freeing every owned middleware.
 *
 * @param pipeline Pipeline to tear down (no-op if zeroed).
 */
void pn_pipeline_deinit(pn_pipeline_t* pipeline);

/**
 * @brief Dispatch a PENDING request through the middleware chain.
 *
 * Starts the SDK-level deadline timer atomically when the slot
 * transitions to IN_FLIGHT (if timeout_ms is non-zero).
 *
 * @param pipeline Initialized pipeline (borrowed).
 * @param req      Request to dispatch (must be PENDING).
 * @param platform Platform provider for deadline timer (borrowed, may
 *                 be NULL — timer is skipped when NULL).
 * @return PUBNUB_OK when req entered IN_FLIGHT, or an error code.
 */
pubnub_res_t pn_request_dispatch(pn_pipeline_t*              pipeline,
                                 pn_request_t*               req,
                                 pubnub_platform_provider_t* platform);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_PIPELINE_INTERNAL_H */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_MIDDLEWARE_COMPRESSION_H
#define PN_MIDDLEWARE_COMPRESSION_H

#include "pubnub/providers/transport.h"

struct pubnub_allocator_provider;
struct pubnub_logger_provider;

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Create a compression middleware layer.
 *
 * Compresses POST/PATCH request bodies with gzip before passing to
 * the next transport layer. Adds Content-Encoding: gzip header.
 * Mutates the request body in-place during transit; original state is
 * restored automatically on completion, cancellation, or middleware
 * teardown (safe for retry/re-signing).
 *
 * @param next      Next transport layer in the chain.
 * @param allocator Allocator for compressed buffer (freed after send).
 * @param logger    Logger for diagnostic messages (borrowed, may be NULL).
 * @return Transport provider wrapping next, or NULL on allocation failure.
 */
pubnub_transport_provider_t*
pn_middleware_compression_create(pubnub_transport_provider_t*      next,
                                 struct pubnub_allocator_provider* allocator,
                                 struct pubnub_logger_provider*    logger);

/**
 * @brief Destroy the compression middleware and free resources.
 *
 * @param mw        Middleware instance (from _create). Safe with NULL.
 * @param allocator Allocator used for creation.
 */
void pn_middleware_compression_destroy(pubnub_transport_provider_t* mw,
                                       struct pubnub_allocator_provider* allocator);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_MIDDLEWARE_COMPRESSION_H */

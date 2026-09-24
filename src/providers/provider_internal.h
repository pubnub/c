/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Internal default-provider resolution (not installed).
 *
 * Each pn_<family>_default() returns the compiled-in default singleton,
 * or NULL if no builtin backend was selected for that family.
 */

#ifndef PN_PROVIDER_INTERNAL_H
#define PN_PROVIDER_INTERNAL_H

#include "config_internal.h"

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/crypto.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"

#if PN_USE_BUILTIN_ALLOCATOR
/** @brief Return the compiled-in default allocator provider singleton.
 *  @return Provider pointer (static singleton, never freed), or NULL if
 *          no builtin was selected. */
pubnub_allocator_provider_t* pn_allocator_default(void);
#else
static inline pubnub_allocator_provider_t* pn_allocator_default(void)
{
    return NULL;
}
#endif

#if PN_USE_BUILTIN_TRANSPORT
/** @brief Allocate a fresh per-context transport provider instance.
 *
 *  @param alloc  Resolved allocator (must be non-NULL with valid alloc).
 *  @return Transport provider ready for `init()`, or NULL on failure.
 */
pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc);
#else
static inline pubnub_transport_provider_t*
pn_transport_default(pubnub_allocator_provider_t* alloc)
{
    (void)alloc;
    return NULL;
}
#endif

#if PN_USE_BUILTIN_SERIALIZATION
/** @brief Return the compiled-in default serialization provider singleton.
 *  @return Provider pointer (static singleton, never freed), or NULL if
 *          no builtin was selected. */
pubnub_serialization_provider_t* pn_serialization_default(void);
#else
static inline pubnub_serialization_provider_t* pn_serialization_default(void)
{
    return NULL;
}
#endif

#if PN_USE_BUILTIN_CRYPTO
/** @brief Return the compiled-in default crypto provider singleton.
 *  @return Provider pointer (static singleton, never freed), or NULL if
 *          no builtin was selected. */
pubnub_crypto_provider_t* pn_crypto_default(void);
#else
static inline pubnub_crypto_provider_t* pn_crypto_default(void)
{
    return NULL;
}
#endif

#if PN_USE_BUILTIN_LOGGER
/** @brief Return the compiled-in default logger provider singleton.
 *  @return Provider pointer (static singleton, never freed), or NULL if
 *          no builtin was selected. */
pubnub_logger_provider_t* pn_logger_default(void);
#else
static inline pubnub_logger_provider_t* pn_logger_default(void)
{
    return NULL;
}
#endif

#if PN_USE_BUILTIN_PLATFORM
/** @brief Return the compiled-in default platform provider singleton.
 *  @return Provider pointer (static singleton, never freed), or NULL if
 *          no builtin was selected. */
pubnub_platform_provider_t* pn_platform_default(void);
#else
static inline pubnub_platform_provider_t* pn_platform_default(void)
{
    return NULL;
}
#endif

#endif /* PN_PROVIDER_INTERNAL_H */

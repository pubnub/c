/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief NULL-returning stubs for pn_*_default() factory functions.
 *
 * White-box tests link pn_core as OBJECT, pulling in client.c which
 * references these symbols. Real providers can't be linked here
 * (transport mocks would conflict; others drag in OpenSSL/cjson).
 */

#include "providers/provider_internal.h"

#if PN_USE_BUILTIN_TRANSPORT
pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc)
{
    (void)alloc;
    return NULL;
}
#endif

#if PN_USE_BUILTIN_SERIALIZATION
pubnub_serialization_provider_t* pn_serialization_default(void)
{
    return NULL;
}
#endif

#if PN_USE_BUILTIN_CRYPTO
pubnub_crypto_provider_t* pn_crypto_default(void)
{
    return NULL;
}
#endif

#if PN_USE_BUILTIN_LOGGER
pubnub_logger_provider_t* pn_logger_default(void)
{
    return NULL;
}
#endif

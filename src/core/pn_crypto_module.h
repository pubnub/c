/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_CRYPTO_MODULE_H
#define PN_CRYPTO_MODULE_H

#include "pubnub/config.h"

#if PUBNUB_ENABLE_CRYPTO

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/pubnub_compat.h"
#include "pubnub/types_fwd.h"

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

#ifndef PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS
#define PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS 4
#endif

/**
 * @brief Crypto module: manages a default cryptor and fallback
 *        cryptors for encrypt/decrypt dispatch.
 */
typedef struct pubnub_crypto_module {
    /** Default cryptor for encryption (always non-NULL). */
    pubnub_crypto_provider_t* default_cryptor;

    /** Fallback cryptors for decryption dispatch. */
    pubnub_crypto_provider_t* others[PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS];

    /** Number of valid entries in @c others. */
    size_t others_count;

    /** 1 = module owns cryptors (factory-created); 0 = borrowed. */
    int owns_cryptors;

    /** Allocator stored at creation for use by destroy. */
    pubnub_allocator_provider_t* alloc;
} pubnub_crypto_module_t;

PUBNUB_STATIC_ASSERT(
    PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS >= 1,
    "PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS must be at least 1");

/**
 * @brief Call init() on each cryptor in the module.
 *
 * Iterates the default cryptor and all fallback cryptors, calling
 * each non-NULL init() vtable entry with the provided deps. On
 * failure, already-initialized cryptors are rolled back via their
 * deinit().
 *
 * @param module Crypto module (may be NULL — returns 0 immediately).
 * @param deps   Provider dependency bag.
 * @return 0 on success, non-zero if any cryptor's init failed.
 */
int pn_crypto_module_providers_init(pubnub_crypto_module_t*       module,
                                    const pubnub_provider_deps_t* deps);

/**
 * @brief Call deinit() on each cryptor in the module.
 *
 * Iterates in reverse init order: fallback cryptors last-to-first,
 * then the default cryptor.
 *
 * @param module Crypto module (may be NULL — no-op).
 */
void pn_crypto_module_providers_deinit(pubnub_crypto_module_t* module);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_ENABLE_CRYPTO */

#endif /* PN_CRYPTO_MODULE_H */

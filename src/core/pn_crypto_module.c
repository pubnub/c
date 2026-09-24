/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_crypto_module.h"

#if PUBNUB_ENABLE_CRYPTO

#include <stddef.h>

int pn_crypto_module_providers_init(pubnub_crypto_module_t*       module,
                                    const pubnub_provider_deps_t* deps)
{
    if (NULL == module) {
        return 0;
    }

    pubnub_crypto_provider_t* dc = module->default_cryptor;
    if (NULL != dc && NULL != dc->init) {
        if (0 != dc->init(dc, deps)) {
            return -1;
        }
    }

    for (size_t i = 0; i < module->others_count; i++) {
        pubnub_crypto_provider_t* cp = module->others[i];
        if (NULL == cp || NULL == cp->init) {
            continue;
        }
        if (0 != cp->init(cp, deps)) {
            /* Roll back previously initialized fallbacks. */
            while (i > 0) {
                i--;
                pubnub_crypto_provider_t* prev = module->others[i];
                if (NULL != prev && NULL != prev->deinit) {
                    prev->deinit(prev);
                }
            }
            /* Roll back the default cryptor. */
            if (NULL != dc && NULL != dc->deinit) {
                dc->deinit(dc);
            }
            return -1;
        }
    }

    return 0;
}

void pn_crypto_module_providers_deinit(pubnub_crypto_module_t* module)
{
    if (NULL == module) {
        return;
    }

    /* Deinit in reverse init order: fallbacks last-to-first. */
    size_t i = module->others_count;
    while (i > 0) {
        i--;
        pubnub_crypto_provider_t* cp = module->others[i];
        if (NULL != cp && NULL != cp->deinit) {
            cp->deinit(cp);
        }
    }

    /* Deinit the default cryptor last. */
    if (NULL != module->default_cryptor && NULL != module->default_cryptor->deinit) {
        module->default_cryptor->deinit(module->default_cryptor);
    }
}

#else
typedef int pn_nonempty_crypto_module_;
#endif /* PUBNUB_ENABLE_CRYPTO */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_feature_registry.h"

#include <string.h>

void pn_feature_registry_init(pn_feature_registry_t* reg)
{
    if (NULL == reg) {
        return;
    }
    /* NULL == all-zero-bits on all supported targets (ARM, x86, RISC-V, Xtensa). */
    memset(reg, 0, sizeof(*reg));
}

void pn_feature_register(pn_feature_registry_t*  reg,
                         pubnub_feature_t        feature,
                         void*                   state,
                         pn_feature_cleanup_fn_t cleanup)
{
    if (NULL == reg || (unsigned)feature >= PUBNUB_FEATURE_COUNT) {
        return;
    }

    reg->slots[feature].state   = state;
    reg->slots[feature].cleanup = cleanup;
    reg->active_mask |= (uint32_t)1U << (unsigned)feature;
}

int pn_feature_registry_has(const pn_feature_registry_t* reg, pubnub_feature_t feature)
{
    if (NULL == reg || (unsigned)feature >= PUBNUB_FEATURE_COUNT) {
        return 0;
    }
    return 0 != (reg->active_mask & ((uint32_t)1U << (unsigned)feature));
}

void* pn_feature_registry_state(const pn_feature_registry_t* reg,
                                pubnub_feature_t             feature)
{
    if (NULL == reg || (unsigned)feature >= PUBNUB_FEATURE_COUNT) {
        return NULL;
    }
    if (0 == (reg->active_mask & ((uint32_t)1U << (unsigned)feature))) {
        return NULL;
    }
    return reg->slots[feature].state;
}

void pn_feature_registry_set_tick(pn_feature_registry_t* reg,
                                  pubnub_feature_t       feature,
                                  pn_feature_tick_fn_t   tick)
{
    if (NULL == reg || (unsigned)feature >= PUBNUB_FEATURE_COUNT) {
        return;
    }
    if (0 == (reg->active_mask & ((uint32_t)1U << (unsigned)feature))) {
        return;
    }
    reg->slots[feature].tick = tick;
}

int pn_feature_registry_tick_all(pn_feature_registry_t* reg)
{
    if (NULL == reg || 0 == reg->active_mask) {
        return 0;
    }

    int any_active = 0;
    for (unsigned i = 0; i < PUBNUB_FEATURE_COUNT; i++) {
        if (0 == (reg->active_mask & ((uint32_t)1U << i))) {
            continue;
        }
        if (NULL == reg->slots[i].tick || NULL == reg->slots[i].state) {
            continue;
        }
        if (reg->slots[i].tick(reg->slots[i].state)) {
            any_active = 1;
        }
    }
    return any_active;
}

void pn_feature_registry_cleanup_all(pn_feature_registry_t*       reg,
                                     pubnub_allocator_provider_t* alloc)
{
    if (NULL == reg) {
        return;
    }

    /* Reverse order: higher-level features torn down before deps. */
    unsigned i = PUBNUB_FEATURE_COUNT;
    while (i > 0) {
        --i;
        if (0 == (reg->active_mask & ((uint32_t)1U << i))) {
            continue;
        }
        if (NULL != reg->slots[i].cleanup && NULL != reg->slots[i].state) {
            reg->slots[i].cleanup(reg->slots[i].state, alloc);
        }
        reg->slots[i].state   = NULL;
        reg->slots[i].cleanup = NULL;
        reg->slots[i].tick    = NULL;
    }
    reg->active_mask = 0;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_channel_dispatch_state.h"

#include <stddef.h>

void pn_channel_dispatch_state_cleanup(void* state, pubnub_allocator_provider_t* alloc)
{
    pn_channel_dispatch_state_t* ds;

    if (NULL == state) {
        return;
    }

    ds = (pn_channel_dispatch_state_t*)state;

    if (NULL != ds->allocator) {
        if (NULL != ds->encoded_channels) {
            PN_FREE(ds->allocator, ds->encoded_channels);
        }
        if (NULL != ds->encoded_channel_groups) {
            PN_FREE(ds->allocator, ds->encoded_channel_groups);
        }
    }

    if (NULL != alloc) {
        PN_FREE(alloc, state);
    }
}

pn_channel_dispatch_state_t*
pn_channel_dispatch_state_create(char*                        encoded_channels,
                                 char*                        encoded_groups,
                                 pubnub_allocator_provider_t* allocator)
{
    pn_channel_dispatch_state_t* ds;

    if (NULL == allocator) {
        return NULL;
    }
    if (NULL == encoded_channels) {
        if (NULL != encoded_groups) {
            PN_FREE(allocator, encoded_groups);
        }
        return NULL;
    }

    ds = (pn_channel_dispatch_state_t*)PN_ALLOC(
        allocator, sizeof(pn_channel_dispatch_state_t), sizeof(void*));
    if (NULL == ds) {
        PN_FREE(allocator, encoded_channels);
        if (NULL != encoded_groups) {
            PN_FREE(allocator, encoded_groups);
        }
        return NULL;
    }

    ds->encoded_channels       = encoded_channels;
    ds->encoded_channel_groups = encoded_groups;
    ds->allocator              = allocator;

    return ds;
}

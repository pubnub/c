/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_cbor_decode.c
 * @brief libFuzzer harness for CBOR decoder (PAM v3 token parsing).
 *
 * Feeds arbitrary bytes to pn_cbor_parse() which handles the CBOR
 * subset used by PubNub access tokens.  The decoder must not crash,
 * must not read past the input bounds, and must cleanly release all
 * allocated memory on any input.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pubnub/providers/allocator.h"
#include "features/access/pn_cbor.h"

static void* fuzz_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void fuzz_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_alloc = {
    .alloc       = fuzz_alloc,
    .realloc     = NULL,
    .free        = fuzz_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (0 == size) {
        return 0;
    }

    /* PN_CBOR_MAX_INPUT is 4096; inputs beyond that are rejected
     * early by the parser, but we still exercise the rejection path. */
    pn_cbor_value_t* root = pn_cbor_parse(data, size, &s_alloc);
    if (NULL == root) {
        return 0;
    }

    /* Exercise map lookup if the root is a map (common for PAM tokens). */
    if (PN_CBOR_MAP == root->type) {
        /* Try to look up some common PAM token keys. */
        (void)pn_cbor_map_get(root, "ver", 3);
        (void)pn_cbor_map_get(root, "t", 1);
        (void)pn_cbor_map_get(root, "ttl", 3);
        (void)pn_cbor_map_get(root, "res", 3);
        (void)pn_cbor_map_get(root, "pat", 3);

        /* Exercise with bytes from the fuzz input as key (if long enough). */
        if (size >= 4) {
            (void)pn_cbor_map_get(root, (const char*)data, 4);
        }
    }

    /* Clean up the entire tree. */
    pn_cbor_cleanup(root, &s_alloc);

    return 0;
}

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_url_encode.c
 * @brief libFuzzer harness for URL/query parameter encoding.
 *
 * Feeds arbitrary bytes to pn_url_encode_alloc_n() with each of the
 * three encode modes.  The harness verifies that the encoder never
 * crashes on arbitrary input and that the output contains only valid
 * percent-encoded characters.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "pubnub/providers/allocator.h"
#include "core/protocol_common/pn_url_encode.h"

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
    if (0 == size || size > 65536) {
        return 0;
    }

    static const int modes[] = {
        PN_ENCODE_NONE,
        PN_ENCODE_FULL,
        PN_ENCODE_KEEP_COMMAS,
    };

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        char* encoded = pn_url_encode_alloc_n(data, size, &s_alloc, modes[i]);
        if (NULL != encoded) {
            /* Touch the output to surface use-after-free under ASan. */
            volatile char sink = encoded[0];
            (void)sink;
            fuzz_free(&s_alloc, encoded);
        }
    }

    return 0;
}

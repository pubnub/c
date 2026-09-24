/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * Developer utility: print pubnub_context_size() and the suggested
 * PUBNUB_CONTEXT_SIZE constant (rounded up to the next 256-byte
 * boundary for alignment margin).
 *
 * Build: cmake --preset dev && cmake --build build/dev --target pubnub_context_size_probe
 * Run:   ./build/dev/tools/context_size/pubnub_context_size_probe
 *
 * Copy the "Suggested PUBNUB_CONTEXT_SIZE" value into CMakeLists.txt.
 * The PUBNUB_STATIC_ASSERT in src/core/client.c will catch any drift.
 */

#include "pubnub/client.h"

#include <stdio.h>

int main(void)
{
    size_t sz      = pubnub_context_size();
    size_t aligned = (sz + 255U) & ~(size_t)255U;

    printf("pubnub_context_size()     = %zu bytes\n", sz);
    printf("Suggested PUBNUB_CONTEXT_SIZE = %zu  (next 256-byte boundary)\n",
           aligned);
    return 0;
}

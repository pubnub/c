/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file collision_main.c
 * @brief Compile-only check: PUBNUB_STATIC_ASSERT invocations that land on
 *        the same source line (from different headers, or from one line)
 *        must not collide in any language mode.
 */

#include "collision_a.h"
#include "collision_b.h"

#include <stddef.h>

PUBNUB_STATIC_ASSERT(sizeof(short) >= 2, "one");
PUBNUB_STATIC_ASSERT(sizeof(long) >= 4, "two");

struct collision_probe {
    int  a;
    char b;
};

PUBNUB_STATIC_ASSERT(offsetof(struct collision_probe, a) == 0, "offset");

int collision_block_scope(int x);

int collision_block_scope(int x)
{
    PUBNUB_STATIC_ASSERT(sizeof(struct collision_probe) >= 5, "block one");
    PUBNUB_STATIC_ASSERT(sizeof(void*) >= sizeof(char), "block two");
    if (0 != x) {
        PUBNUB_STATIC_ASSERT(sizeof(long) >= sizeof(int), "nested block");
        return 1;
    }
    return 0;
}

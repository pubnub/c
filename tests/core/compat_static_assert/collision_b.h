/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TEST_COMPAT_COLLISION_B_H
#define PN_TEST_COMPAT_COLLISION_B_H

#include "pubnub/pubnub_compat.h"

/* Same line number as collision_a.h on purpose. */
#line 100
PUBNUB_STATIC_ASSERT(sizeof(int) >= 2, "collision_b: int is >= 16 bits");

#endif

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TEST_COMPAT_COLLISION_A_H
#define PN_TEST_COMPAT_COLLISION_A_H

#include "pubnub/pubnub_compat.h"

/* Force the assertion onto a fixed line so that it coincides with the
 * one in collision_b.h regardless of how either header is edited. */
#line 100
PUBNUB_STATIC_ASSERT(sizeof(char) == 1, "collision_a: char is one byte");

#endif

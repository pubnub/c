/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file assert_false.c
 * @brief Negative check: a false PUBNUB_STATIC_ASSERT must fail to compile.
 *        Registered with WILL_FAIL.
 */

#include "pubnub/pubnub_compat.h"

PUBNUB_STATIC_ASSERT(sizeof(char) == 2, "must not compile");

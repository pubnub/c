/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/types.h"
#include "pubnub/pubnub_compat.h"

/* Field value clear marker. */
const char pubnub_clear_value_marker[] = "\0PN_CLEAR_VALUE";

PUBNUB_STATIC_ASSERT(
    sizeof(pubnub_clear_value_marker) > 1,
    "clear-value marker must hold unique non-foldable content");

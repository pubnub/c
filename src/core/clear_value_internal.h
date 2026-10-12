/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file clear_value_internal.h
 * @brief Internal helper for detecting the PUBNUB_CLEAR_VALUE sentinel.
 *
 * Not installed. Features that accept the clear-value marker use
 * @c PN_IS_CLEAR_VALUE to distinguish an explicit clear request from an
 * ordinary string value before wire encoding.
 */

#ifndef PN_CLEAR_VALUE_INTERNAL_H
#define PN_CLEAR_VALUE_INTERNAL_H

#include "pubnub/types.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Test whether a pointer is the PUBNUB_CLEAR_VALUE sentinel.
 *
 * @param p Candidate pointer (may be @c NULL).
 * @retval non-zero @p p is the clear-value sentinel.
 * @retval 0 @p p is any other pointer (including @c NULL).
 */
#define PN_IS_CLEAR_VALUE(p) ((const char*)(p) == pubnub_clear_value_marker)

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_CLEAR_VALUE_INTERNAL_H */

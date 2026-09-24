/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#ifndef PUBNUB_IT_CHANNEL_H
#define PUBNUB_IT_CHANNEL_H

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/** Maximum suffix length (excluding NUL). */
#define IT_NAME_SUFFIX_MAX 63

/**
 * @brief Return a unique name with prefix @c "pn-it-<8hex>-<suffix>".
 *
 * Uses 16 rotating static buffers; safe for up to 16 calls per test
 * body before the oldest pointer is reused.  All returned pointers
 * remain valid for the duration of the test process.
 *
 * @param suffix NUL-terminated label appended after the hex token.
 *               Truncated to @c IT_NAME_SUFFIX_MAX characters.
 * @return Pointer into a static buffer containing the formatted name.
 */
const char* it_unique_name(const char* suffix);

/**
 * @brief Same as it_unique_name() but prefix is @c "pn-xs-" (cross-SDK
 * tests).
 *
 * @param suffix NUL-terminated label; truncated to @c IT_NAME_SUFFIX_MAX.
 * @return Pointer into a static buffer containing the formatted name.
 */
const char* it_xs_channel(const char* suffix);

/** @brief Alias for it_unique_name() — channel name variant. */
#define IT_CHANNEL(suffix) it_unique_name(suffix)
/** @brief Alias for it_unique_name() — channel-group name variant. */
#define IT_GROUP(suffix) it_unique_name(suffix)
/** @brief Alias for it_unique_name() — UUID variant. */
#define IT_UUID(suffix) it_unique_name(suffix)

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PUBNUB_IT_CHANNEL_H */

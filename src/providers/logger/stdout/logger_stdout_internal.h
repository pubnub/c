/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Internal header for the stdout logger provider.
 *
 * Not installed. Only included by logger_stdout.c and its unit tests.
 */

#ifndef PN_LOGGER_STDOUT_INTERNAL_H
#define PN_LOGGER_STDOUT_INTERNAL_H

#include "pubnub/providers/logger.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Stdout logger instance.
 *
 * Embed this struct or declare it on the stack. Call
 * pubnub_logger_stdout_init() to wire the vtable.
 */
typedef struct pubnub_logger_stdout {
    /** Logger vtable (must be first member for safe casting). */
    pubnub_logger_provider_t base;
} pubnub_logger_stdout_t;

/**
 * @brief Initialize a stdout logger instance. No heap allocation.
 *
 * @param logger Non-NULL pointer to the instance.
 */
void pubnub_logger_stdout_init(pubnub_logger_stdout_t* logger);

/**
 * @brief Return the stdout logger singleton used as the built-in default.
 *
 * Called by the SDK core when the stdout provider is selected. The
 * singleton is initialized on first call and is never freed.
 *
 * @return Pointer to the static singleton, or NULL in stub builds.
 */
pubnub_logger_provider_t* pn_logger_default(void);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_LOGGER_STDOUT_INTERNAL_H */

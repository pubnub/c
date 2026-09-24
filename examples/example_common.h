/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PUBNUB_EXAMPLE_COMMON_H
#define PUBNUB_EXAMPLE_COMMON_H

/**
 * @brief Portable millisecond sleep for example programs.
 *
 * On async builds the background thread drives I/O, so this is used
 * only to yield CPU while spinning on a completion flag.
 */
#ifdef _WIN32
#include <windows.h>
#define PUBNUB_EXAMPLE_SLEEP_MS(ms) Sleep((DWORD)(ms))
#else
#include <unistd.h>
#define PUBNUB_EXAMPLE_SLEEP_MS(ms) usleep((unsigned)(ms) * 1000U)
#endif

#endif /* PUBNUB_EXAMPLE_COMMON_H */

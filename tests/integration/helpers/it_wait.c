/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "it_wait.h"

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <time.h>
#endif

void pn_test_sleep_ms(unsigned int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000U);
    while (-1 == nanosleep(&ts, &ts) && EINTR == errno) {}
#endif
}

int pn_test_wait_until(int (*condition_fn)(void* arg),
                       void*        arg,
                       unsigned int max_ms,
                       unsigned int poll_ms)
{
#ifdef _WIN32
    ULONGLONG start = GetTickCount64();
    for (;;) {
        if (0 != condition_fn(arg)) {
            return 1;
        }
        ULONGLONG elapsed = GetTickCount64() - start;
        if (elapsed >= (ULONGLONG)max_ms) {
            return 0;
        }
        pn_test_sleep_ms(poll_ms);
    }
#else
    struct timespec start;
    struct timespec now;
    int64_t         elapsed_ns;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (0 != condition_fn(arg)) {
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ns = (int64_t)(now.tv_sec - start.tv_sec) * (int64_t)1000000000
                   + (int64_t)(now.tv_nsec - start.tv_nsec);
        if (elapsed_ns >= (int64_t)max_ms * (int64_t)1000000) {
            return 0;
        }
        pn_test_sleep_ms(poll_ms);
    }
#endif
}

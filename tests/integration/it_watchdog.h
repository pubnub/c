/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#ifndef PN_TEST_IT_WATCHDOG_H
#define PN_TEST_IT_WATCHDOG_H

#include <stdlib.h>
#include <string.h>

/*
 * Header-only deadlock watchdog for threading integration tests.
 *
 * it_watchdog_arm(seconds, name) starts a timer; if it_watchdog_disarm()
 * is not called before it expires, the process prints a diagnostic and
 * calls abort(). A hung test therefore terminates the binary with a
 * non-zero exit code (ctest FAILURE) instead of hanging silently until
 * the ctest wall-clock timeout.
 *
 * POSIX  : alarm() + a SIGALRM handler (async-signal-safe write + abort).
 * Windows: a watchdog thread that abort()s once the deadline passes.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <windows.h>

/** Name of the currently armed test (for the diagnostic message). */
static char pn_it_wd_name_[128];
/** Deadline in seconds, captured at arm time. */
static unsigned int pn_it_wd_seconds_;
/** 1 = disarmed (thread should exit), 0 = armed. */
static volatile LONG pn_it_wd_disarm_ = 1;
/** Watchdog thread handle, or NULL when not armed. */
static HANDLE pn_it_wd_thread_ = NULL;

static DWORD WINAPI pn_it_wd_thread_fn_(LPVOID arg)
{
    ULONGLONG deadline;

    (void)arg;
    deadline = GetTickCount64() + (ULONGLONG)pn_it_wd_seconds_ * 1000ULL;
    while (0 == InterlockedCompareExchange(&pn_it_wd_disarm_, 0, 0)) {
        if (GetTickCount64() >= deadline) {
            (void)fprintf(
                stderr, "\n[WATCHDOG] DEADLOCK DETECTED in %s\n", pn_it_wd_name_);
            (void)fflush(stderr);
            abort();
        }
        Sleep(50);
    }
    return 0;
}

/**
 * @brief Arm the watchdog for @p seconds, labelled with @p test_name.
 *
 * @param seconds   Timeout budget in seconds.
 * @param test_name Diagnostic label printed if the watchdog fires.
 */
static __inline void it_watchdog_arm(unsigned int seconds, const char* test_name)
{
    size_t n = (NULL == test_name) ? 0U : strlen(test_name);

    if (n >= sizeof(pn_it_wd_name_)) {
        n = sizeof(pn_it_wd_name_) - 1U;
    }
    memcpy(pn_it_wd_name_, (NULL == test_name) ? "" : test_name, n);
    pn_it_wd_name_[n] = '\0';
    pn_it_wd_seconds_ = seconds;

    InterlockedExchange(&pn_it_wd_disarm_, 0);
    pn_it_wd_thread_ = CreateThread(NULL, 0, pn_it_wd_thread_fn_, NULL, 0, NULL);
}

/** @brief Disarm the watchdog. Safe to call even if never armed. */
static __inline void it_watchdog_disarm(void)
{
    InterlockedExchange(&pn_it_wd_disarm_, 1);
    if (NULL != pn_it_wd_thread_) {
        WaitForSingleObject(pn_it_wd_thread_, INFINITE);
        CloseHandle(pn_it_wd_thread_);
        pn_it_wd_thread_ = NULL;
    }
}

#else /* !_WIN32 */

#include <signal.h>
#include <unistd.h>

/** Name of the currently armed test (for the diagnostic message). */
static char pn_it_wd_name_[128];
/** Length of @c pn_it_wd_name_ captured at arm time (handler must not
 *  call strlen — it is not async-signal-safe). */
static volatile int pn_it_wd_name_len_;

static void pn_it_wd_handler_(int sig)
{
    static const char pfx[] = "\n[WATCHDOG] DEADLOCK DETECTED in ";

    (void)sig;
    /* Only async-signal-safe calls here: write() then abort(). */
    (void)write(STDERR_FILENO, pfx, sizeof(pfx) - 1U);
    (void)write(STDERR_FILENO, pn_it_wd_name_, (size_t)pn_it_wd_name_len_);
    (void)write(STDERR_FILENO, "\n", 1U);
    abort();
}

/**
 * @brief Arm the watchdog for @p seconds, labelled with @p test_name.
 *
 * @param seconds   Timeout budget in seconds.
 * @param test_name Diagnostic label printed if the watchdog fires.
 */
static inline void it_watchdog_arm(unsigned int seconds, const char* test_name)
{
    struct sigaction sa;
    size_t           n = (NULL == test_name) ? 0U : strlen(test_name);

    if (n >= sizeof(pn_it_wd_name_)) {
        n = sizeof(pn_it_wd_name_) - 1U;
    }
    memcpy(pn_it_wd_name_, (NULL == test_name) ? "" : test_name, n);
    pn_it_wd_name_[n]  = '\0';
    pn_it_wd_name_len_ = (int)n;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = pn_it_wd_handler_;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    (void)sigaction(SIGALRM, &sa, NULL);
    (void)alarm(seconds);
}

/** @brief Disarm the watchdog. Safe to call even if never armed. */
static inline void it_watchdog_disarm(void)
{
    (void)alarm(0);
}

#endif /* _WIN32 */

#endif /* PN_TEST_IT_WATCHDOG_H */

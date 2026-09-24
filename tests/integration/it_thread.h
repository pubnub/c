/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#ifndef PN_TEST_IT_THREAD_H
#define PN_TEST_IT_THREAD_H

#ifdef _WIN32

/* WIN32_LEAN_AND_MEAN strips the old winsock.h from windows.h; winsock2.h
 * may still be included by callers without conflict. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>

typedef HANDLE pn_test_thread_t;

typedef struct {
    void* (*fn)(void*);
    void* arg;
} pn_test_thread_tramp_t;

static DWORD WINAPI pn_test_thread_entry_(LPVOID p)
{
    pn_test_thread_tramp_t t = *(pn_test_thread_tramp_t*)p;
    free(p);
    t.fn(t.arg);
    return 0;
}

/* Start fn(arg) in a new thread; write handle to *t. Return 0 on
   success, non-zero on failure. */
static inline int pn_test_thread_create(pn_test_thread_t* t,
                                        void* (*fn)(void*),
                                        void* arg)
{
    pn_test_thread_tramp_t* tramp =
        (pn_test_thread_tramp_t*)malloc(sizeof(*tramp));
    if (NULL == tramp) {
        return -1;
    }
    tramp->fn  = fn;
    tramp->arg = arg;
    *t         = CreateThread(NULL, 0, pn_test_thread_entry_, tramp, 0, NULL);
    if (NULL == *t) {
        free(tramp);
        return -1;
    }
    return 0;
}

/* Block until thread finishes and release the handle. */
static inline void pn_test_thread_join(pn_test_thread_t t)
{
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

#else /* !_WIN32 */

#include <pthread.h>

typedef pthread_t pn_test_thread_t;

/* Start fn(arg) in a new thread; write handle to *t. Return 0 on
   success, non-zero on failure. */
static inline int pn_test_thread_create(pn_test_thread_t* t,
                                        void* (*fn)(void*),
                                        void* arg)
{
    return pthread_create(t, NULL, fn, arg);
}

/* Block until thread finishes. */
static inline void pn_test_thread_join(pn_test_thread_t t)
{
    pthread_join(t, NULL);
}

#endif /* _WIN32 */

#endif /* PN_TEST_IT_THREAD_H */

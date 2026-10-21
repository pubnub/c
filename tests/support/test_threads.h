/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TEST_THREADS_H
#define PN_TEST_THREADS_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#endif

#include <stddef.h>

/** Thread entry point. */
typedef void (*pn_test_thread_fn)(void* arg);

#if defined(_WIN32)

/** Counter shared between threads; use only through pn_test_atomic_*(). */
typedef volatile LONG pn_test_atomic_t;

/** Opaque thread identity comparable with pn_test_thread_id_equal(). */
typedef DWORD pn_test_thread_id_t;

/** Joinable thread handle. */
typedef struct pn_test_thread {
    HANDLE            handle;
    pn_test_thread_fn fn;
    void*             arg;
} pn_test_thread_t;

#else

/** Counter shared between threads; use only through pn_test_atomic_*(). */
typedef int pn_test_atomic_t;

/** Opaque thread identity comparable with pn_test_thread_id_equal(). */
typedef pthread_t pn_test_thread_id_t;

/** Joinable thread handle. */
typedef struct pn_test_thread {
    pthread_t         handle;
    pn_test_thread_fn fn;
    void*             arg;
} pn_test_thread_t;

#endif

/**
 * @brief Atomically add @p delta to @p counter.
 * @param counter Shared counter.
 * @param delta   Signed amount to add.
 */
static inline void pn_test_atomic_add(pn_test_atomic_t* counter, int delta)
{
#if defined(_WIN32)
    (void)InterlockedExchangeAdd(counter, (LONG)delta);
#else
    (void)__atomic_fetch_add(counter, delta, __ATOMIC_SEQ_CST);
#endif
}

/**
 * @brief Atomically add @p delta to @p counter and return the prior value.
 * @param counter Shared counter.
 * @param delta   Signed amount to add.
 * @return Value held before the addition.
 */
static inline int pn_test_atomic_fetch_add(pn_test_atomic_t* counter, int delta)
{
#if defined(_WIN32)
    return (int)InterlockedExchangeAdd(counter, (LONG)delta);
#else
    return __atomic_fetch_add(counter, delta, __ATOMIC_SEQ_CST);
#endif
}

/**
 * @brief Atomically read @p counter.
 * @param counter Shared counter.
 * @return Current value.
 */
static inline int pn_test_atomic_load(pn_test_atomic_t* counter)
{
#if defined(_WIN32)
    return (int)InterlockedCompareExchange(counter, 0, 0);
#else
    return __atomic_load_n(counter, __ATOMIC_SEQ_CST);
#endif
}

/**
 * @brief Atomically replace the value of @p counter.
 * @param counter Shared counter.
 * @param value   New value.
 */
static inline void pn_test_atomic_store(pn_test_atomic_t* counter, int value)
{
#if defined(_WIN32)
    (void)InterlockedExchange(counter, (LONG)value);
#else
    __atomic_store_n(counter, value, __ATOMIC_SEQ_CST);
#endif
}

#if defined(_WIN32)
static DWORD WINAPI pn_test_thread_trampoline(LPVOID param)
{
    pn_test_thread_t* thread = (pn_test_thread_t*)param;

    thread->fn(thread->arg);
    return 0;
}
#else
static void* pn_test_thread_trampoline(void* param)
{
    pn_test_thread_t* thread = (pn_test_thread_t*)param;

    thread->fn(thread->arg);
    return NULL;
}
#endif

/**
 * @brief Start a thread running @p fn(@p arg).
 * @param thread Receives the handle; must outlive the thread (it is read by
 *               the new thread) and be passed to pn_test_thread_join().
 * @param fn     Entry point.
 * @param arg    Opaque argument forwarded to @p fn.
 * @return 0 on success, non-zero when the thread could not be created.
 */
static inline int pn_test_thread_create(pn_test_thread_t* thread,
                                        pn_test_thread_fn fn,
                                        void*             arg)
{
    thread->fn  = fn;
    thread->arg = arg;
#if defined(_WIN32)
    thread->handle =
        CreateThread(NULL, 0, pn_test_thread_trampoline, thread, 0, NULL);
    return (NULL == thread->handle) ? 1 : 0;
#else
    return pthread_create(&thread->handle, NULL, pn_test_thread_trampoline, thread);
#endif
}

/**
 * @brief Wait for @p thread to finish and release its handle.
 * @param thread Handle filled by a successful pn_test_thread_create().
 * @return 0 on success, non-zero on failure.
 */
static inline int pn_test_thread_join(pn_test_thread_t* thread)
{
#if defined(_WIN32)
    DWORD rc = WaitForSingleObject(thread->handle, INFINITE);

    (void)CloseHandle(thread->handle);
    thread->handle = NULL;
    return (WAIT_OBJECT_0 == rc) ? 0 : 1;
#else
    return pthread_join(thread->handle, NULL);
#endif
}

/**
 * @brief Identity of the calling thread.
 * @return Value comparable with pn_test_thread_id_equal().
 */
static inline pn_test_thread_id_t pn_test_thread_self(void)
{
#if defined(_WIN32)
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif
}

/**
 * @brief Compare two thread identities.
 * @param a First identity.
 * @param b Second identity.
 * @retval 0 The identities differ.
 * @retval non-zero The identities name the same thread.
 */
static inline int pn_test_thread_id_equal(pn_test_thread_id_t a,
                                          pn_test_thread_id_t b)
{
#if defined(_WIN32)
    return a == b;
#else
    return 0 != pthread_equal(a, b);
#endif
}

/**
 * @brief Give up the processor for roughly @p microseconds.
 *
 * Windows has no sub-millisecond sleep, so short requests only yield to
 * another ready thread; longer ones sleep in whole milliseconds.
 *
 * @param microseconds Requested pause; 0 yields only.
 */
static inline void pn_test_pause_us(unsigned long microseconds)
{
#if defined(_WIN32)
    if (microseconds < 1000UL) {
        (void)SwitchToThread();
    } else {
        Sleep((DWORD)(microseconds / 1000UL));
    }
#else
    struct timespec ts;

    ts.tv_sec  = (time_t)(microseconds / 1000000UL);
    ts.tv_nsec = (long)(microseconds % 1000000UL) * 1000L;
    (void)nanosleep(&ts, NULL);
#endif
}

#endif /* PN_TEST_THREADS_H */

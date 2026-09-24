/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file platform_posix.c
 * @brief POSIX platform provider for hosted profiles (Linux, macOS, BSD).
 *
 * Entropy source: getentropy > getrandom > /dev/urandom (compile-time).
 * Clock: CLOCK_MONOTONIC for timeouts, CLOCK_REALTIME for PAM wall-clock.
 * Sync: pthreads binary semaphore.
 * Stateless singleton shared across all contexts.
 */

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* Pick the best-available entropy source. Order:
 *   1. getentropy()  - macOS 10.12+, Linux (glibc 2.25+), OpenBSD,
 *                       FreeBSD 12+. The 256-byte per-call cap is
 *                       the OpenBSD origin spec, mirrored verbatim
 *                       by the macOS and glibc man pages.
 *   2. getrandom()   - Linux 3.17+ (glibc 2.25+).
 *   3. /dev/urandom  - universal POSIX fallback.
 *
 * OpenBSD ships `getentropy` in `<unistd.h>` and does not provide
 * `<sys/random.h>`; every other target declares it in
 * `<sys/random.h>`, so the OpenBSD branch is handled separately to
 * avoid a missing-header compile error.
 */
#if defined(__OpenBSD__)
#define PN_PLATFORM_POSIX_HAS_GETENTROPY 1
/* getentropy declared in <unistd.h>, already included above. */
#elif defined(__APPLE__) || defined(__FreeBSD__) \
    || (defined(__GLIBC__)                       \
        && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
#define PN_PLATFORM_POSIX_HAS_GETENTROPY 1
#include <sys/random.h>
#else
#define PN_PLATFORM_POSIX_HAS_GETENTROPY 0
#include <fcntl.h>
#endif

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_platform_provider_t* pn_platform_default(void);

/** @brief Boot-relative monotonic clock for timeouts and deadlines. */
static pubnub_milliseconds_t posix_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;

    struct timespec mono_now;
    if (0 != clock_gettime(CLOCK_MONOTONIC, &mono_now)) {
        /* CLOCK_MONOTONIC mandatory on POSIX.1-2001; failure means a
         * broken kernel or stripped sandbox. Return 0 (timers use
         * deltas, so a zero reading is safe). */
        return 0;
    }

    return (pubnub_milliseconds_t)mono_now.tv_sec * 1000U
         + (pubnub_milliseconds_t)(mono_now.tv_nsec / 1000000);
}

/** @brief Wall-clock time in milliseconds since Unix epoch. */
static pubnub_milliseconds_t posix_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;

    struct timespec real_now;
    if (0 != clock_gettime(CLOCK_REALTIME, &real_now)) {
        return 0;
    }

    return (pubnub_milliseconds_t)real_now.tv_sec * 1000U
         + (pubnub_milliseconds_t)(real_now.tv_nsec / 1000000);
}

/** @brief Sleep via nanosleep; retries on EINTR with remaining time. */
static void posix_sleep_ms(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;

    struct timespec req = {
        .tv_sec  = (time_t)(ms / 1000),
        .tv_nsec = (long)((ms % 1000) * 1000000L),
    };
    struct timespec rem;

    /* Loop on EINTR so signals (profiler SIGPROF, test SIGALRM) don't
     * cut the sleep short. */
    while (nanosleep(&req, &rem) == -1 && errno == EINTR) {
        req = rem;
    }
}

#if !PN_PLATFORM_POSIX_HAS_GETENTROPY
/* Fallback: fill from /dev/urandom when getentropy unavailable. */
static int posix_random_bytes_urandom(uint8_t* buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }

    close(fd);

    return 0;
}
#endif

/** @brief Fill buf with len cryptographic random bytes. */
static int posix_random_bytes(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;

    if (len == 0) {
        return 0;
    }
    if (buf == NULL) {
        return -1;
    }

#if PN_PLATFORM_POSIX_HAS_GETENTROPY
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) {
            chunk = 256;
        }
        if (getentropy(buf + off, chunk) != 0) {
            return -1;
        }
        off += chunk;
    }

    return 0;
#else
    return posix_random_bytes_urandom(buf, len);
#endif
}

static size_t posix_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return sizeof(pthread_mutex_t);
}

static int posix_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return -1;
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#ifdef NDEBUG
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
#else
    /* ERRORCHECK returns EDEADLK on double-lock instead of UB. */
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int rc = pthread_mutex_init((pthread_mutex_t*)lock, &attr);
    pthread_mutexattr_destroy(&attr);

    return rc;
}

static void posix_lock_destroy(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return;
    }
    pthread_mutex_destroy((pthread_mutex_t*)lock);
}

static void posix_lock_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t*)lock);
}

static void posix_lock_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return;
    }
    pthread_mutex_unlock((pthread_mutex_t*)lock);
}

/** @brief Thread handle wrapping a pthread_t for join. */
typedef struct posix_thread_handle {
    pthread_t tid;
} posix_thread_handle_t;

/** @brief Trampoline context bridging void(*)(void*) to void*(*)(void*). */
typedef struct posix_thread_trampoline {
    void (*fn)(void*);
    void*                             arg;
    struct pubnub_allocator_provider* allocator;
} posix_thread_trampoline_t;

static void* posix_thread_entry(void* raw)
{
    posix_thread_trampoline_t ctx = *(posix_thread_trampoline_t*)raw;
    PN_FREE(ctx.allocator, raw);
    ctx.fn(ctx.arg);
    return NULL;
}

static void* posix_thread_create(pubnub_platform_provider_t*       self,
                                 struct pubnub_allocator_provider* allocator,
                                 void (*fn)(void*),
                                 void* arg)
{
    (void)self;
    if (NULL == fn || NULL == allocator || NULL == allocator->alloc) {
        return NULL;
    }

    posix_thread_trampoline_t* trampoline = (posix_thread_trampoline_t*)PN_ALLOC(
        allocator, sizeof(posix_thread_trampoline_t), sizeof(void*));
    if (NULL == trampoline) {
        return NULL;
    }
    trampoline->fn        = fn;
    trampoline->arg       = arg;
    trampoline->allocator = allocator;

    posix_thread_handle_t* handle = (posix_thread_handle_t*)PN_ALLOC(
        allocator, sizeof(posix_thread_handle_t), sizeof(void*));
    if (NULL == handle) {
        PN_FREE(allocator, trampoline);
        return NULL;
    }

    int rc = pthread_create(&handle->tid, NULL, posix_thread_entry, trampoline);
    if (0 != rc) {
        PN_FREE(allocator, trampoline);
        PN_FREE(allocator, handle);
        return NULL;
    }

    return handle;
}

static void posix_thread_join(pubnub_platform_provider_t*       self,
                              struct pubnub_allocator_provider* allocator,
                              void*                             thread_handle)
{
    (void)self;
    if (NULL == thread_handle) {
        return;
    }

    posix_thread_handle_t* handle = (posix_thread_handle_t*)thread_handle;
    pthread_join(handle->tid, NULL);

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, handle);
    }
}

/** @brief Report whether @p thread_handle is the calling thread. */
static int posix_thread_is_current(pubnub_platform_provider_t* self,
                                   void*                       thread_handle)
{
    posix_thread_handle_t* handle;
    (void)self;
    if (NULL == thread_handle) {
        return 0;
    }

    handle = (posix_thread_handle_t*)thread_handle;
    return 0 != pthread_equal(pthread_self(), handle->tid);
}

/** @brief Load file content into an allocator-owned buffer. */
static pubnub_res_t posix_file_load(pubnub_platform_provider_t*       self,
                                    const char*                       path,
                                    struct pubnub_allocator_provider* allocator,
                                    uint8_t**                         out_data,
                                    size_t*                           out_len)
{
    (void)self;

    if (NULL == path || NULL == allocator || NULL == out_data || NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_data = NULL;
    *out_len  = 0;

    FILE* fp = fopen(path, "rb");
    if (NULL == fp) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (0 != fseek(fp, 0, SEEK_END)) {
        (void)fclose(fp);
        return PUBNUB_ERR_INTERNAL;
    }
    const long sz = ftell(fp);
    if (sz < 0) {
        (void)fclose(fp);
        return PUBNUB_ERR_INTERNAL;
    }

    if (0 != fseek(fp, 0, SEEK_SET)) {
        (void)fclose(fp);
        return PUBNUB_ERR_INTERNAL;
    }

    if (sz > 0) {
        uint8_t* buf = (uint8_t*)PN_ALLOC(allocator, (size_t)sz, sizeof(void*));
        if (NULL == buf) {
            (void)fclose(fp);
            return PUBNUB_ERR_OUT_OF_MEMORY;
        }
        if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
            PN_FREE(allocator, buf);
            (void)fclose(fp);
            return PUBNUB_ERR_INTERNAL;
        }
        *out_data = buf;
    }

    (void)fclose(fp);
    *out_len = (size_t)sz;
    return PUBNUB_OK;
}

/* Stateless singleton shared across all contexts. */
static pubnub_platform_provider_t pn_posix_platform = {
    .monotonic_ms      = posix_monotonic_ms,
    .wall_clock_ms     = posix_wall_clock_ms,
    .sleep_ms          = posix_sleep_ms,
    .random_bytes      = posix_random_bytes,
    .secure_zero       = NULL,
    .lock_size         = posix_lock_size,
    .lock_init         = posix_lock_init,
    .lock_destroy      = posix_lock_destroy,
    .lock_acquire      = posix_lock_acquire,
    .lock_release      = posix_lock_release,
    .thread_create     = posix_thread_create,
    .thread_join       = posix_thread_join,
    .thread_is_current = posix_thread_is_current,
    .file_load         = PUBNUB_ENABLE_FILESYSTEM ? posix_file_load : NULL,
};

pubnub_platform_provider_t* pn_platform_default(void)
{
    return &pn_posix_platform;
}

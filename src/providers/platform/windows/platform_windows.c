/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifdef _WIN32

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <bcrypt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_platform_provider_t* pn_platform_default(void);

/* QueryPerformanceFrequency is fixed for the lifetime of the system, so it is
 * cached once. InitOnceExecuteOnce (Vista+) serializes concurrent first-calls
 * so racing threads observe a fully-written frequency. */
static INIT_ONCE     s_qpc_once = INIT_ONCE_STATIC_INIT;
static LARGE_INTEGER s_qpc_freq = {0};

/** @brief One-time initializer for the cached QPC frequency. */
static BOOL CALLBACK win_qpc_freq_init(PINIT_ONCE init_once,
                                       PVOID      parameter,
                                       PVOID*     context)
{
    (void)init_once;
    (void)parameter;
    (void)context;
    QueryPerformanceFrequency(&s_qpc_freq);
    return TRUE;
}

/** @brief Boot-relative monotonic clock via QueryPerformanceCounter. */
static pubnub_milliseconds_t win_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;

    LARGE_INTEGER qpc_now;
    uint64_t      ticks;
    uint64_t      freq;

    InitOnceExecuteOnce(&s_qpc_once, win_qpc_freq_init, NULL, NULL);
    QueryPerformanceCounter(&qpc_now);

    ticks = (uint64_t)qpc_now.QuadPart;
    freq  = (uint64_t)s_qpc_freq.QuadPart;
    if (0 == freq) {
        return 0;
    }

    /* Divide before scaling to avoid overflowing uint64: ticks * 1000 would
     * wrap after ~71 days on a ~3 GHz TSC-based counter. The remainder term
     * preserves sub-second precision without exceeding uint64 range. */
    return (pubnub_milliseconds_t)((ticks / freq) * 1000U
                                   + (ticks % freq) * 1000U / freq);
}

/** @brief Wall-clock time in milliseconds since Unix epoch. */
static pubnub_milliseconds_t win_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;

    /* GetSystemTimeAsFileTime returns 100-nanosecond intervals
     * since January 1, 1601 UTC. Subtract 11644473600 seconds
     * (the delta between 1601 and 1970 Unix epoch). */
    FILETIME       ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    /* UINT64_C ensures 64-bit arithmetic on MSVC where unsigned long
     * is 32-bit; 11644473600 seconds * 1000 ms/s = 11644473600000 ms. */
    return (pubnub_milliseconds_t)(uli.QuadPart / UINT64_C(10000))
         - UINT64_C(11644473600) * UINT64_C(1000);
}

/** @brief Sleep via Win32 Sleep(). */
static void win_sleep_ms(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    Sleep((DWORD)ms);
}

/** @brief Fill buf with len cryptographic random bytes via BCrypt. */
static int win_random_bytes(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;

    if (0 == len) {
        return 0;
    }
    if (NULL == buf) {
        return -1;
    }

    NTSTATUS status =
        BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return (0 == status) ? 0 : -1;
}

/** @brief Secure-zeroize via SecureZeroMemory. */
static void win_secure_zero(pubnub_platform_provider_t* self, void* buf, size_t len)
{
    (void)self;
    if (NULL != buf && len > 0) {
        SecureZeroMemory(buf, len);
    }
}

static size_t win_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return sizeof(CRITICAL_SECTION);
}

static int win_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return -1;
    }
    InitializeCriticalSection((CRITICAL_SECTION*)lock);
    return 0;
}

static void win_lock_destroy(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return;
    }
    DeleteCriticalSection((CRITICAL_SECTION*)lock);
}

static void win_lock_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return;
    }
    EnterCriticalSection((CRITICAL_SECTION*)lock);
}

static void win_lock_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    if (NULL == lock) {
        return;
    }
    LeaveCriticalSection((CRITICAL_SECTION*)lock);
}

/** @brief Thread handle wrapping a Win32 thread HANDLE. */
typedef struct win_thread_handle {
    HANDLE thread;
} win_thread_handle_t;

/** @brief Trampoline bridging void(*)(void*) to DWORD(LPVOID). */
typedef struct win_thread_trampoline {
    void (*fn)(void*);
    void*                             arg;
    struct pubnub_allocator_provider* allocator;
} win_thread_trampoline_t;

static DWORD WINAPI win_thread_entry(LPVOID raw)
{
    win_thread_trampoline_t ctx = *(win_thread_trampoline_t*)raw;
    PN_FREE(ctx.allocator, raw);
    ctx.fn(ctx.arg);
    return 0;
}

static void* win_thread_create(pubnub_platform_provider_t*       self,
                               struct pubnub_allocator_provider* allocator,
                               void (*fn)(void*),
                               void* arg)
{
    (void)self;
    if (NULL == fn || NULL == allocator || NULL == allocator->alloc) {
        return NULL;
    }

    win_thread_trampoline_t* trampoline = (win_thread_trampoline_t*)PN_ALLOC(
        allocator, sizeof(win_thread_trampoline_t), sizeof(void*));
    if (NULL == trampoline) {
        return NULL;
    }
    trampoline->fn        = fn;
    trampoline->arg       = arg;
    trampoline->allocator = allocator;

    win_thread_handle_t* handle = (win_thread_handle_t*)PN_ALLOC(
        allocator, sizeof(win_thread_handle_t), sizeof(void*));
    if (NULL == handle) {
        PN_FREE(allocator, trampoline);
        return NULL;
    }

    handle->thread = CreateThread(NULL, 0, win_thread_entry, trampoline, 0, NULL);
    if (NULL == handle->thread) {
        PN_FREE(allocator, trampoline);
        PN_FREE(allocator, handle);
        return NULL;
    }

    return handle;
}

static void win_thread_join(pubnub_platform_provider_t*       self,
                            struct pubnub_allocator_provider* allocator,
                            void*                             thread_handle)
{
    (void)self;
    if (NULL == thread_handle) {
        return;
    }

    win_thread_handle_t* handle = (win_thread_handle_t*)thread_handle;
    WaitForSingleObject(handle->thread, INFINITE);
    CloseHandle(handle->thread);

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, handle);
    }
}

/** @brief Report whether @p thread_handle is the calling thread. */
static int win_thread_is_current(pubnub_platform_provider_t* self, void* thread_handle)
{
    win_thread_handle_t* handle;
    (void)self;
    if (NULL == thread_handle) {
        return 0;
    }

    handle = (win_thread_handle_t*)thread_handle;
    return GetThreadId(handle->thread) == GetCurrentThreadId();
}

/** @brief Load file content into an allocator-owned buffer. */
static pubnub_res_t win_file_load(pubnub_platform_provider_t*       self,
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
static pubnub_platform_provider_t pn_windows_platform = {
    .monotonic_ms      = win_monotonic_ms,
    .wall_clock_ms     = win_wall_clock_ms,
    .sleep_ms          = win_sleep_ms,
    .random_bytes      = win_random_bytes,
    .secure_zero       = win_secure_zero,
    .lock_size         = win_lock_size,
    .lock_init         = win_lock_init,
    .lock_destroy      = win_lock_destroy,
    .lock_acquire      = win_lock_acquire,
    .lock_release      = win_lock_release,
    .thread_create     = win_thread_create,
    .thread_join       = win_thread_join,
    .thread_is_current = win_thread_is_current,
    .file_load         = PUBNUB_ENABLE_FILESYSTEM ? win_file_load : NULL,
};

pubnub_platform_provider_t* pn_platform_default(void)
{
    return &pn_windows_platform;
}

#endif /* _WIN32 */

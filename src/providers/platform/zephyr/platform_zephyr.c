/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/providers/platform.h"

#if defined(__ZEPHYR__)

#include "pubnub/providers/allocator.h"
#include "pubnub/pubnub_compat.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/atomic.h>

#if defined(CONFIG_POSIX_CLOCK)
#include <zephyr/posix/time.h>
#endif

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_platform_provider_t* pn_platform_default(void);

PUBNUB_STATIC_ASSERT(sizeof(struct k_sem) <= 64, "k_sem exceeds lock budget");

/* 8KB: 4-6KB for mbedTLS handshake + ~2KB HTTP parsing overhead.
 * Override with -DPN_ZEPHYR_THREAD_STACK_SIZE=<n> for larger cert chains. */
#ifndef PN_ZEPHYR_THREAD_STACK_SIZE
#define PN_ZEPHYR_THREAD_STACK_SIZE 8192
#endif

PUBNUB_STATIC_ASSERT(PN_ZEPHYR_THREAD_STACK_SIZE >= 4096,
                     "SDK thread needs at least 4KB for TLS handshake");

#ifndef PN_ZEPHYR_THREAD_PRIORITY
#define PN_ZEPHYR_THREAD_PRIORITY 5
#endif

#if defined(CONFIG_DYNAMIC_THREAD) && (CONFIG_DYNAMIC_THREAD_POOL_SIZE > 0)
/* Dynamic thread stack allocation path. */
#else
/* Static thread stack pool for targets without CONFIG_DYNAMIC_THREAD. */
#ifndef PN_ZEPHYR_MAX_THREADS
#define PN_ZEPHYR_MAX_THREADS 2
#endif

K_THREAD_STACK_ARRAY_DEFINE(pn_zephyr_stacks,
                            PN_ZEPHYR_MAX_THREADS,
                            PN_ZEPHYR_THREAD_STACK_SIZE);
ATOMIC_DEFINE(pn_zephyr_stack_used, PN_ZEPHYR_MAX_THREADS);
#endif /* CONFIG_DYNAMIC_THREAD */

/**
 * @brief Thread handle wrapping a Zephyr k_thread and stack info.
 *
 * Allocated via the SDK allocator in thread_create, freed in
 * thread_join after the thread terminates.
 */
typedef struct pn_zephyr_thread_handle {
    struct k_thread   thread;
    k_thread_stack_t* dyn_stack;
    int               pool_slot;
} pn_zephyr_thread_handle_t;

/**
 * @brief Boot-relative monotonic clock in milliseconds.
 *
 * k_uptime_get() returns a 64-bit millisecond count since boot --
 * no rollover detection needed unlike FreeRTOS 32-bit ticks.
 */
static pubnub_milliseconds_t zephyr_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return (pubnub_milliseconds_t)k_uptime_get();
}

/**
 * @brief Wall-clock time in milliseconds since Unix epoch.
 *
 * Requires CONFIG_POSIX_CLOCK=y and NTP synchronization for
 * correct results. Returns 0 when the POSIX clock subsystem is
 * not enabled or when the clock has not been synchronized.
 */
static pubnub_milliseconds_t zephyr_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;

#if defined(CONFIG_POSIX_CLOCK)
    struct timespec ts;
    if (0 != clock_gettime(CLOCK_REALTIME, &ts)) {
        return 0;
    }
    /* Pre-NTP Zephyr returns seconds near 0; treat as unavailable. */
    if (ts.tv_sec < 946684800) { /* 2000-01-01 00:00:00 UTC */
        return 0;
    }
    return (pubnub_milliseconds_t)ts.tv_sec * 1000U
         + (pubnub_milliseconds_t)(ts.tv_nsec / 1000000);
#else
    return 0;
#endif
}

/**
 * @brief Delay the calling thread for at least ms milliseconds.
 *
 * A request for 0 ms yields the CPU to other ready threads.
 */
static void zephyr_sleep_ms(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;

    if (0 == ms) {
        k_yield();
        return;
    }

    k_sleep(K_MSEC(ms));
}

/**
 * @brief Fill buf with cryptographic random bytes.
 *
 * Uses Zephyr's sys_csrand_fill which requires
 * CONFIG_ENTROPY_HAS_DRIVER=y in the project's prj.conf.
 */
static int zephyr_random_bytes(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;

    if (0 == len) {
        return 0;
    }
    if (NULL == buf) {
        return -1;
    }

    return sys_csrand_get(buf, len);
}

/**
 * @brief Secure-zeroize a buffer via volatile writes.
 *
 * Prevents the compiler from optimizing out the zeroing operation.
 * Zephyr does not provide a portable explicit_bzero equivalent
 * across all supported architectures.
 */
static void zephyr_secure_zero(pubnub_platform_provider_t* self, void* buf, size_t len)
{
    (void)self;

    if (NULL == buf || 0 == len) {
        return;
    }

    volatile uint8_t* p = (volatile uint8_t*)buf;
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

/**
 * @brief Return size of k_sem used as a non-recursive lock.
 *
 * Zephyr k_mutex is recursive (owner-tracking). The SDK contract
 * requires non-recursive locks, so we use k_sem with count 1
 * instead. A double-take from the same thread blocks indefinitely
 * (desired: surfaces bugs as detectable hangs).
 */
static size_t zephyr_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return sizeof(struct k_sem);
}

/**
 * @brief Initialize a binary semaphore (count=1) as a non-recursive lock.
 */
static int zephyr_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;

    if (NULL == lock) {
        return -1;
    }

    k_sem_init((struct k_sem*)lock, 1, 1);
    return 0;
}

/**
 * @brief Destroy a lock (no-op: k_sem has no teardown).
 */
static void zephyr_lock_destroy(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
}

/**
 * @brief Acquire the lock (blocks indefinitely until available).
 */
static void zephyr_lock_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;

    if (NULL == lock) {
        return;
    }

    k_sem_take((struct k_sem*)lock, K_FOREVER);
}

/**
 * @brief Release the lock.
 */
static void zephyr_lock_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;

    if (NULL == lock) {
        return;
    }

    k_sem_give((struct k_sem*)lock);
}

/** @brief Trampoline context bridging void(*)(void*) to Zephyr thread. */
typedef struct pn_zephyr_trampoline {
    void (*fn)(void*);
    void*                             arg;
    struct pubnub_allocator_provider* allocator;
} pn_zephyr_trampoline_t;

/**
 * @brief Zephyr thread entry point.
 *
 * Copies the trampoline, frees it, then invokes the user function.
 * Zephyr threads terminate naturally by returning from this entry
 * point; k_thread_join waits for that termination.
 */
static void zephyr_thread_entry(void* p1, void* p2, void* p3)
{
    (void)p2;
    (void)p3;

    pn_zephyr_trampoline_t ctx = *(pn_zephyr_trampoline_t*)p1;
    PN_FREE(ctx.allocator, p1);
    ctx.fn(ctx.arg);
}

#if defined(CONFIG_DYNAMIC_THREAD) && (CONFIG_DYNAMIC_THREAD_POOL_SIZE > 0)

/**
 * @brief Create a thread using dynamic stack allocation.
 *
 * Requires CONFIG_DYNAMIC_THREAD=y and CONFIG_DYNAMIC_THREAD_POOL_SIZE > 0
 * in the Zephyr project configuration.
 */
static void* zephyr_thread_create(pubnub_platform_provider_t*       self,
                                  struct pubnub_allocator_provider* allocator,
                                  void (*fn)(void*),
                                  void* arg)
{
    (void)self;

    if (NULL == fn || NULL == allocator || NULL == allocator->alloc) {
        return NULL;
    }

    pn_zephyr_trampoline_t* trampoline = (pn_zephyr_trampoline_t*)PN_ALLOC(
        allocator, sizeof(pn_zephyr_trampoline_t), sizeof(void*));
    if (NULL == trampoline) {
        return NULL;
    }
    trampoline->fn        = fn;
    trampoline->arg       = arg;
    trampoline->allocator = allocator;

    pn_zephyr_thread_handle_t* handle = (pn_zephyr_thread_handle_t*)PN_ALLOC(
        allocator, sizeof(pn_zephyr_thread_handle_t), sizeof(void*));
    if (NULL == handle) {
        PN_FREE(allocator, trampoline);
        return NULL;
    }
    memset(handle, 0, sizeof(*handle));
    handle->pool_slot = -1;

    k_thread_stack_t* stack = k_thread_stack_alloc(PN_ZEPHYR_THREAD_STACK_SIZE, 0);
    if (NULL == stack) {
        PN_FREE(allocator, trampoline);
        PN_FREE(allocator, handle);
        return NULL;
    }
    handle->dyn_stack = stack;

    k_thread_create(&handle->thread,
                    stack,
                    PN_ZEPHYR_THREAD_STACK_SIZE,
                    zephyr_thread_entry,
                    trampoline,
                    NULL,
                    NULL,
                    PN_ZEPHYR_THREAD_PRIORITY,
                    0,
                    K_NO_WAIT);

    return handle;
}

#else  /* Static stack pool path */

/**
 * @brief Create a thread using a pre-allocated static stack pool.
 *
 * The pool has PN_ZEPHYR_MAX_THREADS slots. Returns NULL when all
 * slots are in use.
 */
static void* zephyr_thread_create(pubnub_platform_provider_t*       self,
                                  struct pubnub_allocator_provider* allocator,
                                  void (*fn)(void*),
                                  void* arg)
{
    (void)self;

    if (NULL == fn || NULL == allocator || NULL == allocator->alloc) {
        return NULL;
    }

    /* Find a free stack slot atomically. */
    int slot = -1;
    for (int i = 0; i < PN_ZEPHYR_MAX_THREADS; ++i) {
        if (!atomic_test_and_set_bit(pn_zephyr_stack_used, i)) {
            slot = i;
            break;
        }
    }
    if (-1 == slot) {
        return NULL;
    }

    pn_zephyr_trampoline_t* trampoline = (pn_zephyr_trampoline_t*)PN_ALLOC(
        allocator, sizeof(pn_zephyr_trampoline_t), sizeof(void*));
    if (NULL == trampoline) {
        atomic_clear_bit(pn_zephyr_stack_used, slot);
        return NULL;
    }
    trampoline->fn        = fn;
    trampoline->arg       = arg;
    trampoline->allocator = allocator;

    pn_zephyr_thread_handle_t* handle = (pn_zephyr_thread_handle_t*)PN_ALLOC(
        allocator, sizeof(pn_zephyr_thread_handle_t), sizeof(void*));
    if (NULL == handle) {
        PN_FREE(allocator, trampoline);
        atomic_clear_bit(pn_zephyr_stack_used, slot);
        return NULL;
    }
    memset(handle, 0, sizeof(*handle));
    handle->dyn_stack = NULL;
    handle->pool_slot = slot;

    k_thread_create(&handle->thread,
                    pn_zephyr_stacks[slot],
                    K_THREAD_STACK_SIZEOF(pn_zephyr_stacks[slot]),
                    zephyr_thread_entry,
                    trampoline,
                    NULL,
                    NULL,
                    PN_ZEPHYR_THREAD_PRIORITY,
                    0,
                    K_NO_WAIT);

    return handle;
}

#endif /* CONFIG_DYNAMIC_THREAD */

/**
 * @brief Join a previously created thread and release resources.
 *
 * Blocks until the thread terminates, then frees the stack (dynamic)
 * or releases the pool slot (static), and frees the handle.
 */
static void zephyr_thread_join(pubnub_platform_provider_t*       self,
                               struct pubnub_allocator_provider* allocator,
                               void*                             thread_handle)
{
    (void)self;

    if (NULL == thread_handle) {
        return;
    }

    pn_zephyr_thread_handle_t* handle = (pn_zephyr_thread_handle_t*)thread_handle;

    k_thread_join(&handle->thread, K_FOREVER);

#if defined(CONFIG_DYNAMIC_THREAD) && (CONFIG_DYNAMIC_THREAD_POOL_SIZE > 0)
    if (NULL != handle->dyn_stack) {
        k_thread_stack_free(handle->dyn_stack);
    }
#else
    if (handle->pool_slot >= 0 && handle->pool_slot < PN_ZEPHYR_MAX_THREADS) {
        atomic_clear_bit(pn_zephyr_stack_used, handle->pool_slot);
    }
#endif

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, handle);
    }
}

/** @brief Report whether @p thread_handle is the calling thread. */
static int zephyr_thread_is_current(pubnub_platform_provider_t* self,
                                    void*                       thread_handle)
{
    pn_zephyr_thread_handle_t* handle;

    (void)self;

    if (NULL == thread_handle) {
        return 0;
    }

    handle = (pn_zephyr_thread_handle_t*)thread_handle;
    return k_current_get() == &handle->thread ? 1 : 0;
}

/* Stateless singleton shared across all contexts. */
static pubnub_platform_provider_t pn_zephyr_platform = {
    .monotonic_ms      = zephyr_monotonic_ms,
    .wall_clock_ms     = zephyr_wall_clock_ms,
    .sleep_ms          = zephyr_sleep_ms,
    .random_bytes      = zephyr_random_bytes,
    .secure_zero       = zephyr_secure_zero,
    .lock_size         = zephyr_lock_size,
    .lock_init         = zephyr_lock_init,
    .lock_destroy      = zephyr_lock_destroy,
    .lock_acquire      = zephyr_lock_acquire,
    .lock_release      = zephyr_lock_release,
    .thread_create     = zephyr_thread_create,
    .thread_join       = zephyr_thread_join,
    .thread_is_current = zephyr_thread_is_current,
    .file_load         = NULL,
};

pubnub_platform_provider_t* pn_platform_default(void)
{
    return &pn_zephyr_platform;
}

#else
/* Not compiling for a Zephyr target (e.g., hosted CI on Linux/macOS).
 * All function pointers are NULL - client init will fail with
 * PUBNUB_ERR_PROVIDER_MISSING unless cfg.platform is set to a valid
 * host provider (e.g., POSIX). */
static pubnub_platform_provider_t pn_zephyr_stub_platform = {0};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_platform_provider_t* pn_platform_default(void)
{
    return &pn_zephyr_stub_platform;
}

#pragma GCC diagnostic pop
#endif /* __ZEPHYR__ */

/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file platform_freertos.c
 * @brief FreeRTOS platform provider for embedded profiles (ESP32,
 * generic FreeRTOS targets).
 *
 * Clock: 64-bit boot-relative monotonic clock built on xTaskGetTickCount
 * with software rollover detection. Wall-clock time for PAM signing
 * via time() on ESP-IDF (NTP-synced) or 0 on targets without RTC.
 * Sync: binary semaphore via static allocation, ISR-safe signalling.
 * Locks: FreeRTOS mutexes via StaticSemaphore_t (no heap needed).
 * Thread: xTaskCreate with allocator-managed trampoline.
 * Stateless singleton shared across all contexts.
 */

#include "pubnub/providers/platform.h"

#if defined(PUBNUB_PLATFORM_FREERTOS) || defined(ESP_PLATFORM) || defined(FREERTOS)

#include "pubnub/providers/allocator.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#else
#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#endif

#if defined(ESP_PLATFORM)
#include "esp_random.h"
#endif

#if !defined(ESP_PLATFORM)
#include <stdlib.h>
#endif

#if defined(ESP_PLATFORM) || defined(CONFIG_POSIX_API)
#include <sys/time.h>
#include <time.h>
#endif

#if PUBNUB_ENABLE_FILESYSTEM
#include <stdio.h>
#endif

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_platform_provider_t* pn_platform_default(void);

#if defined(ESP_PLATFORM)
static portMUX_TYPE s_tick_spinlock = portMUX_INITIALIZER_UNLOCKED;
#endif

/**
 * @brief 64-bit monotonic clock state for rollover detection.
 *
 * xTaskGetTickCount() is 32-bit on most FreeRTOS ports and wraps
 * every ~49.7 days at 1 kHz tick rate. The SDK's connection FSM uses
 * absolute deadline comparisons (now >= deadline) that are NOT
 * wrap-safe. This state extends the tick counter to 64 bits by
 * detecting 32-bit rollovers, yielding a monotonic clock that will
 * not overflow for ~585 million years.
 *
 * Requirement: monotonic_ms must be called at least once per wrap
 * period (~49.7 days). The transport layer calls it continuously
 * during I/O polling, so this is always satisfied.
 */
static volatile uint64_t s_tick_ms_high = 0;
static volatile uint32_t s_tick_last    = 0;

/**
 * @brief Boot-relative monotonic clock in milliseconds (64-bit).
 *
 * Combines xTaskGetTickCount (32-bit) with software rollover
 * detection to produce a 64-bit monotonic timestamp. A critical
 * section protects the shared rollover state from concurrent access
 * by multiple tasks.
 */
static pubnub_milliseconds_t freertos_monotonic_ms(pubnub_platform_provider_t* self)
{
    uint64_t   result;
    TickType_t now_ticks;

    (void)self;

#if defined(ESP_PLATFORM)
    taskENTER_CRITICAL(&s_tick_spinlock);
#else
    taskENTER_CRITICAL();
#endif

    now_ticks = xTaskGetTickCount();

    if ((uint32_t)now_ticks < s_tick_last) {
        /* 32-bit rollover detected. Accumulate the full wrap period
         * into the high bits. */
        s_tick_ms_high += ((uint64_t)UINT32_MAX + 1U) * (uint64_t)portTICK_PERIOD_MS;
    }
    s_tick_last = (uint32_t)now_ticks;

    result = s_tick_ms_high + (uint64_t)now_ticks * (uint64_t)portTICK_PERIOD_MS;

#if defined(ESP_PLATFORM)
    taskEXIT_CRITICAL(&s_tick_spinlock);
#else
    taskEXIT_CRITICAL();
#endif

    return (pubnub_milliseconds_t)result;
}

/**
 * @brief Wall-clock time in milliseconds since Unix epoch.
 *
 * On ESP-IDF, time() returns the NTP-synced wall-clock value
 * after esp_sntp_init() completes. On generic FreeRTOS targets
 * without a POSIX-compatible time(), returns 0 (PAM middleware
 * treats 0 as "wall-clock unavailable").
 */
static pubnub_milliseconds_t freertos_wall_clock_ms(pubnub_platform_provider_t* self)
{
#if defined(ESP_PLATFORM) || defined(CONFIG_POSIX_API)
    struct timeval tv;
#endif

    (void)self;

#if defined(ESP_PLATFORM) || defined(CONFIG_POSIX_API)
    if (0 != gettimeofday(&tv, NULL) || 0 == tv.tv_sec) {
        return 0;
    }
    return (pubnub_milliseconds_t)tv.tv_sec * 1000U
         + (pubnub_milliseconds_t)(tv.tv_usec / 1000);
#else
    return 0;
#endif
}

/**
 * @brief Delay the calling task for at least ms milliseconds.
 *
 * Minimum granularity is one tick. A request for 0 ms yields the
 * CPU for the remainder of the current tick (taskYIELD behavior).
 */
static void freertos_sleep_ms(pubnub_platform_provider_t* self, uint32_t ms)
{
    TickType_t ticks;

    (void)self;

    if (0 == ms) {
        taskYIELD();
        return;
    }

    ticks = (TickType_t)(ms / portTICK_PERIOD_MS);
    if (0 == ticks) {
        ticks = 1;
    }

    vTaskDelay(ticks);
}

/**
 * @brief Fill @p buf with cryptographically-secure random bytes.
 *
 * ESP32: delegates to esp_fill_random. All other FreeRTOS targets:
 * returns failure — a hardware RNG must be wired via the provider vtable.
 * DNS, proxy auth, and file uploads fail by design without one.
 *
 * @param self Pointer to this provider instance (unused).
 * @param buf  Output buffer to fill with random bytes.
 * @param len  Number of bytes to generate.
 * @retval 0        Bytes generated (ESP32 hardware RNG).
 * @retval non-zero No hardware RNG available, or invalid arguments.
 */
static int freertos_random_bytes(pubnub_platform_provider_t* self,
                                 uint8_t*                    buf,
                                 size_t                      len)
{
    (void)self;

    if (0 == len) {
        return 0;
    }
    if (NULL == buf) {
        return -1;
    }

#if defined(ESP_PLATFORM)
    esp_fill_random(buf, len);
    return 0;
#else
    /* No cryptographically-secure RNG is available. Fail loudly rather
     * than emit predictable bytes that callers would treat as random.
     * The platform vtable carries no logger reference, so warn once via
     * the FreeRTOS-idiomatic configPRINTF hook when the port defines it
     * (zero cost when absent). */
    {
        static volatile uint8_t warned = 0;
        if (0 == warned) {
            warned = 1;
#ifdef configPRINTF
            configPRINTF(("[PubNub] random_bytes: no hardware RNG"
                          " configured; DNS, files, and proxy auth"
                          " will fail on this target\r\n"));
#endif
        }
    }
    (void)buf;
    (void)len;
    return -1;
#endif
}

/**
 * @brief Secure-zeroize a buffer via volatile writes.
 *
 * Prevents the compiler from optimizing out the zeroing operation.
 * FreeRTOS does not provide memset_s or explicit_bzero.
 */
static void freertos_secure_zero(pubnub_platform_provider_t* self, void* buf, size_t len)
{
    volatile uint8_t* p;
    size_t            i;

    (void)self;

    if (NULL == buf || 0 == len) {
        return;
    }

    p = (volatile uint8_t*)buf;
    for (i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

/**
 * @brief Return the size of a FreeRTOS mutex (StaticSemaphore_t).
 *
 * The SDK allocates this many bytes and passes the memory to
 * lock_init. Using StaticSemaphore_t avoids any heap allocation
 * inside FreeRTOS for the mutex.
 */
static size_t freertos_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return sizeof(StaticSemaphore_t);
}

/**
 * @brief Initialize a FreeRTOS mutex in caller-provided memory.
 *
 * Uses xSemaphoreCreateMutexStatic to place the mutex in the
 * provided buffer without heap allocation. On all standard FreeRTOS
 * ports, the returned SemaphoreHandle_t is numerically equal to the
 * StaticSemaphore_t pointer passed in.
 */
static int freertos_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    SemaphoreHandle_t handle;

    (void)self;

    if (NULL == lock) {
        return -1;
    }

    handle = xSemaphoreCreateMutexStatic((StaticSemaphore_t*)lock);

    if (NULL == handle) {
        return -1;
    }

    return 0;
}

/**
 * @brief Destroy a FreeRTOS mutex.
 *
 * vSemaphoreDelete releases kernel bookkeeping. The backing memory
 * (StaticSemaphore_t) is owned by the SDK allocator, not freed here.
 */
static void freertos_lock_destroy(pubnub_platform_provider_t* self,
                                  pubnub_lock_t*              lock)
{
    (void)self;

    if (NULL == lock) {
        return;
    }

    vSemaphoreDelete((SemaphoreHandle_t)lock);
}

/**
 * @brief Acquire a FreeRTOS mutex (blocking, non-recursive).
 */
static void freertos_lock_acquire(pubnub_platform_provider_t* self,
                                  pubnub_lock_t*              lock)
{
    (void)self;

    if (NULL == lock) {
        return;
    }

    xSemaphoreTake((SemaphoreHandle_t)lock, portMAX_DELAY);
}

/**
 * @brief Release a FreeRTOS mutex.
 */
static void freertos_lock_release(pubnub_platform_provider_t* self,
                                  pubnub_lock_t*              lock)
{
    (void)self;

    if (NULL == lock) {
        return;
    }

    xSemaphoreGive((SemaphoreHandle_t)lock);
}

/** @brief Thread handle wrapping a FreeRTOS TaskHandle_t. */
typedef struct freertos_thread_handle {
    TaskHandle_t task;
} freertos_thread_handle_t;

/** @brief Trampoline context bridging void(*)(void*) to FreeRTOS task. */
typedef struct freertos_thread_trampoline {
    void (*fn)(void*);
    void*                             arg;
    struct pubnub_allocator_provider* allocator;
} freertos_thread_trampoline_t;

/**
 * @brief FreeRTOS task entry point that invokes the user function.
 *
 * Frees the trampoline struct, invokes the function, then suspends
 * the task so the handle remains valid for thread_join.
 * vTaskDelete is called from the joining side.
 */
static void freertos_task_entry(void* raw)
{
    freertos_thread_trampoline_t ctx = *(freertos_thread_trampoline_t*)raw;
    PN_FREE(ctx.allocator, raw);
    ctx.fn(ctx.arg);

    /* Suspend self - thread_join polls for eSuspended then deletes. */
    vTaskSuspend(NULL);
}

/** @brief Default stack depth for SDK-spawned tasks (in words). */
#ifndef PN_FREERTOS_TASK_STACK_DEPTH
#define PN_FREERTOS_TASK_STACK_DEPTH 4096
#endif

/** @brief Default priority for SDK-spawned tasks. */
#ifndef PN_FREERTOS_TASK_PRIORITY
#define PN_FREERTOS_TASK_PRIORITY (tskIDLE_PRIORITY + 1)
#endif

/**
 * @brief Create a new FreeRTOS task executing fn(arg).
 *
 * Stack depth and priority are compile-time tunables
 * (PN_FREERTOS_TASK_STACK_DEPTH, PN_FREERTOS_TASK_PRIORITY).
 */
static void* freertos_thread_create(pubnub_platform_provider_t*       self,
                                    struct pubnub_allocator_provider* allocator,
                                    void (*fn)(void*),
                                    void* arg)
{
    freertos_thread_trampoline_t* trampoline;
    freertos_thread_handle_t*     handle;
    BaseType_t                    rc;

    (void)self;

    if (NULL == fn || NULL == allocator || NULL == allocator->alloc) {
        return NULL;
    }

    trampoline = (freertos_thread_trampoline_t*)PN_ALLOC(
        allocator, sizeof(freertos_thread_trampoline_t), sizeof(void*));
    if (NULL == trampoline) {
        return NULL;
    }
    trampoline->fn        = fn;
    trampoline->arg       = arg;
    trampoline->allocator = allocator;

    handle = (freertos_thread_handle_t*)PN_ALLOC(
        allocator, sizeof(freertos_thread_handle_t), sizeof(void*));
    if (NULL == handle) {
        PN_FREE(allocator, trampoline);
        return NULL;
    }

    rc = xTaskCreate(freertos_task_entry,
                     "pn_worker",
                     PN_FREERTOS_TASK_STACK_DEPTH,
                     trampoline,
                     PN_FREERTOS_TASK_PRIORITY,
                     &handle->task);
    if (pdPASS != rc) {
        PN_FREE(allocator, trampoline);
        PN_FREE(allocator, handle);
        return NULL;
    }

    return handle;
}

/**
 * @brief Wait for a FreeRTOS task to finish and release its resources.
 *
 * Polls eTaskGetState until the task is suspended (task entry suspends
 * itself after fn returns), then deletes it. This is the simplest
 * portable join pattern for FreeRTOS which has no native join API.
 */
static void freertos_thread_join(pubnub_platform_provider_t*       self,
                                 struct pubnub_allocator_provider* allocator,
                                 void* thread_handle)
{
    freertos_thread_handle_t* handle;

    (void)self;

    if (NULL == thread_handle) {
        return;
    }

    handle = (freertos_thread_handle_t*)thread_handle;

    /* Wait for the task to reach suspended state. */
    while (eSuspended != eTaskGetState(handle->task)) {
        vTaskDelay(1);
    }

    vTaskDelete(handle->task);

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, handle);
    }
}

/** @brief Report whether @p thread_handle is the calling task. */
static int freertos_thread_is_current(pubnub_platform_provider_t* self,
                                      void*                       thread_handle)
{
    freertos_thread_handle_t* handle;

    (void)self;

    if (NULL == thread_handle) {
        return 0;
    }

    handle = (freertos_thread_handle_t*)thread_handle;
    return xTaskGetCurrentTaskHandle() == handle->task ? 1 : 0;
}

#if PUBNUB_ENABLE_FILESYSTEM
/** @brief Load file content into an allocator-owned buffer via POSIX VFS. */
static pubnub_res_t freertos_file_load(pubnub_platform_provider_t* self,
                                       const char*                 path,
                                       struct pubnub_allocator_provider* allocator,
                                       uint8_t** out_data,
                                       size_t*   out_len)
{
    FILE* fp;
    long  sz;

    (void)self;

    if (NULL == path || NULL == allocator || NULL == out_data || NULL == out_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    *out_data = NULL;
    *out_len  = 0;

    fp = fopen(path, "rb");
    if (NULL == fp) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    if (0 != fseek(fp, 0, SEEK_END)) {
        (void)fclose(fp);
        return PUBNUB_ERR_INTERNAL;
    }
    sz = ftell(fp);
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
#endif /* PUBNUB_ENABLE_FILESYSTEM */

/* Stateless singleton shared across all contexts. */
static pubnub_platform_provider_t pn_freertos_platform = {
    .monotonic_ms      = freertos_monotonic_ms,
    .wall_clock_ms     = freertos_wall_clock_ms,
    .sleep_ms          = freertos_sleep_ms,
    .random_bytes      = freertos_random_bytes,
    .secure_zero       = freertos_secure_zero,
    .lock_size         = freertos_lock_size,
    .lock_init         = freertos_lock_init,
    .lock_destroy      = freertos_lock_destroy,
    .lock_acquire      = freertos_lock_acquire,
    .lock_release      = freertos_lock_release,
    .thread_create     = freertos_thread_create,
    .thread_join       = freertos_thread_join,
    .thread_is_current = freertos_thread_is_current,
#if PUBNUB_ENABLE_FILESYSTEM
    .file_load = freertos_file_load,
#endif
};

pubnub_platform_provider_t* pn_platform_default(void)
{
    return &pn_freertos_platform;
}

#else
/* Not compiling for a FreeRTOS target (e.g., hosted CI on Linux/macOS).
 * All function pointers are NULL — client init will fail with
 * PUBNUB_ERR_PROVIDER_MISSING unless cfg.platform is set to a valid
 * host provider (e.g., POSIX). */
static pubnub_platform_provider_t pn_freertos_stub_platform = {0};

/* Not in a header: suppress the missing-prototype warning for this
 * stub that only exists on non-FreeRTOS host builds. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_platform_provider_t* pn_platform_default(void)
{
    return &pn_freertos_stub_platform;
}

#pragma GCC diagnostic pop
#endif /* PUBNUB_PLATFORM_FREERTOS || ESP_PLATFORM || FREERTOS */

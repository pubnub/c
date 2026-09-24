/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "it_bus.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#endif

/** Number of slots in each ring. */
#define IT_BUS_RING_SIZE 32U
/** Maximum bytes (including NUL) copied per string-view field. */
#define IT_BUS_STR_MAX 512U

/**
 * One message ring slot.  The char arrays own the bytes that the
 * string-view fields in @c ev point at.
 */
typedef struct {
    pubnub_subscribe_event_t ev;
    char                     channel_buf[IT_BUS_STR_MAX];
    char                     subscription_buf[IT_BUS_STR_MAX];
    char                     publisher_buf[IT_BUS_STR_MAX];
    char                     custom_message_type_buf[IT_BUS_STR_MAX];
    char                     timetoken_buf[IT_BUS_STR_MAX];
} it_bus_msg_slot_t;

struct it_bus {
    it_bus_msg_slot_t msg_ring[IT_BUS_RING_SIZE];
    unsigned int      msg_head;  /**< Next write index. */
    unsigned int      msg_count; /**< Occupied slots. */

    pubnub_subscribe_status_t status_ring[IT_BUS_RING_SIZE];
    unsigned int              status_head;
    unsigned int              status_count;

#ifdef _WIN32
    CRITICAL_SECTION   msg_cs;
    CONDITION_VARIABLE msg_cv;
    CRITICAL_SECTION   status_cs;
    CONDITION_VARIABLE status_cv;
#else
    pthread_mutex_t msg_mutex;
    pthread_cond_t  msg_cond;
    pthread_mutex_t status_mutex;
    pthread_cond_t  status_cond;
#endif
};

/** Copy at most IT_BUS_STR_MAX-1 bytes from @p src into @p buf and
 *  wire @p dst to point at the result. */
static void copy_str_view(pubnub_string_view_t*       dst,
                          char* const                 buf,
                          const pubnub_string_view_t* src)
{
    size_t len = src->len;
    if (len >= IT_BUS_STR_MAX) {
        len = IT_BUS_STR_MAX - 1U;
    }
    if (NULL != src->ptr && 0U < len) {
        memcpy(buf, src->ptr, len);
    }
    buf[len] = '\0';
    dst->ptr = buf;
    dst->len = len;
}

#ifndef _WIN32
/** Compute an absolute CLOCK_REALTIME deadline from a relative
 *  @p timeout_ms offset. */
static void ms_to_abs_deadline(unsigned int timeout_ms, struct timespec* deadline)
{
    clock_gettime(CLOCK_REALTIME, deadline);
    deadline->tv_sec += (time_t)(timeout_ms / 1000U);
    deadline->tv_nsec += (long)((timeout_ms % 1000U) * 1000000L);
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}
#endif

it_bus_t* it_bus_create(void)
{
    it_bus_t* bus = calloc(1, sizeof(*bus));
    if (NULL == bus) {
        return NULL;
    }
#ifdef _WIN32
    InitializeCriticalSection(&bus->msg_cs);
    InitializeConditionVariable(&bus->msg_cv);
    InitializeCriticalSection(&bus->status_cs);
    InitializeConditionVariable(&bus->status_cv);
#else
    pthread_mutex_init(&bus->msg_mutex, NULL);
    pthread_cond_init(&bus->msg_cond, NULL);
    pthread_mutex_init(&bus->status_mutex, NULL);
    pthread_cond_init(&bus->status_cond, NULL);
#endif
    return bus;
}

void it_bus_destroy(it_bus_t* bus)
{
    if (NULL == bus) {
        return;
    }
#ifdef _WIN32
    DeleteCriticalSection(&bus->msg_cs);
    DeleteCriticalSection(&bus->status_cs);
#else
    pthread_cond_destroy(&bus->msg_cond);
    pthread_mutex_destroy(&bus->msg_mutex);
    pthread_cond_destroy(&bus->status_cond);
    pthread_mutex_destroy(&bus->status_mutex);
#endif
    free(bus);
}

void it_bus_push_message(it_bus_t* bus, const pubnub_subscribe_event_t* ev)
{
    it_bus_msg_slot_t* slot;

#ifdef _WIN32
    EnterCriticalSection(&bus->msg_cs);
    if (bus->msg_count >= IT_BUS_RING_SIZE) {
        LeaveCriticalSection(&bus->msg_cs);
        return;
    }
#else
    pthread_mutex_lock(&bus->msg_mutex);
    if (bus->msg_count >= IT_BUS_RING_SIZE) {
        pthread_mutex_unlock(&bus->msg_mutex);
        return;
    }
#endif

    slot     = &bus->msg_ring[bus->msg_head];
    slot->ev = *ev;
    /* JSON tree pointers alias SDK-internal parsed nodes valid only
     * for the callback duration; set to NULL in the slot copy. */
    slot->ev.payload       = NULL;
    slot->ev.user_metadata = NULL;
    copy_str_view(&slot->ev.channel, slot->channel_buf, &ev->channel);
    copy_str_view(&slot->ev.subscription, slot->subscription_buf, &ev->subscription);
    copy_str_view(&slot->ev.publisher, slot->publisher_buf, &ev->publisher);
    copy_str_view(&slot->ev.custom_message_type,
                  slot->custom_message_type_buf,
                  &ev->custom_message_type);
    copy_str_view(&slot->ev.timetoken, slot->timetoken_buf, &ev->timetoken);
    bus->msg_head = (bus->msg_head + 1U) % IT_BUS_RING_SIZE;
    bus->msg_count++;

#ifdef _WIN32
    WakeConditionVariable(&bus->msg_cv);
    LeaveCriticalSection(&bus->msg_cs);
#else
    pthread_cond_signal(&bus->msg_cond);
    pthread_mutex_unlock(&bus->msg_mutex);
#endif
}

void it_bus_push_status(it_bus_t* bus, pubnub_subscribe_status_t status)
{
#ifdef _WIN32
    EnterCriticalSection(&bus->status_cs);
    if (bus->status_count >= IT_BUS_RING_SIZE) {
        LeaveCriticalSection(&bus->status_cs);
        return;
    }
    bus->status_ring[bus->status_head] = status;
    bus->status_head = (bus->status_head + 1U) % IT_BUS_RING_SIZE;
    bus->status_count++;
    WakeConditionVariable(&bus->status_cv);
    LeaveCriticalSection(&bus->status_cs);
#else
    pthread_mutex_lock(&bus->status_mutex);
    if (bus->status_count >= IT_BUS_RING_SIZE) {
        pthread_mutex_unlock(&bus->status_mutex);
        return;
    }
    bus->status_ring[bus->status_head] = status;
    bus->status_head = (bus->status_head + 1U) % IT_BUS_RING_SIZE;
    bus->status_count++;
    pthread_cond_signal(&bus->status_cond);
    pthread_mutex_unlock(&bus->status_mutex);
#endif
}

int it_bus_wait_message(it_bus_t*                 bus,
                        unsigned int              timeout_ms,
                        pubnub_subscribe_event_t* out)
{
    unsigned int tail;

#ifdef _WIN32
    ULONGLONG start  = GetTickCount64();
    DWORD     remain = (DWORD)timeout_ms;

    EnterCriticalSection(&bus->msg_cs);
    while (0U == bus->msg_count) {
        if (!SleepConditionVariableCS(&bus->msg_cv, &bus->msg_cs, remain)) {
            LeaveCriticalSection(&bus->msg_cs);
            return 0;
        }
        ULONGLONG elapsed = GetTickCount64() - start;
        if (elapsed >= (ULONGLONG)timeout_ms) {
            LeaveCriticalSection(&bus->msg_cs);
            return 0;
        }
        remain = (DWORD)((ULONGLONG)timeout_ms - elapsed);
    }
    tail = (bus->msg_head + IT_BUS_RING_SIZE - bus->msg_count) % IT_BUS_RING_SIZE;
    *out = bus->msg_ring[tail].ev;
    bus->msg_count--;
    LeaveCriticalSection(&bus->msg_cs);
    return 1;
#else
    struct timespec deadline;
    int             rc;

    ms_to_abs_deadline(timeout_ms, &deadline);
    pthread_mutex_lock(&bus->msg_mutex);
    while (0U == bus->msg_count) {
        rc = pthread_cond_timedwait(&bus->msg_cond, &bus->msg_mutex, &deadline);
        if (0 != rc) {
            pthread_mutex_unlock(&bus->msg_mutex);
            return 0;
        }
    }
    tail = (bus->msg_head + IT_BUS_RING_SIZE - bus->msg_count) % IT_BUS_RING_SIZE;
    *out = bus->msg_ring[tail].ev;
    bus->msg_count--;
    pthread_mutex_unlock(&bus->msg_mutex);
    return 1;
#endif
}

int it_bus_wait_status(it_bus_t*                 bus,
                       unsigned int              timeout_ms,
                       pubnub_subscribe_status_t expected)
{
    pubnub_subscribe_status_t got;
    unsigned int              tail;

#ifdef _WIN32
    ULONGLONG start  = GetTickCount64();
    DWORD     remain = (DWORD)timeout_ms;

    EnterCriticalSection(&bus->status_cs);
    for (;;) {
        while (0U == bus->status_count) {
            if (!SleepConditionVariableCS(&bus->status_cv, &bus->status_cs, remain)) {
                LeaveCriticalSection(&bus->status_cs);
                return 0;
            }
            ULONGLONG elapsed = GetTickCount64() - start;
            if (elapsed >= (ULONGLONG)timeout_ms) {
                LeaveCriticalSection(&bus->status_cs);
                return 0;
            }
            remain = (DWORD)((ULONGLONG)timeout_ms - elapsed);
        }
        tail = (bus->status_head + IT_BUS_RING_SIZE - bus->status_count)
             % IT_BUS_RING_SIZE;
        got = bus->status_ring[tail];
        bus->status_count--;
        if (got == expected) {
            LeaveCriticalSection(&bus->status_cs);
            return 1;
        }
    }
#else
    struct timespec deadline;
    int             rc;

    ms_to_abs_deadline(timeout_ms, &deadline);
    pthread_mutex_lock(&bus->status_mutex);
    for (;;) {
        while (0U == bus->status_count) {
            rc = pthread_cond_timedwait(
                &bus->status_cond, &bus->status_mutex, &deadline);
            if (0 != rc) {
                pthread_mutex_unlock(&bus->status_mutex);
                return 0;
            }
        }
        tail = (bus->status_head + IT_BUS_RING_SIZE - bus->status_count)
             % IT_BUS_RING_SIZE;
        got = bus->status_ring[tail];
        bus->status_count--;
        if (got == expected) {
            pthread_mutex_unlock(&bus->status_mutex);
            return 1;
        }
    }
#endif
}

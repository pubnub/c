/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "it_channel.h"

/* libc snprintf is acceptable — this file is test-only host code that
 * never runs on embedded targets. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#define IT_POOL_SIZE 16
/* "pn-it-" (6) + 8 hex chars + "-" (1) + suffix (63) + NUL (1) = 79 */
#define IT_BUF_SIZE 80

/* Seed for rand_r() / rand_s().  Initialized once; any init race is
 * benign for test uniqueness — both threads would compute the same
 * value. */
static unsigned int s_seed;
static int          s_seed_init;

static unsigned int it_next_hex(void)
{
    if (0 == s_seed_init) {
#ifdef _WIN32
        /* rand_s() is cryptographically seeded by the OS; s_seed unused. */
        s_seed = 0;
#else
        /* Mix nanosecond clock with PID so two jobs starting at the same
         * second on the same host still get distinct channel names. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        s_seed = (unsigned int)ts.tv_nsec ^ ((unsigned int)ts.tv_sec << 17)
               ^ (unsigned int)getpid();
#endif
        s_seed_init = 1;
    }
#ifdef _WIN32
    unsigned int val = 0;
    rand_s(&val);
    return val;
#else
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    /* libc rand_r is deprecated on POSIX.1-2008 but is acceptable
     * for test-only host code that needs no cryptographic quality. */
    return (unsigned int)rand_r(&s_seed);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif /* _WIN32 */
}

static char    s_it_pool[IT_POOL_SIZE][IT_BUF_SIZE];
static uint8_t s_it_ring;

static char    s_xs_pool[IT_POOL_SIZE][IT_BUF_SIZE];
static uint8_t s_xs_ring;

const char* it_unique_name(const char* suffix)
{
    int          idx = s_it_ring;
    unsigned int hex = it_next_hex();
    s_it_ring        = (s_it_ring + 1) % IT_POOL_SIZE;
    snprintf(s_it_pool[idx],
             IT_BUF_SIZE,
             "pn-it-%08x-%.*s",
             hex,
             IT_NAME_SUFFIX_MAX,
             (NULL != suffix) ? suffix : "");
    return s_it_pool[idx];
}

const char* it_xs_channel(const char* suffix)
{
    int          idx = s_xs_ring;
    unsigned int hex = it_next_hex();
    s_xs_ring        = (s_xs_ring + 1) % IT_POOL_SIZE;
    snprintf(s_xs_pool[idx],
             IT_BUF_SIZE,
             "pn-xs-%08x-%.*s",
             hex,
             IT_NAME_SUFFIX_MAX,
             (NULL != suffix) ? suffix : "");
    return s_xs_pool[idx];
}

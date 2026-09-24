/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/* nanosleep() requires _POSIX_C_SOURCE >= 199309L for its declaration
 * via <time.h> on strict C99/C11 compilers (notably Clang on Linux). */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 199309L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

/**
 * @file posix_platform_units.c
 * @brief Unit tests for the POSIX platform provider.
 *
 * Exercises the three mandatory callbacks on a real kernel
 * (monotonic_ms, sleep_ms, random_bytes) plus the vtable surface.
 * Tests that depend on wall-clock-like behaviour use generous
 * tolerances so they remain reliable on shared CI runners where
 * scheduling jitter can delay a thread by tens of milliseconds.
 *
 * Optional hooks are asserted against the shape the provider actually
 * publishes: lock and thread primitives are wired, secure_zero is not,
 * and file_load follows PUBNUB_ENABLE_FILESYSTEM.
 */

#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"

#include "support/test_allocator.h"

pubnub_platform_provider_t* pn_platform_default(void);

/**
 * @brief Shannon-style sanity check: return non-zero if @p buf is
 *        "mostly zeros" (>= 90% of bytes are 0x00).
 *
 * Real entropy output will not trip this even for short buffers.
 * The test is intentionally conservative -- we want to catch the
 * "forgot to fill the buffer" bug, not to validate randomness
 * quality, which is the kernel CSPRNG's job.
 */
static int buffer_is_mostly_zero(const uint8_t* buf, size_t len)
{
    size_t zeros = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0) {
            zeros++;
        }
    }
    return (zeros * 10) >= (len * 9);
}

static void monotonic_ms_should_return_nonzero_after_boot(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* CLOCK_MONOTONIC starts at an arbitrary positive epoch on every
     * POSIX kernel we target. Even on the rare system that starts
     * at zero, by the time a test process has reached this line the
     * kernel has necessarily ticked past 0 ms, so nonzero is a safe
     * expectation. */
    pubnub_milliseconds_t now = p->monotonic_ms(p);

    assert_true(now > 0);
}

static void monotonic_ms_should_be_monotonically_nondecreasing(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    pubnub_milliseconds_t t0 = p->monotonic_ms(p);
    pubnub_milliseconds_t t1 = p->monotonic_ms(p);
    pubnub_milliseconds_t t2 = p->monotonic_ms(p);

    /* No sleep between readings. Two successive readings may return
     * the same value (both within the same millisecond), but must
     * never go backwards. This is the property the whole retry /
     * timeout machinery depends on. */
    assert_true(t1 >= t0);
    assert_true(t2 >= t1);
}

static void monotonic_ms_should_advance_after_real_sleep(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    pubnub_milliseconds_t before = p->monotonic_ms(p);
    struct timespec       nap    = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
    /* Use the standard nanosleep here so that a regression in
     * posix_sleep_ms cannot mask a regression in posix_monotonic_ms:
     * each test depends on only one callback at a time. */
    nanosleep(&nap, NULL);
    pubnub_milliseconds_t after = p->monotonic_ms(p);

    /* We slept 10 ms; a 5 ms advance is more than sufficient
     * evidence that the clock is progressing without being tight
     * enough to fail under scheduler jitter on loaded CI hosts. */
    assert_true(after - before >= 5);
}

static void sleep_ms_should_sleep_for_at_least_requested_duration(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    pubnub_milliseconds_t before = p->monotonic_ms(p);
    p->sleep_ms(p, 20);
    pubnub_milliseconds_t after = p->monotonic_ms(p);

    /* nanosleep guarantees at least the requested duration, never
     * less; the upper bound is unbounded in theory but typically
     * within a few ms of the request on idle hardware. We assert
     * only the lower bound -- that is the property the SDK relies
     * on (retries must wait AT LEAST the backoff). */
    assert_true(after - before >= 20);
}

static void sleep_ms_with_zero_should_return_promptly(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    pubnub_milliseconds_t before = p->monotonic_ms(p);
    p->sleep_ms(p, 0);
    pubnub_milliseconds_t after = p->monotonic_ms(p);

    /* nanosleep with a zero timespec is a valid no-op / yield.
     * The 100 ms ceiling is generous because a heavily loaded CI
     * host (shared-core GitHub Actions runner) can schedule the
     * thread out for tens of milliseconds at a time; we want to
     * catch a regression that turns zero-sleep into a real wait,
     * not fire on scheduler jitter. */
    assert_true(after - before < 100);
}

static void random_bytes_should_return_zero_on_success(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    uint8_t buf[16] = {0};
    int     rc      = p->random_bytes(p, buf, sizeof(buf));

    assert_int_equal(rc, 0);
}

static void random_bytes_should_fill_buffer_with_nonzero_entropy(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* 256 bytes lets us amortise the tiny probability that a true
     * CSPRNG emits a mostly-zero run. The statistical probability
     * of 230+ of 256 random bytes being exactly 0x00 is vanishingly
     * small (~10^-505); if this test fires it's because the buffer
     * wasn't actually written to. */
    uint8_t buf[256] = {0};
    int     rc       = p->random_bytes(p, buf, sizeof(buf));

    assert_int_equal(rc, 0);
    assert_false(buffer_is_mostly_zero(buf, sizeof(buf)));
}

static void random_bytes_should_chunk_requests_above_getentropy_limit(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* getentropy caps a single call at 256 bytes. A request for 1024
     * bytes exercises the chunk loop. We assert success + content
     * not mostly zero, which together mean every chunk was written. */
    uint8_t buf[1024] = {0};
    int     rc        = p->random_bytes(p, buf, sizeof(buf));

    assert_int_equal(rc, 0);
    assert_false(buffer_is_mostly_zero(buf, sizeof(buf)));
}

static void random_bytes_with_zero_len_should_be_no_op_success(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* Passing NULL with len==0 is the canonical "no-op" shape; the
     * provider must not dereference buf. */
    int rc = p->random_bytes(p, NULL, 0);

    assert_int_equal(rc, 0);
}

static void
random_bytes_with_nonnull_buf_and_zero_len_should_leave_buffer_unchanged(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* The (non-NULL, 0) shape is the other half of the "no-op" pair:
     * a caller with a pre-existing buffer asks for zero bytes of
     * entropy. Success is required and the buffer must be left
     * untouched (the len==0 short-circuit runs before any write). */
    uint8_t buf[8];
    memset(buf, 0xA5, sizeof(buf));

    int rc = p->random_bytes(p, buf, 0);

    assert_int_equal(rc, 0);
    for (size_t i = 0; i < sizeof(buf); i++) {
        assert_int_equal(buf[i], 0xA5);
    }
}

static void random_bytes_with_null_buf_and_nonzero_len_should_fail(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* Defensive: a caller passing a NULL buf with a non-zero length
     * is a programming error. We want a hard failure, not a
     * segfault inside the kernel syscall. */
    int rc = p->random_bytes(p, NULL, 16);

    assert_int_not_equal(rc, 0);
}

static void provider_should_expose_every_mandatory_callback(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    assert_non_null(p);
    assert_non_null(p->monotonic_ms);
    assert_non_null(p->sleep_ms);
    assert_non_null(p->random_bytes);
}

static void provider_should_expose_lock_and_thread_callbacks(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    /* Lock primitives: used for per-context thread safety. */
    assert_non_null(p->lock_size);
    assert_non_null(p->lock_init);
    assert_non_null(p->lock_destroy);
    assert_non_null(p->lock_acquire);
    assert_non_null(p->lock_release);

    /* Thread primitives: used for background processing. */
    assert_non_null(p->thread_create);
    assert_non_null(p->thread_join);

    /* file_load is a standalone-optional hook: the POSIX provider wires it
     * only when the filesystem feature is compiled in, and leaves it NULL
     * otherwise so callers fall back to PUBNUB_ERR_NOT_SUPPORTED. */
    if (PUBNUB_ENABLE_FILESYSTEM) {
        assert_non_null(p->file_load);
    } else {
        assert_null(p->file_load);
    }

    /* secure_zero is still optional (not yet implemented). */
    assert_null(p->secure_zero);
}

static volatile int s_thread_ran;

static void thread_test_fn(void* arg)
{
    int* flag = (int*)arg;
    *flag     = 42;
}

static void thread_create_and_join_should_run_function(void** state)
{
    (void)state;
    pubnub_platform_provider_t*  p     = pn_platform_default();
    pubnub_allocator_provider_t* alloc = pn_test_allocator();

    s_thread_ran = 0;
    void* handle = p->thread_create(p, alloc, thread_test_fn, (void*)&s_thread_ran);
    assert_non_null(handle);

    p->thread_join(p, alloc, handle);
    assert_int_equal(s_thread_ran, 42);
}

static void thread_create_with_null_fn_should_return_null(void** state)
{
    (void)state;
    pubnub_platform_provider_t*  p     = pn_platform_default();
    pubnub_allocator_provider_t* alloc = pn_test_allocator();

    void* handle = p->thread_create(p, alloc, NULL, NULL);
    assert_null(handle);
}

static void thread_create_with_null_allocator_should_return_null(void** state)
{
    (void)state;
    pubnub_platform_provider_t* p = pn_platform_default();

    void* handle = p->thread_create(p, NULL, thread_test_fn, NULL);
    assert_null(handle);
}

static void file_load_should_read_a_real_file(void** state)
{
    (void)state;
    pubnub_platform_provider_t*  p         = pn_platform_default();
    pubnub_allocator_provider_t* alloc     = pn_test_allocator();
    const uint8_t                content[] = {0x50, 0x4E, 0x42, 0x21};
    char                         path[] = "/tmp/pubnub_test_file_load_XXXXXX";
    uint8_t*                     data   = NULL;
    size_t                       len    = 0;
    pubnub_res_t                 rc;
    int                          fd;

    if (!PUBNUB_ENABLE_FILESYSTEM) {
        skip();
        return;
    }

    fd = mkstemp(path);
    assert_true(fd >= 0);
    write(fd, content, sizeof(content));
    close(fd);

    rc = p->file_load(p, path, alloc, &data, &len);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(data);
    assert_int_equal(len, sizeof(content));
    assert_memory_equal(data, content, sizeof(content));

    alloc->free(alloc, data);
    unlink(path);
}

static void file_load_should_return_error_for_missing_path(void** state)
{
    (void)state;
    pubnub_platform_provider_t*  p     = pn_platform_default();
    pubnub_allocator_provider_t* alloc = pn_test_allocator();

    uint8_t*     data = NULL;
    size_t       len  = 0;
    pubnub_res_t rc;

    if (!PUBNUB_ENABLE_FILESYSTEM) {
        skip();
        return;
    }

    rc = p->file_load(
        p, "/tmp/pubnub_test_nonexistent_XYZZY_12345.bin", alloc, &data, &len);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(data);
    assert_int_equal(len, 0);
}

static void pn_platform_default_should_return_same_singleton(void** state)
{
    (void)state;

    /* Stateless provider; every call returns the same address.
     * Contexts can share the instance without coordination. */
    assert_ptr_equal(pn_platform_default(), pn_platform_default());
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(monotonic_ms_should_return_nonzero_after_boot),
        cmocka_unit_test(monotonic_ms_should_be_monotonically_nondecreasing),
        cmocka_unit_test(monotonic_ms_should_advance_after_real_sleep),
        cmocka_unit_test(sleep_ms_should_sleep_for_at_least_requested_duration),
        cmocka_unit_test(sleep_ms_with_zero_should_return_promptly),
        cmocka_unit_test(random_bytes_should_return_zero_on_success),
        cmocka_unit_test(random_bytes_should_fill_buffer_with_nonzero_entropy),
        cmocka_unit_test(random_bytes_should_chunk_requests_above_getentropy_limit),
        cmocka_unit_test(random_bytes_with_zero_len_should_be_no_op_success),
        cmocka_unit_test(
            random_bytes_with_nonnull_buf_and_zero_len_should_leave_buffer_unchanged),
        cmocka_unit_test(random_bytes_with_null_buf_and_nonzero_len_should_fail),
        cmocka_unit_test(provider_should_expose_every_mandatory_callback),
        cmocka_unit_test(provider_should_expose_lock_and_thread_callbacks),
        cmocka_unit_test(thread_create_and_join_should_run_function),
        cmocka_unit_test(thread_create_with_null_fn_should_return_null),
        cmocka_unit_test(thread_create_with_null_allocator_should_return_null),
        cmocka_unit_test(file_load_should_read_a_real_file),
        cmocka_unit_test(file_load_should_return_error_for_missing_path),
        cmocka_unit_test(pn_platform_default_should_return_same_singleton),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

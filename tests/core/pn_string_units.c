/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "core/pn_string.h"

static void* real_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void real_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static void* oom_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)size;
    (void)align;
    return NULL;
}

static pubnub_allocator_provider_t s_alloc = {
    .alloc = real_alloc,
    .free  = real_free,
};

static pubnub_allocator_provider_t s_oom_alloc = {
    .alloc = oom_alloc,
    .free  = real_free,
};

/* ------------------------------------------------------------------
 * pn_strdup tests
 * ------------------------------------------------------------------ */

static void test_strdup_normal(void** state)
{
    (void)state;
    char* copy = pn_strdup("hello", &s_alloc);
    assert_non_null(copy);
    assert_string_equal("hello", copy);
    pn_strfree(copy, &s_alloc);
}

static void test_strdup_empty_string(void** state)
{
    (void)state;
    char* copy = pn_strdup("", &s_alloc);
    assert_non_null(copy);
    assert_string_equal("", copy);
    assert_int_equal(0, copy[0]);
    pn_strfree(copy, &s_alloc);
}

static void test_strdup_null_src(void** state)
{
    (void)state;
    char* result = pn_strdup(NULL, &s_alloc);
    assert_null(result);
}

static void test_strdup_null_allocator(void** state)
{
    (void)state;
    char* result = pn_strdup("hello", NULL);
    assert_null(result);
}

static void test_strdup_oom(void** state)
{
    (void)state;
    char* result = pn_strdup("hello", &s_oom_alloc);
    assert_null(result);
}

/* ------------------------------------------------------------------
 * pn_strndup tests
 * ------------------------------------------------------------------ */

static void test_strndup_copies_exact_len_bytes(void** state)
{
    (void)state;
    const char* src  = "hello world";
    char*       copy = pn_strndup(src, 5, &s_alloc);
    assert_non_null(copy);
    assert_string_equal("hello", copy);
    assert_int_equal(5, strlen(copy));
    pn_strfree(copy, &s_alloc);
}

static void test_strndup_nul_terminates(void** state)
{
    (void)state;
    char* copy = pn_strndup("abcdef", 3, &s_alloc);
    assert_non_null(copy);
    assert_int_equal('\0', copy[3]);
    assert_string_equal("abc", copy);
    pn_strfree(copy, &s_alloc);
}

static void test_strndup_zero_length(void** state)
{
    (void)state;
    char* copy = pn_strndup("hello", 0, &s_alloc);
    assert_non_null(copy);
    assert_int_equal('\0', copy[0]);
    assert_int_equal(0, strlen(copy));
    pn_strfree(copy, &s_alloc);
}

static void test_strndup_null_src(void** state)
{
    (void)state;
    char* result = pn_strndup(NULL, 5, &s_alloc);
    assert_null(result);
}

static void test_strndup_null_allocator(void** state)
{
    (void)state;
    char* result = pn_strndup("hello", 5, NULL);
    assert_null(result);
}

static void test_strndup_oom(void** state)
{
    (void)state;
    char* result = pn_strndup("hello", 5, &s_oom_alloc);
    assert_null(result);
}

static void test_strndup_non_nul_terminated_src(void** state)
{
    (void)state;
    /* Buffer that is NOT NUL-terminated. */
    char  buf[4] = {'A', 'B', 'C', 'D'};
    char* copy   = pn_strndup(buf, 4, &s_alloc);
    assert_non_null(copy);
    assert_int_equal(4, strlen(copy));
    assert_memory_equal("ABCD", copy, 4);
    assert_int_equal('\0', copy[4]);
    pn_strfree(copy, &s_alloc);
}

static void test_strndup_partial_copy(void** state)
{
    (void)state;
    const char* src  = "longer string here";
    char*       copy = pn_strndup(src, 6, &s_alloc);
    assert_non_null(copy);
    assert_string_equal("longer", copy);
    pn_strfree(copy, &s_alloc);
}

static void test_strlcpy_exact_fit(void** state)
{
    (void)state;
    char dst[6];
    /* "hello" is 5 chars; n=6 fits exactly with NUL. */
    size_t ret = pn_strlcpy(dst, "hello", sizeof(dst));
    assert_int_equal(5, ret);
    assert_string_equal("hello", dst);
    assert_int_equal('\0', dst[5]);
}

static void test_strlcpy_truncation(void** state)
{
    (void)state;
    char dst[4];
    /* "hello world" (11 chars) into 4 bytes → "hel\0". */
    size_t ret = pn_strlcpy(dst, "hello world", sizeof(dst));
    assert_int_equal(11, ret);
    assert_string_equal("hel", dst);
    assert_int_equal('\0', dst[3]);
}

static void test_strlcpy_empty_source(void** state)
{
    (void)state;
    char   dst[8] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
    size_t ret    = pn_strlcpy(dst, "", sizeof(dst));
    assert_int_equal(0, ret);
    assert_int_equal('\0', dst[0]);
}

static void test_strlcpy_n_equals_1(void** state)
{
    (void)state;
    char   dst[1] = {0x42};
    size_t ret    = pn_strlcpy(dst, "abcdef", 1);
    /* Only NUL written; returns strlen("abcdef") = 6. */
    assert_int_equal(6, ret);
    assert_int_equal('\0', dst[0]);
}

static void test_strlcpy_n_equals_0(void** state)
{
    (void)state;
    char   dst[4] = {0x42, 0x43, 0x44, 0x45};
    size_t ret    = pn_strlcpy(dst, "abc", 0);
    /* dst must remain untouched. */
    assert_int_equal(3, ret);
    assert_int_equal(0x42, dst[0]);
    assert_int_equal(0x43, dst[1]);
}

/* ------------------------------------------------------------------
 * pn_strfree tests
 * ------------------------------------------------------------------ */

static void test_strfree_null_ptr_is_noop(void** state)
{
    (void)state;
    /* Should not crash. */
    pn_strfree(NULL, &s_alloc);
}

static void test_strfree_null_allocator_is_noop(void** state)
{
    (void)state;
    /* Should not crash. */
    pn_strfree("anything", NULL);
}

static void test_strfree_both_null_is_noop(void** state)
{
    (void)state;
    /* Should not crash. */
    pn_strfree(NULL, NULL);
}

/* ------------------------------------------------------------------
 * pn_strdup with allocator missing .alloc
 * ------------------------------------------------------------------ */

static void test_strdup_allocator_missing_alloc_fn(void** state)
{
    (void)state;
    pubnub_allocator_provider_t bad    = {.alloc = NULL, .free = real_free};
    char*                       result = pn_strdup("hello", &bad);
    assert_null(result);
}

static void test_strndup_allocator_missing_alloc_fn(void** state)
{
    (void)state;
    pubnub_allocator_provider_t bad    = {.alloc = NULL, .free = real_free};
    char*                       result = pn_strndup("hello", 5, &bad);
    assert_null(result);
}

static void test_header_unsafe_null_is_safe(void** state)
{
    (void)state;
    assert_int_equal(0, pn_str_has_header_unsafe_byte(NULL));
}

static void test_header_unsafe_clean_string(void** state)
{
    (void)state;
    assert_int_equal(0, pn_str_has_header_unsafe_byte("ps.pndsn.com"));
    assert_int_equal(0, pn_str_has_header_unsafe_byte(""));
    assert_int_equal(0, pn_str_has_header_unsafe_byte("host:8080"));
}

static void test_header_unsafe_detects_cr_lf_space(void** state)
{
    (void)state;
    assert_int_equal(1, pn_str_has_header_unsafe_byte("host\r"));
    assert_int_equal(1, pn_str_has_header_unsafe_byte("host\n"));
    assert_int_equal(1, pn_str_has_header_unsafe_byte("host name"));
    assert_int_equal(1, pn_str_has_header_unsafe_byte("h\r\nInjected: 1"));
    /* Unsafe byte at the very end must still be caught. */
    assert_int_equal(1, pn_str_has_header_unsafe_byte("host "));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* pn_strdup */
        cmocka_unit_test(test_strdup_normal),
        cmocka_unit_test(test_strdup_empty_string),
        cmocka_unit_test(test_strdup_null_src),
        cmocka_unit_test(test_strdup_null_allocator),
        cmocka_unit_test(test_strdup_oom),
        cmocka_unit_test(test_strdup_allocator_missing_alloc_fn),
        /* pn_strndup */
        cmocka_unit_test(test_strndup_copies_exact_len_bytes),
        cmocka_unit_test(test_strndup_nul_terminates),
        cmocka_unit_test(test_strndup_zero_length),
        cmocka_unit_test(test_strndup_null_src),
        cmocka_unit_test(test_strndup_null_allocator),
        cmocka_unit_test(test_strndup_oom),
        cmocka_unit_test(test_strndup_non_nul_terminated_src),
        cmocka_unit_test(test_strndup_partial_copy),
        cmocka_unit_test(test_strndup_allocator_missing_alloc_fn),
        /* pn_strlcpy */
        cmocka_unit_test(test_strlcpy_exact_fit),
        cmocka_unit_test(test_strlcpy_truncation),
        cmocka_unit_test(test_strlcpy_empty_source),
        cmocka_unit_test(test_strlcpy_n_equals_1),
        cmocka_unit_test(test_strlcpy_n_equals_0),
        /* pn_strfree */
        cmocka_unit_test(test_strfree_null_ptr_is_noop),
        cmocka_unit_test(test_strfree_null_allocator_is_noop),
        cmocka_unit_test(test_strfree_both_null_is_noop),
        /* pn_str_has_header_unsafe_byte */
        cmocka_unit_test(test_header_unsafe_null_is_safe),
        cmocka_unit_test(test_header_unsafe_clean_string),
        cmocka_unit_test(test_header_unsafe_detects_cr_lf_space),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

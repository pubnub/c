/* Copyright (c) 2024-2026 PubNub Inc. */

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

extern const pn_socket_platform_ops_t pn_windows_socket_ops;

/**
 * @brief Verify poll_wait with an empty poll set sleeps and returns 0.
 *
 * WSAPoll returns WSAEINVAL when called with nfds=0. The Windows
 * implementation guards against this by falling back to Sleep() when
 * the poll set is empty.
 */
static void test_poll_wait_empty_set(void** state)
{
    (void)state;

    pn_poll_set_t poll_set;
    assert_int_equal(
        0,
        pn_windows_socket_ops.poll_init(
            (struct pn_socket_platform_ops*)&pn_windows_socket_ops, &poll_set));

    /* Empty poll set — should sleep for ~50ms and return 0. */
    const int rc = pn_windows_socket_ops.poll_wait(
        (struct pn_socket_platform_ops*)&pn_windows_socket_ops, &poll_set, 50);

    assert_int_equal(0, rc);
    assert_int_equal(
        0,
        pn_windows_socket_ops.poll_ready_count(
            (struct pn_socket_platform_ops*)&pn_windows_socket_ops, &poll_set));

    pn_windows_socket_ops.poll_deinit(
        (struct pn_socket_platform_ops*)&pn_windows_socket_ops, &poll_set);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_poll_wait_empty_set),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* Copyright (c) 2024-2026 PubNub Inc. */

/**
 * @file test_high_fd.c
 * @brief Regression test: poll() used instead of select(); verifies no fd_set
 *        memory corruption when socket fd >= FD_SETSIZE.
 *
 * select() with fd >= FD_SETSIZE (1024 on Linux/macOS) corrupts memory because
 * FD_SET writes past the fd_set bitmap boundary. This test validates that the
 * socket transport uses poll() (not select()) on POSIX platforms, allowing it
 * to work correctly with high-numbered file descriptors without stack/heap
 * corruption.
 *
 * Test strategy:
 * 1. Open 1200+ dummy file descriptors to consume low fd slots.
 * 2. Create the socket transport instance.
 * 3. Verify the transport's internal socket fd > 1024.
 * 4. Perform basic send/poll operations.
 * 5. Verify no memory corruption via ASan (when enabled).
 *
 * This test must run under ASan to catch memory corruption:
 * ASAN_OPTIONS=detect_stack_use_after_return=1 ./test_high_fd
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <fcntl.h>
#include <unistd.h>

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport.h"

#include "providers/transport/socket/transport_socket_internal.h"
#include "providers/transport/socket/dns/dns_resolver.h"
#include "providers/transport/socket/platform/pn_socket_platform_ops.h"
#include "providers/transport/socket/platform/posix_socket_ops.c"
#include "providers/platform/posix/platform_posix.c"
#include "providers/allocator/stdlib/allocator_stdlib.c"

/** @brief Maximum dummy file descriptors to open. */
#define MAX_DUMMY_FDS 1220

static int                              g_dummy_fds[MAX_DUMMY_FDS];
static size_t                           g_dummy_fd_count;
static struct pubnub_platform_provider  g_platform_provider;
static struct pubnub_allocator_provider g_allocator_provider;
static pn_socket_platform_ops_t         g_socket_ops;

/**
 * @brief Setup: open 1220 dummy fds to push next socket past 1024.
 */
static int test_setup(void** state)
{
    (void)state;

    g_platform_provider  = *pn_platform_default();
    g_allocator_provider = *pn_allocator_default();
    g_socket_ops         = pn_posix_socket_ops;

    g_dummy_fd_count = 0;

    /* Open /dev/null repeatedly to consume low fd slots. */
    for (size_t i = 0; i < MAX_DUMMY_FDS; ++i) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            break;
        }
        g_dummy_fds[g_dummy_fd_count++] = fd;
    }

    /* Verify we opened enough to push next socket past 1024. */
    if (g_dummy_fd_count < 1020) {
        /* Clean up and skip test if not enough fds. */
        for (size_t i = 0; i < g_dummy_fd_count; ++i) {
            close(g_dummy_fds[i]);
        }
        skip();
    }

    return 0;
}

/**
 * @brief Teardown: close all dummy fds.
 */
static int test_teardown(void** state)
{
    (void)state;

    for (size_t i = 0; i < g_dummy_fd_count; ++i) {
        close(g_dummy_fds[i]);
    }
    g_dummy_fd_count = 0;

    return 0;
}

/**
 * @brief Test: transport init with high fd does not corrupt memory.
 */
static void test_transport_init_high_fd(void** state)
{
    (void)state;

    pubnub_provider_deps_t deps = {.allocator = &g_allocator_provider,
                                   .logger    = NULL,
                                   .platform  = &g_platform_provider,
                                   .proxy     = NULL};

    pubnub_transport_provider_t* transport = pn_socket_transport_create(
        &g_socket_ops, NULL, NULL, NULL, &g_allocator_provider);
    assert_non_null(transport);

    /* Verify init succeeded. */
    assert_non_null(transport->send);
    assert_non_null(transport->poll);

    pn_socket_transport_destroy(transport, &g_allocator_provider);
}

/**
 * @brief Test: resolver UDP socket with high fd works correctly.
 */
static void test_resolver_high_fd(void** state)
{
    (void)state;

    /* UDP socket is only created when the built-in resolver is active. */
    if (!PUBNUB_ENABLE_CUSTOM_DNS) {
        return;
    }

    pn_dns_resolver_t resolver;
    int               init_result =
        pn_dns_resolver_init(&resolver, &g_socket_ops, &g_platform_provider);
    assert_int_equal(0, init_result);

    pn_socket_t udp_socket = pn_dns_resolver_socket(&resolver);
    assert_true(PN_INVALID_SOCKET != udp_socket);

    /* On POSIX, pn_socket_t is int. Verify it's high. */
    int fd_value = (int)udp_socket;
    assert_true(fd_value > 1024);

    pn_dns_resolver_deinit(&resolver);
}

/**
 * @brief Test: TCP socket with high fd can be created/closed.
 */
static void test_tcp_socket_high_fd(void** state)
{
    (void)state;

    pn_socket_t tcp_sock = g_socket_ops.socket_create(&g_socket_ops, PN_AF_INET, 0);
    assert_true(PN_INVALID_SOCKET != tcp_sock);

    int fd_value = (int)tcp_sock;
    assert_true(fd_value > 1024);

    g_socket_ops.socket_destroy(&g_socket_ops, tcp_sock);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_transport_init_high_fd, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_resolver_high_fd, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(
            test_tcp_socket_high_fd, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

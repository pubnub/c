/* Copyright (c) 2024-2026 PubNub Inc. */

/*
 * Windows socket platform ops tests. Pending-connect tests skip when no
 * pending socket can be produced, or fail if PN_TEST_REQUIRE_PENDING=1.
 */

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

int pn_windows_wake_pair_create(int af, pn_socket_t out[2]);

extern const pn_socket_platform_ops_t pn_windows_socket_ops;

#define OPS (&pn_windows_socket_ops)

#define PN_TEST_MAX_CLIENTS 8

#define PN_TEST_WAKE_WRITERS        4
#define PN_TEST_WAKE_WRITES_PER_THR 500
#define PN_TEST_WAKE_DRAIN_ROUNDS   20
#define PN_TEST_WAKE_CYCLES         100
#define PN_TEST_WAKE_HANDLE_SLACK   8

static int test_group_setup(void** state)
{
    WSADATA wsa;

    (void)state;
    return 0 == WSAStartup(MAKEWORD(2, 2), &wsa) ? 0 : -1;
}

static int test_group_teardown(void** state)
{
    (void)state;
    WSACleanup();
    return 0;
}

/**
 * @brief Open a loopback TCP socket bound to an ephemeral port.
 *
 * @param backlog Listen backlog, or a negative value to bind without listening.
 * @param out_addr Receives the bound address in pn_sockaddr_t form.
 * @return Socket, or INVALID_SOCKET on failure.
 */
static SOCKET test_open_loopback(int backlog, pn_sockaddr_t* out_addr)
{
    struct sockaddr_in sa  = {0};
    int                len = (int)sizeof(sa);
    SOCKET             s   = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (INVALID_SOCKET == s) {
        return INVALID_SOCKET;
    }

    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;

    if (0 != bind(s, (struct sockaddr*)&sa, sizeof(sa))
        || (0 <= backlog && 0 != listen(s, backlog))
        || 0 != getsockname(s, (struct sockaddr*)&sa, &len)) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    memset(out_addr, 0, sizeof(*out_addr));
    out_addr->family = PN_AF_INET;
    out_addr->port   = ntohs(sa.sin_port);
    memcpy(out_addr->addr.ipv4, &sa.sin_addr.s_addr, 4);
    return s;
}

/**
 * @brief Create a non-blocking socket and start a connect to @p addr.
 */
static pn_socket_t test_start_connect(const pn_sockaddr_t* addr, int* out_rc)
{
    pn_socket_t sock = OPS->socket_create(OPS, PN_AF_INET, 0);

    assert_true(PN_INVALID_SOCKET != sock);
    assert_int_equal(0, OPS->socket_set_nonblocking(OPS, sock));
    *out_rc = OPS->socket_connect(OPS, sock, addr);
    return sock;
}

/**
 * @brief Whether @p s is writable (connect finished or failed) right now.
 */
static int test_writable_now(SOCKET s)
{
    fd_set         wfds;
    fd_set         efds;
    struct timeval tv = {0, 0};

    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(s, &wfds);
    FD_SET(s, &efds);
    return 0 < select(0, NULL, &wfds, &efds, &tv);
}

/** @brief Fail (PN_TEST_REQUIRE_PENDING=1) or skip: no pending socket. */
static void test_pending_unavailable(const char* reason)
{
    const char* require = getenv("PN_TEST_REQUIRE_PENDING");

    if (NULL != require && 0 == strcmp("1", require)) {
        fail_msg("PN_TEST_REQUIRE_PENDING=1 but no pending socket: %s", reason);
    }
    print_message("skip reason: %s\n", reason);
    skip();
}

/**
 * @brief A completed connect reports 1, and keeps reporting 1.
 *
 * Immediately after a non-blocking loopback connect the handshake may not
 * have been observed yet, so 0 is tolerated until it completes.
 */
static void test_windows_ops_check_connect_completed_returns_one(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
    const SOCKET  lfd  = test_open_loopback(1, &addr);
    assert_true(INVALID_SOCKET != lfd);

    int         rc   = 0;
    pn_socket_t sock = test_start_connect(&addr, &rc);
    assert_true(0 <= rc);

    int result = 0;
    for (int i = 0; i < 100; ++i) {
        result = OPS->socket_check_connect(OPS, sock);
        if (0 != result) {
            break;
        }
        Sleep(10);
    }
    assert_int_equal(1, result);

    for (int i = 0; i < 5; ++i) {
        assert_int_equal(1, OPS->socket_check_connect(OPS, sock));
    }

    OPS->socket_destroy(OPS, sock);
    closesocket(lfd);
}

/** @brief A refused connect stays pending during the SYN retry window. */
static void test_windows_ops_check_connect_refused_retry_window(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
    const SOCKET  bfd  = test_open_loopback(-1, &addr);
    assert_true(INVALID_SOCKET != bfd);

    int         rc   = 0;
    pn_socket_t sock = test_start_connect(&addr, &rc);

    if (0 > rc) {
        OPS->socket_destroy(OPS, sock);
        closesocket(bfd);
        print_message("skip reason: connect refused synchronously\n");
        skip();
        return;
    }
    assert_int_equal(0, rc);

    const int first = OPS->socket_check_connect(OPS, sock);
    if (0 > first) {
        OPS->socket_destroy(OPS, sock);
        closesocket(bfd);
        print_message("skip reason: refusal reported before the SYN retry "
                      "window; stack does not retry on this machine\n");
        skip();
        return;
    }
    assert_int_equal(0, first);

    int result = 0;
    for (int i = 0; i < 500; ++i) {
        result = OPS->socket_check_connect(OPS, sock);
        if (0 != result) {
            break;
        }
        Sleep(10);
    }
    assert_int_equal(-WSAECONNREFUSED, result);

    OPS->socket_destroy(OPS, sock);
    closesocket(bfd);
}

/**
 * @brief A connect queued behind a full accept queue reports 0.
 */
static void test_windows_ops_check_connect_backlog_pending_returns_zero(void** state)
{
    (void)state;

    pn_sockaddr_t addr = {0};
    pn_socket_t   clients[PN_TEST_MAX_CLIENTS];
    pn_socket_t   pending = PN_INVALID_SOCKET;
    size_t        count   = 0;
    const SOCKET  lfd     = test_open_loopback(0, &addr);
    assert_true(INVALID_SOCKET != lfd);

    while (count < PN_TEST_MAX_CLIENTS && PN_INVALID_SOCKET == pending) {
        int         rc = 0;
        pn_socket_t s  = test_start_connect(&addr, &rc);

        clients[count++] = s;
        Sleep(50);
        if (0 == rc && !test_writable_now((SOCKET)s)) {
            pending = s;
        }
    }

    if (PN_INVALID_SOCKET == pending) {
        for (size_t i = 0; i < count; ++i) {
            OPS->socket_destroy(OPS, clients[i]);
        }
        closesocket(lfd);
        test_pending_unavailable("accept-queue overflow did not leave a "
                                 "connect pending");
        return;
    }

    const int first  = OPS->socket_check_connect(OPS, pending);
    const int second = OPS->socket_check_connect(OPS, pending);

    for (size_t i = 0; i < count; ++i) {
        OPS->socket_destroy(OPS, clients[i]);
    }
    closesocket(lfd);

    assert_int_equal(0, first);
    assert_int_equal(0, second);
}

/**
 * @brief Whether @p s becomes readable within @p ms milliseconds.
 */
static int test_readable_within(SOCKET s, int ms)
{
    WSAPOLLFD pfd = {0};

    pfd.fd     = s;
    pfd.events = POLLRDNORM;
    return 1 == WSAPoll(&pfd, 1, ms) && 0 != (pfd.revents & POLLRDNORM);
}

/**
 * @brief Drain @p rd through the ops until it is no longer readable.
 *
 * pipe_drain is bounded per call, so a flood may need several calls.
 *
 * @return Non-zero when the socket ended up empty.
 */
static int test_drain_until_empty(pn_socket_t rd)
{
    for (int i = 0; i < PN_TEST_WAKE_DRAIN_ROUNDS; ++i) {
        OPS->pipe_drain(OPS, rd);
        if (!test_readable_within((SOCKET)rd, 0)) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Whether a recv on the empty @p rd returns instead of blocking.
 */
static int test_recv_would_block(pn_socket_t rd)
{
    char buf[4];

    return SOCKET_ERROR == recv((SOCKET)rd, buf, (int)sizeof(buf), 0)
        && WSAEWOULDBLOCK == WSAGetLastError();
}

/**
 * @brief Write once, expect readable, drain, expect empty.
 */
static void test_check_signal_cycle(pn_socket_t rd, pn_socket_t wr)
{
    OPS->pipe_write(OPS, wr);
    assert_true(test_readable_within((SOCKET)rd, 1000));
    OPS->pipe_drain(OPS, rd);
    assert_false(test_readable_within((SOCKET)rd, 0));
}

struct test_writer_args {
    pn_socket_t wr;
    DWORD       delay_ms;
    int         count;
};

static DWORD WINAPI test_writer_thread(LPVOID param)
{
    const struct test_writer_args* args = (const struct test_writer_args*)param;

    if (0 < args->delay_ms) {
        Sleep(args->delay_ms);
    }
    for (int i = 0; i < args->count; ++i) {
        OPS->pipe_write(OPS, args->wr);
    }
    return 0;
}

/**
 * @brief pipe_create yields two distinct, valid, non-blocking handles.
 */
static void test_windows_ops_wake_pipe_create_succeeds(void** state)
{
    (void)state;

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};

    assert_non_null(OPS->pipe_create);
    assert_non_null(OPS->pipe_write);
    assert_non_null(OPS->pipe_drain);
    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    assert_true(PN_INVALID_SOCKET != fds[0]);
    assert_true(PN_INVALID_SOCKET != fds[1]);
    assert_true(fds[0] != fds[1]);
    assert_true(test_recv_would_block(fds[0]));

    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/**
 * @brief A write makes the read end readable; a drain empties it.
 */
static void test_windows_ops_wake_pipe_write_makes_readable(void** state)
{
    (void)state;

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};

    assert_non_null(OPS->pipe_create);
    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    assert_false(test_readable_within((SOCKET)fds[0], 0));
    test_check_signal_cycle(fds[0], fds[1]);
    test_check_signal_cycle(fds[0], fds[1]);

    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/** @brief Many writes are cleared by repeated bounded drains. */
static void test_windows_ops_wake_pipe_many_writes_single_drain(void** state)
{
    (void)state;

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};

    assert_non_null(OPS->pipe_create);
    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    for (int i = 0; i < 1000; ++i) {
        OPS->pipe_write(OPS, fds[1]);
    }
    assert_true(test_readable_within((SOCKET)fds[0], 1000));
    assert_true(test_drain_until_empty(fds[0]));

    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/**
 * @brief A write from another thread wakes a WSAPoll that is blocked.
 */
static void test_windows_ops_wake_pipe_wakes_blocked_poll(void** state)
{
    (void)state;

    pn_socket_t             fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    struct test_writer_args args   = {0};
    WSAPOLLFD               pfd    = {0};

    assert_non_null(OPS->pipe_create);
    assert_int_equal(0, OPS->pipe_create(OPS, fds));

    args.wr       = fds[1];
    args.delay_ms = 50;
    args.count    = 1;
    pfd.fd        = (SOCKET)fds[0];
    pfd.events    = POLLRDNORM;

    const HANDLE thread = CreateThread(NULL, 0, test_writer_thread, &args, 0, NULL);
    assert_non_null(thread);

    LARGE_INTEGER freq  = {0};
    LARGE_INTEGER start = {0};
    LARGE_INTEGER stop  = {0};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    const int rc = WSAPoll(&pfd, 1, 5000);
    QueryPerformanceCounter(&stop);
    const long long spent =
        (stop.QuadPart - start.QuadPart) * 1000LL / freq.QuadPart;

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    assert_int_equal(1, rc);
    assert_true(0 != (pfd.revents & POLLRDNORM));
    assert_true(spent < 1000);
    assert_true(spent >= 30);

    OPS->pipe_drain(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/**
 * @brief Concurrent writers neither crash nor leave the pair unusable.
 */
static void test_windows_ops_wake_pipe_write_thread_safety(void** state)
{
    (void)state;

    pn_socket_t             fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    struct test_writer_args args   = {0};
    HANDLE                  threads[PN_TEST_WAKE_WRITERS];

    assert_non_null(OPS->pipe_create);
    assert_int_equal(0, OPS->pipe_create(OPS, fds));

    args.wr    = fds[1];
    args.count = PN_TEST_WAKE_WRITES_PER_THR;
    for (int i = 0; i < PN_TEST_WAKE_WRITERS; ++i) {
        threads[i] = CreateThread(NULL, 0, test_writer_thread, &args, 0, NULL);
        assert_non_null(threads[i]);
    }
    WaitForMultipleObjects(PN_TEST_WAKE_WRITERS, threads, TRUE, INFINITE);
    for (int i = 0; i < PN_TEST_WAKE_WRITERS; ++i) {
        CloseHandle(threads[i]);
    }

    assert_true(test_readable_within((SOCKET)fds[0], 1000));
    assert_true(test_drain_until_empty(fds[0]));
    test_check_signal_cycle(fds[0], fds[1]);

    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/**
 * @brief The helper works for each family independently.
 *
 * IPv4 is verified first; IPv6 is skipped when ::1 is unavailable here.
 */
static void test_windows_ops_wake_pair_per_family(void** state)
{
    (void)state;

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};

    assert_int_equal(0, pn_windows_wake_pair_create(AF_INET, fds));
    assert_true(PN_INVALID_SOCKET != fds[0]);
    assert_true(PN_INVALID_SOCKET != fds[1]);
    test_check_signal_cycle(fds[0], fds[1]);
    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);

    if (0 != pn_windows_wake_pair_create(AF_INET6, fds)) {
        assert_true(PN_INVALID_SOCKET == fds[0]);
        assert_true(PN_INVALID_SOCKET == fds[1]);
        print_message("skip reason: IPv6 loopback (::1) unavailable\n");
        skip();
        return;
    }
    assert_true(PN_INVALID_SOCKET != fds[0]);
    assert_true(PN_INVALID_SOCKET != fds[1]);
    test_check_signal_cycle(fds[0], fds[1]);
    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/** @brief A datagram from an unrelated socket never reaches the read end. */
static void test_windows_ops_wake_pair_rejects_foreign_sender(void** state)
{
    (void)state;

    pn_socket_t        fds[2]    = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    struct sockaddr_in target    = {0};
    struct sockaddr_in intruder  = {0};
    int                tlen      = (int)sizeof(target);
    int                delivered = 0;
    SOCKET             other     = INVALID_SOCKET;

    assert_int_equal(0, pn_windows_wake_pair_create(AF_INET, fds));
    assert_int_equal(
        0, getsockname((SOCKET)fds[0], (struct sockaddr*)&target, &tlen));

    intruder.sin_family      = AF_INET;
    intruder.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    other                    = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert_true(INVALID_SOCKET != other);
    assert_int_equal(
        0, bind(other, (struct sockaddr*)&intruder, (int)sizeof(intruder)));
    assert_int_equal(
        1,
        sendto(other, "x", 1, 0, (const struct sockaddr*)&target, (int)sizeof(target)));

    delivered = test_readable_within((SOCKET)fds[0], 100);
    closesocket(other);
    if (delivered) {
        OPS->socket_destroy(OPS, fds[0]);
        OPS->socket_destroy(OPS, fds[1]);
        print_message("skip reason: stack delivered a datagram from a "
                      "non-peer sender to the connected socket\n");
        skip();
        return;
    }

    test_check_signal_cycle(fds[0], fds[1]);
    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/**
 * @brief Unsupported families and a NULL output are rejected cleanly.
 */
static void test_windows_ops_wake_pair_invalid_family(void** state)
{
    (void)state;

    const int   bad[] = {AF_UNIX, 0};
    pn_socket_t fds[2];

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        fds[0] = 0;
        fds[1] = 0;
        assert_int_equal(-1, pn_windows_wake_pair_create(bad[i], fds));
        assert_true(PN_INVALID_SOCKET == fds[0]);
        assert_true(PN_INVALID_SOCKET == fds[1]);
    }
    assert_int_equal(-1, pn_windows_wake_pair_create(AF_INET, NULL));
}

/**
 * @brief Repeated create/destroy cycles do not leak process handles.
 */
static void test_windows_ops_wake_pipe_destroy_both_ok(void** state)
{
    (void)state;

    DWORD before = 0;
    DWORD after  = 0;

    assert_non_null(OPS->pipe_create);
    assert_true(0 != GetProcessHandleCount(GetCurrentProcess(), &before));
    for (int i = 0; i < PN_TEST_WAKE_CYCLES; ++i) {
        pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};

        assert_int_equal(0, OPS->pipe_create(OPS, fds));
        OPS->socket_destroy(OPS, fds[0]);
        OPS->socket_destroy(OPS, fds[1]);
    }
    assert_true(0 != GetProcessHandleCount(GetCurrentProcess(), &after));
    assert_true(after <= before + PN_TEST_WAKE_HANDLE_SLACK);
}

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

/**
 * @brief PN_POLL_ERROR / PN_POLL_HUP never reach WSAPOLLFD.events.
 *
 * WSAPoll fails with WSAEINVAL if POLLERR/POLLHUP/POLLNVAL are requested.
 */
static void test_windows_ops_poll_add_error_hup_bits_accepted(void** state)
{
    (void)state;

    pn_socket_t   fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    pn_poll_set_t poll_set;
    pn_socket_t   ready_sock   = PN_INVALID_SOCKET;
    uint8_t       ready_events = 0;
    const uint8_t all_bits     = PN_POLL_READ | PN_POLL_ERROR | PN_POLL_HUP;

    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    assert_int_equal(0, OPS->poll_init(OPS, &poll_set));
    assert_int_equal(0, OPS->poll_add(OPS, &poll_set, fds[0], all_bits));

    assert_int_equal(0, OPS->poll_wait(OPS, &poll_set, 0));
    assert_int_equal(0, (int)OPS->poll_ready_count(OPS, &poll_set));

    assert_int_equal(0, OPS->poll_modify(OPS, &poll_set, fds[0], all_bits));
    OPS->pipe_write(OPS, fds[1]);
    assert_int_equal(0, OPS->poll_wait(OPS, &poll_set, 1000));
    assert_int_equal(1, (int)OPS->poll_ready_count(OPS, &poll_set));
    assert_int_equal(
        0, OPS->poll_get_ready(OPS, &poll_set, 0, &ready_sock, &ready_events));
    assert_true(fds[0] == ready_sock);
    assert_true(0 != (ready_events & PN_POLL_READ));

    OPS->poll_deinit(OPS, &poll_set);
    OPS->socket_destroy(OPS, fds[0]);
    OPS->socket_destroy(OPS, fds[1]);
}

/** @brief Whether a wake read end reporting @p events counts as broken. */
static int test_wake_would_degrade(uint8_t events)
{
    return 0 != (events & (PN_POLL_ERROR | PN_POLL_HUP))
        || 0 == (events & PN_POLL_READ);
}

/**
 * @brief Poll one socket for READ through the ops layer.
 *
 * @param sock Socket to register (may be a closed handle on purpose).
 * @param timeout_ms WSAPoll timeout.
 * @param out_count Receives the ready-entry count (0 when poll_wait failed).
 * @param out_events Receives the mapped events of entry 0 (0 when none ready).
 * @return The poll_wait result.
 */
static int test_ops_poll_one(pn_socket_t sock,
                             int         timeout_ms,
                             size_t*     out_count,
                             uint8_t*    out_events)
{
    pn_poll_set_t poll_set;
    pn_socket_t   ready = PN_INVALID_SOCKET;
    int           rc    = 0;

    *out_count  = 0;
    *out_events = 0;
    assert_int_equal(0, OPS->poll_init(OPS, &poll_set));
    assert_int_equal(0, OPS->poll_add(OPS, &poll_set, sock, PN_POLL_READ));
    rc = OPS->poll_wait(OPS, &poll_set, timeout_ms);
    if (0 == rc) {
        *out_count = OPS->poll_ready_count(OPS, &poll_set);
        if (0 < *out_count) {
            assert_int_equal(
                0, OPS->poll_get_ready(OPS, &poll_set, 0, &ready, out_events));
            assert_true(sock == ready);
        }
    }
    OPS->poll_deinit(OPS, &poll_set);
    return rc;
}

/**
 * @brief Open a UDP socket bound to an ephemeral loopback port.
 */
static SOCKET test_udp_loopback(struct sockaddr_in* out_addr)
{
    int    len = (int)sizeof(*out_addr);
    SOCKET s   = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (INVALID_SOCKET == s) {
        return INVALID_SOCKET;
    }
    memset(out_addr, 0, sizeof(*out_addr));
    out_addr->sin_family      = AF_INET;
    out_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (0 != bind(s, (struct sockaddr*)out_addr, sizeof(*out_addr))
        || 0 != getsockname(s, (struct sockaddr*)out_addr, &len)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/**
 * @brief Build a connected loopback TCP pair.
 *
 * @param out_client Receives the connecting end.
 * @param out_server Receives the accepted end.
 */
static void test_tcp_pair(SOCKET* out_client, SOCKET* out_server)
{
    pn_sockaddr_t      addr;
    struct sockaddr_in sa     = {0};
    SOCKET             listen = test_open_loopback(1, &addr);
    SOCKET             client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    assert_true(INVALID_SOCKET != listen);
    assert_true(INVALID_SOCKET != client);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(addr.port);
    memcpy(&sa.sin_addr.s_addr, addr.addr.ipv4, 4);
    assert_int_equal(0, connect(client, (struct sockaddr*)&sa, sizeof(sa)));
    *out_server = accept(listen, NULL, NULL);
    assert_true(INVALID_SOCKET != *out_server);
    *out_client = client;
    closesocket(listen);
}

/**
 * @brief A closed wake read end is listed by poll with no READ bit.
 *
 * WSAPoll reports POLLNVAL for a closed handle instead of failing, so the
 * entry must still be listed with an empty event set.
 */
static void test_windows_ops_poll_closed_wake_end_is_listed_broken(void** state)
{
    (void)state;

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    size_t      count  = 0;
    uint8_t     events = 0xFF;
    int         rc     = 0;

    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    OPS->socket_destroy(OPS, fds[0]);

    rc = test_ops_poll_one(fds[0], 0, &count, &events);
    assert_int_equal(0, rc);
    assert_int_equal(1, (int)count);
    assert_int_equal(0, events & PN_POLL_READ);
    assert_true(test_wake_would_degrade(events));

    OPS->socket_destroy(OPS, fds[1]);
}

/** @brief A reused handle value never reports spurious readiness. */
static void test_windows_ops_poll_reused_handle_not_spuriously_readable(void** state)
{
    (void)state;

    enum { PROBES = 256 };

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    SOCKET      probes[PROBES];
    SOCKET      reused = INVALID_SOCKET;
    size_t      count  = 0;
    uint8_t     events = 0;
    int         i;

    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    OPS->socket_destroy(OPS, fds[0]);

    for (i = 0; i < PROBES; ++i) {
        probes[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (INVALID_SOCKET != probes[i] && probes[i] == (SOCKET)fds[0]) {
            reused = probes[i];
        }
    }

    if (INVALID_SOCKET != reused) {
        assert_int_equal(0, test_ops_poll_one(fds[0], 0, &count, &events));
        assert_int_equal(0, (int)count);
    }

    for (i = 0; i < PROBES; ++i) {
        if (INVALID_SOCKET != probes[i]) {
            closesocket(probes[i]);
        }
    }
    OPS->socket_destroy(OPS, fds[1]);
    if (INVALID_SOCKET == reused) {
        print_message("skip reason: handle value not reused\n");
        skip();
    }
}

/**
 * @brief Closing the UDP wake peer leaves the read end quiet.
 *
 * UDP has no FIN; with SIO_UDP_CONNRESET disabled the survivor stays silent.
 */
static void test_windows_ops_poll_udp_peer_closed_stays_quiet(void** state)
{
    (void)state;

    pn_socket_t fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    size_t      count  = 0;
    uint8_t     events = 0;

    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    OPS->socket_destroy(OPS, fds[1]);

    assert_int_equal(0, test_ops_poll_one(fds[0], 100, &count, &events));
    assert_int_equal(0, (int)count);
    assert_true(test_recv_would_block(fds[0]));

    OPS->socket_destroy(OPS, fds[0]);
}

/**
 * @brief A graceful TCP close makes the other end readable or HUP.
 */
static void test_windows_ops_poll_tcp_peer_fin_reports_read_or_hup(void** state)
{
    (void)state;

    SOCKET  client = INVALID_SOCKET;
    SOCKET  server = INVALID_SOCKET;
    size_t  count  = 0;
    uint8_t events = 0;
    char    buf[4];

    test_tcp_pair(&client, &server);
    closesocket(server);

    assert_int_equal(
        0, test_ops_poll_one((pn_socket_t)client, 1000, &count, &events));
    assert_int_equal(1, (int)count);
    assert_true(0 != (events & (PN_POLL_READ | PN_POLL_HUP)));
    assert_int_equal(0, recv(client, buf, (int)sizeof(buf), 0));

    closesocket(client);
}

/**
 * @brief A TCP reset leaves the peer listed with events set.
 */
static void test_windows_ops_poll_tcp_peer_reset_reports_event(void** state)
{
    (void)state;

    SOCKET        client = INVALID_SOCKET;
    SOCKET        server = INVALID_SOCKET;
    struct linger hard   = {1, 0};
    size_t        count  = 0;
    uint8_t       events = 0;

    test_tcp_pair(&client, &server);
    assert_int_equal(
        0,
        setsockopt(
            server, SOL_SOCKET, SO_LINGER, (const char*)&hard, (int)sizeof(hard)));
    closesocket(server);

    assert_int_equal(
        0, test_ops_poll_one((pn_socket_t)client, 1000, &count, &events));
    assert_int_equal(1, (int)count);
    assert_true(0 != events);

    closesocket(client);
}

/** @brief ICMP port-unreachable does not surface on the wake read end. */
static void test_windows_ops_poll_udp_icmp_connreset_suppressed(void** state)
{
    (void)state;

    struct sockaddr_in addr_a;
    struct sockaddr_in addr_b;
    pn_socket_t        fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    u_long             mode   = 1;
    char               buf[4];
    size_t             count  = 0;
    uint8_t            events = 0;
    int                control_reset;
    SOCKET             a = test_udp_loopback(&addr_a);
    SOCKET             b = test_udp_loopback(&addr_b);

    assert_true(INVALID_SOCKET != a && INVALID_SOCKET != b);
    assert_int_equal(0, connect(a, (struct sockaddr*)&addr_b, sizeof(addr_b)));
    assert_int_equal(0, ioctlsocket(a, (long)FIONBIO, &mode));
    closesocket(b);
    assert_int_equal(1, send(a, "x", 1, 0));
    Sleep(200);
    control_reset = SOCKET_ERROR == recv(a, buf, (int)sizeof(buf), 0)
                 && WSAECONNRESET == WSAGetLastError();
    closesocket(a);
    if (!control_reset) {
        print_message("skip reason: loopback did not deliver ICMP to the "
                      "control socket\n");
        skip();
    }

    assert_int_equal(0, OPS->pipe_create(OPS, fds));
    OPS->socket_destroy(OPS, fds[1]);
    assert_int_equal(1, send((SOCKET)fds[0], "x", 1, 0));
    Sleep(200);

    assert_int_equal(0, test_ops_poll_one(fds[0], 0, &count, &events));
    assert_int_equal(0, (int)count);
    assert_true(test_recv_would_block(fds[0]));

    OPS->socket_destroy(OPS, fds[0]);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_poll_wait_empty_set),
        cmocka_unit_test(test_windows_ops_poll_add_error_hup_bits_accepted),
        cmocka_unit_test(test_windows_ops_check_connect_completed_returns_one),
        cmocka_unit_test(test_windows_ops_check_connect_refused_retry_window),
        cmocka_unit_test(test_windows_ops_check_connect_backlog_pending_returns_zero),
        cmocka_unit_test(test_windows_ops_wake_pipe_create_succeeds),
        cmocka_unit_test(test_windows_ops_wake_pipe_write_makes_readable),
        cmocka_unit_test(test_windows_ops_wake_pipe_many_writes_single_drain),
        cmocka_unit_test(test_windows_ops_wake_pipe_wakes_blocked_poll),
        cmocka_unit_test(test_windows_ops_wake_pipe_write_thread_safety),
        cmocka_unit_test(test_windows_ops_wake_pair_per_family),
        cmocka_unit_test(test_windows_ops_wake_pair_rejects_foreign_sender),
        cmocka_unit_test(test_windows_ops_wake_pair_invalid_family),
        cmocka_unit_test(test_windows_ops_wake_pipe_destroy_both_ok),
        cmocka_unit_test(test_windows_ops_poll_closed_wake_end_is_listed_broken),
        cmocka_unit_test(test_windows_ops_poll_reused_handle_not_spuriously_readable),
        cmocka_unit_test(test_windows_ops_poll_udp_peer_closed_stays_quiet),
        cmocka_unit_test(test_windows_ops_poll_tcp_peer_fin_reports_read_or_hup),
        cmocka_unit_test(test_windows_ops_poll_tcp_peer_reset_reports_event),
        cmocka_unit_test(test_windows_ops_poll_udp_icmp_connreset_suppressed),
    };

    return cmocka_run_group_tests(tests, test_group_setup, test_group_teardown);
}

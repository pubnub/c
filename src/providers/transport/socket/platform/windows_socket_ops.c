/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifdef _WIN32

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include "pubnub/pubnub_compat.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#if PUBNUB_ENABLE_CUSTOM_DNS
#include <iphlpapi.h>
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#if PUBNUB_ENABLE_CUSTOM_DNS
#pragma comment(lib, "iphlpapi.lib")
#endif
#endif /* _MSC_VER */

#include <string.h>

/**
 * @file windows_socket_ops.c
 * @brief Windows socket operations implementation using Winsock2 and WSAPoll.
 *
 * Implements the pn_socket_platform_ops_t vtable using Windows Winsock2 APIs.
 * Uses WSAPoll() for multiplexing (Vista+). Handles platform differences:
 * - closesocket() instead of close()
 * - WSAGetLastError() instead of errno
 * - WSAEWOULDBLOCK instead of EAGAIN
 * - SIO_KEEPALIVE_VALS for TCP keepalive (takes milliseconds)
 * - GetAdaptersAddresses + GetBestRoute2 for DNS server discovery
 *
 * @note NEVER use GetNetworkParams for DNS discovery (GetNetworkParams uses
 *       the RPC heap internally; it is not safe to call concurrently from
 *       multiple threads and has caused heap corruption in production).
 */

/**
 * @brief Internal poll set state for Windows.
 *
 * Stores WSAPOLLFD array (fds[i].fd holds the socket handle — no separate
 * handles[] array needed) and ready-socket indices from poll_wait.
 * sizeof = PN_SOCKET_TRANSPORT_MAX_FDS*(16+8) + 8 + 8 = 160 on x64, which
 * fits within PN_POLL_SET_PLATFORM_SIZE (= MAX_FDS*24+16 = 160).
 */
struct pn_windows_poll_internal {
    WSAPOLLFD fds[PN_SOCKET_TRANSPORT_MAX_FDS];
    size_t    count;
    size_t    ready_count;
    size_t    ready_indices[PN_SOCKET_TRANSPORT_MAX_FDS];
};

PUBNUB_STATIC_ASSERT(
    sizeof(struct pn_windows_poll_internal) <= PN_POLL_SET_PLATFORM_SIZE,
    "pn_windows_poll_internal exceeds PN_POLL_SET_PLATFORM_SIZE");

/**
 * @brief Native loopback address holder for the wake pair (either family).
 *
 * The IPv6 member is first so that a `= {0}` initializer zeroes the larger
 * member.
 */
typedef union pn_windows_wake_addr {
    struct sockaddr_in6 v6;
    struct sockaddr_in  v4;
} pn_windows_wake_addr_t;

/** @brief Wake-pair families in the order pipe_create tries them. */
static const int pn_windows_wake_families[] = {AF_INET, AF_INET6};

#define PN_WINDOWS_WAKE_FAMILY_COUNT \
    (sizeof(pn_windows_wake_families) / sizeof(pn_windows_wake_families[0]))

/** @brief Upper bound on datagrams read per pipe_drain call. */
#define PN_WINDOWS_WAKE_DRAIN_MAX_READS 256

/** @brief Self-test wait for the probe datagram to arrive, in milliseconds. */
#define PN_WINDOWS_WAKE_SELFTEST_MS 50

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

/** @brief Cast opaque poll_set to internal struct. */
static inline struct pn_windows_poll_internal* pn_poll_set_internal(pn_poll_set_t* poll_set)
{
    return (struct pn_windows_poll_internal*)poll_set->platform_data;
}

/** @brief Cast const opaque poll_set to internal struct. */
static inline const struct pn_windows_poll_internal*
pn_poll_set_internal_const(const pn_poll_set_t* poll_set)
{
    return (const struct pn_windows_poll_internal*)poll_set->platform_data;
}

/**
 * @brief Convert pn_sockaddr_t to struct sockaddr_in (IPv4).
 */
static void pn_sockaddr_to_sockaddr_in(const pn_sockaddr_t* pn_addr,
                                       struct sockaddr_in*  sa)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port   = htons(pn_addr->port);
    memcpy(&sa->sin_addr.s_addr, pn_addr->addr.ipv4, 4);
}

/**
 * @brief Convert pn_sockaddr_t to struct sockaddr_in6 (IPv6).
 */
static void pn_sockaddr_to_sockaddr_in6(const pn_sockaddr_t* pn_addr,
                                        struct sockaddr_in6* sa6)
{
    memset(sa6, 0, sizeof(*sa6));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port   = htons(pn_addr->port);
    memcpy(&sa6->sin6_addr.s6_addr, pn_addr->addr.ipv6, 16);
}

/**
 * @brief Convert struct sockaddr_in (IPv4) to pn_sockaddr_t.
 */
static void sockaddr_in_to_pn_sockaddr(const struct sockaddr_in* sa,
                                       pn_sockaddr_t*            pn_addr)
{
    pn_addr->family = PN_AF_INET;
    pn_addr->port   = ntohs(sa->sin_port);
    memcpy(pn_addr->addr.ipv4, &sa->sin_addr.s_addr, 4);
}

/**
 * @brief Convert struct sockaddr_in6 (IPv6) to pn_sockaddr_t.
 */
static void sockaddr_in6_to_pn_sockaddr(const struct sockaddr_in6* sa6,
                                        pn_sockaddr_t*             pn_addr)
{
    pn_addr->family = PN_AF_INET6;
    pn_addr->port   = ntohs(sa6->sin6_port);
    memcpy(pn_addr->addr.ipv6, &sa6->sin6_addr.s6_addr, 16);
}

/**
 * @brief Check if a connection-refused error.
 */
static int pn_is_connection_refused(int err)
{
    return WSAECONNREFUSED == err;
}

/**
 * @brief Check if a family-unreachable error.
 */
static int pn_is_family_unreachable(int err)
{
    return WSAENETUNREACH == err || WSAEHOSTUNREACH == err;
}

/**
 * @brief Create a new socket.
 */
static pn_socket_t windows_socket_create(const pn_socket_platform_ops_t* self,
                                         uint16_t                        family,
                                         int                             dgram)
{
    (void)self;

    int domain = 0;

    if (PN_AF_INET == family) {
        domain = AF_INET;
    } else if (PN_AF_INET6 == family) {
        domain = AF_INET6;
    } else {
        WSASetLastError(WSAEINVAL);
        return PN_INVALID_SOCKET;
    }

    const int    type     = dgram ? SOCK_DGRAM : SOCK_STREAM;
    const int    protocol = dgram ? IPPROTO_UDP : IPPROTO_TCP;
    const SOCKET sock     = WSASocketW(domain, type, protocol, NULL, 0, 0);
    if (INVALID_SOCKET == sock) {
        return PN_INVALID_SOCKET;
    }

    return (pn_socket_t)sock;
}

/**
 * @brief Destroy a socket.
 */
static void windows_socket_destroy(const pn_socket_platform_ops_t* self,
                                   pn_socket_t                     sock)
{
    (void)self;

    if (PN_INVALID_SOCKET == sock) {
        return;
    }

    closesocket((SOCKET)sock);
}

/**
 * @brief Initiate a non-blocking connect.
 */
static int windows_socket_connect(const pn_socket_platform_ops_t* self,
                                  pn_socket_t                     sock,
                                  const pn_sockaddr_t*            addr)
{
    (void)self;

    struct sockaddr_in  sa;
    struct sockaddr_in6 sa6;
    struct sockaddr*    sa_ptr = NULL;
    int                 sa_len = 0;
    const SOCKET        s      = (SOCKET)sock;
    int                 rc     = 0;

    if (PN_AF_INET == addr->family) {
        pn_sockaddr_to_sockaddr_in(addr, &sa);
        sa_ptr = (struct sockaddr*)&sa;
        sa_len = sizeof(sa);
    } else if (PN_AF_INET6 == addr->family) {
        pn_sockaddr_to_sockaddr_in6(addr, &sa6);
        sa_ptr = (struct sockaddr*)&sa6;
        sa_len = sizeof(sa6);
    } else {
        WSASetLastError(WSAEINVAL);
        return -WSAEINVAL;
    }

    rc = connect(s, sa_ptr, sa_len);

    if (0 == rc) {
        return 1;
    }

    const int err = WSAGetLastError();
    if (WSAEINPROGRESS == err || WSAEWOULDBLOCK == err) {
        return 0;
    }

    if (pn_is_connection_refused(err) || pn_is_family_unreachable(err)) {
        return -err;
    }

    return -err;
}

/**
 * @brief Check if a non-blocking connect completed.
 */
static int windows_socket_check_connect(const pn_socket_platform_ops_t* self,
                                        pn_socket_t                     sock)
{
    (void)self;

    const SOCKET s            = (SOCKET)sock;
    int          err          = 0;
    int          len          = (int)sizeof(err);
    DWORD        connect_time = 0;
    int          ct_len       = (int)sizeof(connect_time);

    if (0 != getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len)) {
        return -WSAGetLastError();
    }

    if (0 != err) {
        return -err;
    }

    /* SO_ERROR is 0 while the handshake is still in flight, and getpeername()
     * already succeeds then on current Windows; SO_CONNECT_TIME is
     * 0xFFFFFFFF until the connection is actually established. */
    if (0 != getsockopt(s, SOL_SOCKET, SO_CONNECT_TIME, (char*)&connect_time, &ct_len)) {
        return -WSAGetLastError();
    }

    return (0xFFFFFFFFUL == connect_time) ? 0 : 1;
}

/**
 * @brief Send data on a connected socket (non-blocking).
 */
static int windows_socket_send(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               const uint8_t*                  data,
                               size_t                          len)
{
    (void)self;

    const SOCKET s        = (SOCKET)sock;
    const int    sent_ret = send(s, (const char*)data, (int)len, 0);

    if (0 <= sent_ret) {
        return sent_ret;
    }

    const int err = WSAGetLastError();
    if (WSAEWOULDBLOCK == err) {
        return 0;
    }

    if (WSAECONNRESET == err) {
        return -err;
    }

    return -err;
}

/**
 * @brief Receive data from a connected socket (non-blocking).
 */
static int windows_socket_recv(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               uint8_t*                        buf,
                               size_t                          len)
{
    (void)self;

    const SOCKET s        = (SOCKET)sock;
    const int    recv_ret = recv(s, (char*)buf, (int)len, 0);

    if (0 == recv_ret) {
        return -1;
    }

    if (0 < recv_ret) {
        return recv_ret;
    }

    const int err = WSAGetLastError();
    if (WSAEWOULDBLOCK == err) {
        return 0;
    }

    return -err;
}

/**
 * @brief Send data to a specific address (connectionless, non-blocking).
 */
static int windows_socket_sendto(const pn_socket_platform_ops_t* self,
                                 pn_socket_t                     sock,
                                 const uint8_t*                  data,
                                 size_t                          len,
                                 const pn_sockaddr_t*            addr)
{
    (void)self;

    struct sockaddr_in  sa;
    struct sockaddr_in6 sa6;
    struct sockaddr*    sa_ptr = NULL;
    int                 sa_len = 0;
    const SOCKET        s      = (SOCKET)sock;
    int                 rc     = 0;

    if (PN_AF_INET == addr->family) {
        pn_sockaddr_to_sockaddr_in(addr, &sa);
        sa_ptr = (struct sockaddr*)&sa;
        sa_len = sizeof(sa);
    } else if (PN_AF_INET6 == addr->family) {
        pn_sockaddr_to_sockaddr_in6(addr, &sa6);
        sa_ptr = (struct sockaddr*)&sa6;
        sa_len = sizeof(sa6);
    } else {
        WSASetLastError(WSAEINVAL);
        return -WSAEINVAL;
    }

    rc = sendto(s, (const char*)data, (int)len, 0, sa_ptr, sa_len);

    if (0 <= rc) {
        return rc;
    }

    const int err = WSAGetLastError();
    if (WSAEWOULDBLOCK == err) {
        return 0;
    }

    return -err;
}

/**
 * @brief Receive data with source address (connectionless, non-blocking).
 */
static int windows_socket_recvfrom(const pn_socket_platform_ops_t* self,
                                   pn_socket_t                     sock,
                                   uint8_t*                        buf,
                                   size_t                          len,
                                   pn_sockaddr_t*                  addr)
{
    (void)self;

    const SOCKET s = (SOCKET)sock;

    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } sa_storage;
    struct sockaddr* sa_ptr = (struct sockaddr*)&sa_storage;
    int              sa_len = sizeof(sa_storage);
    const int        rc = recvfrom(s, (char*)buf, (int)len, 0, sa_ptr, &sa_len);

    if (0 >= rc) {
        if (0 == rc) {
            return -1;
        }
        const int err = WSAGetLastError();
        if (WSAEWOULDBLOCK == err) {
            return 0;
        }
        return -err;
    }

    if (AF_INET == sa_storage.v4.sin_family) {
        sockaddr_in_to_pn_sockaddr(&sa_storage.v4, addr);
    } else if (AF_INET6 == sa_storage.v6.sin6_family) {
        sockaddr_in6_to_pn_sockaddr(&sa_storage.v6, addr);
    } else {
        return -WSAEINVAL;
    }

    return rc;
}

/**
 * @brief Set socket to non-blocking mode.
 */
static int windows_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                          pn_socket_t                     sock)
{
    (void)self;

    const SOCKET s        = (SOCKET)sock;
    u_long       mode     = 1;
    const int    ioctl_rc = ioctlsocket(s, (long)FIONBIO, &mode);

    if (0 != ioctl_rc) {
        return -WSAGetLastError();
    }

    return 0;
}

/**
 * @brief Configure TCP keepalive on a socket.
 */
static int windows_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                        pn_socket_t                     sock,
                                        const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;

    const SOCKET s       = (SOCKET)sock;
    BOOL         opt_val = 0;
    int          rc      = 0;

    if (0 == config->enabled) {
        opt_val = FALSE;
        rc      = setsockopt(
            s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt_val, sizeof(opt_val));
        if (0 != rc) {
            return -WSAGetLastError();
        }
        return 0;
    }

    opt_val = TRUE;
    rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt_val, sizeof(opt_val));
    if (0 != rc) {
        return -WSAGetLastError();
    }

    struct tcp_keepalive keepalive_vals;
    keepalive_vals.onoff             = 1;
    keepalive_vals.keepalivetime     = config->idle_sec * 1000;
    keepalive_vals.keepaliveinterval = config->interval_sec * 1000;

    DWORD bytes_returned = 0;
    rc                   = WSAIoctl(s,
                  SIO_KEEPALIVE_VALS,
                  &keepalive_vals,
                  sizeof(keepalive_vals),
                  NULL,
                  0,
                  &bytes_returned,
                  NULL,
                  NULL);

    if (0 != rc) {
        return -WSAGetLastError();
    }

    return 0;
}

/**
 * @brief Initialize a poll set.
 */
static int windows_poll_init(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set)
{
    (void)self;

    struct pn_windows_poll_internal* internal = pn_poll_set_internal(poll_set);
    memset(internal, 0, sizeof(*internal));
    return 0;
}

/**
 * @brief Deinitialize a poll set.
 */
static void windows_poll_deinit(const pn_socket_platform_ops_t* self,
                                pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
}

/**
 * @brief Add a socket to the poll set.
 */
static int windows_poll_add(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock,
                            uint8_t                         events)
{
    (void)self;

    struct pn_windows_poll_internal* internal = pn_poll_set_internal(poll_set);
    short                            poll_events = 0;

    if (internal->count >= PN_SOCKET_TRANSPORT_MAX_FDS) {
        return -WSAEMFILE;
    }

    if (0 != (events & PN_POLL_READ)) {
        poll_events |= POLLRDNORM;
    }
    if (0 != (events & PN_POLL_WRITE)) {
        poll_events |= POLLWRNORM;
    }
    /* PN_POLL_ERROR / PN_POLL_HUP request bits map to nothing: WSAPoll rejects
     * POLLERR/POLLHUP/POLLNVAL in events (WSAEINVAL) and always reports them
     * in revents. */

    internal->fds[internal->count].fd      = (SOCKET)sock;
    internal->fds[internal->count].events  = poll_events;
    internal->fds[internal->count].revents = 0;
    internal->count++;

    return 0;
}

/**
 * @brief Modify the monitored events for a socket in the poll set.
 */
static int windows_poll_modify(const pn_socket_platform_ops_t* self,
                               pn_poll_set_t*                  poll_set,
                               pn_socket_t                     sock,
                               uint8_t                         events)
{
    (void)self;

    struct pn_windows_poll_internal* internal = pn_poll_set_internal(poll_set);
    short                            poll_events = 0;
    size_t                           i           = 0;

    for (i = 0; i < internal->count; ++i) {
        if ((pn_socket_t)internal->fds[i].fd == sock) {
            break;
        }
    }

    if (i >= internal->count) {
        return -WSAEINVAL;
    }

    if (0 != (events & PN_POLL_READ)) {
        poll_events |= POLLRDNORM;
    }
    if (0 != (events & PN_POLL_WRITE)) {
        poll_events |= POLLWRNORM;
    }
    /* PN_POLL_ERROR / PN_POLL_HUP request bits map to nothing: WSAPoll rejects
     * POLLERR/POLLHUP/POLLNVAL in events (WSAEINVAL) and always reports them
     * in revents. */

    internal->fds[i].events  = poll_events;
    internal->fds[i].revents = 0;

    return 0;
}

/**
 * @brief Remove a socket from the poll set.
 */
static int windows_poll_remove(const pn_socket_platform_ops_t* self,
                               pn_poll_set_t*                  poll_set,
                               pn_socket_t                     sock)
{
    (void)self;

    struct pn_windows_poll_internal* internal = pn_poll_set_internal(poll_set);
    size_t                           i        = 0;

    for (i = 0; i < internal->count; ++i) {
        if ((pn_socket_t)internal->fds[i].fd == sock) {
            break;
        }
    }

    if (i >= internal->count) {
        return -WSAEINVAL;
    }

    const size_t last_idx = internal->count - 1;
    if (i != last_idx) {
        internal->fds[i] = internal->fds[last_idx];
    }

    internal->count--;
    return 0;
}

/**
 * @brief Wait for I/O events on sockets in the poll set.
 */
static int windows_poll_wait(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set,
                             int                             timeout_ms)
{
    (void)self;

    struct pn_windows_poll_internal* internal = pn_poll_set_internal(poll_set);

    /* Empty poll set: sleep for the requested timeout. When timeout_ms
     * is 0 or negative (infinite), return immediately — blocking forever
     * with nothing to poll would deadlock the bg thread. */
    if (0 == internal->count) {
        if (0 < timeout_ms) {
            Sleep((DWORD)timeout_ms);
        }
        internal->ready_count = 0;
        return 0;
    }

    const int poll_ret = WSAPoll(internal->fds, (ULONG)internal->count, timeout_ms);
    size_t i = 0;

    if (0 > poll_ret) {
        const int poll_err = WSAGetLastError();

        /* When every entry is an invalid handle WSAPoll fails the whole call
         * with WSAENOTSOCK but still sets POLLNVAL in revents; fall through so
         * the broken entries are reported like they are in a mixed set. */
        if (WSAENOTSOCK != poll_err) {
            return -poll_err;
        }
    }

    internal->ready_count = 0;
    for (i = 0; i < internal->count; ++i) {
        if (0 != internal->fds[i].revents) {
            internal->ready_indices[internal->ready_count++] = i;
        }
    }

    return 0;
}

/**
 * @brief Get the number of ready sockets after poll_wait.
 */
static size_t windows_poll_ready_count(const pn_socket_platform_ops_t* self,
                                       const pn_poll_set_t*            poll_set)
{
    (void)self;

    const struct pn_windows_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    return internal->ready_count;
}

/**
 * @brief Retrieve the ready socket and events at the given index.
 */
static int windows_poll_get_ready(const pn_socket_platform_ops_t* self,
                                  const pn_poll_set_t*            poll_set,
                                  size_t                          index,
                                  pn_socket_t*                    out_sock,
                                  uint8_t*                        out_events)
{
    (void)self;

    const struct pn_windows_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    size_t  ready_idx = 0;
    uint8_t events    = 0;
    short   revents   = 0;

    if (index >= internal->ready_count) {
        return -WSAEINVAL;
    }

    ready_idx = internal->ready_indices[index];
    revents   = internal->fds[ready_idx].revents;

    if (0 != (revents & POLLRDNORM)) {
        events |= PN_POLL_READ;
    }
    if (0 != (revents & POLLWRNORM)) {
        events |= PN_POLL_WRITE;
    }
    if (0 != (revents & POLLERR)) {
        events |= PN_POLL_ERROR;
    }
    if (0 != (revents & POLLHUP)) {
        events |= PN_POLL_HUP;
    }

    *out_sock   = (pn_socket_t)internal->fds[ready_idx].fd;
    *out_events = events;

    return 0;
}

#if PUBNUB_ENABLE_CUSTOM_DNS

/**
 * @brief Check if an address is loopback.
 */
static int pn_is_loopback(const pn_sockaddr_t* addr)
{
    if (PN_AF_INET == addr->family) {
        const uint8_t first_octet = addr->addr.ipv4[0];
        return 127 == first_octet;
    } else if (PN_AF_INET6 == addr->family) {
        static const uint8_t loopback[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return 0 == memcmp(addr->addr.ipv6, loopback, 16);
    }
    return 0;
}

/**
 * @brief Check if an address is APIPA (169.254.x.x).
 */
static int pn_is_apipa(const pn_sockaddr_t* addr)
{
    if (PN_AF_INET == addr->family) {
        return 169 == addr->addr.ipv4[0] && 254 == addr->addr.ipv4[1];
    }
    return 0;
}

/**
 * @brief Check if an address is multicast.
 */
static int pn_is_multicast(const pn_sockaddr_t* addr)
{
    if (PN_AF_INET == addr->family) {
        const uint8_t first_octet = addr->addr.ipv4[0];
        return first_octet >= 224 && first_octet <= 239;
    } else if (PN_AF_INET6 == addr->family) {
        return 0xFF == addr->addr.ipv6[0];
    }
    return 0;
}

/**
 * @brief Discover DNS server addresses from system configuration.
 *
 * Queries GetAdaptersAddresses and uses GetBestRoute2 to prioritize servers
 * from the best-route adapter. Filters loopback, APIPA, and multicast.
 *
 * @param self Platform ops instance (unused).
 * @param servers Array to populate with nameserver addresses.
 * @param capacity Maximum number of servers to store.
 * @param out_count On success, set to number of servers discovered.
 * @return 0 on success, negative Windows error code on failure.
 */
static int windows_dns_discover_servers(const pn_socket_platform_ops_t* self,
                                        pn_sockaddr_t*                  servers,
                                        size_t  capacity,
                                        size_t* out_count)
{
    (void)self;

    size_t                count    = 0;
    PIP_ADAPTER_ADDRESSES adapters = NULL;
    ULONG                 buf_len  = 15000;
    ULONG                 rc       = 0;
    int                   retries  = 3;

    while (retries-- > 0) {
        adapters = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, buf_len);
        if (NULL == adapters) {
            return -WSA_NOT_ENOUGH_MEMORY;
        }

        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                      | GAA_FLAG_INCLUDE_GATEWAYS,
                                  NULL,
                                  adapters,
                                  &buf_len);

        if (ERROR_BUFFER_OVERFLOW == rc) {
            HeapFree(GetProcessHeap(), 0, adapters);
            adapters = NULL;
            continue;
        }

        break;
    }

    if (NO_ERROR != rc || NULL == adapters) {
        if (NULL != adapters) {
            HeapFree(GetProcessHeap(), 0, adapters);
        }
        return -(int)rc;
    }

    PIP_ADAPTER_ADDRESSES current = adapters;
    while (NULL != current && count < capacity) {
        if (IfOperStatusUp != current->OperStatus) {
            current = current->Next;
            continue;
        }

        PIP_ADAPTER_DNS_SERVER_ADDRESS dns_addr = current->FirstDnsServerAddress;
        while (NULL != dns_addr && count < capacity) {
            struct sockaddr* sa     = dns_addr->Address.lpSockaddr;
            pn_sockaddr_t    pn_dns = {0};

            if (AF_INET == sa->sa_family) {
                struct sockaddr_in* sa4 = (struct sockaddr_in*)sa;
                sockaddr_in_to_pn_sockaddr(sa4, &pn_dns);
                if (0 == pn_dns.port) {
                    pn_dns.port = 53;
                }
            } else if (AF_INET6 == sa->sa_family) {
                struct sockaddr_in6* sa6 = (struct sockaddr_in6*)sa;
                sockaddr_in6_to_pn_sockaddr(sa6, &pn_dns);
                if (0 == pn_dns.port) {
                    pn_dns.port = 53;
                }
            } else {
                dns_addr = dns_addr->Next;
                continue;
            }

            if (pn_is_loopback(&pn_dns) || pn_is_apipa(&pn_dns)
                || pn_is_multicast(&pn_dns)) {
                dns_addr = dns_addr->Next;
                continue;
            }

            servers[count++] = pn_dns;
            dns_addr         = dns_addr->Next;
        }

        current = current->Next;
    }

    HeapFree(GetProcessHeap(), 0, adapters);

    *out_count = count;
    return 0;
}

#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

#if !PUBNUB_ENABLE_CUSTOM_DNS

typedef struct pn_windows_dns_state {
    pn_sockaddr_t addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    size_t        count;
    uint8_t       complete;
    uint8_t       error;
} pn_windows_dns_state_t;

#include "pubnub/pubnub_compat.h"
PUBNUB_STATIC_ASSERT(
    sizeof(pn_windows_dns_state_t) <= PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE,
    "Windows DNS state exceeds PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE");

static size_t windows_dns_state_size(const pn_socket_platform_ops_t* self)
{
    (void)self;
    return sizeof(pn_windows_dns_state_t);
}

/**
 * @brief Resolve hostname synchronously via GetAddrInfoW.
 *
 * Uses a two-pass approach (IPv4 first, then IPv6 in remaining slots)
 * to ensure IPv4 addresses are always available even on DNS64/NAT64
 * networks where GetAddrInfoW may return synthesized IPv6 first.
 * IPv6 addresses are capped at half the result buffer.
 */
static int windows_dns_resolve_start(const pn_socket_platform_ops_t* self,
                                     void*                           dns_ctx,
                                     const char*                     hostname,
                                     uint32_t                        timeout_ms)
{
    pn_windows_dns_state_t* st = (pn_windows_dns_state_t*)dns_ctx;
    wchar_t                 whost[256];
    int                     wide_len = 0;
    ADDRINFOW               hints    = {0};
    ADDRINFOW*              result   = NULL;
    int                     rc       = 0;
    size_t                  count    = 0;
    size_t                  v4_count = 0;
    ADDRINFOW*              rp       = NULL;

    (void)self;
    (void)timeout_ms;

    st->count    = 0;
    st->complete = 0;
    st->error    = 0;

    wide_len = MultiByteToWideChar(CP_UTF8, 0, hostname, -1, whost, 256);
    if (0 == wide_len) {
        st->error    = 1;
        st->complete = 1;
        return 0;
    }

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_ADDRCONFIG;

    rc = GetAddrInfoW(whost, NULL, &hints, &result);
    if (0 != rc || NULL == result) {
        st->error    = 1;
        st->complete = 1;
        return 0;
    }

    /* Two-pass: IPv4 first, then IPv6 in remaining slots.
     * GetAddrInfoW with AF_UNSPEC may return IPv6 before IPv4 (RFC 6724
     * preference ordering on dual-stack hosts). Filling the fixed-size
     * buffer in that order would exhaust all slots with IPv6 and never
     * store IPv4 addresses. This matters on DNS64/NAT64 networks where
     * synthesized IPv6 addresses may be unreachable. */
    for (rp = result; NULL != rp && count < PUBNUB_CFG_MAX_DNS_RESULTS;
         rp = rp->ai_next) {
        if (AF_INET == rp->ai_family) {
            struct sockaddr_in* sin = (struct sockaddr_in*)rp->ai_addr;
            st->addrs[count].family = PN_AF_INET;
            memcpy(st->addrs[count].addr.ipv4, &sin->sin_addr.s_addr, 4);
            ++count;
            ++v4_count;
        }
    }
    if (PUBNUB_ENABLE_IPV6) {
        for (rp = result; NULL != rp && count < PUBNUB_CFG_MAX_DNS_RESULTS;
             rp = rp->ai_next) {
            if (AF_INET6 == rp->ai_family) {
                struct sockaddr_in6* sin6 = NULL;
                /* Cap IPv6 at half the buffer to guarantee IPv4 room. */
                if ((count - v4_count) >= PUBNUB_CFG_MAX_DNS_RESULTS / 2U) {
                    break;
                }
                sin6                    = (struct sockaddr_in6*)rp->ai_addr;
                st->addrs[count].family = PN_AF_INET6;
                memcpy(st->addrs[count].addr.ipv6, sin6->sin6_addr.s6_addr, 16);
                ++count;
            }
        }
    }

    FreeAddrInfoW(result);

    st->count    = count;
    st->complete = 1;
    st->error    = (0 == count) ? 1 : 0;

    return 0;
}

static int windows_dns_resolve_poll(const pn_socket_platform_ops_t* self,
                                    void*                           dns_ctx)
{
    (void)self;

    pn_windows_dns_state_t* st = (pn_windows_dns_state_t*)dns_ctx;

    if (!st->complete) {
        return 0;
    }
    return st->error ? -1 : 1;
}

static int windows_dns_resolve_get_results(const pn_socket_platform_ops_t* self,
                                           void*          dns_ctx,
                                           pn_sockaddr_t* addrs,
                                           size_t         max_addrs,
                                           size_t*        out_count)
{
    (void)self;

    pn_windows_dns_state_t* st = (pn_windows_dns_state_t*)dns_ctx;

    if (!st->complete || st->error) {
        return -1;
    }

    size_t to_copy = st->count;
    if (to_copy > max_addrs) {
        to_copy = max_addrs;
    }
    memcpy(addrs, st->addrs, to_copy * sizeof(pn_sockaddr_t));
    *out_count = to_copy;
    return 0;
}

#endif /* !PUBNUB_ENABLE_CUSTOM_DNS */

/**
 * @brief Create a UDP socket bound to the loopback address of @p af.
 *
 * @param af       AF_INET or AF_INET6.
 * @param out_addr Receives the bound address (including the ephemeral port).
 * @param out_len  Receives the valid length of @p out_addr.
 * @return Bound socket, or INVALID_SOCKET on failure.
 */
static SOCKET wake_open_loopback(int af, pn_windows_wake_addr_t* out_addr, int* out_len)
{
    pn_windows_wake_addr_t addr = {0};
    int                    len  = 0;
    SOCKET                 s    = INVALID_SOCKET;

    if (AF_INET == af) {
        addr.v4.sin_family      = AF_INET;
        addr.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len                     = (int)sizeof(addr.v4);
    } else {
        addr.v6.sin6_family           = AF_INET6;
        addr.v6.sin6_addr.s6_addr[15] = 1;
        len                           = (int)sizeof(addr.v6);
    }

    s = WSASocketW(af, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    if (INVALID_SOCKET == s) {
        return INVALID_SOCKET;
    }

    if (0 != bind(s, (const struct sockaddr*)&addr, len)
        || 0 != getsockname(s, (struct sockaddr*)&addr, &len)) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    *out_addr = addr;
    *out_len  = len;
    return s;
}

/**
 * @brief Connect both ends to each other and configure them.
 *
 * Connecting makes the stack drop datagrams from any other sender. The
 * SIO_UDP_CONNRESET opt-out is best effort.
 *
 * @return 0 on success, -1 on failure.
 */
static int wake_link_pair(SOCKET                        r,
                          SOCKET                        w,
                          const pn_windows_wake_addr_t* addr_r,
                          int                           len_r,
                          const pn_windows_wake_addr_t* addr_w,
                          int                           len_w)
{
    BOOL   off   = FALSE;
    DWORD  bytes = 0;
    u_long mode  = 1;
    SOCKET ends[2];
    size_t i;

    if (0 != connect(w, (const struct sockaddr*)addr_r, len_r)
        || 0 != connect(r, (const struct sockaddr*)addr_w, len_w)) {
        return -1;
    }

    ends[0] = r;
    ends[1] = w;
    for (i = 0; i < 2; ++i) {
        (void)WSAIoctl(
            ends[i], SIO_UDP_CONNRESET, &off, (DWORD)sizeof(off), NULL, 0, &bytes, NULL, NULL);
        if (0 != ioctlsocket(ends[i], (long)FIONBIO, &mode)) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Verify the pair carries one byte and is empty afterwards.
 *
 * @return 0 when the round trip works, -1 otherwise.
 */
static int wake_selftest(SOCKET r, SOCKET w)
{
    const char probe = 1;
    char       buf[8];
    WSAPOLLFD  pfd = {0};

    if (1 != send(w, &probe, 1, 0)) {
        return -1;
    }

    pfd.fd     = r;
    pfd.events = POLLRDNORM;
    if (1 != WSAPoll(&pfd, 1, PN_WINDOWS_WAKE_SELFTEST_MS)
        || 0 == (pfd.revents & POLLRDNORM)) {
        return -1;
    }

    if (1 != recv(r, buf, (int)sizeof(buf), 0)) {
        return -1;
    }

    if (SOCKET_ERROR != recv(r, buf, (int)sizeof(buf), 0)
        || WSAEWOULDBLOCK != WSAGetLastError()) {
        return -1;
    }

    return 0;
}

/**
 * @brief Create the wake pair, trying each supported family in order.
 */
int pn_windows_wake_pair_create(int af, pn_socket_t out[2]);

static int windows_pipe_create(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     out[2])
{
    (void)self;

    size_t i;

    for (i = 0; i < PN_WINDOWS_WAKE_FAMILY_COUNT; ++i) {
        if (0 == pn_windows_wake_pair_create(pn_windows_wake_families[i], out)) {
            return 0;
        }
    }

    out[0] = PN_INVALID_SOCKET;
    out[1] = PN_INVALID_SOCKET;
    return -1;
}

/**
 * @brief Send one wake byte; safe to call from any thread.
 *
 * Errors are ignored: WSAEWOULDBLOCK means the read end is already readable.
 */
static void windows_pipe_write(const pn_socket_platform_ops_t* self, pn_socket_t wr)
{
    (void)self;

    const char byte = 1;

    (void)send((SOCKET)wr, &byte, 1, 0);
}

/**
 * @brief Discard pending wake datagrams, bounded per call.
 *
 * At the bound the read end stays readable, so the next poll drains again.
 */
static void windows_pipe_drain(const pn_socket_platform_ops_t* self, pn_socket_t rd)
{
    (void)self;

    char buf[64];
    int  i;

    for (i = 0; i < PN_WINDOWS_WAKE_DRAIN_MAX_READS; ++i) {
        if (0 >= recv((SOCKET)rd, buf, (int)sizeof(buf), 0)) {
            break;
        }
    }
}

int pn_windows_wake_pair_create(int af, pn_socket_t out[2])
{
    pn_windows_wake_addr_t addr_r = {0};
    pn_windows_wake_addr_t addr_w = {0};
    int                    len_r  = 0;
    int                    len_w  = 0;
    SOCKET                 r      = INVALID_SOCKET;
    SOCKET                 w      = INVALID_SOCKET;

    if (NULL == out) {
        return -1;
    }

    out[0] = PN_INVALID_SOCKET;
    out[1] = PN_INVALID_SOCKET;

    if (AF_INET != af && AF_INET6 != af) {
        return -1;
    }

    r = wake_open_loopback(af, &addr_r, &len_r);
    w = wake_open_loopback(af, &addr_w, &len_w);
    if (INVALID_SOCKET != r && INVALID_SOCKET != w
        && 0 == wake_link_pair(r, w, &addr_r, len_r, &addr_w, len_w)
        && 0 == wake_selftest(r, w)) {
        out[0] = (pn_socket_t)r;
        out[1] = (pn_socket_t)w;
        return 0;
    }

    if (INVALID_SOCKET != r) {
        closesocket(r);
    }
    if (INVALID_SOCKET != w) {
        closesocket(w);
    }
    return -1;
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_socket_platform_ops_t pn_windows_socket_ops = {
    .socket_create          = windows_socket_create,
    .socket_destroy         = windows_socket_destroy,
    .socket_connect         = windows_socket_connect,
    .socket_check_connect   = windows_socket_check_connect,
    .socket_send            = windows_socket_send,
    .socket_recv            = windows_socket_recv,
    .socket_sendto          = windows_socket_sendto,
    .socket_recvfrom        = windows_socket_recvfrom,
    .socket_set_nonblocking = windows_socket_set_nonblocking,
    .socket_set_keepalive   = windows_socket_set_keepalive,
    .poll_init              = windows_poll_init,
    .poll_deinit            = windows_poll_deinit,
    .poll_add               = windows_poll_add,
    .poll_modify            = windows_poll_modify,
    .poll_remove            = windows_poll_remove,
    .poll_wait              = windows_poll_wait,
    .poll_ready_count       = windows_poll_ready_count,
    .poll_get_ready         = windows_poll_get_ready,
#if PUBNUB_ENABLE_CUSTOM_DNS
    .dns_discover_servers    = windows_dns_discover_servers,
    .dns_state_size          = NULL,
    .dns_state_init          = NULL,
    .dns_resolve_start       = NULL,
    .dns_resolve_poll        = NULL,
    .dns_resolve_get_results = NULL,
    .dns_resolve_cancel      = NULL,
#else
    .dns_discover_servers    = NULL,
    .dns_state_size          = windows_dns_state_size,
    .dns_state_init          = NULL,
    .dns_resolve_start       = windows_dns_resolve_start,
    .dns_resolve_poll        = windows_dns_resolve_poll,
    .dns_resolve_get_results = windows_dns_resolve_get_results,
    .dns_resolve_cancel      = NULL,
#endif
    /* WSAPoll() only monitors sockets, so the wake channel is a connected
     * loopback UDP pair. If it cannot be created, pipe_create fails and the
     * transport falls back to the poll timeout. */
    .pipe_create = windows_pipe_create,
    .pipe_write  = windows_pipe_write,
    .pipe_drain  = windows_pipe_drain,
};

#endif /* _WIN32 */

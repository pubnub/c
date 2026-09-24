/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if PUBNUB_ENABLE_CUSTOM_DNS
#if defined(__APPLE__)
#include <resolv.h>
#endif

#ifndef PUBNUB_CFG_RESOLV_CONF_PATH
/** @brief Path to resolv.conf for DNS server discovery (Linux/BSD). */
#define PUBNUB_CFG_RESOLV_CONF_PATH "/etc/resolv.conf"
#endif
#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

#if !PUBNUB_ENABLE_CUSTOM_DNS
#if defined(__APPLE__)
#include <dns_sd.h>
#else
#include <netdb.h>
#endif
#endif /* !PUBNUB_ENABLE_CUSTOM_DNS */

/**
 * @file posix_socket_ops.c
 * @brief POSIX socket operations implementation for Linux, macOS, BSD.
 *
 * Implements the pn_socket_platform_ops_t vtable using POSIX socket APIs.
 * Uses poll() for multiplexing (not select(): fd_set is a fixed 1024-bit
 * bitmap; FD_SET(fd) with fd >= FD_SETSIZE corrupts memory beyond the bitmap
 * boundary). Handles macOS vs Linux differences in TCP keepalive socket
 * options and DNS resolution.
 */

/**
 * @brief Internal poll set state for POSIX.
 *
 * Stores pollfd array, socket handles for correlation, and ready-socket
 * indices computed during poll_wait.
 */
struct pn_posix_poll_internal {
    struct pollfd fds[PN_SOCKET_TRANSPORT_MAX_FDS];
    pn_socket_t   handles[PN_SOCKET_TRANSPORT_MAX_FDS];
    nfds_t        count;
    size_t        ready_count;
    size_t        ready_indices[PN_SOCKET_TRANSPORT_MAX_FDS];
};

#include "pubnub/pubnub_compat.h"
PUBNUB_STATIC_ASSERT(
    sizeof(struct pn_posix_poll_internal) <= PN_POLL_SET_PLATFORM_SIZE,
    "pn_posix_poll_internal exceeds PN_POLL_SET_PLATFORM_SIZE");
PUBNUB_STATIC_ASSERT(PN_SOCKET_TRANSPORT_MAX_FDS <= (nfds_t)-1,
                     "PN_SOCKET_TRANSPORT_MAX_FDS exceeds nfds_t range");

/** @brief Cast opaque poll_set to internal struct. */
static inline struct pn_posix_poll_internal* pn_poll_set_internal(pn_poll_set_t* poll_set)
{
    return (struct pn_posix_poll_internal*)poll_set->platform_data;
}

/** @brief Cast const opaque poll_set to internal struct. */
static inline const struct pn_posix_poll_internal*
pn_poll_set_internal_const(const pn_poll_set_t* poll_set)
{
    return (const struct pn_posix_poll_internal*)poll_set->platform_data;
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

static pn_socket_t posix_socket_create(const pn_socket_platform_ops_t* self,
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
        errno = EINVAL;
        return PN_INVALID_SOCKET;
    }

    const int type = dgram ? SOCK_DGRAM : SOCK_STREAM;
    const int fd   = socket(domain, type, 0);
    if (0 > fd) {
        return PN_INVALID_SOCKET;
    }

#ifdef __APPLE__
    const int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));
#endif

    return (pn_socket_t)fd;
}

static void posix_socket_destroy(const pn_socket_platform_ops_t* self,
                                 pn_socket_t                     sock)
{
    (void)self;

    if (PN_INVALID_SOCKET == sock) {
        return;
    }

    close((int)sock);
}

static int posix_socket_connect(const pn_socket_platform_ops_t* self,
                                pn_socket_t                     sock,
                                const pn_sockaddr_t*            addr)
{
    (void)self;

    struct sockaddr_in  sa;
    struct sockaddr_in6 sa6;
    struct sockaddr*    sa_ptr      = NULL;
    socklen_t           sa_len      = 0;
    const int           fd          = (int)sock;
    int                 connect_ret = 0;

    if (PN_AF_INET == addr->family) {
        pn_sockaddr_to_sockaddr_in(addr, &sa);
        sa_ptr = (struct sockaddr*)&sa;
        sa_len = sizeof(sa);
    } else if (PN_AF_INET6 == addr->family) {
        pn_sockaddr_to_sockaddr_in6(addr, &sa6);
        sa_ptr = (struct sockaddr*)&sa6;
        sa_len = sizeof(sa6);
    } else {
        errno = EINVAL;
        return -EINVAL;
    }

    connect_ret = connect(fd, sa_ptr, sa_len);

    if (0 == connect_ret) {
        return 1;
    }

    if (EINPROGRESS == errno || EAGAIN == errno) {
        return 0;
    }

    return -errno;
}

static int posix_socket_check_connect(const pn_socket_platform_ops_t* self,
                                      pn_socket_t                     sock)
{
    (void)self;

    const int fd      = (int)sock;
    int       err     = 0;
    socklen_t len     = sizeof(err);
    const int gso_ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

    if (0 != gso_ret) {
        return -errno;
    }

    if (0 == err) {
        return 1;
    }

    if (EINPROGRESS == err) {
        return 0;
    }

    return -err;
}

static int posix_socket_send(const pn_socket_platform_ops_t* self,
                             pn_socket_t                     sock,
                             const uint8_t*                  data,
                             size_t                          len)
{
    (void)self;

    const int fd    = (int)sock;
    int       flags = 0;

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif

    const ssize_t sent_sz = send(fd, data, len, flags);

    if (0 <= sent_sz) {
        return (int)sent_sz;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINPROGRESS == errno) {
        return 0;
    }

    return -errno;
}

static int posix_socket_recv(const pn_socket_platform_ops_t* self,
                             pn_socket_t                     sock,
                             uint8_t*                        buf,
                             size_t                          len)
{
    (void)self;

    const int     fd       = (int)sock;
    const ssize_t recv_ret = recv(fd, buf, len, 0);

    if (0 == recv_ret) {
        return -1;
    }

    if (0 < recv_ret) {
        return (int)recv_ret;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINPROGRESS == errno) {
        return 0;
    }

    return -errno;
}

static int posix_socket_sendto(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               const uint8_t*                  data,
                               size_t                          len,
                               const pn_sockaddr_t*            addr)
{
    (void)self;

    struct sockaddr_in  sa;
    struct sockaddr_in6 sa6;
    struct sockaddr*    sa_ptr = NULL;
    socklen_t           sa_len = 0;
    const int           fd     = (int)sock;

    if (PN_AF_INET == addr->family) {
        pn_sockaddr_to_sockaddr_in(addr, &sa);
        sa_ptr = (struct sockaddr*)&sa;
        sa_len = sizeof(sa);
    } else if (PN_AF_INET6 == addr->family) {
        pn_sockaddr_to_sockaddr_in6(addr, &sa6);
        sa_ptr = (struct sockaddr*)&sa6;
        sa_len = sizeof(sa6);
    } else {
        errno = EINVAL;
        return -EINVAL;
    }

    const ssize_t sendto_ret = sendto(fd, data, len, 0, sa_ptr, sa_len);

    if (0 <= sendto_ret) {
        return (int)sendto_ret;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno) {
        return 0;
    }

    return -errno;
}

static int posix_socket_recvfrom(const pn_socket_platform_ops_t* self,
                                 pn_socket_t                     sock,
                                 uint8_t*                        buf,
                                 size_t                          len,
                                 pn_sockaddr_t*                  addr)
{
    (void)self;

    const int fd = (int)sock;

    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } sa_storage;
    struct sockaddr* sa_ptr = (struct sockaddr*)&sa_storage;
    socklen_t        sa_len = sizeof(sa_storage);

    const ssize_t recv_ret = recvfrom(fd, buf, len, 0, sa_ptr, &sa_len);

    if (0 >= recv_ret) {
        if (0 == recv_ret) {
            return -1;
        }
        if (EAGAIN == errno || EWOULDBLOCK == errno) {
            return 0;
        }
        return -errno;
    }

    if (AF_INET == sa_storage.v4.sin_family) {
        sockaddr_in_to_pn_sockaddr(&sa_storage.v4, addr);
    } else if (AF_INET6 == sa_storage.v6.sin6_family) {
        sockaddr_in6_to_pn_sockaddr(&sa_storage.v6, addr);
    } else {
        return -EINVAL;
    }

    return (int)recv_ret;
}

static int posix_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                        pn_socket_t                     sock)
{
    (void)self;

    const int fd        = (int)sock;
    const int flags     = fcntl(fd, F_GETFL, 0);
    int       fcntl_ret = 0;

    if (0 > flags) {
        return -errno;
    }

    fcntl_ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (0 > fcntl_ret) {
        return -errno;
    }

    return 0;
}

static int posix_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                      pn_socket_t                     sock,
                                      const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;

    const int fd      = (int)sock;
    int       opt_val = 0;
    int       sso_ret = 0;

    if (0 == config->enabled) {
        opt_val = 0;
        sso_ret =
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
        if (0 > sso_ret) {
            return -errno;
        }
        return 0;
    }

    opt_val = 1;
    sso_ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

#ifdef __APPLE__
    opt_val = (int)config->idle_sec;
    sso_ret =
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &opt_val, sizeof(opt_val));
#else
    opt_val = (int)config->idle_sec;
    sso_ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt_val, sizeof(opt_val));
#endif
    if (0 > sso_ret) {
        return -errno;
    }

    opt_val = (int)config->interval_sec;
    sso_ret =
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

    opt_val = (int)config->probe_count;
    sso_ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

    return 0;
}

static int posix_poll_init(const pn_socket_platform_ops_t* self,
                           pn_poll_set_t*                  poll_set)
{
    (void)self;

    struct pn_posix_poll_internal* internal = pn_poll_set_internal(poll_set);
    memset(internal, 0, sizeof(*internal));
    return 0;
}

static void posix_poll_deinit(const pn_socket_platform_ops_t* self,
                              pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
}

static int posix_poll_add(const pn_socket_platform_ops_t* self,
                          pn_poll_set_t*                  poll_set,
                          pn_socket_t                     sock,
                          uint8_t                         events)
{
    (void)self;

    struct pn_posix_poll_internal* internal    = pn_poll_set_internal(poll_set);
    short                          poll_events = 0;

    if (internal->count >= PN_SOCKET_TRANSPORT_MAX_FDS) {
        return -ENOMEM;
    }

    if (0 != (events & PN_POLL_READ)) {
        poll_events |= POLLIN;
    }
    if (0 != (events & PN_POLL_WRITE)) {
        poll_events |= POLLOUT;
    }
    if (0 != (events & PN_POLL_ERROR)) {
        poll_events |= POLLERR;
    }

    internal->fds[internal->count].fd      = (int)sock;
    internal->fds[internal->count].events  = poll_events;
    internal->fds[internal->count].revents = 0;
    internal->handles[internal->count]     = sock;
    internal->count++;

    return 0;
}

static int posix_poll_modify(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set,
                             pn_socket_t                     sock,
                             uint8_t                         events)
{
    (void)self;

    struct pn_posix_poll_internal* internal    = pn_poll_set_internal(poll_set);
    short                          poll_events = 0;
    size_t                         i           = 0;

    for (i = 0; i < internal->count; ++i) {
        if (internal->handles[i] == sock) {
            break;
        }
    }

    if (i >= internal->count) {
        return -EINVAL;
    }

    if (0 != (events & PN_POLL_READ)) {
        poll_events |= POLLIN;
    }
    if (0 != (events & PN_POLL_WRITE)) {
        poll_events |= POLLOUT;
    }
    if (0 != (events & PN_POLL_ERROR)) {
        poll_events |= POLLERR;
    }

    internal->fds[i].events  = poll_events;
    internal->fds[i].revents = 0;

    return 0;
}

static int posix_poll_remove(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set,
                             pn_socket_t                     sock)
{
    (void)self;

    struct pn_posix_poll_internal* internal = pn_poll_set_internal(poll_set);
    size_t                         i        = 0;

    for (i = 0; i < internal->count; ++i) {
        if (internal->handles[i] == sock) {
            break;
        }
    }

    if (i >= internal->count) {
        return -EINVAL;
    }

    const size_t last_idx = internal->count - 1;
    if (i != last_idx) {
        internal->fds[i]     = internal->fds[last_idx];
        internal->handles[i] = internal->handles[last_idx];
    }

    internal->count--;
    return 0;
}

static int posix_poll_wait(const pn_socket_platform_ops_t* self,
                           pn_poll_set_t*                  poll_set,
                           int                             timeout_ms)
{
    (void)self;

    struct pn_posix_poll_internal* internal = pn_poll_set_internal(poll_set);
    const int poll_ret = poll(internal->fds, internal->count, timeout_ms);
    size_t    i        = 0;

    if (0 > poll_ret) {
        return -errno;
    }

    internal->ready_count = 0;
    for (i = 0; i < internal->count; ++i) {
        if (0 != internal->fds[i].revents) {
            internal->ready_indices[internal->ready_count++] = i;
        }
    }

    return 0;
}

static size_t posix_poll_ready_count(const pn_socket_platform_ops_t* self,
                                     const pn_poll_set_t*            poll_set)
{
    (void)self;

    const struct pn_posix_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    return internal->ready_count;
}

static int posix_poll_get_ready(const pn_socket_platform_ops_t* self,
                                const pn_poll_set_t*            poll_set,
                                size_t                          index,
                                pn_socket_t*                    out_sock,
                                uint8_t*                        out_events)
{
    (void)self;

    const struct pn_posix_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    size_t  ready_idx = 0;
    uint8_t events    = 0;
    short   revents   = 0;

    if (index >= internal->ready_count) {
        return -EINVAL;
    }

    ready_idx = internal->ready_indices[index];
    revents   = internal->fds[ready_idx].revents;

    if (0 != (revents & POLLIN)) {
        events |= PN_POLL_READ;
    }
    if (0 != (revents & POLLOUT)) {
        events |= PN_POLL_WRITE;
    }
    if (0 != (revents & POLLERR)) {
        events |= PN_POLL_ERROR;
    }
    if (0 != (revents & POLLHUP)) {
        events |= PN_POLL_HUP;
    }

    *out_sock   = internal->handles[ready_idx];
    *out_events = events;

    return 0;
}

#if PUBNUB_ENABLE_CUSTOM_DNS

/**
 * @brief Discover DNS nameservers from system configuration.
 *
 * Queries system resolver configuration (via res_ninit on macOS,
 * PUBNUB_CFG_RESOLV_CONF_PATH on Linux/BSD) and populates the
 * servers array.
 *
 * @param self Platform ops instance (unused).
 * @param servers Array to populate with nameserver addresses.
 * @param capacity Maximum number of servers to store.
 * @param out_count On success, set to number of servers discovered.
 * @return 0 on success, negative errno on failure.
 *
 * @note Stack usage: ~420 bytes (Linux path). Ensure sufficient stack
 *       headroom on deeply-nested or constrained-stack targets.
 */
static int posix_dns_discover_servers(const pn_socket_platform_ops_t* self,
                                      pn_sockaddr_t*                  servers,
                                      size_t                          capacity,
                                      size_t*                         out_count)
{
    (void)self;

    size_t count = 0;

#ifdef __APPLE__
    struct __res_state res;
    memset(&res, 0, sizeof(res));

    if (0 != res_ninit(&res)) {
        return -errno;
    }

    /* res_getservers() returns both IPv4 and IPv6 nameservers, including
     * IPv6 entries that nsaddr_list[] (struct sockaddr_in only) omits. */
    union res_sockaddr_union ns_union[MAXNS];
    int                      ns_count = res_getservers(&res, ns_union, MAXNS);

    for (int i = 0; i < ns_count && count < capacity; ++i) {
        if (AF_INET == ns_union[i].sin.sin_family) {
            servers[count].family = PN_AF_INET;
            servers[count].port   = ntohs(ns_union[i].sin.sin_port);
            if (0 == servers[count].port) {
                servers[count].port = 53;
            }
            memcpy(servers[count].addr.ipv4, &ns_union[i].sin.sin_addr.s_addr, 4);
            count++;
        } else if (AF_INET6 == ns_union[i].sin6.sin6_family) {
            servers[count].family = PN_AF_INET6;
            servers[count].port   = ntohs(ns_union[i].sin6.sin6_port);
            if (0 == servers[count].port) {
                servers[count].port = 53;
            }
            memcpy(servers[count].addr.ipv6, &ns_union[i].sin6.sin6_addr, 16);
            count++;
        }
    }

    res_ndestroy(&res);

#else
    FILE* resolv = fopen(PUBNUB_CFG_RESOLV_CONF_PATH, "r");
    if (NULL == resolv) {
        return -errno;
    }

    char            line[256];
    struct in_addr  ipv4_addr;
    struct in6_addr ipv6_addr;

    while (NULL != fgets(line, sizeof(line), resolv) && count < capacity) {
        char ns_str[128];
        if (1 == sscanf(line, "nameserver %127s", ns_str)) {
            if (1 == inet_pton(AF_INET, ns_str, &ipv4_addr)) {
                servers[count].family = PN_AF_INET;
                servers[count].port   = 53;
                memcpy(servers[count].addr.ipv4, &ipv4_addr.s_addr, 4);
                count++;
            } else if (1 == inet_pton(AF_INET6, ns_str, &ipv6_addr)) {
                servers[count].family = PN_AF_INET6;
                servers[count].port   = 53;
                memcpy(servers[count].addr.ipv6, &ipv6_addr.s6_addr, 16);
                count++;
            }
        }
    }

    (void)fclose(resolv);
#endif

    *out_count = count;
    return 0;
}

#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

#if !PUBNUB_ENABLE_CUSTOM_DNS && defined(__APPLE__)

typedef struct pn_macos_dns_state {
    pn_sockaddr_t addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    size_t        count;
    uint8_t       v4_count;
    uint8_t       complete;
    uint8_t       error;
    DNSServiceRef service_ref;
} pn_macos_dns_state_t;

#include "pubnub/pubnub_compat.h"
PUBNUB_STATIC_ASSERT(
    sizeof(pn_macos_dns_state_t) <= PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE,
    "macOS DNS state exceeds PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE");

static void macos_dns_callback(DNSServiceRef          sdRef,
                               DNSServiceFlags        flags,
                               uint32_t               interfaceIndex,
                               DNSServiceErrorType    errorCode,
                               const char*            hostname,
                               const struct sockaddr* address,
                               uint32_t               ttl,
                               void*                  context)
{
    pn_macos_dns_state_t* st = (pn_macos_dns_state_t*)context;

    (void)sdRef;
    (void)interfaceIndex;
    (void)hostname;
    (void)ttl;

    if (kDNSServiceErr_NoError != errorCode) {
        if (!(flags & kDNSServiceFlagsMoreComing)) {
            st->error    = (0 == st->count) ? 1 : 0;
            st->complete = 1;
        }
        return;
    }

    if (st->count >= PUBNUB_CFG_MAX_DNS_RESULTS) {
        goto check_done;
    }

    if (AF_INET == address->sa_family) {
        struct sockaddr_in* sin     = (struct sockaddr_in*)address;
        st->addrs[st->count].family = PN_AF_INET;
        memcpy(st->addrs[st->count].addr.ipv4, &sin->sin_addr.s_addr, 4);
        ++st->v4_count;
        ++st->count;
    } else if (PUBNUB_ENABLE_IPV6 && AF_INET6 == address->sa_family) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)address;
        /* Cap IPv6 at half the buffer to guarantee IPv4 room. */
        if ((st->count - st->v4_count) >= PUBNUB_CFG_MAX_DNS_RESULTS / 2U) {
            goto check_done;
        }
        st->addrs[st->count].family = PN_AF_INET6;
        memcpy(st->addrs[st->count].addr.ipv6, sin6->sin6_addr.s6_addr, 16);
        ++st->count;
    }

check_done:
    if (!(flags & kDNSServiceFlagsMoreComing)) {
        pn_sort_addrs_ipv4_first(st->addrs, st->count);
        st->error    = (0 == st->count) ? 1 : 0;
        st->complete = 1;
    }
}

static size_t macos_dns_state_size(const pn_socket_platform_ops_t* self)
{
    (void)self;
    return sizeof(pn_macos_dns_state_t);
}

static int macos_dns_resolve_start(const pn_socket_platform_ops_t* self,
                                   void*                           dns_ctx,
                                   const char*                     hostname,
                                   uint32_t                        timeout_ms)
{
    (void)self;
    (void)timeout_ms;

    pn_macos_dns_state_t* st = (pn_macos_dns_state_t*)dns_ctx;

    if (NULL != st->service_ref) {
        DNSServiceRefDeallocate(st->service_ref);
    }

    st->count       = 0;
    st->v4_count    = 0;
    st->complete    = 0;
    st->error       = 0;
    st->service_ref = NULL;

    DNSServiceProtocol protocol = kDNSServiceProtocol_IPv4;
    if (PUBNUB_ENABLE_IPV6) {
        protocol |= kDNSServiceProtocol_IPv6;
    }

    DNSServiceErrorType err = DNSServiceGetAddrInfo(&st->service_ref,
                                                    0,
                                                    kDNSServiceInterfaceIndexAny,
                                                    protocol,
                                                    hostname,
                                                    macos_dns_callback,
                                                    st);

    if (kDNSServiceErr_NoError != err || NULL == st->service_ref) {
        st->error    = 1;
        st->complete = 1;
        return 0;
    }

    return 0;
}

static int macos_dns_resolve_poll(const pn_socket_platform_ops_t* self, void* dns_ctx)
{
    (void)self;

    pn_macos_dns_state_t* st = (pn_macos_dns_state_t*)dns_ctx;

    if (st->complete) {
        if (NULL != st->service_ref) {
            DNSServiceRefDeallocate(st->service_ref);
            st->service_ref = NULL;
        }
        return st->error ? -1 : 1;
    }

    if (NULL == st->service_ref) {
        return -1;
    }

    int dns_fd = DNSServiceRefSockFD(st->service_ref);
    if (dns_fd < 0) {
        st->error    = 1;
        st->complete = 1;
        return -1;
    }

    struct pollfd pfd = {.fd = dns_fd, .events = POLLIN, .revents = 0};
    int           sel = poll(&pfd, 1, 0);
    if (sel > 0 && (pfd.revents & POLLIN)) {
        DNSServiceProcessResult(st->service_ref);
    }

    if (st->complete) {
        DNSServiceRefDeallocate(st->service_ref);
        st->service_ref = NULL;
        return st->error ? -1 : 1;
    }

    return 0;
}

static int macos_dns_resolve_get_results(const pn_socket_platform_ops_t* self,
                                         void*          dns_ctx,
                                         pn_sockaddr_t* addrs,
                                         size_t         max_addrs,
                                         size_t*        out_count)
{
    (void)self;

    pn_macos_dns_state_t* st = (pn_macos_dns_state_t*)dns_ctx;

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

static void macos_dns_resolve_cancel(const pn_socket_platform_ops_t* self,
                                     void*                           dns_ctx)
{
    (void)self;

    pn_macos_dns_state_t* st = (pn_macos_dns_state_t*)dns_ctx;

    if (NULL != st->service_ref) {
        DNSServiceRefDeallocate(st->service_ref);
        st->service_ref = NULL;
    }
}

#endif /* !PUBNUB_ENABLE_CUSTOM_DNS && __APPLE__ */

#if !PUBNUB_ENABLE_CUSTOM_DNS && !defined(__APPLE__)

typedef struct pn_posix_dns_state {
    pn_sockaddr_t addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    size_t        count;
    uint8_t       complete;
    uint8_t       error;
} pn_posix_dns_state_t;

#include "pubnub/pubnub_compat.h"
PUBNUB_STATIC_ASSERT(
    sizeof(pn_posix_dns_state_t) <= PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE,
    "POSIX DNS state exceeds PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE");

static size_t posix_dns_state_size(const pn_socket_platform_ops_t* self)
{
    (void)self;
    return sizeof(pn_posix_dns_state_t);
}

static int posix_dns_resolve_start(const pn_socket_platform_ops_t* self,
                                   void*                           dns_ctx,
                                   const char*                     hostname,
                                   uint32_t                        timeout_ms)
{
    (void)self;
    (void)timeout_ms;

    pn_posix_dns_state_t* st = (pn_posix_dns_state_t*)dns_ctx;

    st->count    = 0;
    st->complete = 0;
    st->error    = 0;

    struct addrinfo  hints  = {0};
    struct addrinfo* result = NULL;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_ADDRCONFIG;

    int rc = getaddrinfo(hostname, NULL, &hints, &result);
    if (0 != rc || NULL == result) {
        st->error    = 1;
        st->complete = 1;
        return 0;
    }

    /* Two-pass: IPv4 first, then IPv6 in remaining slots.
     * getaddrinfo with AF_UNSPEC may return IPv6 before IPv4 (RFC 6724
     * preference ordering on dual-stack hosts). Filling the fixed-size
     * buffer in that order would exhaust all slots with IPv6 and never
     * store IPv4 addresses. This matters on hosts where IPv6 is configured
     * on the interface but not routed to the remote endpoint. */
    size_t count = 0;
    for (struct addrinfo* rp = result;
         NULL != rp && count < PUBNUB_CFG_MAX_DNS_RESULTS;
         rp = rp->ai_next) {
        if (AF_INET == rp->ai_family) {
            struct sockaddr_in* sin = (struct sockaddr_in*)rp->ai_addr;
            st->addrs[count].family = PN_AF_INET;
            memcpy(st->addrs[count].addr.ipv4, &sin->sin_addr.s_addr, 4);
            ++count;
        }
    }
    if (PUBNUB_ENABLE_IPV6) {
        for (struct addrinfo* rp = result;
             NULL != rp && count < PUBNUB_CFG_MAX_DNS_RESULTS;
             rp = rp->ai_next) {
            if (AF_INET6 == rp->ai_family) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)rp->ai_addr;
                st->addrs[count].family   = PN_AF_INET6;
                memcpy(st->addrs[count].addr.ipv6, sin6->sin6_addr.s6_addr, 16);
                ++count;
            }
        }
    }

    freeaddrinfo(result);

    st->count    = count;
    st->complete = 1;
    st->error    = (0 == count) ? 1 : 0;

    return 0;
}

static int posix_dns_resolve_poll(const pn_socket_platform_ops_t* self, void* dns_ctx)
{
    (void)self;

    pn_posix_dns_state_t* st = (pn_posix_dns_state_t*)dns_ctx;

    if (!st->complete) {
        return 0;
    }
    return st->error ? -1 : 1;
}

static int posix_dns_resolve_get_results(const pn_socket_platform_ops_t* self,
                                         void*          dns_ctx,
                                         pn_sockaddr_t* addrs,
                                         size_t         max_addrs,
                                         size_t*        out_count)
{
    (void)self;

    pn_posix_dns_state_t* st = (pn_posix_dns_state_t*)dns_ctx;

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

#endif /* !PUBNUB_ENABLE_CUSTOM_DNS && !__APPLE__ */

/** @brief Create a non-blocking pipe pair for the self-pipe wake trick. */
static int posix_pipe_create(const pn_socket_platform_ops_t* self,
                             pn_socket_t                     out[2])
{
    int fds[2];
    int flags;
    (void)self;

    out[0] = PN_INVALID_SOCKET;
    out[1] = PN_INVALID_SOCKET;

    if (0 != pipe(fds)) {
        return -1;
    }

    /* Set both ends non-blocking. Check F_GETFL separately to avoid
     * OR-ing -1 into flags on error (corrupts O_NONBLOCK bitmask). */
    flags = fcntl(fds[0], F_GETFL, 0);
    if (0 > flags || -1 == fcntl(fds[0], F_SETFL, flags | O_NONBLOCK)) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    flags = fcntl(fds[1], F_GETFL, 0);
    if (0 > flags || -1 == fcntl(fds[1], F_SETFL, flags | O_NONBLOCK)) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    out[0] = fds[0];
    out[1] = fds[1];
    return 0;
}

/** @brief Write a single wake byte to a POSIX pipe(2) write end. */
static void posix_pipe_write(const pn_socket_platform_ops_t* self, pn_socket_t wr)
{
    const uint8_t b = 0;
    (void)self;
    ssize_t n = write((int)wr, &b, 1);
    (void)n;
}

/** @brief Drain all pending bytes from a POSIX pipe(2) read end. */
static void posix_pipe_drain(const pn_socket_platform_ops_t* self, pn_socket_t rd)
{
    uint8_t buf[64];
    (void)self;
    while (0 < read((int)rd, buf, sizeof(buf))) {
        /* keep draining */
    }
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_socket_platform_ops_t pn_posix_socket_ops = {
    .socket_create          = posix_socket_create,
    .socket_destroy         = posix_socket_destroy,
    .socket_connect         = posix_socket_connect,
    .socket_check_connect   = posix_socket_check_connect,
    .socket_send            = posix_socket_send,
    .socket_recv            = posix_socket_recv,
    .socket_sendto          = posix_socket_sendto,
    .socket_recvfrom        = posix_socket_recvfrom,
    .socket_set_nonblocking = posix_socket_set_nonblocking,
    .socket_set_keepalive   = posix_socket_set_keepalive,
    .poll_init              = posix_poll_init,
    .poll_deinit            = posix_poll_deinit,
    .poll_add               = posix_poll_add,
    .poll_modify            = posix_poll_modify,
    .poll_remove            = posix_poll_remove,
    .poll_wait              = posix_poll_wait,
    .poll_ready_count       = posix_poll_ready_count,
    .poll_get_ready         = posix_poll_get_ready,
#if PUBNUB_ENABLE_CUSTOM_DNS
    .dns_discover_servers    = posix_dns_discover_servers,
    .dns_state_size          = NULL,
    .dns_state_init          = NULL,
    .dns_resolve_start       = NULL,
    .dns_resolve_poll        = NULL,
    .dns_resolve_get_results = NULL,
    .dns_resolve_cancel      = NULL,
#elif defined(__APPLE__)
    .dns_discover_servers    = NULL,
    .dns_state_size          = macos_dns_state_size,
    .dns_state_init          = NULL,
    .dns_resolve_start       = macos_dns_resolve_start,
    .dns_resolve_poll        = macos_dns_resolve_poll,
    .dns_resolve_get_results = macos_dns_resolve_get_results,
    .dns_resolve_cancel      = macos_dns_resolve_cancel,
#else
    .dns_discover_servers    = NULL,
    .dns_state_size          = posix_dns_state_size,
    .dns_state_init          = NULL,
    .dns_resolve_start       = posix_dns_resolve_start,
    .dns_resolve_poll        = posix_dns_resolve_poll,
    .dns_resolve_get_results = posix_dns_resolve_get_results,
    .dns_resolve_cancel      = NULL,
#endif
    .pipe_create = posix_pipe_create,
    .pipe_write  = posix_pipe_write,
    .pipe_drain  = posix_pipe_drain,
};

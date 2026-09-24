/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#if defined(PUBNUB_PLATFORM_FREERTOS) || defined(ESP_PLATFORM) \
    || defined(LWIP_SOCKET)

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include "pubnub/pubnub_compat.h"

#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include <errno.h>
#include <string.h>

/**
 * @file freertos_socket_ops.c
 * @brief FreeRTOS/lwIP socket operations implementation for ESP32 and
 * FreeRTOS-based targets.
 *
 * Implements the pn_socket_platform_ops_t vtable using lwIP socket APIs.
 * Uses select() for multiplexing (safe on lwIP, as fd space is small and
 * sequential starting from LWIP_SOCKET_OFFSET). Handles platform differences
 * in TCP keepalive (conditional on LWIP_TCP_KEEPALIVE) and DNS discovery
 * (via dns_getserver() API).
 */

/**
 * @brief Internal poll set state for lwIP/select.
 *
 * Stores socket handles, monitored events, result mask, and ready-socket
 * indices computed during poll_wait. Uses select() with fd_set bitmaps.
 */
struct pn_lwip_poll_internal {
    pn_socket_t handles[PN_SOCKET_TRANSPORT_MAX_FDS];
    uint8_t     event_mask[PN_SOCKET_TRANSPORT_MAX_FDS];
    uint8_t     result_mask[PN_SOCKET_TRANSPORT_MAX_FDS];
    size_t      count;
    size_t      ready_count;
    size_t      ready_indices[PN_SOCKET_TRANSPORT_MAX_FDS];
};

PUBNUB_STATIC_ASSERT(sizeof(struct pn_lwip_poll_internal) <= PN_POLL_SET_PLATFORM_SIZE,
                     "pn_lwip_poll_internal exceeds PN_POLL_SET_PLATFORM_SIZE");

/** @brief Cast opaque poll_set to internal struct. */
static inline struct pn_lwip_poll_internal* pn_poll_set_internal(pn_poll_set_t* poll_set)
{
    return (struct pn_lwip_poll_internal*)poll_set->platform_data;
}

/** @brief Cast const opaque poll_set to internal struct. */
static inline const struct pn_lwip_poll_internal*
pn_poll_set_internal_const(const pn_poll_set_t* poll_set)
{
    return (const struct pn_lwip_poll_internal*)poll_set->platform_data;
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
 * @brief Create a new socket.
 */
static pn_socket_t freertos_socket_create(const pn_socket_platform_ops_t* self,
                                          uint16_t family,
                                          int      dgram)
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
    const int fd   = lwip_socket(domain, type, 0);
    if (0 > fd) {
        return PN_INVALID_SOCKET;
    }

#ifdef PN_DEBUG_SOCKET_OPS
    printf("[DBG socket-open] fd=%d\n", (int)fd);
#endif

    return (pn_socket_t)fd;
}

/**
 * @brief Destroy a socket.
 */
static void freertos_socket_destroy(const pn_socket_platform_ops_t* self,
                                    pn_socket_t                     sock)
{
    (void)self;

    if (PN_INVALID_SOCKET == sock) {
        return;
    }

#ifdef PN_DEBUG_SOCKET_OPS
    printf("[DBG socket-close] fd=%d\n", (int)sock);
#endif
    lwip_close((int)sock);
}

/**
 * @brief Initiate a non-blocking connect.
 */
static int freertos_socket_connect(const pn_socket_platform_ops_t* self,
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

    connect_ret = lwip_connect(fd, sa_ptr, sa_len);

    if (0 == connect_ret) {
        return 1;
    }

    if (EINPROGRESS == errno || EAGAIN == errno) {
        return 0;
    }

    return -errno;
}

/**
 * @brief Check if a non-blocking connect completed.
 */
static int freertos_socket_check_connect(const pn_socket_platform_ops_t* self,
                                         pn_socket_t                     sock)
{
    (void)self;

    const int fd      = (int)sock;
    int       err     = 0;
    socklen_t len     = sizeof(err);
    const int gso_ret = lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

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

/**
 * @brief Send data on a connected socket (non-blocking).
 */
static int freertos_socket_send(const pn_socket_platform_ops_t* self,
                                pn_socket_t                     sock,
                                const uint8_t*                  data,
                                size_t                          len)
{
    (void)self;

    const int     fd      = (int)sock;
    const ssize_t sent_sz = lwip_send(fd, data, len, 0);

    if (0 <= sent_sz) {
        return (int)sent_sz;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINPROGRESS == errno) {
        return 0;
    }

    return -errno;
}

/**
 * @brief Receive data from a connected socket (non-blocking).
 */
static int freertos_socket_recv(const pn_socket_platform_ops_t* self,
                                pn_socket_t                     sock,
                                uint8_t*                        buf,
                                size_t                          len)
{
    (void)self;

    const int     fd       = (int)sock;
    const ssize_t recv_ret = lwip_recv(fd, buf, len, 0);

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

/**
 * @brief Send data to a specific address (connectionless, non-blocking).
 */
static int freertos_socket_sendto(const pn_socket_platform_ops_t* self,
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

    const ssize_t sendto_ret = lwip_sendto(fd, data, len, 0, sa_ptr, sa_len);

    if (0 <= sendto_ret) {
        return (int)sendto_ret;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno) {
        return 0;
    }

    return -errno;
}

/**
 * @brief Receive data with source address (connectionless, non-blocking).
 */
static int freertos_socket_recvfrom(const pn_socket_platform_ops_t* self,
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

    const ssize_t recv_ret = lwip_recvfrom(fd, buf, len, 0, sa_ptr, &sa_len);

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

/**
 * @brief Set socket to non-blocking mode.
 */
static int freertos_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                           pn_socket_t                     sock)
{
    (void)self;

    const int fd      = (int)sock;
    int       on      = 1;
    const int iol_ret = lwip_ioctl(fd, FIONBIO, &on);

    if (0 > iol_ret) {
        return -errno;
    }

    return 0;
}

/**
 * @brief Configure TCP keepalive on a socket.
 */
static int freertos_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                         pn_socket_t                     sock,
                                         const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;

    const int fd      = (int)sock;
    int       opt_val = 0;
    int       sso_ret = 0;

    if (0 == config->enabled) {
        opt_val = 0;
        sso_ret = lwip_setsockopt(
            fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
        if (0 > sso_ret) {
            return -errno;
        }
        return 0;
    }

    opt_val = 1;
    sso_ret =
        lwip_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

#if defined(LWIP_TCP_KEEPALIVE) && LWIP_TCP_KEEPALIVE
    opt_val = (int)config->idle_sec;
    sso_ret =
        lwip_setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

    opt_val = (int)config->interval_sec;
    sso_ret =
        lwip_setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

    opt_val = (int)config->probe_count;
    sso_ret =
        lwip_setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }
#endif

    return 0;
}

/**
 * @brief Initialize a poll set.
 */
static int freertos_poll_init(const pn_socket_platform_ops_t* self,
                              pn_poll_set_t*                  poll_set)
{
    (void)self;

    struct pn_lwip_poll_internal* internal = pn_poll_set_internal(poll_set);
    memset(internal, 0, sizeof(*internal));
    return 0;
}

/**
 * @brief Deinitialize a poll set.
 */
static void freertos_poll_deinit(const pn_socket_platform_ops_t* self,
                                 pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
}

/**
 * @brief Add a socket to the poll set.
 */
static int freertos_poll_add(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set,
                             pn_socket_t                     sock,
                             uint8_t                         events)
{
    (void)self;

    struct pn_lwip_poll_internal* internal = pn_poll_set_internal(poll_set);

    if (internal->count >= PN_SOCKET_TRANSPORT_MAX_FDS) {
        return -ENOMEM;
    }

    internal->handles[internal->count]    = sock;
    internal->event_mask[internal->count] = events;
    internal->count++;

    return 0;
}

/**
 * @brief Modify the monitored events for a socket in the poll set.
 */
static int freertos_poll_modify(const pn_socket_platform_ops_t* self,
                                pn_poll_set_t*                  poll_set,
                                pn_socket_t                     sock,
                                uint8_t                         events)
{
    (void)self;

    struct pn_lwip_poll_internal* internal = pn_poll_set_internal(poll_set);
    size_t                        i        = 0;

    for (i = 0; i < internal->count; ++i) {
        if (internal->handles[i] == sock) {
            break;
        }
    }

    if (i >= internal->count) {
        return -EINVAL;
    }

    internal->event_mask[i] = events;

    return 0;
}

/**
 * @brief Remove a socket from the poll set.
 */
static int freertos_poll_remove(const pn_socket_platform_ops_t* self,
                                pn_poll_set_t*                  poll_set,
                                pn_socket_t                     sock)
{
    (void)self;

    struct pn_lwip_poll_internal* internal = pn_poll_set_internal(poll_set);
    size_t                        i        = 0;

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
        internal->handles[i]    = internal->handles[last_idx];
        internal->event_mask[i] = internal->event_mask[last_idx];
    }

    internal->count--;
    return 0;
}

/**
 * @brief Wait for I/O events on sockets in the poll set.
 *
 * Uses select() to wait for readiness. Safe on lwIP as fd space is small.
 * timeout_ms=0 returns immediately (poll), timeout_ms=-1 blocks indefinitely.
 */
static int freertos_poll_wait(const pn_socket_platform_ops_t* self,
                              pn_poll_set_t*                  poll_set,
                              int                             timeout_ms)
{
    (void)self;

    struct pn_lwip_poll_internal* internal = pn_poll_set_internal(poll_set);
    fd_set                        readfds;
    fd_set                        writefds;
    fd_set                        exceptfds;
    int                           max_fd = -1;
    struct timeval                tv;
    struct timeval*               tv_ptr     = NULL;
    size_t                        i          = 0;
    int                           select_ret = 0;

    /* Empty poll set: sleep for the requested timeout. When timeout_ms
     * is 0 or negative (infinite), return immediately — blocking forever
     * with nothing to poll would deadlock the bg thread. */
    if (0 == internal->count) {
        if (0 < timeout_ms) {
            vTaskDelay(pdMS_TO_TICKS((TickType_t)timeout_ms));
        }
        internal->ready_count = 0;
        return 0;
    }

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);

    for (i = 0; i < internal->count; ++i) {
        const int     fd     = (int)internal->handles[i];
        const uint8_t events = internal->event_mask[i];

        if (0 != (events & PN_POLL_READ)) {
            FD_SET(fd, &readfds);
        }
        if (0 != (events & PN_POLL_WRITE)) {
            FD_SET(fd, &writefds);
        }
        if (0 != (events & PN_POLL_ERROR)) {
            FD_SET(fd, &exceptfds);
        }

        if (fd > max_fd) {
            max_fd = fd;
        }
    }

    if (-1 != timeout_ms) {
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tv_ptr     = &tv;
    }

    /* lwIP socket fds are allocated from a fixed pool bounded by
     * MEMP_NUM_NETCONN, starting at LWIP_SOCKET_OFFSET (typically 0
     * but configurable). The highest fd value is therefore
     * LWIP_SOCKET_OFFSET + count - 1. Verify that the offset plus
     * our in-flight count fits within FD_SETSIZE so FD_SET never
     * writes out of bounds. */
#ifndef LWIP_SOCKET_OFFSET
#define LWIP_SOCKET_OFFSET 0
#endif
    PUBNUB_STATIC_ASSERT(LWIP_SOCKET_OFFSET + PN_SOCKET_TRANSPORT_MAX_FDS <= FD_SETSIZE,
                         "lwIP socket offset + in-flight request count exceeds "
                         "FD_SETSIZE — increase FD_SETSIZE, reduce "
                         "LWIP_SOCKET_OFFSET, or reduce "
                         "PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS");

    select_ret = lwip_select(max_fd + 1, &readfds, &writefds, &exceptfds, tv_ptr);

    if (0 > select_ret) {
        return -errno;
    }

    internal->ready_count = 0;
    for (i = 0; i < internal->count; ++i) {
        const int fd            = (int)internal->handles[i];
        uint8_t   result_events = 0;

        if (FD_ISSET(fd, &readfds)) {
            result_events |= PN_POLL_READ;
        }
        if (FD_ISSET(fd, &writefds)) {
            result_events |= PN_POLL_WRITE;
        }
        if (FD_ISSET(fd, &exceptfds)) {
            result_events |= PN_POLL_ERROR;
        }

        if (0 != result_events) {
            internal->result_mask[i]                         = result_events;
            internal->ready_indices[internal->ready_count++] = i;
        }
    }

    return 0;
}

/**
 * @brief Get the number of ready sockets after poll_wait.
 */
static size_t freertos_poll_ready_count(const pn_socket_platform_ops_t* self,
                                        const pn_poll_set_t* poll_set)
{
    (void)self;

    const struct pn_lwip_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    return internal->ready_count;
}

/**
 * @brief Retrieve the ready socket and events at the given index.
 */
static int freertos_poll_get_ready(const pn_socket_platform_ops_t* self,
                                   const pn_poll_set_t*            poll_set,
                                   size_t                          index,
                                   pn_socket_t*                    out_sock,
                                   uint8_t*                        out_events)
{
    (void)self;

    const struct pn_lwip_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    size_t ready_idx = 0;

    if (index >= internal->ready_count) {
        return -EINVAL;
    }

    ready_idx = internal->ready_indices[index];

    *out_sock   = internal->handles[ready_idx];
    *out_events = internal->result_mask[ready_idx];

    return 0;
}

#if PUBNUB_ENABLE_CUSTOM_DNS || !defined(LWIP_DNS) || !LWIP_DNS

/**
 * @brief Discover DNS server addresses from lwIP configuration.
 *
 * Queries lwIP's DNS configuration via dns_getserver() and populates the
 * servers array with up to capacity addresses.
 *
 * @param self Platform ops instance (unused).
 * @param servers Array to populate with nameserver addresses.
 * @param capacity Maximum number of servers to store.
 * @param out_count On success, set to number of servers discovered.
 * @return 0 on success, negative errno on failure.
 */
static int freertos_dns_discover_servers(const pn_socket_platform_ops_t* self,
                                         pn_sockaddr_t* servers,
                                         size_t         capacity,
                                         size_t*        out_count)
{
    (void)self;

    size_t count = 0;

#if LWIP_DNS
    for (uint8_t i = 0; i < DNS_MAX_SERVERS && count < capacity; ++i) {
        const ip_addr_t* dns_server = dns_getserver(i);

        if (NULL == dns_server || ip_addr_isany(dns_server)) {
            break;
        }

#if LWIP_IPV4 && LWIP_IPV6
        if (IP_IS_V4(dns_server)) {
            servers[count].family = PN_AF_INET;
            servers[count].port   = 53;
            memcpy(servers[count].addr.ipv4, &dns_server->u_addr.ip4.addr, 4);
            count++;
        } else if (IP_IS_V6(dns_server)) {
            servers[count].family = PN_AF_INET6;
            servers[count].port   = 53;
            memcpy(servers[count].addr.ipv6, dns_server->u_addr.ip6.addr, 16);
            count++;
        }
#elif LWIP_IPV4
        servers[count].family = PN_AF_INET;
        servers[count].port   = 53;
        memcpy(servers[count].addr.ipv4, &dns_server->addr, 4);
        count++;
#elif LWIP_IPV6
        servers[count].family = PN_AF_INET6;
        servers[count].port   = 53;
        memcpy(servers[count].addr.ipv6, dns_server->addr, 16);
        count++;
#endif
    }
#endif

    *out_count = count;
    return 0;
}

#endif /* PUBNUB_ENABLE_CUSTOM_DNS || !LWIP_DNS */

#if !PUBNUB_ENABLE_CUSTOM_DNS && defined(LWIP_DNS) && LWIP_DNS
#define PN_FREERTOS_HAS_NATIVE_DNS 1

typedef struct pn_freertos_dns_state {
    pn_sockaddr_t addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    size_t        count;
    uint8_t       complete;
    uint8_t       error;
} pn_freertos_dns_state_t;

PUBNUB_STATIC_ASSERT(
    sizeof(pn_freertos_dns_state_t) <= PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE,
    "FreeRTOS DNS state exceeds PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE");

static size_t freertos_dns_state_size(const pn_socket_platform_ops_t* self)
{
    (void)self;
    return sizeof(pn_freertos_dns_state_t);
}

static int freertos_dns_resolve_start(const pn_socket_platform_ops_t* self,
                                      void*                           dns_ctx,
                                      const char*                     hostname,
                                      uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;

    pn_freertos_dns_state_t* st = (pn_freertos_dns_state_t*)dns_ctx;

    st->count    = 0;
    st->complete = 0;
    st->error    = 0;

    struct addrinfo  hints  = {0};
    struct addrinfo* result = NULL;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* lwip_getaddrinfo blocks the calling task until resolution completes
     * or times out. For cooperative event-loop targets where blocking is
     * unacceptable, set PUBNUB_ENABLE_CUSTOM_DNS=ON to use the non-blocking
     * UDP resolver. When lwIP DNS cache is warm (MEMP_NUM_DNS_TABLE > 0),
     * this call typically returns without network I/O. */
    int rc = lwip_getaddrinfo(hostname, NULL, &hints, &result);
    if (0 != rc || NULL == result) {
        st->error    = 1;
        st->complete = 1;
        return 0;
    }

    /* Two-pass: IPv4 first, then IPv6 in remaining slots.
     * lwip_getaddrinfo may return IPv6 before IPv4 depending on lwIP
     * configuration and DNS response order. */
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

    lwip_freeaddrinfo(result);

    st->count    = count;
    st->complete = 1;
    st->error    = (0 == count) ? 1 : 0;

    return 0;
}

static int freertos_dns_resolve_poll(const pn_socket_platform_ops_t* self,
                                     void*                           dns_ctx)
{
    (void)self;

    pn_freertos_dns_state_t* st = (pn_freertos_dns_state_t*)dns_ctx;

    if (!st->complete) {
        return 0;
    }
    return st->error ? -1 : 1;
}

static int freertos_dns_resolve_get_results(const pn_socket_platform_ops_t* self,
                                            void*          dns_ctx,
                                            pn_sockaddr_t* addrs,
                                            size_t         max_addrs,
                                            size_t*        out_count)
{
    (void)self;

    pn_freertos_dns_state_t* st = (pn_freertos_dns_state_t*)dns_ctx;

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

#else
#define PN_FREERTOS_HAS_NATIVE_DNS 0
#endif /* !PUBNUB_ENABLE_CUSTOM_DNS && LWIP_DNS */

#if !PUBNUB_ENABLE_CUSTOM_DNS && !PN_FREERTOS_HAS_NATIVE_DNS
#pragma message("PUBNUB_ENABLE_CUSTOM_DNS=OFF but lwIP DNS unavailable. " \
                "The DNS resolver will use UDP queries but wastes "       \
                "PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE bytes. "              \
                "Set PUBNUB_ENABLE_CUSTOM_DNS=ON to eliminate the unused buffer.")
#endif

// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_socket_platform_ops_t pn_freertos_socket_ops = {
    .socket_create          = freertos_socket_create,
    .socket_destroy         = freertos_socket_destroy,
    .socket_connect         = freertos_socket_connect,
    .socket_check_connect   = freertos_socket_check_connect,
    .socket_send            = freertos_socket_send,
    .socket_recv            = freertos_socket_recv,
    .socket_sendto          = freertos_socket_sendto,
    .socket_recvfrom        = freertos_socket_recvfrom,
    .socket_set_nonblocking = freertos_socket_set_nonblocking,
    .socket_set_keepalive   = freertos_socket_set_keepalive,
    .poll_init              = freertos_poll_init,
    .poll_deinit            = freertos_poll_deinit,
    .poll_add               = freertos_poll_add,
    .poll_modify            = freertos_poll_modify,
    .poll_remove            = freertos_poll_remove,
    .poll_wait              = freertos_poll_wait,
    .poll_ready_count       = freertos_poll_ready_count,
    .poll_get_ready         = freertos_poll_get_ready,
#if PN_FREERTOS_HAS_NATIVE_DNS
    .dns_discover_servers    = NULL,
    .dns_state_size          = freertos_dns_state_size,
    .dns_state_init          = NULL,
    .dns_resolve_start       = freertos_dns_resolve_start,
    .dns_resolve_poll        = freertos_dns_resolve_poll,
    .dns_resolve_get_results = freertos_dns_resolve_get_results,
    .dns_resolve_cancel      = NULL,
#else
    .dns_discover_servers    = freertos_dns_discover_servers,
    .dns_state_size          = NULL,
    .dns_state_init          = NULL,
    .dns_resolve_start       = NULL,
    .dns_resolve_poll        = NULL,
    .dns_resolve_get_results = NULL,
    .dns_resolve_cancel      = NULL,
#endif
    .pipe_create = NULL, /* 100ms fallback — lwIP lacks reliable loopback pipe. */
    .pipe_write = NULL,
    .pipe_drain = NULL,
};

#endif /* PUBNUB_PLATFORM_FREERTOS || ESP_PLATFORM || LWIP_SOCKET */

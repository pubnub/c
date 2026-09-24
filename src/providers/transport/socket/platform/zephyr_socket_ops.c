/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#if defined(__ZEPHYR__)

#include "pn_socket_platform_ops.h"
#include "pn_socket_types.h"

#include "pubnub/pubnub_compat.h"

#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/socket.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

/**
 * @file zephyr_socket_ops.c
 * @brief Zephyr RTOS socket operations implementation.
 *
 * Implements the pn_socket_platform_ops_t vtable using Zephyr's native zsock_*
 * APIs. Does NOT rely on CONFIG_NET_SOCKETS_POSIX_NAMES. Uses zsock_poll() with
 * struct zsock_pollfd for I/O multiplexing. DNS server discovery queries the
 * Zephyr DNS resolver context; applications configure DNS servers via prj.conf
 * CONFIG_DNS_SERVER_IP_ADDRESSES.
 */

/**
 * @brief Internal poll set state for Zephyr.
 *
 * Stores zsock_pollfd array, socket handles for correlation, and ready-socket
 * indices computed during poll_wait.
 */
struct pn_zsock_poll_internal {
    struct zsock_pollfd fds[PN_SOCKET_TRANSPORT_MAX_FDS];
    pn_socket_t         handles[PN_SOCKET_TRANSPORT_MAX_FDS];
    size_t              count;
    size_t              ready_count;
    size_t              ready_indices[PN_SOCKET_TRANSPORT_MAX_FDS];
};

PUBNUB_STATIC_ASSERT(
    sizeof(struct pn_zsock_poll_internal) <= PN_POLL_SET_PLATFORM_SIZE,
    "pn_zsock_poll_internal exceeds PN_POLL_SET_PLATFORM_SIZE");

/** @brief Cast opaque poll_set to internal struct. */
static inline struct pn_zsock_poll_internal* pn_poll_set_internal(pn_poll_set_t* poll_set)
{
    return (struct pn_zsock_poll_internal*)poll_set->platform_data;
}

/** @brief Cast const opaque poll_set to internal struct. */
static inline const struct pn_zsock_poll_internal*
pn_poll_set_internal_const(const pn_poll_set_t* poll_set)
{
    return (const struct pn_zsock_poll_internal*)poll_set->platform_data;
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

static pn_socket_t zephyr_socket_create(const pn_socket_platform_ops_t* self,
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
    const int fd   = zsock_socket(domain, type, 0);
    if (0 > fd) {
        return PN_INVALID_SOCKET;
    }

    return (pn_socket_t)fd;
}

static void zephyr_socket_destroy(const pn_socket_platform_ops_t* self,
                                  pn_socket_t                     sock)
{
    (void)self;

    if (PN_INVALID_SOCKET == sock) {
        return;
    }

    zsock_close((int)sock);
}

static int zephyr_socket_connect(const pn_socket_platform_ops_t* self,
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

    connect_ret = zsock_connect(fd, sa_ptr, sa_len);

    if (0 == connect_ret) {
        return 1;
    }

    if (EINPROGRESS == errno || EAGAIN == errno) {
        return 0;
    }

    return -errno;
}

static int zephyr_socket_check_connect(const pn_socket_platform_ops_t* self,
                                       pn_socket_t                     sock)
{
    (void)self;

    const int fd = (int)sock;

    /* On Zephyr, getsockopt(SO_ERROR)==0 does not guarantee the TCP
     * handshake completed — it may simply mean no error has been posted
     * yet. Probe writability with a zero-timeout poll first: POLLOUT
     * fires only after the connection is established (or failed). */
    struct zsock_pollfd pfd = {.fd = fd, .events = ZSOCK_POLLOUT, .revents = 0};
    int                 prc = zsock_poll(&pfd, 1, 0);

    if (prc <= 0) {
        return 0; /* Not yet writable — still connecting. */
    }

    if (pfd.revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP)) {
        int       err = 0;
        socklen_t len = sizeof(err);
        zsock_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        return (0 != err) ? -err : -EIO;
    }

    /* POLLOUT fired — verify via SO_ERROR. */
    int       err     = 0;
    socklen_t len     = sizeof(err);
    const int gso_ret = zsock_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

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

static int zephyr_socket_send(const pn_socket_platform_ops_t* self,
                              pn_socket_t                     sock,
                              const uint8_t*                  data,
                              size_t                          len)
{
    (void)self;

    const int     fd      = (int)sock;
    const ssize_t sent_sz = zsock_send(fd, data, len, 0);

    if (0 <= sent_sz) {
        return (int)sent_sz;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINPROGRESS == errno) {
        return 0;
    }

    return -errno;
}

static int zephyr_socket_recv(const pn_socket_platform_ops_t* self,
                              pn_socket_t                     sock,
                              uint8_t*                        buf,
                              size_t                          len)
{
    (void)self;

    const int     fd       = (int)sock;
    const ssize_t recv_ret = zsock_recv(fd, buf, len, 0);

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

static int zephyr_socket_sendto(const pn_socket_platform_ops_t* self,
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

    const ssize_t sendto_ret = zsock_sendto(fd, data, len, 0, sa_ptr, sa_len);

    if (0 <= sendto_ret) {
        return (int)sendto_ret;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno) {
        return 0;
    }

    return -errno;
}

static int zephyr_socket_recvfrom(const pn_socket_platform_ops_t* self,
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

    const ssize_t recv_ret = zsock_recvfrom(fd, buf, len, 0, sa_ptr, &sa_len);

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

static int zephyr_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                         pn_socket_t                     sock)
{
    (void)self;

    const int fd      = (int)sock;
    int       on      = 1;
    const int iol_ret = zsock_ioctl(fd, ZFD_IOCTL_FIONBIO, &on);

    if (0 > iol_ret) {
        return -errno;
    }

    return 0;
}

static int zephyr_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                       pn_socket_t                     sock,
                                       const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;

    const int fd      = (int)sock;
    int       opt_val = 0;
    int       sso_ret = 0;

    if (0 == config->enabled) {
        opt_val = 0;
        sso_ret = zsock_setsockopt(
            fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
        if (0 > sso_ret) {
            return -errno;
        }
        return 0;
    }

    opt_val = 1;
    sso_ret =
        zsock_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }

#ifdef TCP_KEEPIDLE
    opt_val = (int)config->idle_sec;
    sso_ret =
        zsock_setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }
#endif

#ifdef TCP_KEEPINTVL
    opt_val = (int)config->interval_sec;
    sso_ret = zsock_setsockopt(
        fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }
#endif

#ifdef TCP_KEEPCNT
    opt_val = (int)config->probe_count;
    sso_ret =
        zsock_setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt_val, sizeof(opt_val));
    if (0 > sso_ret) {
        return -errno;
    }
#endif

    return 0;
}

static int zephyr_poll_init(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set)
{
    (void)self;

    struct pn_zsock_poll_internal* internal = pn_poll_set_internal(poll_set);
    memset(internal, 0, sizeof(*internal));
    return 0;
}

static void zephyr_poll_deinit(const pn_socket_platform_ops_t* self,
                               pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
}

static int zephyr_poll_add(const pn_socket_platform_ops_t* self,
                           pn_poll_set_t*                  poll_set,
                           pn_socket_t                     sock,
                           uint8_t                         events)
{
    (void)self;

    struct pn_zsock_poll_internal* internal    = pn_poll_set_internal(poll_set);
    short                          poll_events = 0;

    if (internal->count >= PN_SOCKET_TRANSPORT_MAX_FDS) {
        return -ENOMEM;
    }

    if (0 != (events & PN_POLL_READ)) {
        poll_events |= ZSOCK_POLLIN;
    }
    if (0 != (events & PN_POLL_WRITE)) {
        poll_events |= ZSOCK_POLLOUT;
    }
    if (0 != (events & PN_POLL_ERROR)) {
        poll_events |= ZSOCK_POLLERR;
    }

    internal->fds[internal->count].fd      = (int)sock;
    internal->fds[internal->count].events  = poll_events;
    internal->fds[internal->count].revents = 0;
    internal->handles[internal->count]     = sock;
    internal->count++;

    return 0;
}

static int zephyr_poll_modify(const pn_socket_platform_ops_t* self,
                              pn_poll_set_t*                  poll_set,
                              pn_socket_t                     sock,
                              uint8_t                         events)
{
    (void)self;

    struct pn_zsock_poll_internal* internal    = pn_poll_set_internal(poll_set);
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
        poll_events |= ZSOCK_POLLIN;
    }
    if (0 != (events & PN_POLL_WRITE)) {
        poll_events |= ZSOCK_POLLOUT;
    }
    if (0 != (events & PN_POLL_ERROR)) {
        poll_events |= ZSOCK_POLLERR;
    }

    internal->fds[i].events  = poll_events;
    internal->fds[i].revents = 0;

    return 0;
}

static int zephyr_poll_remove(const pn_socket_platform_ops_t* self,
                              pn_poll_set_t*                  poll_set,
                              pn_socket_t                     sock)
{
    (void)self;

    struct pn_zsock_poll_internal* internal = pn_poll_set_internal(poll_set);
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

static int zephyr_poll_wait(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            int                             timeout_ms)
{
    (void)self;

    struct pn_zsock_poll_internal* internal = pn_poll_set_internal(poll_set);
    int                            poll_ret = 0;
    size_t                         i        = 0;

    /* Empty poll set: sleep for the requested timeout. When timeout_ms
     * is 0 or negative (infinite), return immediately — blocking forever
     * with nothing to poll would deadlock the bg thread. */
    if (0 == internal->count) {
        if (0 < timeout_ms) {
            k_msleep(timeout_ms);
        }
        internal->ready_count = 0;
        return 0;
    }

    poll_ret = zsock_poll(internal->fds, (int)internal->count, timeout_ms);

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

static size_t zephyr_poll_ready_count(const pn_socket_platform_ops_t* self,
                                      const pn_poll_set_t*            poll_set)
{
    (void)self;

    const struct pn_zsock_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    return internal->ready_count;
}

static int zephyr_poll_get_ready(const pn_socket_platform_ops_t* self,
                                 const pn_poll_set_t*            poll_set,
                                 size_t                          index,
                                 pn_socket_t*                    out_sock,
                                 uint8_t*                        out_events)
{
    (void)self;

    const struct pn_zsock_poll_internal* internal =
        pn_poll_set_internal_const(poll_set);
    size_t  ready_idx = 0;
    uint8_t events    = 0;
    short   revents   = 0;

    if (index >= internal->ready_count) {
        return -EINVAL;
    }

    ready_idx = internal->ready_indices[index];
    revents   = internal->fds[ready_idx].revents;

    if (0 != (revents & ZSOCK_POLLIN)) {
        events |= PN_POLL_READ;
    }
    if (0 != (revents & ZSOCK_POLLOUT)) {
        events |= PN_POLL_WRITE;
    }
    if (0 != (revents & ZSOCK_POLLERR)) {
        events |= PN_POLL_ERROR;
    }
    if (0 != (revents & ZSOCK_POLLHUP)) {
        events |= PN_POLL_HUP;
    }

    *out_sock   = internal->handles[ready_idx];
    *out_events = events;

    return 0;
}

#if PUBNUB_ENABLE_CUSTOM_DNS

/**
 * @brief Discover DNS server addresses from Zephyr resolver configuration.
 *
 * Queries the Zephyr DNS resolver context for configured servers. Falls back
 * to Google DNS 8.8.8.8:53 if no servers are configured or if
 * CONFIG_DNS_RESOLVER is not enabled. Applications should configure DNS
 * servers via prj.conf CONFIG_DNS_SERVER_IP_ADDRESSES.
 *
 * @param self Platform ops instance (unused).
 * @param servers Array to populate with nameserver addresses.
 * @param capacity Maximum number of servers to store.
 * @param out_count On success, set to number of servers discovered.
 * @return 0 on success, negative errno on failure.
 */
static int zephyr_dns_discover_servers(const pn_socket_platform_ops_t* self,
                                       pn_sockaddr_t*                  servers,
                                       size_t                          capacity,
                                       size_t* out_count)
{
    (void)self;

    size_t count = 0;

#if defined(CONFIG_DNS_RESOLVER)
    struct dns_resolve_context* ctx = dns_resolve_get_default();

    if (NULL != ctx) {
        for (int i = 0; i < CONFIG_DNS_RESOLVER_MAX_SERVERS && count < capacity;
             ++i) {
            const struct sockaddr* sa = &ctx->servers[i].dns_server;

            if (AF_INET == sa->sa_family) {
                const struct sockaddr_in* sin = (const struct sockaddr_in*)sa;
                servers[count].family         = PN_AF_INET;
                servers[count].port           = ntohs(sin->sin_port);
                if (0 == servers[count].port) {
                    servers[count].port = 53;
                }
                memcpy(servers[count].addr.ipv4, &sin->sin_addr.s_addr, 4);
                count++;
            } else if (AF_INET6 == sa->sa_family) {
                const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)sa;
                servers[count].family = PN_AF_INET6;
                servers[count].port   = ntohs(sin6->sin6_port);
                if (0 == servers[count].port) {
                    servers[count].port = 53;
                }
                memcpy(servers[count].addr.ipv6, &sin6->sin6_addr.s6_addr, 16);
                count++;
            }
        }
    }
#endif /* CONFIG_DNS_RESOLVER */

    /* Hardcoded fallback: Google DNS 8.8.8.8:53 */
    if (0 == count && capacity > 0) {
        servers[0].family       = PN_AF_INET;
        servers[0].port         = 53;
        servers[0].addr.ipv4[0] = 8;
        servers[0].addr.ipv4[1] = 8;
        servers[0].addr.ipv4[2] = 8;
        servers[0].addr.ipv4[3] = 8;
        count                   = 1;
    }

    *out_count = count;
    return 0;
}

#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

#if !PUBNUB_ENABLE_CUSTOM_DNS

#if defined(CONFIG_SMP)
#include <zephyr/sys/atomic.h>
#endif

/**
 * @brief Per-instance state for Zephyr platform-native DNS resolution.
 *
 * Passed as dns_ctx to all dns_resolve_* vtable calls. The resolver
 * serializes requests — only one resolution is active per resolver
 * instance at a time.
 *
 * Thread-safety model: on SMP targets, atomic_t provides correct
 * visibility between Zephyr's DNS callback thread and the SDK poll
 * loop. On single-core Cortex-M, volatile int is sufficient (context
 * switch includes DSB).
 */
typedef struct pn_zephyr_dns_state {
    pn_sockaddr_t addrs[PUBNUB_CFG_MAX_DNS_RESULTS];
    size_t        count;
    uint8_t       v4_count;
#if defined(CONFIG_SMP)
    atomic_t          complete;   /**< 1 = done, 0 = pending. */
    atomic_t          error;      /**< 1 = at least one query failed, 0 = ok. */
    struct k_spinlock addrs_lock; /**< Guards count + addrs[] on SMP. */
#else
    volatile int complete; /**< 1 = done, 0 = pending. */
    volatile int error;    /**< 1 = at least one query failed, 0 = ok. */
#endif
    uint16_t dns_id_a;        /**< Zephyr DNS query ID for A (IPv4). */
    uint16_t dns_id_aaaa;     /**< Zephyr DNS query ID for AAAA (IPv6). */
#if defined(CONFIG_SMP)
    atomic_t queries_pending; /**< Outstanding queries (1 or 2). */
#else
    uint8_t queries_pending; /**< Outstanding queries (1 or 2). */
#endif
} pn_zephyr_dns_state_t;

#include "pubnub/pubnub_compat.h"
PUBNUB_STATIC_ASSERT(
    sizeof(pn_zephyr_dns_state_t) <= PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE,
    "Zephyr DNS state exceeds PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE");

/**
 * @brief Zephyr DNS resolution callback.
 *
 * Fires from Zephyr's network thread (single-threaded — A and AAAA
 * callbacks serialize naturally). Receives DNS_EAI_INPROGRESS for each
 * address result and DNS_EAI_ALLDONE when a query finishes. When both
 * A and AAAA queries are in flight, completion is signalled only after
 * both queries have reported ALLDONE or error.
 */
static void zephyr_dns_callback(enum dns_resolve_status status,
                                struct dns_addrinfo*    info,
                                void*                   user_data)
{
    pn_zephyr_dns_state_t* st = (pn_zephyr_dns_state_t*)user_data;

    if (DNS_EAI_INPROGRESS == status && NULL != info) {
        const struct sockaddr* sa = &info->ai_addr;
#if defined(CONFIG_SMP)
        /* Protect count + addrs[] against concurrent A and AAAA callbacks
         * on multi-core targets. k_spin_lock is zero-overhead on single-core
         * (IRQ disable) and a LDREX/STREX pair on ARM SMP. */
        k_spinlock_key_t key = k_spin_lock(&st->addrs_lock);
#endif
        if (st->count < PUBNUB_CFG_MAX_DNS_RESULTS) {
            pn_sockaddr_t* dst = &st->addrs[st->count];
            if (AF_INET == sa->sa_family) {
                const struct sockaddr_in* sin = (const struct sockaddr_in*)sa;
                dst->family                   = PN_AF_INET;
                dst->port                     = 0;
                memcpy(dst->addr.ipv4, &sin->sin_addr.s_addr, 4);
                st->count++;
                st->v4_count++;
            } else if (PUBNUB_ENABLE_IPV6 && AF_INET6 == sa->sa_family) {
                /* Cap IPv6 at half the buffer to guarantee IPv4 room. */
                if ((st->count - st->v4_count) < PUBNUB_CFG_MAX_DNS_RESULTS / 2U) {
                    const struct sockaddr_in6* sin6 =
                        (const struct sockaddr_in6*)sa;
                    dst->family = PN_AF_INET6;
                    dst->port   = 0;
                    memcpy(dst->addr.ipv6, &sin6->sin6_addr.s6_addr, 16);
                    st->count++;
                }
            }
        }
#if defined(CONFIG_SMP)
        k_spin_unlock(&st->addrs_lock, key);
#endif
        return;
    }

    if (DNS_EAI_ALLDONE == status) {
#if defined(CONFIG_SMP)
        atomic_val_t prev = atomic_sub(&st->queries_pending, 1);
        if (1 == prev) {
            pn_sort_addrs_ipv4_first(st->addrs, st->count);
            atomic_set(&st->complete, 1);
        }
#else
        st->queries_pending--;
        if (0 == st->queries_pending) {
            pn_sort_addrs_ipv4_first(st->addrs, st->count);
            st->complete = 1;
        }
#endif
        return;
    }

    /* Any other status is an error (DNS_EAI_CANCELED, DNS_EAI_FAIL, etc).
     * Mark error but allow the other query to still contribute results. */
#if defined(CONFIG_SMP)
    atomic_set(&st->error, 1);
    {
        atomic_val_t prev = atomic_sub(&st->queries_pending, 1);
        if (1 == prev) {
            atomic_set(&st->complete, 1);
        }
    }
#else
    st->error = 1;
    st->queries_pending--;
    if (0 == st->queries_pending) {
        st->complete = 1;
    }
#endif
}

static size_t zephyr_dns_state_size(const pn_socket_platform_ops_t* self)
{
    (void)self;
    return sizeof(pn_zephyr_dns_state_t);
}

static int zephyr_dns_resolve_start(const pn_socket_platform_ops_t* self,
                                    void*                           dns_ctx,
                                    const char*                     hostname,
                                    uint32_t                        timeout_ms)
{
    (void)self;

    pn_zephyr_dns_state_t* st = (pn_zephyr_dns_state_t*)dns_ctx;

    /* Cancel any outstanding queries to prevent stale callbacks from a
     * previous timed-out resolution corrupting the new query's state. */
    if (0 != st->dns_id_a) {
        dns_cancel_addr_info(st->dns_id_a);
    }
    if (0 != st->dns_id_aaaa) {
        dns_cancel_addr_info(st->dns_id_aaaa);
    }

    st->count       = 0;
    st->v4_count    = 0;
    st->dns_id_a    = 0;
    st->dns_id_aaaa = 0;
#if defined(CONFIG_SMP)
    atomic_set(&st->complete, 0);
    atomic_set(&st->error, 0);
#else
    st->complete = 0;
    st->error    = 0;
#endif

    /* Pre-set queries_pending to the maximum expected count BEFORE
     * issuing any query. On SMP, the callback may fire on another core
     * before dns_get_addr_info returns — the counter must already
     * reflect the total expected completions. */
#if defined(CONFIG_SMP)
#if defined(CONFIG_NET_IPV6) && PUBNUB_ENABLE_IPV6
    atomic_set(&st->queries_pending, 2);
#else
    atomic_set(&st->queries_pending, 1);
#endif
#else
#if defined(CONFIG_NET_IPV6) && PUBNUB_ENABLE_IPV6
    st->queries_pending = 2;
#else
    st->queries_pending = 1;
#endif
#endif

    uint16_t dns_id = 0;
    int32_t  timeout =
        (timeout_ms > (uint32_t)INT32_MAX) ? INT32_MAX : (int32_t)timeout_ms;

    /* Issue A (IPv4) query. */
    int rc = dns_get_addr_info(
        hostname, DNS_QUERY_TYPE_A, &dns_id, zephyr_dns_callback, st, timeout);
    if (0 != rc) {
#if defined(CONFIG_SMP)
        atomic_set(&st->queries_pending, 0);
#else
        st->queries_pending = 0;
#endif
        return -1;
    }
    st->dns_id_a = dns_id;

#if defined(CONFIG_NET_IPV6) && PUBNUB_ENABLE_IPV6
    /* Issue AAAA (IPv6) query when IPv6 networking is enabled. If the
     * AAAA query fails to submit, proceed with A-only resolution. */
    uint16_t dns_id_v6 = 0;
    int      rc_v6     = dns_get_addr_info(
        hostname, DNS_QUERY_TYPE_AAAA, &dns_id_v6, zephyr_dns_callback, st, timeout);
    if (0 == rc_v6) {
        st->dns_id_aaaa = dns_id_v6;
    } else {
#if defined(CONFIG_SMP)
        atomic_set(&st->queries_pending, 1);
#else
        st->queries_pending = 1;
#endif
    }
#endif /* CONFIG_NET_IPV6 && PUBNUB_ENABLE_IPV6 */

    return 0;
}

static int zephyr_dns_resolve_poll(const pn_socket_platform_ops_t* self, void* dns_ctx)
{
    (void)self;

    pn_zephyr_dns_state_t* st = (pn_zephyr_dns_state_t*)dns_ctx;

#if defined(CONFIG_SMP)
    if (0 == atomic_get(&st->complete)) {
        return 0;
    }
    /* Report failure only when error is set AND no addresses were
     * collected (e.g. AAAA failed but A returned results is success). */
    if (0 != atomic_get(&st->error) && 0 == st->count) {
        return -1;
    }
    return 1;
#else
    if (0 == st->complete) {
        return 0;
    }
    if (0 != st->error && 0 == st->count) {
        return -1;
    }
    return 1;
#endif
}

static int zephyr_dns_resolve_get_results(const pn_socket_platform_ops_t* self,
                                          void*          dns_ctx,
                                          pn_sockaddr_t* addrs,
                                          size_t         max_addrs,
                                          size_t*        out_count)
{
    (void)self;

    pn_zephyr_dns_state_t* st = (pn_zephyr_dns_state_t*)dns_ctx;

    size_t to_copy = st->count;
    if (to_copy > max_addrs) {
        to_copy = max_addrs;
    }

    memcpy(addrs, st->addrs, to_copy * sizeof(pn_sockaddr_t));
    *out_count = to_copy;

    return 0;
}

static void zephyr_dns_resolve_cancel(const pn_socket_platform_ops_t* self,
                                      void*                           dns_ctx)
{
    (void)self;

    pn_zephyr_dns_state_t* st = (pn_zephyr_dns_state_t*)dns_ctx;

#if defined(CONFIG_SMP)
    if (0 != atomic_get(&st->complete)) {
        return;
    }
#else
    if (0 != st->complete) {
        return;
    }
#endif

    if (0 != st->dns_id_a) {
        dns_cancel_addr_info(st->dns_id_a);
        st->dns_id_a = 0;
    }
    if (0 != st->dns_id_aaaa) {
        dns_cancel_addr_info(st->dns_id_aaaa);
        st->dns_id_aaaa = 0;
    }
}

#endif /* !PUBNUB_ENABLE_CUSTOM_DNS */

/*
 * Self-pipe wake mechanism for Zephyr. Prefers eventfd (single fd,
 * smallest footprint); falls back to zsock_socketpair when available;
 * returns -1 otherwise (100ms poll-timeout fallback).
 */

#if defined(CONFIG_EVENTFD)
#include <zephyr/posix/sys/eventfd.h>

static int zephyr_pipe_create(const pn_socket_platform_ops_t* self,
                              pn_socket_t                     out[2])
{
    int fd;
    (void)self;

    out[0] = PN_INVALID_SOCKET;
    out[1] = PN_INVALID_SOCKET;

    fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    /* eventfd uses the same fd for read and write. */
    out[0] = fd;
    out[1] = fd;
    return 0;
}

static void zephyr_pipe_write(const pn_socket_platform_ops_t* self, pn_socket_t wr)
{
    (void)self;
    (void)eventfd_write(wr, 1);
}

static void zephyr_pipe_drain(const pn_socket_platform_ops_t* self, pn_socket_t rd)
{
    eventfd_t val;
    (void)self;
    (void)eventfd_read(rd, &val);
}

#elif defined(CONFIG_NET_SOCKETS_SOCKETPAIR)

static int zephyr_pipe_create(const pn_socket_platform_ops_t* self,
                              pn_socket_t                     out[2])
{
    int fds[2];
    int on = 1;
    (void)self;

    out[0] = PN_INVALID_SOCKET;
    out[1] = PN_INVALID_SOCKET;

    if (0 != zsock_socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
        return -1;
    }
    /* Set both ends non-blocking — the unconditional drain in
     * socket_poll calls socket_recv on every tick; blocking
     * sockets deadlock the bg thread. */
    if (0 > zsock_ioctl(fds[0], ZFD_IOCTL_FIONBIO, &on)
        || 0 > zsock_ioctl(fds[1], ZFD_IOCTL_FIONBIO, &on)) {
        zsock_close(fds[0]);
        zsock_close(fds[1]);
        return -1;
    }
    out[0] = fds[0];
    out[1] = fds[1];
    return 0;
}

/* socketpair is 1-byte compatible — use NULL pipe_write/pipe_drain. */

#endif /* CONFIG_EVENTFD / CONFIG_NET_SOCKETS_SOCKETPAIR */

// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_socket_platform_ops_t pn_zephyr_socket_ops = {
    .socket_create          = zephyr_socket_create,
    .socket_destroy         = zephyr_socket_destroy,
    .socket_connect         = zephyr_socket_connect,
    .socket_check_connect   = zephyr_socket_check_connect,
    .socket_send            = zephyr_socket_send,
    .socket_recv            = zephyr_socket_recv,
    .socket_sendto          = zephyr_socket_sendto,
    .socket_recvfrom        = zephyr_socket_recvfrom,
    .socket_set_nonblocking = zephyr_socket_set_nonblocking,
    .socket_set_keepalive   = zephyr_socket_set_keepalive,
    .poll_init              = zephyr_poll_init,
    .poll_deinit            = zephyr_poll_deinit,
    .poll_add               = zephyr_poll_add,
    .poll_modify            = zephyr_poll_modify,
    .poll_remove            = zephyr_poll_remove,
    .poll_wait              = zephyr_poll_wait,
    .poll_ready_count       = zephyr_poll_ready_count,
    .poll_get_ready         = zephyr_poll_get_ready,
#if PUBNUB_ENABLE_CUSTOM_DNS
    .dns_discover_servers    = zephyr_dns_discover_servers,
    .dns_state_size          = NULL,
    .dns_state_init          = NULL,
    .dns_resolve_start       = NULL,
    .dns_resolve_poll        = NULL,
    .dns_resolve_get_results = NULL,
    .dns_resolve_cancel      = NULL,
#else
    .dns_discover_servers    = NULL,
    .dns_state_size          = zephyr_dns_state_size,
    .dns_state_init          = NULL,
    .dns_resolve_start       = zephyr_dns_resolve_start,
    .dns_resolve_poll        = zephyr_dns_resolve_poll,
    .dns_resolve_get_results = zephyr_dns_resolve_get_results,
    .dns_resolve_cancel      = zephyr_dns_resolve_cancel,
#endif
#if defined(CONFIG_EVENTFD)
    .pipe_create = zephyr_pipe_create,
    .pipe_write  = zephyr_pipe_write,
    .pipe_drain  = zephyr_pipe_drain,
#elif defined(CONFIG_NET_SOCKETS_SOCKETPAIR)
    .pipe_create = zephyr_pipe_create,
    .pipe_write  = NULL, /* 1-byte fallback is correct for socketpair. */
    .pipe_drain  = NULL,
#else
    /* Neither CONFIG_EVENTFD nor CONFIG_NET_SOCKETS_SOCKETPAIR is
     * available — fall back to 100ms poll timeout. */
    .pipe_create = NULL,
    .pipe_write  = NULL,
    .pipe_drain  = NULL,
#endif
};

#endif /* __ZEPHYR__ */

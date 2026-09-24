/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_SOCKET_PLATFORM_OPS_H
#define PN_SOCKET_PLATFORM_OPS_H

#include "pn_socket_types.h"
#include "config_internal.h"
#include "pubnub/config.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @file pn_socket_platform_ops.h
 * @brief Socket transport platform operations interface.
 *
 * Defines the vtable interface for platform-specific socket and DNS
 * operations. Implementations provide POSIX, Windows, or RTOS backends.
 * All operations use a consistent return convention: >0 for bytes
 * transferred or in-progress, 0 for would-block, -1 for peer disconnected
 * (recv only), <-1 for negated error codes.
 */

/**
 * @brief Maximum concurrent file descriptors for socket transport.
 *
 * The socket transport needs to poll one descriptor per in-flight
 * request plus two for DNS resolution (IPv4 + IPv6) plus one for the
 * self-pipe wake mechanism.
 */
#define PN_SOCKET_TRANSPORT_MAX_FDS (PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 3)

#include "pubnub/pubnub_compat.h"

/*
 * The fd-count and poll-set stack ceilings are profile-dependent.
 *
 * Embedded targets (bare-metal / RTOS-class) run on tiny stacks, so both
 * the descriptor count and the stack-resident poll-set storage are held to
 * tight bounds that MUST NOT loosen. Hosted targets (Linux/macOS/BSD/
 * Windows) run many more concurrent in-flight requests and have ample
 * stack, so the same ceilings are relaxed to cover that larger fd budget.
 *
 * Both ceilings scale together: the poll-set size grows ~24 bytes/slot + 16
 * bytes overhead, so the stack ceiling always satisfies
 * ceiling >= fd_ceiling * 24 + 16 for the profile it applies to.
 */
#if PN_PROFILE_EMBEDDED
#define PN_SOCKET_TRANSPORT_MAX_FDS_LIMIT 16
#define PN_POLL_SET_PLATFORM_SIZE_LIMIT   512
#else
#define PN_SOCKET_TRANSPORT_MAX_FDS_LIMIT 32
#define PN_POLL_SET_PLATFORM_SIZE_LIMIT   1024
#endif

PUBNUB_STATIC_ASSERT(
    PN_SOCKET_TRANSPORT_MAX_FDS <= PN_SOCKET_TRANSPORT_MAX_FDS_LIMIT,
    "PN_SOCKET_TRANSPORT_MAX_FDS exceeds the poll fd budget for this "
    "profile (tight on embedded, relaxed on hosted)");

/**
 * @brief Default size of the platform-specific poll set storage.
 *
 * Must be large enough to hold any platform's internal poll struct.
 * Each platform implementation validates with PUBNUB_STATIC_ASSERT at
 * compile time. Reference sizing (POSIX 64-bit): ~24 bytes/slot + 16
 * bytes overhead. Override via -DPN_POLL_SET_PLATFORM_SIZE=<n> when
 * porting to a platform with larger poll structures.
 */
#ifndef PN_POLL_SET_PLATFORM_SIZE
#define PN_POLL_SET_PLATFORM_SIZE (PN_SOCKET_TRANSPORT_MAX_FDS * 24 + 16)
#endif

PUBNUB_STATIC_ASSERT(
    PN_POLL_SET_PLATFORM_SIZE <= PN_POLL_SET_PLATFORM_SIZE_LIMIT,
    "PN_POLL_SET_PLATFORM_SIZE exceeds the poll-set stack budget for this "
    "profile (tight on embedded, relaxed on hosted)");

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE <= 512, "PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE exceeds 512-byte embedded stack ceiling");

/**
 * @brief Opaque poll set structure.
 *
 * Stack-allocatable storage for platform-specific poll state (e.g., pollfd
 * array on POSIX, fd_set on Windows). Platform implementations cast this to
 * their concrete type.
 */
typedef struct pn_poll_set {
    uint8_t platform_data[PN_POLL_SET_PLATFORM_SIZE]; /**< Opaque storage. */
} pn_poll_set_t;

/**
 * @brief Platform operations vtable for socket transport.
 *
 * Provides platform-specific implementations of socket creation, connection,
 * I/O, polling, and DNS resolution. All function pointers must be non-NULL.
 * Implementations must document thread-safety guarantees; the socket
 * transport assumes platform ops are reentrant.
 *
 * @note All callbacks are invoked outside ISR context.
 * @note All I/O operations use non-blocking sockets.
 */
typedef struct pn_socket_platform_ops {
    /**
     * @brief Create a new socket.
     *
     * @param self   Platform ops instance.
     * @param family Address family (PN_AF_INET or PN_AF_INET6).
     * @param dgram  0 = SOCK_STREAM (TCP), non-zero = SOCK_DGRAM (UDP).
     * @return Socket handle on success, PN_INVALID_SOCKET on failure.
     */
    pn_socket_t (*socket_create)(const struct pn_socket_platform_ops* self,
                                 uint16_t                             family,
                                 int                                  dgram);

    /**
     * @brief Destroy a socket.
     *
     * Closes the socket and releases any associated resources. Safe to call
     * with PN_INVALID_SOCKET (no-op).
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     */
    void (*socket_destroy)(const struct pn_socket_platform_ops* self,
                           pn_socket_t                          sock);

    /**
     * @brief Initiate a non-blocking connect.
     *
     * @param self Platform ops instance.
     * @param sock Socket handle (must be non-blocking).
     * @param addr Destination address.
     * @return >0 if connection completed immediately, 0 if in-progress, <-1
     * on error (negated error code).
     */
    int (*socket_connect)(const struct pn_socket_platform_ops* self,
                          pn_socket_t                          sock,
                          const pn_sockaddr_t*                 addr);

    /**
     * @brief Check if a non-blocking connect completed.
     *
     * Call after poll indicates the socket is writable.
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @return 1 if connected, 0 if still in-progress, <-1 on error (negated
     * error code).
     */
    int (*socket_check_connect)(const struct pn_socket_platform_ops* self,
                                pn_socket_t                          sock);

    /**
     * @brief Send data on a connected socket (non-blocking).
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @param data Data to send.
     * @param len Length of data.
     * @return >0 bytes sent, 0 would-block, <-1 error (negated error code).
     */
    int (*socket_send)(const struct pn_socket_platform_ops* self,
                       pn_socket_t                          sock,
                       const uint8_t*                       data,
                       size_t                               len);

    /**
     * @brief Receive data from a connected socket (non-blocking).
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @param buf Buffer to receive into.
     * @param len Buffer capacity.
     * @return >0 bytes received, 0 would-block, -1 peer disconnected, <-1
     * error (negated error code).
     */
    int (*socket_recv)(const struct pn_socket_platform_ops* self,
                       pn_socket_t                          sock,
                       uint8_t*                             buf,
                       size_t                               len);

    /**
     * @brief Send data to a specific address (connectionless, non-blocking).
     *
     * Used for DNS queries over UDP. Not required for TCP-only
     * implementations.
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @param data Data to send.
     * @param len Length of data.
     * @param addr Destination address.
     * @return >0 bytes sent, 0 would-block, <-1 error (negated error code).
     */
    int (*socket_sendto)(const struct pn_socket_platform_ops* self,
                         pn_socket_t                          sock,
                         const uint8_t*                       data,
                         size_t                               len,
                         const pn_sockaddr_t*                 addr);

    /**
     * @brief Receive data with source address (connectionless, non-blocking).
     *
     * Used for DNS responses over UDP. Not required for TCP-only
     * implementations.
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @param buf Buffer to receive into.
     * @param len Buffer capacity.
     * @param addr Source address output (written on success).
     * @return >0 bytes received, 0 would-block, <-1 error (negated error
     * code).
     */
    int (*socket_recvfrom)(const struct pn_socket_platform_ops* self,
                           pn_socket_t                          sock,
                           uint8_t*                             buf,
                           size_t                               len,
                           pn_sockaddr_t*                       addr);

    /**
     * @brief Set socket to non-blocking mode.
     *
     * All transport I/O operations assume non-blocking sockets. Call this
     * immediately after socket_create.
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*socket_set_nonblocking)(const struct pn_socket_platform_ops* self,
                                  pn_socket_t                          sock);

    /**
     * @brief Configure TCP keepalive on a socket.
     *
     * Applies the keepalive configuration to a TCP socket. Has no effect on
     * UDP sockets.
     *
     * @param self Platform ops instance.
     * @param sock Socket handle.
     * @param config Keepalive configuration.
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*socket_set_keepalive)(const struct pn_socket_platform_ops* self,
                                pn_socket_t                          sock,
                                const pubnub_tcp_keepalive_config_t* config);

    /**
     * @brief Initialize a poll set.
     *
     * Prepares the poll set for use. Must be called before any other poll_*
     * operations.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set to initialize.
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*poll_init)(const struct pn_socket_platform_ops* self,
                     pn_poll_set_t*                       poll_set);

    /**
     * @brief Deinitialize a poll set.
     *
     * Releases any resources associated with the poll set. Safe to call on
     * an already-deinitialized set (no-op).
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set to deinitialize.
     */
    void (*poll_deinit)(const struct pn_socket_platform_ops* self,
                        pn_poll_set_t*                       poll_set);

    /**
     * @brief Add a socket to the poll set.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set.
     * @param sock Socket handle.
     * @param events Bitmask of PN_POLL_* flags indicating which events to
     * monitor.
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*poll_add)(const struct pn_socket_platform_ops* self,
                    pn_poll_set_t*                       poll_set,
                    pn_socket_t                          sock,
                    uint8_t                              events);

    /**
     * @brief Modify the monitored events for a socket in the poll set.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set.
     * @param sock Socket handle (must already be in the poll set).
     * @param events New bitmask of PN_POLL_* flags.
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*poll_modify)(const struct pn_socket_platform_ops* self,
                       pn_poll_set_t*                       poll_set,
                       pn_socket_t                          sock,
                       uint8_t                              events);

    /**
     * @brief Remove a socket from the poll set.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set.
     * @param sock Socket handle.
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*poll_remove)(const struct pn_socket_platform_ops* self,
                       pn_poll_set_t*                       poll_set,
                       pn_socket_t                          sock);

    /**
     * @brief Wait for I/O events on sockets in the poll set.
     *
     * Blocks until at least one socket is ready or the timeout expires.
     * timeout_ms=0 returns immediately (poll), timeout_ms=-1 blocks
     * indefinitely.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set.
     * @param timeout_ms Timeout in milliseconds (0=poll, -1=infinite).
     * @return 0 on success (call poll_ready_count() for the ready count),
     *         <0 on error (negated error code).
     */
    int (*poll_wait)(const struct pn_socket_platform_ops* self,
                     pn_poll_set_t*                       poll_set,
                     int                                  timeout_ms);

    /**
     * @brief Get the number of ready sockets after poll_wait.
     *
     * Call after poll_wait returns 0 to determine how many sockets have
     * pending events.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set.
     * @return Number of ready sockets.
     */
    size_t (*poll_ready_count)(const struct pn_socket_platform_ops* self,
                               const pn_poll_set_t*                 poll_set);

    /**
     * @brief Retrieve the ready socket and events at the given index.
     *
     * Call in a loop from index 0 to poll_ready_count()-1 to retrieve all
     * ready sockets after poll_wait.
     *
     * @param self Platform ops instance.
     * @param poll_set Poll set.
     * @param index Index of the ready socket (0 <= index <
     * poll_ready_count()).
     * @param out_sock Socket handle output.
     * @param out_events Bitmask of PN_POLL_* flags output.
     * @return 0 on success, <-1 on error (negated error code, e.g.,
     * out-of-range index).
     */
    int (*poll_get_ready)(const struct pn_socket_platform_ops* self,
                          const pn_poll_set_t*                 poll_set,
                          size_t                               index,
                          pn_socket_t*                         out_sock,
                          uint8_t*                             out_events);

    /**
     * @brief Discover DNS server addresses from system configuration.
     *
     * Populates the provided array with DNS server addresses read from the
     * platform's resolver configuration (e.g., /etc/resolv.conf on POSIX,
     * registry on Windows).
     *
     * @param self Platform ops instance.
     * @param servers Array to populate with DNS server addresses.
     * @param capacity Maximum number of addresses the array can hold.
     * @param out_count Number of addresses written (set on success).
     * @return 0 on success, <-1 on error (negated error code).
     */
    int (*dns_discover_servers)(const struct pn_socket_platform_ops* self,
                                pn_sockaddr_t*                       servers,
                                size_t                               capacity,
                                size_t*                              out_count);

    /**
     * @brief Return the size of the platform's DNS state struct.
     *
     * Returns sizeof the platform's per-instance DNS state (e.g.,
     * pn_posix_dns_state_t). Returns 0 when the platform does not use
     * native DNS (custom DNS path). The resolver embeds a buffer of
     * PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE bytes; the value returned here
     * must not exceed that limit.
     *
     * May be NULL when the platform does not provide native DNS
     * (PUBNUB_ENABLE_CUSTOM_DNS=ON path).
     *
     * @param self Platform ops instance.
     * @return Size in bytes, or 0 if no platform DNS state is needed.
     */
    size_t (*dns_state_size)(const struct pn_socket_platform_ops* self);

    /**
     * @brief Initialize platform DNS state beyond zero-initialization.
     *
     * Called once during pn_dns_resolver_init after the state buffer has
     * been zeroed. Most platforms need no further initialization and may
     * set this to NULL.
     *
     * @param self    Platform ops instance.
     * @param dns_ctx Pointer to the per-instance DNS state buffer.
     * @return 0 on success, <0 on error.
     */
    int (*dns_state_init)(const struct pn_socket_platform_ops* self, void* dns_ctx);

    /**
     * @brief Start async DNS resolution for a hostname (optional).
     *
     * When non-NULL, the DNS resolver uses this platform-native mechanism
     * instead of the built-in UDP resolver. Called at most once at a time
     * (the resolver serializes requests). Must be non-blocking — returns
     * immediately; resolution completes asynchronously.
     *
     * @param self       Platform ops instance.
     * @param dns_ctx    Per-instance DNS state buffer.
     * @param hostname   NUL-terminated hostname to resolve.
     * @param timeout_ms Advisory timeout hint. The resolver enforces its
     *                   own deadline via pn_dns_resolver_tick(). Platform
     *                   implementations MAY ignore this if the underlying
     *                   API does not support per-query timeouts.
     * @return 0 if resolution started successfully, <0 on error.
     */
    int (*dns_resolve_start)(const struct pn_socket_platform_ops* self,
                             void*                                dns_ctx,
                             const char*                          hostname,
                             uint32_t                             timeout_ms);

    /**
     * @brief Poll the state of an in-progress DNS resolution (optional).
     *
     * Only meaningful when dns_resolve_start is non-NULL.
     *
     * @param self    Platform ops instance.
     * @param dns_ctx Per-instance DNS state buffer.
     * @return 0 = still pending, 1 = complete (results ready), -1 = failed.
     */
    int (*dns_resolve_poll)(const struct pn_socket_platform_ops* self,
                            void*                                dns_ctx);

    /**
     * @brief Retrieve results from a completed DNS resolution (optional).
     *
     * Only valid after dns_resolve_poll() returns 1. Only meaningful when
     * dns_resolve_start is non-NULL.
     *
     * @param self      Platform ops instance.
     * @param dns_ctx   Per-instance DNS state buffer.
     * @param addrs     Output array for resolved addresses.
     * @param max_addrs Maximum addresses to return.
     * @param out_count Actual number of addresses written.
     * @return 0 on success, <0 on error.
     */
    int (*dns_resolve_get_results)(const struct pn_socket_platform_ops* self,
                                   void*                                dns_ctx,
                                   pn_sockaddr_t*                       addrs,
                                   size_t  max_addrs,
                                   size_t* out_count);

    /**
     * @brief Cancel an in-progress platform DNS resolution (optional).
     *
     * Called from pn_dns_resolver_deinit when the resolver is torn down
     * with an active query. Releases any async resources (e.g.,
     * DNSServiceRef on macOS, DnsCancelQuery on Windows, dns_cancel on
     * Zephyr).
     *
     * May be NULL for synchronous resolvers (getaddrinfo, lwip) that
     * complete within dns_resolve_start.
     *
     * @param self    Platform ops instance.
     * @param dns_ctx Per-instance DNS state buffer.
     */
    void (*dns_resolve_cancel)(const struct pn_socket_platform_ops* self,
                               void*                                dns_ctx);

    /**
     * @brief Create a connected pair for the self-pipe wake mechanism.
     *
     * out[0] = read end (added to the poll set), out[1] = write end
     * (written by wake()). Both ends must be non-blocking. On success,
     * returns 0. On failure or when unsupported, sets both to
     * PN_INVALID_SOCKET and returns -1. When NULL, the transport
     * assumes pipe is unsupported and falls back to poll-timeout wake.
     *
     * Optional: @c NULL = pipe unsupported on this platform.
     *
     * @param self Platform ops instance.
     * @param out  Two-element output array [read_fd, write_fd].
     * @return 0 on success, -1 on failure or unsupported.
     */
    int (*pipe_create)(const struct pn_socket_platform_ops* self,
                       pn_socket_t                          out[2]);

    /**
     * @brief Write a single wake signal to the pipe write end.
     *
     * Platform-appropriate payload size (1 byte for POSIX pipe,
     * 8 bytes for eventfd). Thread-safe. When NULL, the transport
     * falls back to a 1-byte socket_send.
     *
     * Optional: @c NULL = use 1-byte socket_send fallback.
     *
     * @param self Platform ops instance.
     * @param wr   Write-end descriptor from pipe_create.
     */
    void (*pipe_write)(const struct pn_socket_platform_ops* self, pn_socket_t wr);

    /**
     * @brief Drain all pending wake signals from the pipe read end.
     *
     * Called from socket_poll() before the connection loop. When NULL,
     * the transport falls back to a 1-byte socket_recv drain.
     *
     * Optional: @c NULL = use 1-byte socket_recv fallback.
     *
     * @param self Platform ops instance.
     * @param rd   Read-end descriptor from pipe_create.
     */
    void (*pipe_drain)(const struct pn_socket_platform_ops* self, pn_socket_t rd);
} pn_socket_platform_ops_t;

/**
 * @brief Partition addrs[] in-place so all IPv4 entries precede IPv6.
 *
 * Uses an in-place swap (Dutch national flag, single-pivot) so no extra
 * allocation is required. Relative order within each family may change,
 * which is acceptable — the connection FSM tries all IPv4 before IPv6.
 * Applied by platform DNS callbacks/resolvers after collecting results to
 * ensure IPv4 is always tried first on dual-stack hosts where IPv6 may be
 * configured but not routed to the remote endpoint.
 *
 * @param addrs  Address array to reorder.
 * @param count  Number of valid entries.
 */
static inline void pn_sort_addrs_ipv4_first(pn_sockaddr_t* addrs, size_t count)
{
    size_t left  = 0;
    size_t right = count;

    while (left < right) {
        if (PN_AF_INET == addrs[left].family) {
            left++;
        } else {
            right--;
            if (left < right) {
                pn_sockaddr_t tmp = addrs[left];
                addrs[left]       = addrs[right];
                addrs[right]      = tmp;
            }
        }
    }
}

#endif /* PN_SOCKET_PLATFORM_OPS_H */

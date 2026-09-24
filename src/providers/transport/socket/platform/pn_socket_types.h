/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_SOCKET_TYPES_H
#define PN_SOCKET_TYPES_H

#include "pubnub/tcp_keepalive.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Platform-neutral socket handle type.
 *
 * intptr_t accommodates both POSIX int fd and Windows SOCKET (UINT_PTR).
 * PN_INVALID_SOCKET (-1) is portable: matches POSIX convention and is
 * distinct from all valid Windows socket handles.
 */
typedef intptr_t pn_socket_t;

/** @brief Sentinel value for an invalid or closed socket. */
#define PN_INVALID_SOCKET ((pn_socket_t) - 1)

/**
 * @brief Address family constants (platform-neutral).
 *
 * These constants abstract over AF_UNSPEC/AF_INET/AF_INET6 on POSIX and
 * Windows, ensuring consistent representation across platforms.
 */
#define PN_AF_UNSPEC 0x0000 /**< Unspecified address family. */
#define PN_AF_INET   0x0100 /**< IPv4 address family. */
#define PN_AF_INET6  0x0200 /**< IPv6 address family. */

/**
 * @brief Platform-neutral socket address structure.
 *
 * Represents an IP address (IPv4 or IPv6) with port. The union holds either
 * a 4-byte IPv4 address or a 16-byte IPv6 address, selected by the family
 * field.
 */
typedef struct pn_sockaddr {
    uint16_t family; /**< Address family: PN_AF_INET or PN_AF_INET6. */
    uint16_t port;   /**< Port number in host byte order. */

    union {
        uint8_t ipv4[4];  /**< IPv4 address bytes (network byte order). */
        uint8_t ipv6[16]; /**< IPv6 address bytes (network byte order). */
    } addr;               /**< Union of IPv4 and IPv6 address storage. */
} pn_sockaddr_t;

/**
 * @brief Poll event flags for socket readiness.
 *
 * Used by the poll abstraction to indicate which I/O events are ready on a
 * socket. Multiple flags may be bitwise-ORed together.
 */
#define PN_POLL_READ  0x01 /**< Socket is readable (data available). */
#define PN_POLL_WRITE 0x02 /**< Socket is writable (send buffer has space). */
#define PN_POLL_ERROR 0x04 /**< Error condition on socket. */
#define PN_POLL_HUP   0x08 /**< Hang-up (peer closed connection). */

#endif                     /* PN_SOCKET_TYPES_H */

/* Copyright (c) 2024-2026 PubNub Inc. */

#ifndef MOCK_DNS_SERVER_H
#define MOCK_DNS_SERVER_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file mock_dns_server.h
 * @brief Mock DNS server for testing the DNS resolver.
 *
 * Runs a UDP server in a background thread that responds to DNS queries with
 * crafted responses. Supports timeout simulation (staying silent) and
 * controlled response injection.
 */

/**
 * @brief Mock DNS server instance.
 *
 * Manages a background thread and UDP socket bound to 127.0.0.1.
 */
typedef struct mock_dns_server {
    int         fd;      /**< UDP socket file descriptor. */
    uint16_t    port;    /**< Bound port (in host byte order). */
    pthread_t   thread;  /**< Background thread handle. */
    uint8_t     running; /**< 1 = thread running, 0 = stopped. */
    uint8_t     silent;  /**< 1 = stay silent (timeout test), 0 = respond. */
    uint32_t    response_ttl_sec; /**< TTL for crafted responses. */
    const char* hostname;         /**< Expected hostname for responses. */
    uint32_t    a_addr;           /**< IPv4 address (network byte order). */
    const uint8_t* aaaa_addr; /**< IPv6 address (16 bytes, network byte order). */
} mock_dns_server_t;

/**
 * @brief Start the mock DNS server.
 *
 * Binds to 127.0.0.1 on a random port and spawns a background thread.
 *
 * @param server Mock server instance (caller-allocated).
 * @return 0 on success, -1 on socket/thread creation failure.
 */
int mock_dns_server_start(mock_dns_server_t* server);

/**
 * @brief Stop the mock DNS server.
 *
 * Joins the background thread and closes the socket. Safe to call multiple
 * times.
 *
 * @param server Mock server instance.
 */
void mock_dns_server_stop(mock_dns_server_t* server);

/**
 * @brief Get the server's bound port.
 *
 * @param server Mock server instance (must be started).
 * @return Port number in host byte order.
 */
uint16_t mock_dns_server_port(const mock_dns_server_t* server);

/**
 * @brief Configure the server to respond with a specific A record.
 *
 * @param server Mock server instance.
 * @param hostname Hostname to match (NUL-terminated).
 * @param a_addr IPv4 address in network byte order (or 0 to skip A response).
 * @param aaaa_addr IPv6 address (16 bytes, network byte order, or NULL to skip AAAA).
 * @param ttl_sec TTL for the response.
 */
void mock_dns_server_set_response(mock_dns_server_t* server,
                                  const char*        hostname,
                                  uint32_t           a_addr,
                                  const uint8_t*     aaaa_addr,
                                  uint32_t           ttl_sec);

/**
 * @brief Configure the server to stay silent (for timeout tests).
 *
 * @param server Mock server instance.
 * @param silent 1 = stay silent, 0 = respond normally.
 */
void mock_dns_server_set_silent(mock_dns_server_t* server, uint8_t silent);

#endif /* MOCK_DNS_SERVER_H */

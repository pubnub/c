/* Copyright (c) 2024-2026 PubNub Inc. */

#include "mock_dns_server.h"

#include "providers/transport/socket/dns/dns_codec.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/**
 * @brief Background thread function for the mock DNS server.
 *
 * Loops reading UDP datagrams and responding with crafted DNS responses.
 */
static void* mock_dns_server_thread_(void* arg)
{
    mock_dns_server_t* server = (mock_dns_server_t*)arg;

    while (0 != server->running) {
        uint8_t            recv_buf[512];
        struct sockaddr_in client_addr;
        socklen_t          client_addr_len = sizeof(client_addr);

        ssize_t recv_len = recvfrom(server->fd,
                                    recv_buf,
                                    sizeof(recv_buf),
                                    0,
                                    (struct sockaddr*)&client_addr,
                                    &client_addr_len);

        if (recv_len < 12) {
            /* Handles timeout (EAGAIN), errors, and truncated datagrams. */
            continue;
        }

        if (0 != server->silent) {
            continue;
        }

        uint16_t txn_id = (uint16_t)((recv_buf[0] << 8) | recv_buf[1]);

        uint16_t flags = (uint16_t)((recv_buf[2] << 8) | recv_buf[3]);
        uint16_t qtype =
            (uint16_t)((recv_buf[recv_len - 4] << 8) | recv_buf[recv_len - 3]);

        if (0 == (flags & 0x0100)) {
            continue;
        }

        uint8_t response_buf[512];
        size_t  response_len = 0;

        memcpy(response_buf, recv_buf, (size_t)recv_len);
        response_len = (size_t)recv_len;

        response_buf[2] = 0x81;
        response_buf[3] = 0x80;

        response_buf[6] = 0x00;
        response_buf[7] = 0x01;

        if (PN_DNS_TYPE_A == qtype && 0 != server->a_addr) {
            response_buf[response_len++] = 0xc0;
            response_buf[response_len++] = 0x0c;

            response_buf[response_len++] = 0x00;
            response_buf[response_len++] = 0x01;

            response_buf[response_len++] = 0x00;
            response_buf[response_len++] = 0x01;

            uint32_t ttl                 = server->response_ttl_sec;
            response_buf[response_len++] = (uint8_t)(ttl >> 24);
            response_buf[response_len++] = (uint8_t)(ttl >> 16);
            response_buf[response_len++] = (uint8_t)(ttl >> 8);
            response_buf[response_len++] = (uint8_t)(ttl);

            response_buf[response_len++] = 0x00;
            response_buf[response_len++] = 0x04;

            response_buf[response_len++] = (uint8_t)(server->a_addr >> 24);
            response_buf[response_len++] = (uint8_t)(server->a_addr >> 16);
            response_buf[response_len++] = (uint8_t)(server->a_addr >> 8);
            response_buf[response_len++] = (uint8_t)(server->a_addr);
        } else if (PN_DNS_TYPE_AAAA == qtype && NULL != server->aaaa_addr) {
            response_buf[response_len++] = 0xc0;
            response_buf[response_len++] = 0x0c;

            response_buf[response_len++] = 0x00;
            response_buf[response_len++] = 0x1c;

            response_buf[response_len++] = 0x00;
            response_buf[response_len++] = 0x01;

            uint32_t ttl                 = server->response_ttl_sec;
            response_buf[response_len++] = (uint8_t)(ttl >> 24);
            response_buf[response_len++] = (uint8_t)(ttl >> 16);
            response_buf[response_len++] = (uint8_t)(ttl >> 8);
            response_buf[response_len++] = (uint8_t)(ttl);

            response_buf[response_len++] = 0x00;
            response_buf[response_len++] = 0x10;

            memcpy(&response_buf[response_len], server->aaaa_addr, 16);
            response_len += 16;
        } else {
            response_buf[6] = 0x00;
            response_buf[7] = 0x00;
        }

        sendto(server->fd,
               response_buf,
               response_len,
               0,
               (struct sockaddr*)&client_addr,
               client_addr_len);
    }

    return NULL;
}

int mock_dns_server_start(mock_dns_server_t* server)
{
    if (NULL == server) {
        return -1;
    }

    memset(server, 0, sizeof(*server));

    server->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == server->fd) {
        return -1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port        = 0;

    if (-1 == bind(server->fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr))) {
        close(server->fd);
        return -1;
    }

    socklen_t addr_len = sizeof(bind_addr);
    if (-1 == getsockname(server->fd, (struct sockaddr*)&bind_addr, &addr_len)) {
        close(server->fd);
        return -1;
    }

    server->port    = ntohs(bind_addr.sin_port);
    server->running = 1;

    /* 200ms receive timeout so the thread wakes up and checks running flag. */
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 200000;
    setsockopt(server->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (0 != pthread_create(&server->thread, NULL, mock_dns_server_thread_, server)) {
        close(server->fd);
        return -1;
    }

    return 0;
}

void mock_dns_server_stop(mock_dns_server_t* server)
{
    if (NULL == server || 0 == server->running) {
        return;
    }

    server->running = 0;

    /* Close fd before join so recvfrom unblocks on Linux; on macOS the
     * SO_RCVTIMEO set at start ensures the thread wakes within 200ms. */
    if (-1 != server->fd) {
        close(server->fd);
        server->fd = -1;
    }

    pthread_join(server->thread, NULL);
}

uint16_t mock_dns_server_port(const mock_dns_server_t* server)
{
    if (NULL == server) {
        return 0;
    }

    return server->port;
}

void mock_dns_server_set_response(mock_dns_server_t* server,
                                  const char*        hostname,
                                  uint32_t           a_addr,
                                  const uint8_t*     aaaa_addr,
                                  uint32_t           ttl_sec)
{
    if (NULL == server) {
        return;
    }

    server->hostname         = hostname;
    server->a_addr           = a_addr;
    server->aaaa_addr        = aaaa_addr;
    server->response_ttl_sec = ttl_sec;
    server->silent           = 0;
}

void mock_dns_server_set_silent(mock_dns_server_t* server, uint8_t silent)
{
    if (NULL == server) {
        return;
    }

    server->silent = silent;
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public server foundation.
 * Invariants: versioned public configuration is validated before allocation,
 * string ownership is copied into the server object, and free is idempotent.
 * Ownership: the caller owns the input config; librdp_server owns copied
 * fields after successful creation.
 * Threading: no internal synchronization; callers serialize access to each
 * server object.
 * Trust boundary: server configuration is local application input and is
 * bounded before any future listener runtime consumes it.
 */

#include "server/server_internal.h"

#include "common/buffer.h"
#include "platform/socket.h"
#include "protocol/tpkt.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RDP_SERVER_DEFAULT_BACKLOG 4u
#define RDP_SERVER_DEFAULT_MAX_PEERS 16u
#define RDP_SERVER_DEFAULT_WIDTH 1024u
#define RDP_SERVER_DEFAULT_HEIGHT 768u
#define RDP_SERVER_MAX_TEXT 512u
#define RDP_SERVER_MAX_BACKLOG 128u
#define RDP_SERVER_MAX_PEERS 1024u
#define RDP_SERVER_MAX_DESKTOP_SIZE 8192u
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_REQUIRED 0x00000001u
#define RDP_SERVER_INITIAL_READ_MAX 65535u

static char* rdp_server_strdup_bounded(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text);
    if (length > RDP_SERVER_MAX_TEXT)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, length + 1u);
    return copy;
}

static int rdp_server_config_valid(const librdp_server_config* config)
{
    if (!config || config->version != LIBRDP_SERVER_CONFIG_VERSION ||
        config->size < sizeof(librdp_server_config))
        return 0;
    if (config->backlog > RDP_SERVER_MAX_BACKLOG || config->max_peers > RDP_SERVER_MAX_PEERS)
        return 0;
    if (config->width > RDP_SERVER_MAX_DESKTOP_SIZE || config->height > RDP_SERVER_MAX_DESKTOP_SIZE)
        return 0;
    if ((config->width == 0) != (config->height == 0))
        return 0;
    return 1;
}

librdp_status librdp_server_config_init(librdp_server_config* config)
{
    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));
    config->version = LIBRDP_SERVER_CONFIG_VERSION;
    config->size = (uint32_t)sizeof(*config);
    config->backlog = RDP_SERVER_DEFAULT_BACKLOG;
    config->max_peers = RDP_SERVER_DEFAULT_MAX_PEERS;
    config->width = RDP_SERVER_DEFAULT_WIDTH;
    config->height = RDP_SERVER_DEFAULT_HEIGHT;
    return LIBRDP_STATUS_OK;
}

librdp_server* librdp_server_new(const librdp_server_config* config)
{
    librdp_server* server = NULL;

    if (!rdp_server_config_valid(config))
        return NULL;
    server = (librdp_server*)calloc(1u, sizeof(*server));
    if (!server)
        return NULL;
    if (config->bind_address)
    {
        server->bind_address = rdp_server_strdup_bounded(config->bind_address);
        if (!server->bind_address)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->server_name)
    {
        server->server_name = rdp_server_strdup_bounded(config->server_name);
        if (!server->server_name)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    server->port = config->port;
    server->backlog = config->backlog ? config->backlog : RDP_SERVER_DEFAULT_BACKLOG;
    server->max_peers = config->max_peers ? config->max_peers : RDP_SERVER_DEFAULT_MAX_PEERS;
    server->width = config->width ? config->width : RDP_SERVER_DEFAULT_WIDTH;
    server->height = config->height ? config->height : RDP_SERVER_DEFAULT_HEIGHT;
    server->listen_fd = -1;
    return server;
}

void librdp_server_free(librdp_server* server)
{
    if (!server)
        return;
    librdp_server_close(server);
    free(server->bind_address);
    free(server->server_name);
    free(server);
}

/*
 * Bind one resolved address and transfer the resulting socket to the server
 * only after non-blocking setup, bind, listen, and local-port discovery all
 * succeed.
 */
static librdp_status rdp_server_bind_address(librdp_server* server, const struct addrinfo* address)
{
    int fd = -1;
    int reuse = 1;
    struct sockaddr_storage local;
    socklen_t local_len = (socklen_t)sizeof(local);

    fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd < 0)
        return LIBRDP_STATUS_IO_ERROR;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (rdp_socket_set_nonblocking(fd, 1) != 0 ||
        bind(fd, address->ai_addr, address->ai_addrlen) != 0 ||
        listen(fd, (int)server->backlog) != 0 ||
        getsockname(fd, (struct sockaddr*)&local, &local_len) != 0)
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (local.ss_family == AF_INET)
        server->local_port = ntohs(((const struct sockaddr_in*)&local)->sin_port);
    else if (local.ss_family == AF_INET6)
        server->local_port = ntohs(((const struct sockaddr_in6*)&local)->sin6_port);
    else
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    server->accepted_peers = 0;
    server->listen_fd = fd;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_listen(librdp_server* server)
{
    struct addrinfo hints;
    struct addrinfo* addresses = NULL;
    struct addrinfo* it = NULL;
    char service[16];
    const char* bind_address = NULL;
    librdp_status status = LIBRDP_STATUS_IO_ERROR;

    if (!server)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    bind_address = server->bind_address ? server->bind_address : "127.0.0.1";
    (void)snprintf(service, sizeof(service), "%u", (unsigned)server->port);
    if (getaddrinfo(bind_address, service, &hints, &addresses) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    for (it = addresses; it; it = it->ai_next)
    {
        status = rdp_server_bind_address(server, it);
        if (status == LIBRDP_STATUS_OK)
            break;
    }
    freeaddrinfo(addresses);
    return status;
}

void librdp_server_close(librdp_server* server)
{
    if (!server)
        return;
    if (server->listen_fd >= 0)
    {
        rdp_socket_close(server->listen_fd);
        server->listen_fd = -1;
    }
    server->local_port = 0;
}

uint16_t librdp_server_local_port(const librdp_server* server)
{
    if (!server || server->listen_fd < 0)
        return 0;
    return server->local_port;
}

librdp_status librdp_server_accept(librdp_server* server, int timeout_ms, librdp_server_peer** peer)
{
    struct pollfd pfd;
    int rc = 0;
    int fd = -1;
    librdp_server_peer* accepted = NULL;

    if (!server || !peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    if (server->listen_fd < 0)
        return LIBRDP_STATUS_STATE;
    if (server->accepted_peers >= server->max_peers)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    pfd.fd = server->listen_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (rc < 0)
        return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    fd = accept(server->listen_fd, NULL, NULL);
    if (fd < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    if (rdp_socket_set_nonblocking(fd, 1) != 0)
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    (void)rdp_socket_set_nodelay(fd);
    accepted = (librdp_server_peer*)calloc(1u, sizeof(*accepted));
    if (!accepted)
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    accepted->fd = fd;
    accepted->state = LIBRDP_SERVER_PEER_NEW;
    rdp_buffer_init(&accepted->input);
    *peer = accepted;
    server->accepted_peers++;
    return LIBRDP_STATUS_OK;
}

/*
 * Validate the first client request at the X.224 boundary. The minimal server
 * only needs to distinguish a real connection request from malformed input
 * before returning a protocol negotiation failure.
 */
static librdp_status rdp_server_validate_x224_connection_request(const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    uint8_t li = 0;

    if (!packet || !packet->payload || packet->payload_len < 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    data = packet->payload;
    li = data[0];
    if ((size_t)li + 1u > packet->payload_len || li < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (data[1] != 0xe0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_append_x224_failure(rdp_buffer* packet)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u8(&payload, 14u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0xd0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_be(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_be(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 3u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 8u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, RDP_SERVER_NEGOTIATION_FAILURE_SSL_REQUIRED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(packet, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status rdp_server_send_all(int fd, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t written = send(fd, data + offset, length - offset, 0);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            struct pollfd pfd;
            int rc = 0;

            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            rc = poll(&pfd, 1, 1000);
            if (rc == 0)
                return LIBRDP_STATUS_TIMEOUT;
            if (rc < 0 && errno == EINTR)
                continue;
            if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
                return LIBRDP_STATUS_IO_ERROR;
            continue;
        }
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_reject_supported_request(librdp_server_peer* peer)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&response);
    status = rdp_server_append_x224_failure(&response);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_all(peer->fd, response.data, response.length);
    rdp_buffer_free(&response);
    peer->state = status == LIBRDP_STATUS_OK ? LIBRDP_SERVER_PEER_CLOSED : LIBRDP_SERVER_PEER_FAILED;
    rdp_socket_close(peer->fd);
    peer->fd = -1;
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_UNSUPPORTED : status;
}

librdp_status librdp_server_peer_run_once(librdp_server_peer* peer, int timeout_ms)
{
    struct pollfd pfd;
    uint8_t chunk[2048];
    ssize_t read_len = 0;
    int poll_result = 0;
    rdp_tpkt packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    pfd.fd = peer->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    peer->state = LIBRDP_SERVER_PEER_NEGOTIATING;
    poll_result = poll(&pfd, 1, timeout_ms);
    if (poll_result == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (poll_result < 0)
        return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        return LIBRDP_STATUS_IO_ERROR;
    }
    read_len = recv(peer->fd, chunk, sizeof(chunk), 0);
    if (read_len == 0)
    {
        peer->state = LIBRDP_SERVER_PEER_CLOSED;
        rdp_socket_close(peer->fd);
        peer->fd = -1;
        return LIBRDP_STATUS_CLOSED;
    }
    if (read_len < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? LIBRDP_STATUS_TIMEOUT
                                                                         : LIBRDP_STATUS_IO_ERROR;
    if (peer->input.length + (size_t)read_len > RDP_SERVER_INITIAL_READ_MAX)
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    status = rdp_buffer_append(&peer->input, chunk, (size_t)read_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (peer->input.length < 4u)
        return LIBRDP_STATUS_TIMEOUT;
    if (peer->input.data[0] == 3u)
    {
        size_t total = ((size_t)peer->input.data[2] << 8) | (size_t)peer->input.data[3];

        if (total > peer->input.length)
            return LIBRDP_STATUS_TIMEOUT;
    }
    status = rdp_tpkt_parse(peer->input.data, peer->input.length, &packet);
    if (status != LIBRDP_STATUS_OK)
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        return status;
    }
    status = rdp_server_validate_x224_connection_request(&packet);
    if (status != LIBRDP_STATUS_OK)
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        return status;
    }
    return rdp_server_reject_supported_request(peer);
}

librdp_server_peer_state librdp_server_peer_get_state(const librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_SERVER_PEER_FAILED;
    return peer->state;
}

void librdp_server_peer_free(librdp_server_peer* peer)
{
    if (!peer)
        return;
    if (peer->fd >= 0)
        rdp_socket_close(peer->fd);
    rdp_buffer_free(&peer->input);
    free(peer);
}

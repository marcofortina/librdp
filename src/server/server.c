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
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"

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
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED 0x00000002u
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
    accepted->share_id = 0x00010001u;
    accepted->user_id = (uint16_t)RDP_MCS_BASE_CHANNEL_ID;
    accepted->width = (uint16_t)server->width;
    accepted->height = (uint16_t)server->height;
    rdp_buffer_init(&accepted->input);
    *peer = accepted;
    server->accepted_peers++;
    return LIBRDP_STATUS_OK;
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

static librdp_status rdp_server_send_x224_data(librdp_server_peer* peer, const void* payload, size_t payload_len)
{
    rdp_buffer x224;
    rdp_buffer tpkt;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&x224);
    rdp_buffer_init(&tpkt);
    status = rdp_x224_wrap_data(&x224, payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(&tpkt, x224.data, x224.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_all(peer->fd, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224);
    return status;
}

static librdp_status rdp_server_send_mcs_pdu(librdp_server_peer* peer, const rdp_buffer* mcs_pdu)
{
    if (!peer || !mcs_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_server_send_x224_data(peer, mcs_pdu->data, mcs_pdu->length);
}

static librdp_status rdp_server_send_slowpath(librdp_server_peer* peer, const rdp_buffer* slowpath_pdu)
{
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !slowpath_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_send_data_indication(&mcs,
                                                peer->user_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                slowpath_pdu->data,
                                                slowpath_pdu->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    return status;
}

static void rdp_server_close_peer(librdp_server_peer* peer, librdp_server_peer_state state)
{
    if (!peer)
        return;
    if (peer->fd >= 0)
    {
        rdp_socket_close(peer->fd);
        peer->fd = -1;
    }
    peer->state = state;
}

static librdp_status rdp_server_send_x224_failure(librdp_server_peer* peer, uint32_t failure_code)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_x224_build_negotiation_failure(&response, failure_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_all(peer->fd, response.data, response.length);
    rdp_buffer_free(&response);
    rdp_server_close_peer(peer, status == LIBRDP_STATUS_OK ? LIBRDP_SERVER_PEER_CLOSED
                                                           : LIBRDP_SERVER_PEER_FAILED);
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_UNSUPPORTED : status;
}

static librdp_status rdp_server_read_tpkt(librdp_server_peer* peer,
                                          int timeout_ms,
                                          rdp_tpkt* packet,
                                          size_t* packet_len)
{
    struct pollfd pfd;
    uint8_t chunk[2048];
    ssize_t read_len = 0;
    int poll_result = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total = 0;

    if (!peer || !packet || !packet_len || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0)
        return LIBRDP_STATUS_STATE;
    pfd.fd = peer->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
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
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
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
    if (peer->input.data[0] != 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = ((size_t)peer->input.data[2] << 8) | (size_t)peer->input.data[3];
    if (total < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (total > peer->input.length)
        return LIBRDP_STATUS_TIMEOUT;
    status = rdp_tpkt_parse(peer->input.data, total, packet);
    if (status != LIBRDP_STATUS_OK)
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        return status;
    }
    *packet_len = total;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_x224(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    rdp_x224_connection_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_x224_parse_connection_request(packet->payload, packet->payload_len, &request);
    if (status != LIBRDP_STATUS_OK)
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        return status;
    }
    if (request.negotiation.present)
        return rdp_server_send_x224_failure(peer, RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED);

    rdp_buffer_init(&response);
    status = rdp_x224_build_connection_confirm(&response, RDP_X224_PROTOCOL_STANDARD);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_all(peer->fd, response.data, response.length);
    rdp_buffer_free(&response);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->selected_protocol = RDP_X224_PROTOCOL_STANDARD;
    peer->state = LIBRDP_SERVER_PEER_X224_CONFIRMED;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_mcs_connect_initial(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    rdp_mcs_connect_initial mcs_initial;
    rdp_gcc_conference_request gcc_request;
    rdp_gcc_client_data_summary client_data;
    rdp_gcc_server_config server_config;
    rdp_buffer server_blocks;
    rdp_buffer gcc_response;
    rdp_buffer mcs_response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&server_blocks);
    rdp_buffer_init(&gcc_response);
    rdp_buffer_init(&mcs_response);
    memset(&server_config, 0, sizeof(server_config));
    status = rdp_x224_parse_data(packet->payload, packet->payload_len, &x224_data, &x224_data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_connect_initial(x224_data, x224_data_len, &mcs_initial);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_parse_conference_create_request(mcs_initial.user_data,
                                                         mcs_initial.user_data_len,
                                                         &gcc_request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_parse_client_data_blocks(gcc_request.user_data,
                                                  gcc_request.user_data_len,
                                                  &client_data);
    if (status == LIBRDP_STATUS_OK && (!client_data.has_core || !client_data.has_security || !client_data.has_network))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        peer->width = client_data.desktop_width ? client_data.desktop_width : peer->width;
        peer->height = client_data.desktop_height ? client_data.desktop_height : peer->height;
        peer->advertised_channel_count = client_data.channel_count;
        server_config.version = client_data.version ? client_data.version : RDP_GCC_CLIENT_VERSION_5;
        server_config.selected_protocol = RDP_X224_PROTOCOL_STANDARD;
        server_config.early_capability_flags = client_data.early_capability_flags;
        server_config.mcs_channel_id = (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID;
        server_config.channel_count = client_data.channel_count;
        status = rdp_gcc_write_server_data_blocks(&server_blocks, &server_config);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_conference_create_response(&gcc_response, server_blocks.data, server_blocks.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_connect_response(&mcs_response, gcc_response.data, gcc_response.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs_response);
    rdp_buffer_free(&mcs_response);
    rdp_buffer_free(&gcc_response);
    rdp_buffer_free(&server_blocks);

    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->state = LIBRDP_SERVER_PEER_MCS_CONNECTED;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_parse_x224_data_packet(const rdp_tpkt* packet, const uint8_t** data, size_t* data_len)
{
    if (!packet || !data || !data_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_x224_parse_data(packet->payload, packet->payload_len, data, data_len);
}

static librdp_status rdp_server_handle_erect_domain(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_erect_domain_request(data, data_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->state = LIBRDP_SERVER_PEER_DOMAIN_READY;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_attach_user(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_buffer confirm;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    rdp_buffer_init(&confirm);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_attach_user_request(data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_attach_user_confirm(&confirm, peer->user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &confirm);
    rdp_buffer_free(&confirm);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->state = LIBRDP_SERVER_PEER_USER_ATTACHED;
    return LIBRDP_STATUS_OK;
}

static int rdp_server_channel_allowed(const librdp_server_peer* peer, uint16_t channel_id)
{
    uint16_t first_static = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    uint16_t last_static = (uint16_t)(first_static + peer->advertised_channel_count);

    if (!peer)
        return 0;
    if (channel_id == peer->user_id || channel_id == RDP_MCS_GLOBAL_CHANNEL_ID)
        return 1;
    return channel_id >= first_static && channel_id < last_static;
}

static librdp_status rdp_server_send_demand_active(librdp_server_peer* peer)
{
    rdp_buffer demand;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&demand);
    status = rdp_slowpath_write_demand_active(&demand,
                                              peer->share_id,
                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                              peer->width,
                                              peer->height,
                                              "librdp");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &demand);
    rdp_buffer_free(&demand);
    if (status == LIBRDP_STATUS_OK)
        peer->state = LIBRDP_SERVER_PEER_ACTIVATING;
    return status;
}

static librdp_status rdp_server_handle_channel_join(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_channel_join_request request;
    rdp_buffer confirm;
    uint16_t required_joins = 0;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    rdp_buffer_init(&confirm);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_channel_join_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK &&
        (request.initiator != peer->user_id || !rdp_server_channel_allowed(peer, request.channel_id)))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_channel_join_confirm(&confirm, peer->user_id, request.channel_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &confirm);
    rdp_buffer_free(&confirm);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->joined_channel_count++;
    required_joins = (uint16_t)(peer->advertised_channel_count + 2u);
    if (peer->joined_channel_count >= required_joins)
        return rdp_server_send_demand_active(peer);
    peer->state = LIBRDP_SERVER_PEER_CHANNEL_JOINING;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_runtime_data(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_send_data_indication request;
    rdp_slowpath_share_control_header header;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_send_data_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK &&
        (request.initiator != peer->user_id || request.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_parse_share_control_header(request.payload, request.payload_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    if ((header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE)
    {
        peer->confirm_active_seen = 1;
        peer->state = LIBRDP_SERVER_PEER_ACTIVE;
        return LIBRDP_STATUS_OK;
    }
    if ((header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
    {
        rdp_slowpath_data_pdu pdu;

        status = rdp_slowpath_parse_data_pdu(request.payload, request.payload_len, &pdu);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            return status;
        }
        if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE)
            peer->synchronize_seen = 1;
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL)
            peer->control_seen = 1;
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST)
            peer->font_list_seen = 1;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_run_once(librdp_server_peer* peer, int timeout_ms)
{
    rdp_tpkt packet;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t packet_len = 0;

    if (!peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (peer->state == LIBRDP_SERVER_PEER_NEW)
        peer->state = LIBRDP_SERVER_PEER_NEGOTIATING;
    status = rdp_server_read_tpkt(peer, timeout_ms, &packet, &packet_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (peer->state == LIBRDP_SERVER_PEER_NEGOTIATING)
        status = rdp_server_handle_x224(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_X224_CONFIRMED)
        status = rdp_server_handle_mcs_connect_initial(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_MCS_CONNECTED)
        status = rdp_server_handle_erect_domain(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_DOMAIN_READY)
        status = rdp_server_handle_attach_user(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_USER_ATTACHED ||
             peer->state == LIBRDP_SERVER_PEER_CHANNEL_JOINING)
        status = rdp_server_handle_channel_join(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_ACTIVATING || peer->state == LIBRDP_SERVER_PEER_ACTIVE)
        status = rdp_server_handle_runtime_data(peer, &packet);
    else
        status = LIBRDP_STATUS_STATE;
    if (packet_len > 0 && peer->input.length >= packet_len)
    {
        librdp_status consume_status = rdp_buffer_consume(&peer->input, packet_len);

        if (status == LIBRDP_STATUS_OK && consume_status != LIBRDP_STATUS_OK)
            status = consume_status;
    }
    return status;
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

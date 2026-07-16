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
#include "common/stream.h"
#include "common/trace.h"
#include "graphics/bitmap.h"
#include "licensing/licensing.h"
#include "platform/socket.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"

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
#define RDP_SERVER_KNOWN_FEATURES                                                                                   \
    ((uint32_t)LIBRDP_FEATURE_AUDIO_OUTPUT | (uint32_t)LIBRDP_FEATURE_AUDIO_INPUT |                                  \
     (uint32_t)LIBRDP_FEATURE_VIDEO | (uint32_t)LIBRDP_FEATURE_CAMERA |                                              \
     (uint32_t)LIBRDP_FEATURE_SMARTCARD | (uint32_t)LIBRDP_FEATURE_USB |                                             \
     (uint32_t)LIBRDP_FEATURE_PNP | (uint32_t)LIBRDP_FEATURE_WEBAUTHN |                                              \
     (uint32_t)LIBRDP_FEATURE_RAIL | (uint32_t)LIBRDP_FEATURE_CR2 |                                                  \
     (uint32_t)LIBRDP_FEATURE_ECHO | (uint32_t)LIBRDP_FEATURE_TELEMETRY |                                            \
     (uint32_t)LIBRDP_FEATURE_MULTITRANSPORT | (uint32_t)LIBRDP_FEATURE_DESKTOP_COMPOSITION |                        \
     (uint32_t)LIBRDP_FEATURE_DISPLAY_CONTROL | (uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT |                             \
     (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT | (uint32_t)LIBRDP_FEATURE_GEOMETRY_TRACKING |                          \
     (uint32_t)LIBRDP_FEATURE_MULTIPARTY)

static void rdp_server_metric_add(uint64_t* metric, uint64_t value)
{
    if (!metric)
        return;
    if (UINT64_MAX - *metric < value)
        *metric = UINT64_MAX;
    else
        *metric += value;
}

static int rdp_server_valid_feature_mask(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return value != 0 && (value & ~RDP_SERVER_KNOWN_FEATURES) == 0;
}

static int rdp_server_valid_single_feature(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return rdp_server_valid_feature_mask(feature) && (value & (value - 1u)) == 0;
}

static int rdp_server_feature_has_runtime(librdp_feature feature)
{
    (void)feature;
    return 0;
}

static void rdp_server_fill_feature_status(uint32_t requested_features,
                                           librdp_feature feature,
                                           librdp_feature_status* status)
{
    memset(status, 0, sizeof(*status));
    status->feature = feature;
    status->requested = (requested_features & (uint32_t)feature) != 0;
    status->built = rdp_server_feature_has_runtime(feature);
    status->backend_ready = status->built;
    if (!status->requested)
        status->reason = LIBRDP_FEATURE_REASON_NOT_REQUESTED;
    else if (!status->built)
        status->reason = LIBRDP_FEATURE_REASON_NOT_BUILT;
    else
        status->reason = LIBRDP_FEATURE_REASON_NOT_NEGOTIATED;
}

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

librdp_status librdp_server_input_event_init(librdp_server_input_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_INPUT_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_static_channel_info_init(librdp_server_static_channel_info* info)
{
    if (!info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    info->version = LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION;
    info->size = (uint32_t)sizeof(*info);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_metrics_init(librdp_server_metrics* metrics)
{
    if (!metrics)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = LIBRDP_SERVER_METRICS_VERSION;
    metrics->size = (uint32_t)sizeof(*metrics);
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

librdp_status librdp_server_enable_feature(librdp_server* server, librdp_feature feature, int enabled)
{
    if (!server || !rdp_server_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        server->requested_features |= (uint32_t)feature;
    else
        server->requested_features &= ~((uint32_t)feature);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_get_feature_status(const librdp_server* server,
                                               librdp_feature feature,
                                               librdp_feature_status* status)
{
    if (!server || !status || !rdp_server_valid_single_feature(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_fill_feature_status(server->requested_features, feature, status);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_get_pollfds(librdp_server* server,
                                        struct pollfd* fds,
                                        size_t capacity,
                                        size_t* count)
{
    if (!server || !count || (!fds && capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd < 0)
        return LIBRDP_STATUS_STATE;
    *count = 1;
    if (capacity == 0)
        return LIBRDP_STATUS_OK;
    if (capacity < 1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&fds[0], 0, sizeof(fds[0]));
    fds[0].fd = server->listen_fd;
    fds[0].events = POLLIN;
    return LIBRDP_STATUS_OK;
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
    accepted->requested_features = server->requested_features;
    accepted->pending_revents = 0;
    if (server->server_name)
    {
        accepted->server_name = rdp_server_strdup_bounded(server->server_name);
        if (!accepted->server_name)
        {
            free(accepted);
            rdp_socket_close(fd);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    (void)librdp_server_metrics_init(&accepted->metrics);
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

static librdp_status rdp_server_peer_send_all(librdp_server_peer* peer, const uint8_t* data, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_send_all(peer->fd, data, length);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.bytes_written, (uint64_t)length);
    return status;
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
        status = rdp_server_peer_send_all(peer, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224);
    return status;
}

static librdp_status rdp_server_send_mcs_pdu(librdp_server_peer* peer, const rdp_buffer* mcs_pdu)
{
    if (!peer || !mcs_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    librdp_status status = rdp_server_send_x224_data(peer, mcs_pdu->data, mcs_pdu->length);

    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    return status;
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
    {
        status = rdp_server_peer_send_all(peer, response.data, response.length);
        if (status == LIBRDP_STATUS_OK)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
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
    if (peer->pending_revents != 0)
    {
        pfd.revents = peer->pending_revents;
        peer->pending_revents = 0;
        poll_result = 1;
    }
    else
    {
        poll_result = poll(&pfd, 1, timeout_ms);
        if (poll_result == 0)
            return LIBRDP_STATUS_TIMEOUT;
        if (poll_result < 0)
            return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    }
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
    rdp_server_metric_add(&peer->metrics.bytes_read, (uint64_t)read_len);
    if (peer->input.length + (size_t)read_len > RDP_SERVER_INITIAL_READ_MAX)
    {
        peer->state = LIBRDP_SERVER_PEER_FAILED;
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
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
    rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
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
    {
        status = rdp_server_peer_send_all(peer, response.data, response.length);
        if (status == LIBRDP_STATUS_OK)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
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
        memset(peer->advertised_channels, 0, sizeof(peer->advertised_channels));
        memset(peer->advertised_channel_ids, 0, sizeof(peer->advertised_channel_ids));
        memset(peer->advertised_channel_joined, 0, sizeof(peer->advertised_channel_joined));
        for (uint16_t channel_index = 0; channel_index < client_data.channel_count; channel_index++)
        {
            peer->advertised_channels[channel_index] = client_data.channels[channel_index];
            peer->advertised_channel_ids[channel_index] =
                (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u + channel_index);
        }
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

static int rdp_server_static_channel_index(const librdp_server_peer* peer, uint16_t channel_id, uint16_t* index)
{
    uint16_t first_static = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);

    if (!peer || channel_id < first_static)
        return 0;
    if ((uint32_t)(channel_id - first_static) >= peer->advertised_channel_count)
        return 0;
    if (index)
        *index = (uint16_t)(channel_id - first_static);
    return 1;
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
                                              peer->server_name ? peer->server_name : "librdp-server");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &demand);
    rdp_buffer_free(&demand);
    if (status == LIBRDP_STATUS_OK)
        peer->state = LIBRDP_SERVER_PEER_ACTIVATING;
    return status;
}

/*
 * Complete the permissive server-side licensing path used by the current
 * Standard RDP server runtime. The alert is sent before Demand Active so real
 * clients leave their licensing state machine before activation parsing.
 */
static librdp_status rdp_server_send_valid_client_license(librdp_server_peer* peer)
{
    rdp_buffer license;
    rdp_buffer security_payload;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&license);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&mcs);
    status = rdp_license_write_error_alert(&license,
                                           RDP_LICENSE_VERSION_3,
                                           RDP_LICENSE_ERROR_STATUS_VALID_CLIENT,
                                           RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION,
                                           RDP_LICENSE_BLOB_ERROR,
                                           NULL,
                                           0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_header(&security_payload,
                                           (uint16_t)(RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&security_payload, license.data, license.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_send_data_indication(&mcs,
                                                    peer->user_id,
                                                    (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                    security_payload.data,
                                                    security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&license);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->licensing_done = 1;
        peer->state = LIBRDP_SERVER_PEER_LICENSING;
    }
    return status;
}

static size_t rdp_server_channel_name_len(const char name[8])
{
    size_t length = 0;

    while (length < 8u && name[length] != '\0')
        length++;
    return length;
}

static void rdp_server_copy_channel_name(char output[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY], const char name[8])
{
    size_t length = rdp_server_channel_name_len(name);

    memset(output, 0, LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY);
    if (length > 0)
        memcpy(output, name, length);
}

static void rdp_server_emit_input(librdp_server_peer* peer, const librdp_server_input_event* event)
{
    if (peer && event)
        rdp_server_metric_add(&peer->metrics.input_events, 1u);
    if (peer && peer->input_callback)
        peer->input_callback(peer, event, peer->input_callback_user_data);
}

static librdp_status rdp_server_send_activation_responses(librdp_server_peer* peer)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_slowpath_write_server_synchronize(&response,
                                                   peer->share_id,
                                                   (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                   peer->user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &response);
    response.length = 0;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_server_control(&response,
                                                   peer->share_id,
                                                   (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                   4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &response);
    response.length = 0;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_server_control(&response,
                                                   peer->share_id,
                                                   (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                   2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &response);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_send_font_map(librdp_server_peer* peer)
{
    rdp_buffer font_map;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&font_map);
    status = rdp_slowpath_write_server_font_map(&font_map,
                                                peer->share_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &font_map);
    rdp_buffer_free(&font_map);
    return status;
}

static librdp_status rdp_server_handle_input_events(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len)
{
    rdp_stream stream;
    uint16_t event_count = 0;
    uint16_t pad = 0;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u16_le(&stream, &event_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        event_count > 256u ||
        pad != 0 ||
        rdp_stream_remaining(&stream) != (size_t)event_count * 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < event_count; i++)
    {
        librdp_server_input_event event;
        uint16_t message_type = 0;

        if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &event.event_time) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &message_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &event.flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &event.param1) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &event.param2) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (message_type == 0x0004u)
            event.type = LIBRDP_SERVER_INPUT_SCANCODE_KEY;
        else if (message_type == 0x0005u)
            event.type = LIBRDP_SERVER_INPUT_UNICODE_KEY;
        else if (message_type == 0x8001u)
        {
            event.type = LIBRDP_SERVER_INPUT_MOUSE;
            event.x = event.param1;
            event.y = event.param2;
        }
        else if (message_type == 0x8002u)
        {
            event.type = LIBRDP_SERVER_INPUT_EXTENDED_MOUSE;
            event.x = event.param1;
            event.y = event.param2;
        }
        else
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_server_emit_input(peer, &event);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_refresh_rect(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len);

static librdp_status rdp_server_handle_suppress_output(librdp_server_peer* peer,
                                                       const uint8_t* payload,
                                                       size_t payload_len)
{
    librdp_server_input_event event;

    if (!peer || !payload || (payload_len != 4u && payload_len != 12u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    event.type = LIBRDP_SERVER_INPUT_SUPPRESS_OUTPUT;
    event.flags = payload[0] != 0 ? 1u : 0u;
    peer->updates_suppressed = (uint8_t)(event.flags ? 0u : 1u);
    if (payload_len == 12u)
    {
        uint16_t right = 0;
        uint16_t bottom = 0;

        event.x = (uint16_t)((uint16_t)payload[4] | ((uint16_t)payload[5] << 8));
        event.y = (uint16_t)((uint16_t)payload[6] | ((uint16_t)payload[7] << 8));
        right = (uint16_t)((uint16_t)payload[8] | ((uint16_t)payload[9] << 8));
        bottom = (uint16_t)((uint16_t)payload[10] | ((uint16_t)payload[11] << 8));
        if (right < event.x || bottom < event.y)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        event.width = (uint16_t)(right - event.x + 1u);
        event.height = (uint16_t)(bottom - event.y + 1u);
    }
    rdp_server_emit_input(peer, &event);
    return LIBRDP_STATUS_OK;
}

static int rdp_server_rect_valid(const librdp_server_peer* peer,
                                 uint32_t x,
                                 uint32_t y,
                                 uint32_t width,
                                 uint32_t height)
{
    if (!peer || width == 0 || height == 0)
        return 0;
    if (x >= peer->width || y >= peer->height)
        return 0;
    if (width > (uint32_t)peer->width - x || height > (uint32_t)peer->height - y)
        return 0;
    return 1;
}

static librdp_status rdp_server_surface_allocate(librdp_server_peer* peer, uint32_t width, uint32_t height)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t total = 0;

    if (!peer || width == 0 || height == 0 ||
        width > RDP_SERVER_MAX_DESKTOP_SIZE ||
        height > RDP_SERVER_MAX_DESKTOP_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    stride = width * 4u;
    if (height > SIZE_MAX / stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = stride * height;
    pixels = (uint8_t*)calloc(1u, total);
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;
    free(peer->framebuffer);
    peer->framebuffer = pixels;
    peer->framebuffer_len = total;
    peer->framebuffer_stride = stride;
    peer->width = (uint16_t)width;
    peer->height = (uint16_t)height;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_surface_ensure(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->framebuffer)
        return LIBRDP_STATUS_OK;
    return rdp_server_surface_allocate(peer, peer->width, peer->height);
}

/*
 * Serialize one already-bounded BGRA tile as an uncompressed slow-path bitmap
 * update. The caller owns tiling and MCS payload sizing; this helper validates
 * 16-bit wire coordinates, copies rows bottom-up as required by bitmap updates,
 * and fails without partially mutating peer state when any nested writer rejects
 * the tile.
 */
static librdp_status rdp_server_present_tile(librdp_server_peer* peer,
                                             uint32_t x,
                                             uint32_t y,
                                             uint32_t width,
                                             uint32_t height)
{
    rdp_buffer raw;
    rdp_buffer update;
    rdp_bitmap_rect rect;
    size_t dst_stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&raw);
    rdp_buffer_init(&update);
    if (!rdp_server_rect_valid(peer, x, y, width, height) ||
        width > 0xffffu ||
        height > 0xffffu ||
        x + width - 1u > 0xffffu ||
        y + height - 1u > 0xffffu)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.invalid",
                        "x=%u y=%u width=%u height=%u peer_width=%u peer_height=%u",
                        x,
                        y,
                        width,
                        height,
                        peer ? peer->width : 0,
                        peer ? peer->height : 0);
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }
    dst_stride = width * 4u;
    if (height > SIZE_MAX / dst_stride)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.overflow",
                        "width=%u height=%u stride=%u",
                        width,
                        height,
                        (unsigned)dst_stride);
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }
    status = rdp_buffer_reserve(&raw, dst_stride * height);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    raw.length = dst_stride * height;
    for (uint32_t row = 0; row < height; row++)
    {
        const uint8_t* src = peer->framebuffer +
                             ((size_t)(y + height - 1u - row) * peer->framebuffer_stride) +
                             ((size_t)x * 4u);
        uint8_t* dst = raw.data + ((size_t)row * dst_stride);

        memcpy(dst, src, dst_stride);
    }
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = (uint16_t)x;
    rect.dest_top = (uint16_t)y;
    rect.dest_right = (uint16_t)(x + width - 1u);
    rect.dest_bottom = (uint16_t)(y + height - 1u);
    rect.width = (uint16_t)width;
    rect.height = (uint16_t)height;
    rect.bits_per_pixel = 32;
    rect.flags = 0;
    rect.data = raw.data;
    rect.data_len = (uint32_t)raw.length;
    status = rdp_bitmap_write_update(&update, &rect, 1);
    if (status != LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.bitmap_failed",
                        "status=%s x=%u y=%u width=%u height=%u raw_len=%u",
                        librdp_status_name(status),
                        x,
                        y,
                        width,
                        height,
                        (unsigned)raw.length);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_buffer slowpath;

        rdp_buffer_init(&slowpath);
        status = rdp_slowpath_write_data_pdu(&slowpath,
                                             peer->share_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             RDP_SLOWPATH_DATA_PDU_UPDATE,
                                             update.data,
                                             update.length);
        if (status != LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.surface.tile.slowpath_failed",
                            "status=%s x=%u y=%u width=%u height=%u update_len=%u",
                            librdp_status_name(status),
                            x,
                            y,
                            width,
                            height,
                            (unsigned)update.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_slowpath(peer, &slowpath);
        if (status != LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.surface.tile.send_failed",
                            "status=%s x=%u y=%u width=%u height=%u slowpath_len=%u",
                            librdp_status_name(status),
                            x,
                            y,
                            width,
                            height,
                            (unsigned)slowpath.length);
        rdp_buffer_free(&slowpath);
    }

out:
    rdp_buffer_free(&update);
    rdp_buffer_free(&raw);
    return status;
}

/*
 * Present a dirty rectangle by splitting it into MCS-sized bitmap tiles. The
 * limiting budget is the T.125 SendDataIndication payload size, so the tile
 * planner accounts for bitmap-update and slow-path headers before choosing
 * horizontal and vertical chunks. Any failed tile aborts the presentation and
 * leaves the stored framebuffer intact for a later retry.
 */
static librdp_status rdp_server_surface_present_rect(librdp_server_peer* peer,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height)
{
    const size_t max_mcs_payload = 0x7fffu;
    const size_t bitmap_update_overhead = 22u;
    const size_t slowpath_data_overhead = 18u;
    size_t max_raw_tile = 0;
    uint32_t max_tile_width = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || peer->updates_suppressed)
        return LIBRDP_STATUS_STATE;
    status = rdp_server_surface_ensure(peer);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_server_rect_valid(peer, x, y, width, height))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.present.invalid",
                        "x=%u y=%u width=%u height=%u peer_width=%u peer_height=%u",
                        x,
                        y,
                        width,
                        height,
                        peer->width,
                        peer->height);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (max_mcs_payload <= bitmap_update_overhead + slowpath_data_overhead)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    max_raw_tile = max_mcs_payload - bitmap_update_overhead - slowpath_data_overhead;
    max_tile_width = (uint32_t)(max_raw_tile / 4u);
    if (max_tile_width == 0 || width > UINT32_MAX - x || height > UINT32_MAX - y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.surface.present.start",
                          "x=%u y=%u width=%u height=%u max_tile_width=%u peer_width=%u peer_height=%u",
                          x,
                          y,
                          width,
                          height,
                          max_tile_width,
                          peer->width,
                          peer->height);
    for (uint32_t column = 0; column < width; column += max_tile_width)
    {
        uint32_t tile_width = width - column;
        uint32_t rows_per_tile = 0;

        if (tile_width > max_tile_width)
            tile_width = max_tile_width;
        rows_per_tile = (uint32_t)(max_raw_tile / ((size_t)tile_width * 4u));
        if (rows_per_tile == 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        for (uint32_t row = 0; row < height; row += rows_per_tile)
        {
            uint32_t tile_height = height - row;

            if (tile_height > rows_per_tile)
                tile_height = rows_per_tile;
            status = rdp_server_present_tile(peer, x + column, y + row, tile_width, tile_height);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "server.surface.present.failed",
                                "status=%s column=%u row=%u tile_width=%u tile_height=%u",
                                librdp_status_name(status),
                                column,
                                row,
                                tile_width,
                                tile_height);
                return status;
            }
        }
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.surface.present.done",
                          "x=%u y=%u width=%u height=%u",
                          x,
                          y,
                          width,
                          height);
    rdp_server_metric_add(&peer->metrics.surface_updates, 1u);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_refresh_rect(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len)
{
    rdp_stream stream;
    uint16_t count = 0;
    uint16_t pad = 0;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        count > 64u ||
        pad != 0 ||
        rdp_stream_remaining(&stream) != (size_t)count * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < count; i++)
    {
        librdp_server_input_event event;
        uint16_t left = 0;
        uint16_t top = 0;
        uint16_t right = 0;
        uint16_t bottom = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &left) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &top) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &right) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &bottom) != LIBRDP_STATUS_OK ||
            right < left ||
            bottom < top)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        event.type = LIBRDP_SERVER_INPUT_REFRESH_RECT;
        event.x = left;
        event.y = top;
        event.width = (uint16_t)(right - left + 1u);
        event.height = (uint16_t)(bottom - top + 1u);
        rdp_server_emit_input(peer, &event);
        if (peer->framebuffer && !peer->updates_suppressed &&
            rdp_server_rect_valid(peer, event.x, event.y, event.width, event.height))
        {
            status = rdp_server_surface_present_rect(peer, event.x, event.y, event.width, event.height);
            if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_STATE)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_input_callback(librdp_server_peer* peer,
                                                    librdp_server_input_callback callback,
                                                    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->input_callback = callback;
    peer->input_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_channel_callback(librdp_server_peer* peer,
                                                      librdp_server_channel_callback callback,
                                                      void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->channel_callback = callback;
    peer->channel_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

uint32_t librdp_server_peer_static_channel_count(const librdp_server_peer* peer)
{
    return peer ? peer->advertised_channel_count : 0;
}

librdp_status librdp_server_peer_static_channel_at(const librdp_server_peer* peer,
                                                   uint32_t index,
                                                   librdp_server_static_channel_info* info)
{
    uint16_t channel_index = 0;

    if (!peer || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (index >= peer->advertised_channel_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_server_static_channel_info_init(info) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel_index = (uint16_t)index;
    info->channel_id = peer->advertised_channel_ids[channel_index];
    info->flags = peer->advertised_channels[channel_index].flags;
    info->joined = peer->advertised_channel_joined[channel_index] != 0;
    rdp_server_copy_channel_name(info->name, peer->advertised_channels[channel_index].name);
    return LIBRDP_STATUS_OK;
}

uint32_t librdp_server_peer_desktop_width(const librdp_server_peer* peer)
{
    return peer ? peer->width : 0;
}

uint32_t librdp_server_peer_desktop_height(const librdp_server_peer* peer)
{
    return peer ? peer->height : 0;
}

librdp_status librdp_server_peer_surface_resize(librdp_server_peer* peer, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;
    int was_active = 0;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    was_active = peer->state == LIBRDP_SERVER_PEER_ACTIVE;
    status = rdp_server_surface_allocate(peer, width, height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (was_active)
    {
        peer->confirm_active_seen = 0;
        peer->synchronize_seen = 0;
        peer->control_seen = 0;
        peer->font_list_seen = 0;
        status = rdp_server_send_demand_active(peer);
    }
    return status;
}

librdp_status librdp_server_peer_surface_blit_bgra32(librdp_server_peer* peer,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     size_t stride,
                                                     const uint8_t* pixels)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !pixels || stride < (size_t)width * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_surface_ensure(peer);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_server_rect_valid(peer, x, y, width, height))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (uint32_t row = 0; row < height; row++)
    {
        const uint8_t* src = pixels + ((size_t)row * stride);
        uint8_t* dst = peer->framebuffer + ((size_t)(y + row) * peer->framebuffer_stride) + ((size_t)x * 4u);

        memcpy(dst, src, (size_t)width * 4u);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_surface_present(librdp_server_peer* peer,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    return rdp_server_surface_present_rect(peer, x, y, width, height);
}

librdp_status librdp_server_peer_send_channel_data(librdp_server_peer* peer,
                                                   uint16_t channel_id,
                                                   const void* data,
                                                   size_t data_len)
{
    uint16_t channel_index = 0;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_server_static_channel_index(peer, channel_id, &channel_index) ||
        !peer->advertised_channel_joined[channel_index])
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > 0x7fffu)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_send_data_indication(&mcs, peer->user_id, channel_id, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_server_metric_add(&peer->metrics.static_channel_out, 1u);
        rdp_server_metric_add(&peer->metrics.static_channel_bytes_out, (uint64_t)data_len);
    }
    rdp_buffer_free(&mcs);
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
    if (rdp_server_static_channel_index(peer, request.channel_id, NULL))
    {
        uint16_t channel_index = 0;

        (void)rdp_server_static_channel_index(peer, request.channel_id, &channel_index);
        peer->advertised_channel_joined[channel_index] = 1;
    }
    peer->joined_channel_count++;
    required_joins = (uint16_t)(peer->advertised_channel_count + 2u);
    if (peer->joined_channel_count >= required_joins)
        return rdp_server_send_valid_client_license(peer);
    peer->state = LIBRDP_SERVER_PEER_CHANNEL_JOINING;
    return LIBRDP_STATUS_OK;
}

/*
 * Validate the client-info PDU sent after licensing and before activation.
 * Only field lengths are retained in trace; credentials stay in the borrowed
 * packet memory and are never copied into the server peer.
 */
static librdp_status rdp_server_handle_client_info(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_send_data_indication request;
    rdp_client_info_summary summary;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_send_data_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK &&
        (request.initiator != peer->user_id || request.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_parse_client_info_pdu(request.payload, request.payload_len, &summary);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->client_info_seen = 1;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "server.client_info.received",
                    "flags=%u username_bytes=%u domain_bytes=%u password_bytes=%u",
                    summary.flags,
                    summary.username_bytes,
                    summary.domain_bytes,
                    summary.password_bytes);
    status = rdp_server_send_demand_active(peer);
    if (status != LIBRDP_STATUS_OK)
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
    return status;
}

static librdp_status rdp_server_unwrap_optional_security_header(const uint8_t* input,
                                                                size_t input_len,
                                                                rdp_buffer* storage,
                                                                const uint8_t** output,
                                                                size_t* output_len)
{
    uint16_t flags = 0;
    uint16_t flags_hi = 0;
    uint16_t allowed = (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_ENCRYPT | RDP_SEC_INFO_PKT |
                                  RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC |
                                  RDP_SEC_SECURE_CHECKSUM);

    if ((!input && input_len > 0) || !storage || !output || !output_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = input;
    *output_len = input_len;
    if (input_len < 4u)
        return LIBRDP_STATUS_OK;
    flags = (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
    flags_hi = (uint16_t)((uint16_t)input[2] | ((uint16_t)input[3] << 8));
    if (flags_hi != 0 || (flags & (uint16_t)~allowed) != 0)
        return LIBRDP_STATUS_OK;
    if ((flags & RDP_SEC_ENCRYPT) != 0)
        return LIBRDP_STATUS_UNSUPPORTED;
    storage->length = 0;
    if (rdp_security_unwrap_pdu(NULL, input, input_len, storage, NULL) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_OK;
    *output = storage->data;
    *output_len = storage->length;
    return LIBRDP_STATUS_OK;
}

/*
 * Dispatch one post-MCS client packet. Global-channel slow-path data drives
 * activation, input, refresh, and output-suppression state; joined static
 * channels are routed to the application callback with borrowed payload
 * views. Malformed runtime input closes the peer because continuing would
 * desynchronize channel and activation state.
 */
static librdp_status rdp_server_handle_runtime_data(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_send_data_indication request;
    rdp_slowpath_share_control_header header;
    rdp_buffer security_payload;
    const uint8_t* runtime_payload = NULL;
    size_t runtime_payload_len = 0;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    rdp_buffer_init(&security_payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_send_data_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK && request.initiator != peer->user_id)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "server.mcs.send_data.request",
                              "state=%d initiator=%u channel_id=%u payload_len=%u",
                              (int)peer->state,
                              request.initiator,
                              request.channel_id,
                              (unsigned)request.payload_len);
        rdp_trace_hexdump("server.mcs.send_data.request",
                          RDP_TRACE_SENSITIVITY_HEADER,
                          request.payload,
                          request.payload_len);
        status = rdp_server_unwrap_optional_security_header(request.payload,
                                                            request.payload_len,
                                                            &security_payload,
                                                            &runtime_payload,
                                                            &runtime_payload_len);
    }
    if (status == LIBRDP_STATUS_OK && request.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        uint16_t channel_index = 0;

        if (!rdp_server_static_channel_index(peer, request.channel_id, &channel_index) ||
            !peer->advertised_channel_joined[channel_index])
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
        {
            rdp_server_metric_add(&peer->metrics.static_channel_in, 1u);
            rdp_server_metric_add(&peer->metrics.static_channel_bytes_in, (uint64_t)runtime_payload_len);
            if (peer->channel_callback)
            {
                char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
                librdp_server_channel_event event;

                rdp_server_copy_channel_name(name, peer->advertised_channels[channel_index].name);
                memset(&event, 0, sizeof(event));
                event.version = LIBRDP_SERVER_CHANNEL_EVENT_VERSION;
                event.size = (uint32_t)sizeof(event);
                event.channel_id = request.channel_id;
                event.name = name;
                event.name_len = strlen(name);
                event.data = runtime_payload;
                event.data_len = runtime_payload_len;
                peer->channel_callback(peer, &event, peer->channel_callback_user_data);
            }
        }
        if (status != LIBRDP_STATUS_OK)
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_parse_share_control_header(runtime_payload, runtime_payload_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.slowpath.header.failed",
                        "status=%s payload_len=%u",
                        librdp_status_name(status),
                        (unsigned)runtime_payload_len);
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.slowpath.header",
                          "pdu_type=%u payload_len=%u",
                          header.pdu_type,
                          (unsigned)runtime_payload_len);
    if ((header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE)
    {
        peer->confirm_active_seen = 1;
        status = rdp_server_send_activation_responses(peer);
        if (status != LIBRDP_STATUS_OK)
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    if ((header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
    {
        rdp_slowpath_data_pdu pdu;
        librdp_server_input_event event;

        status = rdp_slowpath_parse_data_pdu(runtime_payload, runtime_payload_len, &pdu);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            rdp_buffer_free(&security_payload);
            return status;
        }
        if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE)
        {
            peer->synchronize_seen = 1;
            if (librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK)
            {
                event.type = LIBRDP_SERVER_INPUT_SYNCHRONIZE;
                rdp_server_emit_input(peer, &event);
            }
        }
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL)
        {
            peer->control_seen = 1;
            if (librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK && pdu.payload_len >= 2u)
            {
                event.type = LIBRDP_SERVER_INPUT_CONTROL;
                event.control_action = (uint16_t)((uint16_t)pdu.payload[0] | ((uint16_t)pdu.payload[1] << 8));
                rdp_server_emit_input(peer, &event);
            }
        }
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST)
        {
            peer->font_list_seen = 1;
            if (librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK)
            {
                event.type = LIBRDP_SERVER_INPUT_FONT_LIST;
                rdp_server_emit_input(peer, &event);
            }
            status = rdp_server_send_font_map(peer);
            if (status == LIBRDP_STATUS_OK)
                peer->state = LIBRDP_SERVER_PEER_ACTIVE;
            else
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            rdp_buffer_free(&security_payload);
            return status;
        }
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT)
            status = rdp_server_handle_input_events(peer, pdu.payload, pdu.payload_len);
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_REFRESH_RECT)
            status = rdp_server_handle_refresh_rect(peer, pdu.payload, pdu.payload_len);
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT)
            status = rdp_server_handle_suppress_output(peer, pdu.payload, pdu.payload_len);
        if (status != LIBRDP_STATUS_OK)
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    rdp_buffer_free(&security_payload);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_get_pollfds(librdp_server_peer* peer,
                                             struct pollfd* fds,
                                             size_t capacity,
                                             size_t* count)
{
    if (!peer || !count || (!fds && capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    *count = 1;
    if (capacity == 0)
        return LIBRDP_STATUS_OK;
    if (capacity < 1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&fds[0], 0, sizeof(fds[0]));
    fds[0].fd = peer->fd;
    fds[0].events = POLLIN;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_notify_poll(librdp_server_peer* peer, const struct pollfd* fds, size_t count)
{
    int matched = 0;

    if (!peer || !fds || count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    for (size_t i = 0; i < count; i++)
    {
        if (fds[i].fd == peer->fd)
        {
            peer->pending_revents = (short)(peer->pending_revents | fds[i].revents);
            matched = 1;
        }
    }
    return matched ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status librdp_server_peer_dispatch_pending(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (peer->pending_revents == 0)
        return LIBRDP_STATUS_OK;
    return librdp_server_peer_run_once(peer, 0);
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
    else if (peer->state == LIBRDP_SERVER_PEER_LICENSING)
        status = rdp_server_handle_client_info(peer, &packet);
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
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        rdp_server_metric_add(&peer->metrics.errors, 1u);
    return status;
}

librdp_server_peer_state librdp_server_peer_get_state(const librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_SERVER_PEER_FAILED;
    return peer->state;
}

librdp_status librdp_server_peer_get_feature_status(const librdp_server_peer* peer,
                                                    librdp_feature feature,
                                                    librdp_feature_status* status)
{
    if (!peer || !status || !rdp_server_valid_single_feature(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_fill_feature_status(peer->requested_features, feature, status);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_get_metrics(const librdp_server_peer* peer, librdp_server_metrics* metrics)
{
    if (!peer || !metrics ||
        metrics->version != LIBRDP_SERVER_METRICS_VERSION ||
        metrics->size < sizeof(librdp_server_metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *metrics = peer->metrics;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_reset_metrics(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_metrics_init(&peer->metrics);
}

void librdp_server_peer_free(librdp_server_peer* peer)
{
    if (!peer)
        return;
    if (peer->fd >= 0)
        rdp_socket_close(peer->fd);
    rdp_buffer_free(&peer->input);
    free(peer->framebuffer);
    free(peer->server_name);
    free(peer);
}

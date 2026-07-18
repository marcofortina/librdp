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
 * bounded before listener runtime consumes it.
 */

#include "server/server_listener.h"

#include "server/server_features.h"
#include "server/server_security.h"

#include "common/buffer.h"
#include "common/charset.h"
#include "common/stream.h"
#include "common/trace.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/desktop_composition.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/pnp_redirection.h"
#include "channels/remote_programs.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "clipboard/clipboard.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "platform/socket.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>
#include <ctype.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>


/*
 * Purpose: validate public server configuration before any listener, TLS
 * context, or peer state is created.
 * Invariants: size/version gates protect ABI extension, bounded fields are
 * checked before allocation, and TLS material is opened only for TLS/NLA modes.
 * Failure policy: reject invalid metadata or unusable TLS material without
 * mutating caller-owned configuration.
 */
static int rdp_server_config_valid(const librdp_server_config* config)
{
    SSL_CTX* tls_context = NULL;

    if (!config || config->version != LIBRDP_SERVER_CONFIG_VERSION ||
        config->size < sizeof(librdp_server_config))
        return 0;
    if (config->backlog > RDP_SERVER_MAX_BACKLOG || config->max_peers > RDP_SERVER_MAX_PEERS)
        return 0;
    if (config->width > RDP_SERVER_MAX_DESKTOP_SIZE || config->height > RDP_SERVER_MAX_DESKTOP_SIZE)
        return 0;
    if ((config->width == 0) != (config->height == 0))
        return 0;
    if (config->security_mode != LIBRDP_SECURITY_AUTO &&
        config->security_mode != LIBRDP_SECURITY_STANDARD &&
        config->security_mode != LIBRDP_SECURITY_TLS &&
        config->security_mode != LIBRDP_SECURITY_NLA)
        return 0;
    if ((config->security_mode == LIBRDP_SECURITY_TLS || config->security_mode == LIBRDP_SECURITY_NLA) &&
        (!config->tls_certificate_path || !config->tls_private_key_path))
        return 0;
    if ((config->security_mode == LIBRDP_SECURITY_TLS || config->security_mode == LIBRDP_SECURITY_NLA) &&
        rdp_server_create_tls_context(config->tls_certificate_path,
                                      config->tls_private_key_path,
                                      &tls_context,
                                      NULL) != LIBRDP_STATUS_OK)
        return 0;
    SSL_CTX_free(tls_context);
    if (config->security_mode == LIBRDP_SECURITY_NLA &&
        ((config->nla_username != NULL) != (config->nla_password != NULL)))
        return 0;
    if (config->security_mode == LIBRDP_SECURITY_NLA &&
        ((config->nla_username && config->nla_username[0] == '\0') ||
         (config->nla_password && config->nla_password[0] == '\0')))
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
    config->security_mode = LIBRDP_SECURITY_STANDARD;
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

librdp_status librdp_server_dynamic_channel_info_init(librdp_server_dynamic_channel_info* info)
{
    if (!info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    info->version = LIBRDP_SERVER_DYNAMIC_CHANNEL_INFO_VERSION;
    info->size = (uint32_t)sizeof(*info);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_extension_event_init(librdp_server_extension_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_EXTENSION_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    event->status = LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_clipboard_event_init(
    librdp_server_clipboard_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_CLIPBOARD_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    event->status = LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_event_init(librdp_server_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    event->status = LIBRDP_STATUS_OK;
    event->component = LIBRDP_ERROR_COMPONENT_NONE;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_credentials_request_init(librdp_server_credentials_request* request)
{
    if (!request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    request->version = LIBRDP_SERVER_CREDENTIALS_REQUEST_VERSION;
    request->size = (uint32_t)sizeof(*request);
    return LIBRDP_STATUS_OK;
}


int rdp_server_status_valid(const librdp_server_status* status)
{
    return status && status->version == LIBRDP_SERVER_STATUS_VERSION &&
           status->size >= sizeof(librdp_server_status);
}

int rdp_server_clipboard_state_valid(const librdp_server_clipboard_state* state)
{
    return state && state->version == LIBRDP_SERVER_CLIPBOARD_STATE_VERSION &&
           state->size >= sizeof(librdp_server_clipboard_state);
}

int rdp_server_extension_state_valid(const librdp_server_extension_state* state)
{
    return state && state->version == LIBRDP_SERVER_EXTENSION_STATE_VERSION &&
           state->size >= sizeof(librdp_server_extension_state);
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
    if (config->tls_certificate_path)
    {
        server->tls_certificate_path = rdp_server_strdup_bounded(config->tls_certificate_path);
        if (!server->tls_certificate_path)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->tls_private_key_path)
    {
        server->tls_private_key_path = rdp_server_strdup_bounded(config->tls_private_key_path);
        if (!server->tls_private_key_path)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->nla_domain)
    {
        server->nla_domain = rdp_server_strdup_bounded(config->nla_domain);
        if (!server->nla_domain)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->nla_username)
    {
        server->nla_username = rdp_server_strdup_bounded(config->nla_username);
        if (!server->nla_username)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->nla_password)
    {
        server->nla_password = rdp_server_secure_strdup_bounded(config->nla_password);
        if (!server->nla_password)
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
    server->security_mode = config->security_mode;
    server->listen_fd = -1;
    return server;
}

librdp_status librdp_server_set_credentials_provider(librdp_server* server,
                                                     librdp_server_credentials_provider provider,
                                                     void* user_data)
{
    if (!server)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    server->credentials_provider = provider;
    server->credentials_provider_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

void librdp_server_free(librdp_server* server)
{
    if (!server)
        return;
    librdp_server_close(server);
    free(server->bind_address);
    free(server->server_name);
    free(server->tls_certificate_path);
    free(server->tls_private_key_path);
    free(server->nla_domain);
    free(server->nla_username);
    rdp_server_secure_free(server->nla_password);
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

librdp_status librdp_server_enable_feature_provider(librdp_server* server,
                                                    librdp_feature feature,
                                                    int enabled)
{
    if (!server || !rdp_server_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_feature_provider_mask_valid(feature))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        server->backend_features |= (uint32_t)feature;
    else
        server->backend_features &= ~(uint32_t)feature;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_enable_extension_provider(librdp_server* server,
                                                      librdp_server_extension_family family,
                                                      int enabled)
{
    const uint64_t bit = rdp_server_extension_family_bit(family);

    if (!server || bit == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        server->backend_extension_families |= bit;
    else
        server->backend_extension_families &= ~bit;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_get_extension_provider_status(const librdp_server* server,
                                                          librdp_server_extension_family family,
                                                          int* enabled)
{
    const uint64_t bit = rdp_server_extension_family_bit(family);

    if (!server || !enabled || bit == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *enabled = (server->backend_extension_families & bit) != 0;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_get_feature_status(const librdp_server* server,
                                               librdp_feature feature,
                                               librdp_feature_status* status)
{
    if (!server || !status || !rdp_server_valid_single_feature(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_fill_feature_status(server->requested_features,
                                   feature,
                                   rdp_server_listener_feature_backend_ready(server, feature),
                                   status);
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

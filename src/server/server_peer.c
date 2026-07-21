/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: accepted peer lifecycle, callbacks, polling, and dispatch orchestration.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_peer.h"

#include "server/server_channels.h"
#include "server/server_drive.h"
#include "server/server_features.h"
#include "server/server_protocol.h"
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
#include "security/tls_io.h"
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

void rdp_server_copy_token(char* output, size_t output_len, const char* input)
{
    size_t input_len = 0;

    if (!output || output_len == 0)
        return;
    output[0] = '\0';
    if (!input)
        return;
    input_len = strlen(input);
    if (input_len >= output_len)
        input_len = output_len - 1u;
    if (input_len > 0)
        memcpy(output, input, input_len);
    output[input_len] = '\0';
}

librdp_error_component rdp_server_component_for_status(librdp_status status)
{
    if (status == LIBRDP_STATUS_IO_ERROR || status == LIBRDP_STATUS_CLOSED || status == LIBRDP_STATUS_TIMEOUT)
        return LIBRDP_ERROR_COMPONENT_TRANSPORT;
    if (status == LIBRDP_STATUS_LIMIT_EXCEEDED || status == LIBRDP_STATUS_PROTOCOL_ERROR ||
        status == LIBRDP_STATUS_UNSUPPORTED)
        return LIBRDP_ERROR_COMPONENT_PROTOCOL;
    return LIBRDP_ERROR_COMPONENT_CLIENT;
}

void rdp_server_emit_event(librdp_server_peer* peer, const librdp_server_event* event)
{
    if (peer && event && peer->event_callback)
        peer->event_callback(peer, event, peer->event_callback_user_data);
}

void rdp_server_set_state(librdp_server_peer* peer, librdp_server_peer_state state)
{
    librdp_server_event event;
    librdp_server_peer_state old_state = LIBRDP_SERVER_PEER_FAILED;

    if (!peer || peer->state == state)
        return;
    old_state = peer->state;
    peer->state = state;
    if (librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_STATE_CHANGED;
    event.old_state = old_state;
    event.new_state = state;
    rdp_server_emit_event(peer, &event);
}

void rdp_server_record_status(librdp_server_peer* peer,
                                     librdp_status status,
                                     librdp_error_component component,
                                     const char* phase,
                                     const char* message)
{
    librdp_server_event event;

    if (!peer)
        return;
    if (librdp_server_status_init(&peer->last_status) != LIBRDP_STATUS_OK)
        return;
    peer->last_status.status = status;
    peer->last_status.component = component;
    peer->last_status.state = peer->state;
    rdp_server_copy_token(peer->last_status.phase, sizeof(peer->last_status.phase), phase);
    rdp_server_copy_token(peer->last_status.message, sizeof(peer->last_status.message), message);
    if (status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT ||
        status == LIBRDP_STATUS_CLOSED)
        return;
    if (librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_ERROR;
    event.status = status;
    event.component = component;
    event.phase = peer->last_status.phase;
    event.message = peer->last_status.message;
    rdp_server_emit_event(peer, &event);
}

/*
 * Purpose: accept exactly one TCP peer and transfer a copied listener
 * configuration into peer-owned state. Invariants: the peer is visible to the
 * caller only after socket setup, dynamic-channel state, status, metrics, and
 * security buffers are initialized. Failure policy: partially allocated peers
 * and sensitive NLA password copies are released through librdp_server_peer_free().
 */
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
    accepted->backend_features = server->backend_features;
    accepted->backend_extension_families = server->backend_extension_families;
    accepted->credentials_provider = server->credentials_provider;
    accepted->credentials_provider_user_data = server->credentials_provider_user_data;
    accepted->security_mode = server->security_mode;
    accepted->pending_revents = 0;
    rdp_server_drive_state_reset(accepted, 0);
    rdp_server_extension_states_reset(accepted, 0);
    rdp_server_dynamic_channels_reset(accepted, 0);
    rdp_server_static_channels_reset(accepted);
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
    if (server->tls_certificate_path)
    {
        accepted->tls_certificate_path = rdp_server_strdup_bounded(server->tls_certificate_path);
        if (!accepted->tls_certificate_path)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->tls_private_key_path)
    {
        accepted->tls_private_key_path = rdp_server_strdup_bounded(server->tls_private_key_path);
        if (!accepted->tls_private_key_path)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->nla_domain)
    {
        accepted->nla_domain = rdp_server_strdup_bounded(server->nla_domain);
        if (!accepted->nla_domain)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->nla_username)
    {
        accepted->nla_username = rdp_server_strdup_bounded(server->nla_username);
        if (!accepted->nla_username)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->nla_password)
    {
        accepted->nla_password = rdp_server_secure_strdup_bounded(server->nla_password);
        if (!accepted->nla_password)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    (void)librdp_server_metrics_init(&accepted->metrics);
    (void)librdp_server_status_init(&accepted->last_status);
    rdp_buffer_init(&accepted->input);
    rdp_buffer_init(&accepted->standard_certificate);
    rdp_buffer_init(&accepted->credssp_target_name);
    rdp_buffer_init(&accepted->credssp_target_info);
    rdp_buffer_init(&accepted->x224_routing_data);
    *peer = accepted;
    server->accepted_peers++;
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

librdp_status librdp_server_peer_set_dynamic_channel_accept_callback(
    librdp_server_peer* peer,
    librdp_server_dynamic_channel_accept_callback callback,
    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->dynamic_channel_accept_callback = callback;
    peer->dynamic_channel_accept_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_extension_callback(librdp_server_peer* peer,
                                                        librdp_server_extension_callback callback,
                                                        void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->extension_callback = callback;
    peer->extension_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_clipboard_callback(
    librdp_server_peer* peer,
    librdp_server_clipboard_callback callback,
    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    peer->clipboard_callback = callback;
    peer->clipboard_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_extension_family_callback(
    librdp_server_peer* peer,
    librdp_server_extension_family family,
    librdp_server_extension_callback callback,
    void* user_data)
{
    if (!peer || !rdp_server_extension_family_valid(family))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->extension_family_callbacks[(size_t)family] = callback;
    peer->extension_family_user_data[(size_t)family] = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_event_callback(librdp_server_peer* peer,
                                                    librdp_server_event_callback callback,
                                                    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->event_callback = callback;
    peer->event_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_credentials_provider(librdp_server_peer* peer,
                                                          librdp_server_credentials_provider provider,
                                                          void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->nla_authenticated || peer->state == LIBRDP_SERVER_PEER_FAILED ||
        peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    peer->credentials_provider = provider;
    peer->credentials_provider_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_enable_feature_provider(librdp_server_peer* peer,
                                                         librdp_feature feature,
                                                         int enabled)
{
    if (!peer || !rdp_server_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_feature_provider_mask_valid(feature))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        peer->backend_features |= (uint32_t)feature;
    else
        peer->backend_features &= ~(uint32_t)feature;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_enable_extension_provider(librdp_server_peer* peer,
                                                           librdp_server_extension_family family,
                                                           int enabled)
{
    const uint64_t bit = rdp_server_extension_family_bit(family);
    uint64_t previous = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || bit == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    previous = peer->backend_extension_families;
    if (enabled)
        peer->backend_extension_families |= bit;
    else
        peer->backend_extension_families &= ~bit;
    if (enabled && peer->state == LIBRDP_SERVER_PEER_ACTIVE)
        status = rdp_server_device_redirection_start(peer);
    if (status != LIBRDP_STATUS_OK)
        peer->backend_extension_families = previous;
    return status;
}

librdp_status librdp_server_peer_get_extension_provider_status(const librdp_server_peer* peer,
                                                               librdp_server_extension_family family,
                                                               int* enabled)
{
    const uint64_t bit = rdp_server_extension_family_bit(family);

    if (!peer || !enabled || bit == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *enabled = (peer->backend_extension_families & bit) != 0;
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

static int rdp_server_peer_has_complete_tpkt(const librdp_server_peer* peer)
{
    size_t total = 0u;

    if (!peer || peer->input.length < 4u ||
        peer->input.data[0] != 3u)
        return 0;
    total = ((size_t)peer->input.data[2] << 8) |
            (size_t)peer->input.data[3];
    return total >= 4u && total <= peer->input.length;
}

/*
 * Refresh readiness without blocking while dispatch drains a notification.
 * Exact TPKT reads deliberately leave the next plaintext packet or TLS record
 * on the descriptor, while SSL_pending covers records already decrypted by
 * OpenSSL but no longer visible to poll().
 */
static int rdp_server_peer_has_pending_input(librdp_server_peer* peer)
{
    struct pollfd pfd;
    int ready = 0;

    if (!peer || peer->fd < 0)
        return 0;
    if (peer->pending_revents != 0 ||
        rdp_server_peer_has_complete_tpkt(peer))
        return 1;
    if (peer->tls_active && peer->tls && SSL_pending(peer->tls) > 0)
    {
        peer->pending_revents = POLLIN;
        return 1;
    }
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = peer->fd;
    pfd.events = POLLIN;
    do
    {
        ready = poll(&pfd, 1u, 0);
    } while (ready < 0 && errno == EINTR);
    if (ready > 0)
        peer->pending_revents = pfd.revents;
    return peer->pending_revents != 0;
}

librdp_status librdp_server_peer_dispatch_pending(librdp_server_peer* peer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (!rdp_server_peer_has_pending_input(peer))
        return LIBRDP_STATUS_OK;
    do
    {
        status = librdp_server_peer_run_once(peer, 0);
    } while (status == LIBRDP_STATUS_OK &&
             rdp_server_peer_has_pending_input(peer));
    return status == LIBRDP_STATUS_TIMEOUT ? LIBRDP_STATUS_OK : status;
}

static const char* rdp_server_peer_dispatch_phase(
    librdp_server_peer_state state)
{
    switch (state)
    {
        case LIBRDP_SERVER_PEER_NEGOTIATING:
            return "server.x224.negotiation";
        case LIBRDP_SERVER_PEER_X224_CONFIRMED:
            return "server.mcs-gcc.connect";
        case LIBRDP_SERVER_PEER_MCS_CONNECTED:
            return "server.mcs.erect-domain";
        case LIBRDP_SERVER_PEER_DOMAIN_READY:
            return "server.mcs.attach-user";
        case LIBRDP_SERVER_PEER_USER_ATTACHED:
        case LIBRDP_SERVER_PEER_CHANNEL_JOINING:
            return "server.mcs.channel-join";
        case LIBRDP_SERVER_PEER_LICENSING:
            return "server.licensing.client-info";
        case LIBRDP_SERVER_PEER_ACTIVATING:
            return "server.activation";
        case LIBRDP_SERVER_PEER_ACTIVE:
            return "server.runtime";
        default:
            return "server.peer.dispatch";
    }
}

/*
 * Advance one externally-driven server peer phase. TLS handshaking is handled
 * before TPKT parsing because encrypted peers switch transport semantics after
 * the X.224 confirm; every later state consumes exactly one protocol packet
 * and records status at the public boundary.
 */
librdp_status librdp_server_peer_run_once(librdp_server_peer* peer, int timeout_ms)
{
    rdp_tpkt packet;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t packet_len = 0;
    const char* dispatch_phase = NULL;

    if (!peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (peer->state == LIBRDP_SERVER_PEER_NEW)
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_NEGOTIATING);
    dispatch_phase = rdp_server_peer_dispatch_phase(peer->state);
    if (peer->state == LIBRDP_SERVER_PEER_TLS_HANDSHAKING)
    {
        const char* tls_failure_message = "server TLS handshake failed";

        status = rdp_server_start_tls(peer, timeout_ms, &tls_failure_message);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        {
            rdp_server_metric_add(&peer->metrics.errors, 1u);
            rdp_server_record_status(peer,
                                     status,
                                     LIBRDP_ERROR_COMPONENT_TLS,
                                     "server.transport.tls.accept",
                                     tls_failure_message);
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        }
        return status;
    }
    if (peer->state == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING)
    {
        status = rdp_server_handle_credssp(peer, timeout_ms);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        {
            rdp_server_metric_add(&peer->metrics.errors, 1u);
            rdp_server_record_status(peer,
                                     status,
                                     LIBRDP_ERROR_COMPONENT_CREDSSP,
                                     "server.credssp",
                                     "server NLA exchange failed");
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        }
        return status;
    }
    status = rdp_server_read_tpkt(peer, timeout_ms, &packet, &packet_len);
    if (status != LIBRDP_STATUS_OK)
    {
        if (status != LIBRDP_STATUS_TIMEOUT)
            rdp_server_record_status(peer,
                                     status,
                                     rdp_server_component_for_status(status),
                                     "server.peer.read",
                                     "peer packet read failed");
        return status;
    }
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
    {
        rdp_server_metric_add(&peer->metrics.errors, 1u);
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 dispatch_phase,
                                 "peer dispatch failed");
    }
    return status;
}

librdp_server_peer_state librdp_server_peer_get_state(const librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_SERVER_PEER_FAILED;
    return peer->state;
}

librdp_status librdp_server_peer_close(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_dynamic_channels_reset(peer, 1);
    rdp_server_static_channels_reset(peer);
    rdp_server_drive_state_reset(peer, 1);
    rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
    return LIBRDP_STATUS_OK;
}

void librdp_server_peer_free(librdp_server_peer* peer)
{
    if (!peer)
        return;
    if (peer->tls)
    {
        SSL_set_quiet_shutdown(peer->tls, 1);
        (void)rdp_tls_io_shutdown(peer->tls);
        SSL_free(peer->tls);
    }
    if (peer->tls_context)
        SSL_CTX_free(peer->tls_context);
    EVP_PKEY_free(peer->standard_private_key);
    rdp_security_standard_clear(&peer->standard_security);
    rdp_server_dynamic_channels_reset(peer, 0);
    rdp_server_static_channels_reset(peer);
    rdp_server_drive_state_reset(peer, 0);
    if (peer->credssp_security_ready)
    {
        OPENSSL_cleanse(&peer->credssp_security, sizeof(peer->credssp_security));
        peer->credssp_security_ready = 0;
    }
    OPENSSL_cleanse(peer->credssp_server_challenge, sizeof(peer->credssp_server_challenge));
    OPENSSL_cleanse(peer->credssp_client_nonce, sizeof(peer->credssp_client_nonce));
    if (peer->fd >= 0)
        rdp_socket_close(peer->fd);
    rdp_buffer_free(&peer->input);
    rdp_buffer_free(&peer->standard_certificate);
    rdp_buffer_free(&peer->credssp_target_name);
    rdp_buffer_free(&peer->credssp_target_info);
    rdp_buffer_free(&peer->x224_routing_data);
    free(peer->framebuffer);
    free(peer->server_name);
    free(peer->tls_certificate_path);
    free(peer->tls_private_key_path);
    free(peer->nla_domain);
    free(peer->nla_username);
    rdp_server_secure_free(peer->nla_password);
    rdp_server_credssp_expected_clear(peer);
    free(peer);
}

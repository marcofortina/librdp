/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: static and dynamic virtual-channel state, framing, and dispatch.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_channels.h"

#include "server/server_drive.h"
#include "server/server_features.h"
#include "server/server_graphics.h"
#include "server/server_listener.h"
#include "server/server_peer.h"
#include "server/server_protocol.h"
#include "server/server_security.h"
#include "server/server_extensions.h"

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

#define RDP_SERVER_RDPDR_STATUS_NOT_SUPPORTED 0xc00000bbu

static void rdp_server_emit_dynamic_channel_event(
    librdp_server_peer* peer,
    const rdp_server_dynamic_channel* channel,
    librdp_server_channel_event_type type,
    const uint8_t* data,
    size_t data_len);

static void rdp_server_emit_clipboard_cancel(
    librdp_server_peer* peer,
    librdp_server_clipboard_event_type related_type,
    uint32_t format_id,
    uint32_t stream_id)
{
    librdp_server_clipboard_event event;

    if (!peer || !peer->clipboard_callback ||
        librdp_server_clipboard_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_CLIPBOARD_CANCELLED;
    event.related_type = related_type;
    event.status = LIBRDP_STATUS_CANCELLED;
    event.reconnect_generation = peer->clipboard_reconnect_generation;
    event.format_id = format_id;
    event.stream_id = stream_id;
    peer->clipboard_callback(peer,
                             &event,
                             peer->clipboard_callback_user_data);
}

void rdp_server_clipboard_state_reset(librdp_server_peer* peer, int reconnect)
{
    if (!peer)
        return;
    if (reconnect && peer->clipboard_pending_format)
    {
        rdp_server_emit_clipboard_cancel(
            peer,
            LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE,
            peer->clipboard_pending_format_id,
            0u);
    }
    if (reconnect && peer->clipboard_pending_file)
    {
        rdp_server_emit_clipboard_cancel(
            peer,
            LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE,
            0u,
            peer->clipboard_pending_file_stream_id);
    }
    peer->clipboard_monitor_ready_sent = 0;
    peer->clipboard_monitor_ready_received = 0;
    peer->clipboard_capabilities_sent = 0;
    peer->clipboard_capabilities_received = 0;
    peer->clipboard_formats_sent = 0;
    peer->clipboard_formats_accepted = 0;
    peer->clipboard_pending_format = 0;
    peer->clipboard_pending_file = 0;
    peer->clipboard_locked = 0;
    peer->clipboard_format_count = 0;
    peer->clipboard_pending_format_id = 0;
    peer->clipboard_pending_file_stream_id = 0;
    peer->clipboard_locked_clip_data_id = 0;
    if (reconnect)
        peer->clipboard_reconnect_generation++;
}

librdp_server_extension_state* rdp_server_extension_state_mut(librdp_server_peer* peer,
                                                                     librdp_server_extension_family family)
{
    if (!peer || !rdp_server_extension_family_valid(family))
        return NULL;
    return &peer->extension_states[(size_t)family];
}

static void rdp_server_extension_state_prepare(librdp_server_extension_state* state,
                                               librdp_server_extension_family family,
                                               uint32_t reconnect_generation)
{
    if (!state)
        return;
    (void)librdp_server_extension_state_init(state);
    state->family = family;
    state->feature = rdp_server_feature_for_extension_family(family);
    state->reconnect_generation = reconnect_generation;
}

void rdp_server_extension_states_reset(librdp_server_peer* peer, int reconnect)
{
    if (!peer)
        return;
    for (uint32_t family = (uint32_t)LIBRDP_SERVER_EXTENSION_UNKNOWN + 1u;
         family <= (uint32_t)LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING;
         family++)
    {
        librdp_server_extension_state* state =
            &peer->extension_states[(size_t)family];
        uint32_t generation = state->reconnect_generation;

        if (reconnect)
            generation++;
        rdp_server_extension_state_prepare(state,
                                           (librdp_server_extension_family)family,
                                           generation);
        if (reconnect)
            state->close_count++;
    }
}

void rdp_server_extension_state_mark_open(librdp_server_peer* peer,
                                                 librdp_server_extension_family family,
                                                 uint16_t static_channel_id,
                                                 uint32_t dynamic_channel_id,
                                                 uint8_t dynamic_priority)
{
    librdp_server_extension_state* state = rdp_server_extension_state_mut(peer, family);

    if (!state)
        return;
    state->negotiated = 1u;
    state->active = 1u;
    state->open = 1u;
    state->capability_seen = 1u;
    if (state->pending_open && state->pending_requests > 0)
        state->pending_requests--;
    state->pending_open = 0;
    state->closing = 0;
    state->cancelled = 0;
    if (static_channel_id != 0)
        state->static_channel_id = static_channel_id;
    if (dynamic_channel_id != 0)
        state->dynamic_channel_id = dynamic_channel_id;
    state->dynamic_priority = dynamic_priority;
    if (state->open_count != UINT32_MAX)
        state->open_count++;
}

static void rdp_server_extension_state_mark_pending_open(librdp_server_peer* peer,
                                                         librdp_server_extension_family family,
                                                         uint32_t dynamic_channel_id,
                                                         uint8_t dynamic_priority)
{
    librdp_server_extension_state* state = rdp_server_extension_state_mut(peer, family);

    if (!state)
        return;
    state->negotiated = 1u;
    state->capability_seen = 1u;
    state->pending_open = 1u;
    state->cancelled = 0;
    state->dynamic_channel_id = dynamic_channel_id;
    state->dynamic_priority = dynamic_priority;
    if (state->pending_requests != UINT32_MAX)
        state->pending_requests++;
}

static void rdp_server_extension_state_mark_close(librdp_server_peer* peer,
                                                  librdp_server_extension_family family)
{
    librdp_server_extension_state* state = rdp_server_extension_state_mut(peer, family);

    if (!state)
        return;
    state->open = 0;
    state->active = 0;
    state->pending_open = 0;
    state->closing = 0;
    state->pending_requests = 0;
    if (state->close_count != UINT32_MAX)
        state->close_count++;
    if (family == LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION)
        rdp_server_auth_redirection_reset(peer);
}

static void rdp_server_extension_state_mark_tx(librdp_server_peer* peer,
                                               librdp_server_extension_family family,
                                               size_t payload_len)
{
    librdp_server_extension_state* state = rdp_server_extension_state_mut(peer, family);

    if (!state)
        return;
    rdp_server_metric_add(&state->tx_messages, 1u);
    rdp_server_metric_add(&state->tx_bytes, (uint64_t)payload_len);
    state->last_status = LIBRDP_STATUS_OK;
}

static void rdp_server_extension_state_mark_rx(librdp_server_peer* peer,
                                               const librdp_server_extension_event* event)
{
    librdp_server_extension_state* state =
        event ? rdp_server_extension_state_mut(peer, event->family) : NULL;

    if (!state || !event)
        return;
    state->negotiated = 1u;
    state->active = 1u;
    if (event->channel_id != 0)
        state->static_channel_id = event->channel_id;
    if (event->dynamic_channel_id != 0)
    {
        state->dynamic_channel_id = event->dynamic_channel_id;
        state->dynamic_priority = event->dynamic_priority;
    }
    state->open = 1u;
    state->last_message_type = event->message_type;
    state->last_flags = event->flags;
    state->last_status = event->status;
    state->capability_seen = state->capability_seen ||
                             event->message_type == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES;
    rdp_server_metric_add(&state->rx_messages, 1u);
    rdp_server_metric_add(&state->rx_bytes, (uint64_t)event->payload_len);
}

void rdp_server_dynamic_channels_reset(librdp_server_peer* peer, int emit_close_events)
{
    if (!peer)
        return;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (emit_close_events &&
            (peer->dynamic_channels[i].open ||
             peer->dynamic_channels[i].pending_open ||
             peer->dynamic_channels[i].closing))
        {
            librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
            librdp_feature feature = (librdp_feature)0;

            rdp_server_extension_classify_name(peer->dynamic_channels[i].name,
                                               strlen(peer->dynamic_channels[i].name),
                                               &family,
                                               &feature);
            rdp_server_extension_state_mark_close(peer, family);
            rdp_server_emit_dynamic_channel_event(peer,
                                                  &peer->dynamic_channels[i],
                                                  LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE,
                                                  NULL,
                                                  0);
        }
        rdp_buffer_free(&peer->dynamic_channels[i].fragment);
    }
    memset(peer->dynamic_channels, 0, sizeof(peer->dynamic_channels));
    rdp_server_auth_redirection_reset(peer);
    peer->dynamic_channel_count = 0;
    peer->dynamic_channel_static_index = UINT16_MAX;
    peer->dynamic_channels_ready = 0;
    peer->dynamic_channel_capabilities_sent = 0;
    peer->dynamic_channel_version = 0u;
    rdp_server_graphics_frame_state_reset(peer);
}

void rdp_server_static_channels_reset(librdp_server_peer* peer)
{
    uint16_t index = 0;

    if (!peer)
        return;
    for (index = 0; index < RDP_GCC_MAX_SERVER_CHANNELS; index++)
        rdp_buffer_free(&peer->static_channels[index].fragment);
    memset(peer->static_channels, 0, sizeof(peer->static_channels));
    rdp_server_device_redirection_reset(peer);
}

void rdp_server_device_redirection_reset(librdp_server_peer* peer)
{
    if (!peer)
        return;
    peer->device_redirection_channel_id = 0u;
    peer->device_redirection_version_minor = 0u;
    peer->device_redirection_client_id = 0u;
    peer->device_redirection_client_io_code1 = 0u;
    peer->device_redirection_client_capability_types = 0u;
    peer->device_redirection_announce_sent = 0u;
    peer->device_redirection_client_confirmed = 0u;
    peer->device_redirection_client_named = 0u;
    peer->device_redirection_capabilities_sent = 0u;
    peer->device_redirection_capabilities_received = 0u;
    peer->device_redirection_client_id_sent = 0u;
    peer->device_redirection_logged_on_sent = 0u;
    peer->device_redirection_user_logged_on_supported = 0u;
    peer->device_redirection_ready = 0u;
}

static int rdp_server_device_redirection_provider_ready(
    const librdp_server_peer* peer)
{
    static const librdp_server_extension_family families[] = {
        LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION,
        LIBRDP_SERVER_EXTENSION_FILESYSTEM,
        LIBRDP_SERVER_EXTENSION_PRINTER,
        LIBRDP_SERVER_EXTENSION_SERIAL_PORT,
        LIBRDP_SERVER_EXTENSION_PARALLEL_PORT,
        LIBRDP_SERVER_EXTENSION_SMARTCARD,
    };
    size_t index = 0u;

    if (!peer)
        return 0;
    for (index = 0u;
         index < sizeof(families) / sizeof(families[0]);
         index++)
    {
        if (rdp_server_extension_provider_ready(
                peer->backend_extension_families,
                families[index]))
            return 1;
    }
    return 0;
}

/*
 * Start the server-owned RDPDR lifecycle only after activation and only when
 * at least one application provider is ready. The client identifier is
 * unpredictable but carries no credential or persistent identity semantics.
 */
librdp_status rdp_server_device_redirection_start(librdp_server_peer* peer)
{
    rdp_buffer packet;
    uint32_t client_id = 0u;
    uint16_t channel_id = 0u;
    uint16_t index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (peer->device_redirection_announce_sent ||
        !rdp_server_device_redirection_provider_ready(peer))
        return LIBRDP_STATUS_OK;
    for (index = 0u; index < peer->advertised_channel_count; index++)
    {
        char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];

        if (!peer->advertised_channel_joined[index])
            continue;
        rdp_server_copy_channel_name(name,
                                     peer->advertised_channels[index].name);
        if (strcmp(name, RDP_DEVICE_REDIRECTION_CHANNEL_NAME) == 0)
        {
            channel_id = peer->advertised_channel_ids[index];
            break;
        }
    }
    if (channel_id == 0u)
        return LIBRDP_STATUS_OK;
    if (RAND_bytes((unsigned char*)&client_id,
                   (int)sizeof(client_id)) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    if (client_id == 0u)
        client_id = 1u;
    rdp_buffer_init(&packet);
    status = rdp_device_redirection_write_server_announce(
        &packet,
        RDP_DEVICE_REDIRECTION_VERSION_MINOR_13,
        client_id);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_channel_data(peer,
                                                      channel_id,
                                                      packet.data,
                                                      packet.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        peer->device_redirection_channel_id = channel_id;
        peer->device_redirection_version_minor =
            RDP_DEVICE_REDIRECTION_VERSION_MINOR_13;
        peer->device_redirection_client_id = client_id;
        peer->device_redirection_announce_sent = 1u;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.rdpdr.announce",
                        "channel_id=%u version_minor=%u",
                        channel_id,
                        peer->device_redirection_version_minor);
    }
    rdp_buffer_free(&packet);
    return status;
}

void rdp_server_emit_channel_joined_event(librdp_server_peer* peer, uint16_t channel_id)
{
    librdp_server_event event;

    if (!peer || librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_CHANNEL_JOINED;
    event.channel_id = channel_id;
    rdp_server_emit_event(peer, &event);
}

static librdp_status rdp_server_read_u32_le(const uint8_t* data, size_t data_len, uint32_t* value)
{
    rdp_stream stream;

    if (!data || !value || data_len < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, data_len);
    return rdp_stream_read_u32_le(&stream, value);
}

static int rdp_server_name_equals(const char* name, size_t name_len, const char* expected)
{
    size_t expected_len = expected ? strlen(expected) : 0;

    return name && expected && name_len == expected_len && memcmp(name, expected, expected_len) == 0;
}

librdp_server_extension_family rdp_server_redirected_device_family(uint32_t device_type,
                                                                          librdp_feature* feature)
{
    if (feature)
        *feature = (librdp_feature)0;
    switch (device_type)
    {
        case RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM:
            return LIBRDP_SERVER_EXTENSION_FILESYSTEM;
        case RDP_DEVICE_REDIRECTION_TYPE_PRINTER:
            return LIBRDP_SERVER_EXTENSION_PRINTER;
        case RDP_DEVICE_REDIRECTION_TYPE_SERIAL:
            return LIBRDP_SERVER_EXTENSION_SERIAL_PORT;
        case RDP_DEVICE_REDIRECTION_TYPE_PARALLEL:
            return LIBRDP_SERVER_EXTENSION_PARALLEL_PORT;
        case RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD:
            if (feature)
                *feature = LIBRDP_FEATURE_SMARTCARD;
            return LIBRDP_SERVER_EXTENSION_SMARTCARD;
        default:
            return LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION;
    }
}

static void rdp_server_classify_device_payload(const librdp_server_peer* peer,
                                               const uint8_t* data,
                                               size_t data_len,
                                               librdp_server_extension_family* family,
                                               librdp_feature* feature)
{
    rdp_device_redirection_header header;
    uint32_t device_id = 0;
    const rdp_server_redirected_device* device = NULL;

    if (!peer || !data || !family || !feature ||
        rdp_device_redirection_parse_header(data, data_len, &header) != LIBRDP_STATUS_OK)
        return;
    if (header.component == RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER)
    {
        *family = LIBRDP_SERVER_EXTENSION_PRINTER;
        return;
    }
    if (header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE)
        return;
    if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST)
    {
        rdp_device_redirection_io_request request;

        if (rdp_device_redirection_parse_io_request(data, data_len, &request) != LIBRDP_STATUS_OK)
            return;
        device_id = request.device_id;
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION)
    {
        rdp_device_redirection_io_completion completion;

        if (rdp_device_redirection_parse_io_completion(data, data_len, &completion) != LIBRDP_STATUS_OK)
            return;
        device_id = completion.device_id;
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY)
    {
        rdp_device_redirection_device_reply reply;

        if (rdp_device_redirection_parse_device_reply(data, data_len, &reply) != LIBRDP_STATUS_OK)
            return;
        device_id = reply.device_id;
    }
    else
        return;
    device = rdp_server_find_redirected_device_const(peer, device_id);
    if (device)
        *family = rdp_server_redirected_device_family(device->device_type, feature);
}

static int rdp_server_device_type_provider_ready(
    const librdp_server_peer* peer,
    uint32_t device_type)
{
    librdp_server_extension_family family =
        rdp_server_redirected_device_family(device_type, NULL);

    return peer &&
           rdp_server_extension_provider_ready(
               peer->backend_extension_families,
               family);
}

static uint16_t rdp_server_device_capability_type(uint32_t device_type)
{
    switch (device_type)
    {
        case RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM:
            return RDP_DEVICE_REDIRECTION_CAP_DRIVE;
        case RDP_DEVICE_REDIRECTION_TYPE_PRINTER:
            return RDP_DEVICE_REDIRECTION_CAP_PRINTER;
        case RDP_DEVICE_REDIRECTION_TYPE_SERIAL:
        case RDP_DEVICE_REDIRECTION_TYPE_PARALLEL:
            return RDP_DEVICE_REDIRECTION_CAP_PORT;
        case RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD:
            return RDP_DEVICE_REDIRECTION_CAP_SMARTCARD;
        default:
            return 0u;
    }
}

static int rdp_server_device_capability_received(
    const librdp_server_peer* peer,
    uint32_t device_type)
{
    uint16_t type = rdp_server_device_capability_type(device_type);

    return peer && type > 0u && type < 32u &&
           (peer->device_redirection_client_capability_types &
            (UINT32_C(1) << type)) != 0u;
}

static librdp_status rdp_server_send_device_reply_unchecked(
    librdp_server_peer* peer,
    uint32_t device_id,
    uint32_t io_status)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || peer->device_redirection_channel_id == 0u ||
        device_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_device_redirection_write_device_reply(&packet,
                                                       device_id,
                                                       io_status);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_channel_data(
            peer,
            peer->device_redirection_channel_id,
            packet.data,
            packet.length);
    }
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_send_device_redirection_capabilities(
    librdp_server_peer* peer)
{
    rdp_device_redirection_capability_config config;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!peer->device_redirection_client_confirmed ||
        !peer->device_redirection_client_named ||
        peer->device_redirection_capabilities_sent)
        return LIBRDP_STATUS_OK;
    rdp_buffer_init(&packet);
    status = rdp_device_redirection_make_default_capability_config(&config);
    if (status == LIBRDP_STATUS_OK)
    {
        config.general.protocol_minor_version =
            peer->device_redirection_version_minor;
        config.include_drive = (uint8_t)rdp_server_extension_provider_ready(
            peer->backend_extension_families,
            LIBRDP_SERVER_EXTENSION_FILESYSTEM);
        config.include_printer =
            (uint8_t)rdp_server_extension_provider_ready(
                peer->backend_extension_families,
                LIBRDP_SERVER_EXTENSION_PRINTER);
        config.include_port =
            (uint8_t)(rdp_server_extension_provider_ready(
                          peer->backend_extension_families,
                          LIBRDP_SERVER_EXTENSION_SERIAL_PORT) ||
                      rdp_server_extension_provider_ready(
                          peer->backend_extension_families,
                          LIBRDP_SERVER_EXTENSION_PARALLEL_PORT));
        config.include_smartcard =
            (uint8_t)rdp_server_extension_provider_ready(
                peer->backend_extension_families,
                LIBRDP_SERVER_EXTENSION_SMARTCARD);
        status = rdp_device_redirection_write_server_capability_request(
            &packet,
            &config);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_channel_data(
            peer,
            peer->device_redirection_channel_id,
            packet.data,
            packet.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        peer->device_redirection_capabilities_sent = 1u;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.rdpdr.capabilities",
                        "channel_id=%u drive=%u printer=%u port=%u smartcard=%u",
                        peer->device_redirection_channel_id,
                        config.include_drive,
                        config.include_printer,
                        config.include_port,
                        config.include_smartcard);
    }
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Validate capability structure and retain only fields used to gate later
 * requests. Unknown capability types remain forward-compatible, while
 * duplicate or malformed known types fail before any negotiated state changes.
 */
static librdp_status rdp_server_validate_device_redirection_capabilities(
    const librdp_server_peer* peer,
    const uint8_t* data,
    size_t data_len,
    rdp_device_redirection_general_capability* general,
    uint32_t* capability_types)
{
    rdp_device_redirection_capability_list list;
    uint32_t seen = 0u;
    uint16_t index = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !data || !general || !capability_types)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_capability_list(
        data,
        data_len,
        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY,
        &list);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (index = 0u; index < list.count; index++)
    {
        const rdp_device_redirection_capability* capability =
            &list.capabilities[index];
        uint32_t bit = 0u;

        if (capability->type > 0u && capability->type < 32u)
            bit = UINT32_C(1) << capability->type;
        if (bit != 0u && (seen & bit) != 0u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        seen |= bit;
        if (capability->type == RDP_DEVICE_REDIRECTION_CAP_GENERAL)
        {
            status = rdp_device_redirection_parse_general_capability(
                capability,
                general);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (capability->type ==
                     RDP_DEVICE_REDIRECTION_CAP_PRINTER ||
                 capability->type == RDP_DEVICE_REDIRECTION_CAP_PORT ||
                 capability->type ==
                     RDP_DEVICE_REDIRECTION_CAP_SMARTCARD)
        {
            if (capability->length != 8u ||
                capability->data_len != 0u ||
                capability->version !=
                    RDP_DEVICE_REDIRECTION_CAP_VERSION_1)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (capability->type == RDP_DEVICE_REDIRECTION_CAP_DRIVE)
        {
            if (capability->length != 8u ||
                capability->data_len != 0u ||
                (capability->version !=
                     RDP_DEVICE_REDIRECTION_CAP_VERSION_1 &&
                 capability->version !=
                     RDP_DEVICE_REDIRECTION_CAP_VERSION_2))
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    if ((seen &
         (UINT32_C(1) << RDP_DEVICE_REDIRECTION_CAP_GENERAL)) == 0u ||
        general->protocol_minor_version !=
            peer->device_redirection_version_minor)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *capability_types = seen;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_finish_device_redirection_handshake(
    librdp_server_peer* peer)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    if (!peer->device_redirection_client_id_sent)
    {
        status = rdp_device_redirection_write_client_announce(
            &packet,
            peer->device_redirection_version_minor,
            peer->device_redirection_client_id);
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_server_peer_send_channel_data(
                peer,
                peer->device_redirection_channel_id,
                packet.data,
                packet.length);
        }
        if (status == LIBRDP_STATUS_OK)
            peer->device_redirection_client_id_sent = 1u;
    }
    packet.length = 0u;
    if (status == LIBRDP_STATUS_OK &&
        peer->device_redirection_user_logged_on_supported &&
        !peer->device_redirection_logged_on_sent)
    {
        status = rdp_device_redirection_write_user_loggedon(&packet);
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_server_peer_send_channel_data(
                peer,
                peer->device_redirection_channel_id,
                packet.data,
                packet.length);
        }
        if (status == LIBRDP_STATUS_OK)
            peer->device_redirection_logged_on_sent = 1u;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        peer->device_redirection_ready = 1u;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.rdpdr.ready",
                        "channel_id=%u version_minor=%u",
                        peer->device_redirection_channel_id,
                        peer->device_redirection_version_minor);
    }
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Advance the server side of the RDPDR startup exchange in wire order. Device
 * announcements and completions are rejected until both sides have confirmed
 * identity and capabilities; client names are validated but never retained.
 */
static librdp_status rdp_server_handle_device_redirection_lifecycle(
    librdp_server_peer* peer,
    const librdp_server_extension_event* event,
    const rdp_device_redirection_header* header)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !event || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (header->component == RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER)
    {
        return peer->device_redirection_ready
                   ? LIBRDP_STATUS_OK
                   : LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (header->component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE ||
        !peer->device_redirection_announce_sent ||
        event->channel_id != peer->device_redirection_channel_id)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->packet_id ==
        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM)
    {
        rdp_device_redirection_announce confirm;

        if (peer->device_redirection_client_confirmed)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_device_redirection_parse_client_id_confirm(
            event->payload,
            event->payload_len,
            &confirm);
        if (status != LIBRDP_STATUS_OK ||
            confirm.version_major !=
                RDP_DEVICE_REDIRECTION_VERSION_MAJOR ||
            confirm.version_minor !=
                peer->device_redirection_version_minor ||
            confirm.client_id != peer->device_redirection_client_id)
            return status == LIBRDP_STATUS_OK
                       ? LIBRDP_STATUS_PROTOCOL_ERROR
                       : status;
        peer->device_redirection_client_confirmed = 1u;
        return rdp_server_send_device_redirection_capabilities(peer);
    }
    if (header->packet_id ==
        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_NAME)
    {
        rdp_device_redirection_client_name name;

        if (peer->device_redirection_client_named)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_device_redirection_parse_client_name(
            event->payload,
            event->payload_len,
            &name);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (name.name_len > (RDP_SERVER_MAX_TEXT * 2u) + 2u)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        peer->device_redirection_client_named = 1u;
        return rdp_server_send_device_redirection_capabilities(peer);
    }
    if (header->packet_id ==
        RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENT_CAPABILITY)
    {
        rdp_device_redirection_general_capability general;
        uint32_t capability_types = 0u;

        if (!peer->device_redirection_capabilities_sent ||
            peer->device_redirection_capabilities_received)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_server_validate_device_redirection_capabilities(
            peer,
            event->payload,
            event->payload_len,
            &general,
            &capability_types);
        if (status != LIBRDP_STATUS_OK)
            return status;
        peer->device_redirection_client_io_code1 = general.io_code1;
        peer->device_redirection_client_capability_types =
            capability_types;
        peer->device_redirection_user_logged_on_supported =
            (general.extended_pdu &
             RDP_DEVICE_REDIRECTION_EXT_USER_LOGGEDON) != 0u;
        peer->device_redirection_capabilities_received = 1u;
        return rdp_server_finish_device_redirection_handshake(peer);
    }
    if (!peer->device_redirection_ready)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->packet_id ==
            RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE ||
        header->packet_id ==
            RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE ||
        header->packet_id ==
            RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION)
        return LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

/*
 * Apply one validated RDPDR lifecycle or device-state message to the peer.
 * Announcements are committed only after the startup exchange, provider
 * availability, and the matching client capability have all been verified.
 * Malformed lifecycle messages fail the dispatch without retaining devices;
 * unsupported device classes receive a wire-level rejection and are omitted
 * from server state.
 */
static librdp_status rdp_server_update_redirected_devices(
    librdp_server_peer* peer,
    const librdp_server_extension_event* event)
{
    rdp_device_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !event || !event->payload ||
        (event->family != LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION &&
         event->family != LIBRDP_SERVER_EXTENSION_FILESYSTEM &&
         event->family != LIBRDP_SERVER_EXTENSION_PRINTER &&
         event->family != LIBRDP_SERVER_EXTENSION_SERIAL_PORT &&
         event->family != LIBRDP_SERVER_EXTENSION_PARALLEL_PORT &&
         event->family != LIBRDP_SERVER_EXTENSION_SMARTCARD))
        return LIBRDP_STATUS_OK;
    if (rdp_device_redirection_parse_header(event->payload, event->payload_len, &header) != LIBRDP_STATUS_OK ||
        (header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE &&
         header.component != RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_server_handle_device_redirection_lifecycle(peer,
                                                            event,
                                                            &header);
    if (status != LIBRDP_STATUS_OK ||
        header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE)
        return status;
    if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE)
    {
        rdp_device_redirection_device_list list;

        if (rdp_device_redirection_parse_device_list_announce(event->payload,
                                                              event->payload_len,
                                                              &list) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < list.count; i++)
        {
            librdp_feature device_feature = (librdp_feature)0;
            librdp_server_extension_family device_family =
                rdp_server_redirected_device_family(list.devices[i].device_type, &device_feature);
            librdp_status store_status = LIBRDP_STATUS_OK;

            if (!rdp_server_device_type_provider_ready(
                    peer,
                    list.devices[i].device_type) ||
                !rdp_server_device_capability_received(
                    peer,
                    list.devices[i].device_type))
            {
                store_status = rdp_server_send_device_reply_unchecked(
                    peer,
                    list.devices[i].device_id,
                    RDP_SERVER_RDPDR_STATUS_NOT_SUPPORTED);
                if (store_status != LIBRDP_STATUS_OK)
                    return store_status;
                continue;
            }
            store_status = rdp_server_redirected_device_store(
                peer,
                event->channel_id,
                &list.devices[i]);

            if (store_status != LIBRDP_STATUS_OK)
                return store_status;
            rdp_server_extension_state_mark_open(peer, device_family, event->channel_id, 0, 0);
        }
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE)
    {
        rdp_device_redirection_device_remove remove;

        if (rdp_device_redirection_parse_device_remove(event->payload,
                                                       event->payload_len,
                                                       &remove) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < remove.count; i++)
        {
            const rdp_server_redirected_device* device =
                rdp_server_find_redirected_device_const(peer, remove.device_ids[i]);

            if (device)
            {
                librdp_feature device_feature = (librdp_feature)0;
                librdp_server_extension_family device_family =
                    rdp_server_redirected_device_family(device->device_type, &device_feature);

                rdp_server_extension_state_mark_close(peer, device_family);
            }
            rdp_server_redirected_device_remove(peer,
                                                remove.device_ids[i]);
        }
    }
    else if (header.packet_id ==
             RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION)
    {
        return rdp_server_drive_handle_completion(peer,
                                                  event->payload,
                                                  event->payload_len);
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Map a joined channel name to the normalized extension family used by public
 * callbacks, feature status, and runtime state. The function deliberately keeps
 * this as a single switch-like classifier so every channel-family mapping has
 * one review point; callers still validate the concrete payload before marking
 * a message as accepted.
 */
void rdp_server_extension_classify_name(const char* name,
                                               size_t name_len,
                                               librdp_server_extension_family* family,
                                               librdp_feature* feature)
{
    *family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
    *feature = (librdp_feature)0;
    if (rdp_server_name_equals(name, name_len, RDP_SERVER_CLIPBOARD_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_CLIPBOARD;
    else if (rdp_server_name_equals(name, name_len, RDP_DEVICE_REDIRECTION_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION;
        *feature = (librdp_feature)(LIBRDP_FEATURE_SMARTCARD |
                                    LIBRDP_FEATURE_PNP);
    }
    else if (rdp_server_name_equals(name, name_len, RDP_PNP_REDIRECTION_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_PNP;
        *feature = LIBRDP_FEATURE_PNP;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_AUDIO_OUTPUT_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT;
        *feature = LIBRDP_FEATURE_AUDIO_OUTPUT;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_AUDIO_INPUT_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_AUDIO_INPUT;
        *feature = LIBRDP_FEATURE_AUDIO_INPUT;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) ||
             rdp_server_name_equals(name, name_len, RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) ||
             rdp_server_name_equals(name, name_len, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL))
    {
        *family = LIBRDP_SERVER_EXTENSION_VIDEO;
        *feature = LIBRDP_FEATURE_VIDEO;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) ||
             rdp_server_name_equals(name, name_len, RDP_VIDEO_CAPTURE_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_CAMERA;
        *feature = LIBRDP_FEATURE_CAMERA;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_USB_REDIRECTION_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_USB;
        *feature = LIBRDP_FEATURE_USB;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_WEBAUTHN_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_WEBAUTHN;
        *feature = LIBRDP_FEATURE_WEBAUTHN;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_REMOTE_PROGRAMS_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_RAIL;
        *feature = LIBRDP_FEATURE_RAIL;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_COMPOSITED_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_CR2;
        *feature = LIBRDP_FEATURE_CR2;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_ECHO_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_ECHO;
        *feature = LIBRDP_FEATURE_ECHO;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_DISPLAY_CONTROL_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_DISPLAY_CONTROL;
        *feature = LIBRDP_FEATURE_DISPLAY_CONTROL;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_GRAPHICS_PIPELINE_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_GRAPHICS;
    else if (rdp_server_name_equals(name, name_len, RDP_CORE_INPUT_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_CORE_INPUT;
    else if (rdp_server_name_equals(name, name_len, RDP_INPUT_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_TOUCH_INPUT;
    else if (rdp_server_name_equals(name, name_len, RDP_MOUSE_CURSOR_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR;
    else if (rdp_server_name_equals(name, name_len, RDP_AUTH_REDIRECTION_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION;
    else if (rdp_server_name_equals(name, name_len, RDP_TELEMETRY_CHANNEL_NAME) ||
             rdp_server_name_equals(name, name_len, RDP_TELEMETRY_DVC_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_TELEMETRY;
        *feature = LIBRDP_FEATURE_TELEMETRY;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_MULTIPARTY_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_MULTIPARTY;
        *feature = LIBRDP_FEATURE_MULTIPARTY;
    }
}

/*
 * Validate the outer PDU for a known server extension and extract stable
 * metadata for the public extension callback. This deliberately stops at
 * header-level fields so sensitive payloads remain borrowed and opaque; a
 * malformed known extension returns the parser status and prevents raw data
 * from being accepted as a valid runtime message.
 */
librdp_status rdp_server_extension_validate(librdp_server_extension_event* event)
{
    switch (event->family)
    {
        case LIBRDP_SERVER_EXTENSION_CLIPBOARD:
        {
            rdp_clipboard_packet packet;
            librdp_status status = rdp_clipboard_parse_packet(event->payload, event->payload_len, &packet);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = packet.type;
                event->flags = packet.flags;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION:
        case LIBRDP_SERVER_EXTENSION_FILESYSTEM:
        case LIBRDP_SERVER_EXTENSION_PRINTER:
        case LIBRDP_SERVER_EXTENSION_SERIAL_PORT:
        case LIBRDP_SERVER_EXTENSION_PARALLEL_PORT:
        case LIBRDP_SERVER_EXTENSION_SMARTCARD:
        {
            rdp_device_redirection_header header;
            librdp_status status = rdp_device_redirection_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.packet_id;
                event->flags = header.component;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT:
        {
            rdp_audio_output_header header;
            librdp_status status = rdp_audio_output_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.msg_type;
                event->flags = header.pad;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_AUDIO_INPUT:
        {
            rdp_audio_input_header header;
            librdp_status status = rdp_audio_input_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
                event->message_type = header.message_id;
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_VIDEO:
            if (rdp_server_name_equals(event->name, event->name_len, RDP_VIDEO_REDIRECTION_CHANNEL_NAME))
            {
                rdp_video_redirection_header header;
                librdp_status status =
                    rdp_video_redirection_parse_header(event->payload, event->payload_len, 1, &header);
                if (status != LIBRDP_STATUS_OK)
                    status = rdp_video_redirection_parse_header(event->payload, event->payload_len, 0, &header);
                if (status == LIBRDP_STATUS_OK)
                {
                    event->message_type = header.message_id;
                    event->flags = header.interface_id;
                }
                return status;
            }
            {
                rdp_video_optimized_header header;
                librdp_status status =
                    rdp_video_optimized_parse_header(event->payload, event->payload_len, &header);
                if (status == LIBRDP_STATUS_OK)
                    event->message_type = header.packet_type;
                return status;
            }
        case LIBRDP_SERVER_EXTENSION_CAMERA:
        {
            rdp_video_capture_header header;
            librdp_status status = rdp_video_capture_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.message_id;
                event->flags = header.version;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_USB:
        {
            rdp_usb_redirection_header header;
            librdp_status status =
                rdp_usb_redirection_parse_header(event->payload, event->payload_len, 1, &header);
            if (status != LIBRDP_STATUS_OK)
                status = rdp_usb_redirection_parse_header(event->payload, event->payload_len, 0, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.has_function_id ? header.function_id : header.message_id;
                event->flags = header.interface_id;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_WEBAUTHN:
        {
            rdp_webauthn_request request;
            rdp_webauthn_response response;
            librdp_status status = rdp_webauthn_parse_request(event->payload, event->payload_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = request.command;
                event->flags = request.flags;
                return LIBRDP_STATUS_OK;
            }
            status = rdp_webauthn_parse_response(event->payload, event->payload_len, &response);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = response.hresult;
                event->flags = 1u;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_RAIL:
        {
            rdp_remote_programs_header header;
            librdp_status status = rdp_remote_programs_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.order_type;
                event->flags = header.order_length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_CR2:
        {
            rdp_composited_channel_message message;
            librdp_status status =
                rdp_composited_parse_channel_message(event->payload, event->payload_len, &message);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = message.control_code;
                event->flags = message.message_size;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_ECHO:
        {
            rdp_echo_channel_pdu pdu;
            librdp_status status = rdp_echo_channel_parse_request(event->payload, event->payload_len, &pdu);
            if (status == LIBRDP_STATUS_OK)
                event->message_type = 1u;
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_DISPLAY_CONTROL:
        {
            uint32_t pdu_type = 0;
            librdp_status status = rdp_server_read_u32_le(event->payload, event->payload_len, &pdu_type);
            if (status == LIBRDP_STATUS_OK)
                event->message_type = pdu_type;
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_GRAPHICS:
        {
            rdp_graphics_header header;
            librdp_status status = rdp_graphics_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.cmd_id;
                event->flags = header.flags;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_CORE_INPUT:
        {
            rdp_core_input_header header;
            librdp_status status = rdp_core_input_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.pdu_type;
                event->flags = header.event_count;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_TOUCH_INPUT:
        {
            rdp_input_channel_header header;
            librdp_status status = rdp_input_channel_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.event_id;
                event->flags = header.pdu_length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR:
        {
            rdp_mouse_cursor_header header;
            librdp_status status = rdp_mouse_cursor_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.pdu_type;
                event->flags = header.update_type;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION:
        {
            rdp_auth_redirection_call_message call;
            rdp_auth_redirection_response_message response;
            librdp_status status =
                rdp_auth_redirection_parse_call_message(event->payload, event->payload_len, &call);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = call.call.call_id;
                return LIBRDP_STATUS_OK;
            }
            status = rdp_auth_redirection_parse_response_message(event->payload, event->payload_len, &response);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = response.response.call_id;
                event->flags = response.response.status;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_TELEMETRY:
        {
            rdp_telemetry_pdu pdu;
            librdp_status status = rdp_telemetry_parse_pdu(event->payload, event->payload_len, &pdu);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = pdu.id;
                event->flags = pdu.length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_DESKTOP_COMPOSITION:
        {
            rdp_desktop_composition_header header;
            librdp_status status =
                rdp_desktop_composition_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.operation;
                event->flags = header.size;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_MULTIPARTY:
        {
            rdp_multiparty_header header;
            librdp_status status = rdp_multiparty_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.type;
                event->flags = header.length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_PNP:
        {
            rdp_pnp_redirection_info_header info;
            rdp_pnp_redirection_server_io_header server_io;
            rdp_pnp_redirection_client_io_header client_io;
            librdp_status status = rdp_pnp_redirection_parse_info_header(event->payload,
                                                                         event->payload_len,
                                                                         &info);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = info.packet_id;
                event->flags = info.size;
                return LIBRDP_STATUS_OK;
            }
            status = rdp_pnp_redirection_parse_server_io_header(event->payload,
                                                                event->payload_len,
                                                                &server_io);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = server_io.function_id;
                event->flags = server_io.request_id;
                return LIBRDP_STATUS_OK;
            }
            status = rdp_pnp_redirection_parse_client_io_header(event->payload,
                                                                event->payload_len,
                                                                &client_io);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = client_io.packet_type;
                event->flags = client_io.request_id;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_UNKNOWN:
        default:
            return LIBRDP_STATUS_OK;
    }
}

/*
 * Purpose: update the server-side clipboard runtime snapshot from client-origin
 * CLIPRDR PDUs before the generic channel callback observes the event. The
 * function never owns event buffers; it only validates framing, records
 * capability/format readiness, and enforces request correlation for file
 * contents replies so stale or cross-request responses fail before application
 * code can act on them.
 */
static librdp_status rdp_server_update_clipboard_state(librdp_server_peer* peer,
                                                       const librdp_server_extension_event* event)
{
    rdp_clipboard_packet packet;
    librdp_server_clipboard_event typed;
    librdp_server_clipboard_format* formats = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !event || event->family != LIBRDP_SERVER_EXTENSION_CLIPBOARD)
        return LIBRDP_STATUS_OK;
    status = rdp_clipboard_parse_packet(event->payload, event->payload_len, &packet);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_server_clipboard_event_init(&typed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    typed.channel_id = event->channel_id;
    typed.flags = packet.flags;
    typed.reconnect_generation = peer->clipboard_reconnect_generation;
    switch (packet.type)
    {
        case RDP_CLIPBOARD_CB_MONITOR_READY:
            typed.type = LIBRDP_SERVER_CLIPBOARD_MONITOR_READY;
            peer->clipboard_monitor_ready_received = 1u;
            break;
        case RDP_CLIPBOARD_CB_CLIP_CAPS:
        {
            rdp_clipboard_capabilities capabilities;

            status = rdp_clipboard_parse_capabilities(&packet, &capabilities);
            if (status == LIBRDP_STATUS_OK)
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_CAPABILITIES;
                typed.capability_count = capabilities.count;
                if (capabilities.has_general)
                    typed.general_flags = capabilities.general.general_flags;
                peer->clipboard_capabilities_received = 1u;
            }
            break;
        }
        case RDP_CLIPBOARD_CB_FORMAT_LIST:
        {
            rdp_clipboard_format_list list;
            uint32_t count = 0;
            int long_names = (packet.flags & RDP_CLIPBOARD_CB_ASCII_NAMES) == 0;

            status = rdp_clipboard_parse_format_list(&packet, &list);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_clipboard_format_list_entry_count(&list, long_names, &count);
            if (status == LIBRDP_STATUS_OK &&
                count > RDP_SERVER_MAX_CLIPBOARD_FORMATS)
                status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            if (status == LIBRDP_STATUS_OK && count > 0u &&
                peer->clipboard_callback)
            {
                formats = (librdp_server_clipboard_format*)calloc(
                    count,
                    sizeof(*formats));
                if (!formats)
                    status = LIBRDP_STATUS_NO_MEMORY;
            }
            for (uint32_t index = 0;
                 status == LIBRDP_STATUS_OK && formats && index < count;
                 index++)
            {
                rdp_clipboard_format_entry parsed;

                status = rdp_clipboard_format_list_get_entry(&list,
                                                             long_names,
                                                             index,
                                                             &parsed);
                if (status == LIBRDP_STATUS_OK)
                {
                    formats[index].format_id = parsed.format_id;
                    formats[index].name = parsed.name;
                    formats[index].name_len = parsed.name_len;
                }
            }
            if (status == LIBRDP_STATUS_OK)
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST;
                typed.formats = formats;
                typed.format_count = count;
                typed.long_format_names = long_names ? 1u : 0u;
                peer->clipboard_format_count = count;
                peer->clipboard_formats_accepted = 0;
            }
            break;
        }
        case RDP_CLIPBOARD_CB_FORMAT_LIST_RESPONSE:
            if (!peer->clipboard_formats_sent)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            typed.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_LIST_RESPONSE;
            typed.success =
                (packet.flags & RDP_CLIPBOARD_CB_RESPONSE_OK) != 0 ? 1u : 0u;
            peer->clipboard_formats_accepted =
                typed.success;
            break;
        case RDP_CLIPBOARD_CB_FORMAT_DATA_REQUEST:
        {
            rdp_clipboard_format_data_request request;

            status = rdp_clipboard_parse_format_data_request(&packet,
                                                             &request);
            if (status == LIBRDP_STATUS_OK)
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_REQUEST;
                typed.format_id = request.format_id;
            }
            break;
        }
        case RDP_CLIPBOARD_CB_FORMAT_DATA_RESPONSE:
        {
            rdp_clipboard_format_data_response response;

            status = rdp_clipboard_parse_format_data_response(&packet,
                                                              &response);
            if (status == LIBRDP_STATUS_OK &&
                !peer->clipboard_pending_format)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            if (status == LIBRDP_STATUS_OK)
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE;
                typed.success =
                    (response.response_flags &
                     RDP_CLIPBOARD_CB_RESPONSE_OK) != 0 ? 1u : 0u;
                typed.format_id = peer->clipboard_pending_format_id;
                typed.data = response.data;
                typed.data_len = response.data_len;
                peer->clipboard_pending_format = 0;
                peer->clipboard_pending_format_id = 0;
            }
            break;
        }
        case RDP_CLIPBOARD_CB_FILECONTENTS_REQUEST:
        {
            rdp_clipboard_file_contents_request request;

            status = rdp_clipboard_parse_file_contents_request(&packet,
                                                               &request);
            if (status == LIBRDP_STATUS_OK)
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_REQUEST;
                typed.stream_id = request.stream_id;
                typed.file_index = request.lindex;
                typed.file_flags = request.flags;
                typed.position = request.position;
                typed.requested_bytes = request.requested;
                typed.has_clip_data_id = request.has_clip_data_id;
                typed.clip_data_id = request.clip_data_id;
            }
            break;
        }
        case RDP_CLIPBOARD_CB_FILECONTENTS_RESPONSE:
        {
            rdp_clipboard_file_contents_response response;

            status = rdp_clipboard_parse_file_contents_response(&packet, &response);
            if (status == LIBRDP_STATUS_OK && !peer->clipboard_pending_file)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            if (status == LIBRDP_STATUS_OK)
            {
                if (response.stream_id != peer->clipboard_pending_file_stream_id)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                else
                {
                    typed.type =
                        LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE;
                    typed.success =
                        (response.response_flags &
                         RDP_CLIPBOARD_CB_RESPONSE_OK) != 0 ? 1u : 0u;
                    typed.stream_id = response.stream_id;
                    typed.data = response.data;
                    typed.data_len = response.data_len;
                    peer->clipboard_pending_file = 0;
                    peer->clipboard_pending_file_stream_id = 0;
                }
            }
            break;
        }
        case RDP_CLIPBOARD_CB_LOCK_CLIPDATA:
        {
            rdp_clipboard_lock lock;

            status = rdp_clipboard_parse_lock(&packet, &lock);
            if (status == LIBRDP_STATUS_OK)
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_LOCK;
                typed.has_clip_data_id = 1u;
                typed.clip_data_id = lock.clip_data_id;
                peer->clipboard_locked = 1u;
                peer->clipboard_locked_clip_data_id = lock.clip_data_id;
            }
            break;
        }
        case RDP_CLIPBOARD_CB_UNLOCK_CLIPDATA:
        {
            rdp_clipboard_lock lock;

            status = rdp_clipboard_parse_unlock(&packet, &lock);
            if (status == LIBRDP_STATUS_OK &&
                (!peer->clipboard_locked || peer->clipboard_locked_clip_data_id == lock.clip_data_id))
            {
                typed.type = LIBRDP_SERVER_CLIPBOARD_UNLOCK;
                typed.has_clip_data_id = 1u;
                typed.clip_data_id = lock.clip_data_id;
                peer->clipboard_locked = 0;
                peer->clipboard_locked_clip_data_id = 0;
            }
            else if (status == LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        default:
            break;
    }
    if (status == LIBRDP_STATUS_OK && typed.type != 0 &&
        peer->clipboard_callback)
    {
        peer->clipboard_callback(peer,
                                 &typed,
                                 peer->clipboard_callback_user_data);
    }
    free(formats);
    return status;
}

librdp_status rdp_server_emit_extension_event(librdp_server_peer* peer,
                                                     const char* name,
                                                     size_t name_len,
                                                     uint16_t channel_id,
                                                     uint32_t dynamic_channel_id,
                                                     uint8_t dynamic_priority,
                                                     const uint8_t* data,
                                                     size_t data_len)
{
    librdp_server_extension_event event;

    if (!peer || !name || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_server_extension_event_init(&event) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    event.channel_id = channel_id;
    event.dynamic_channel_id = dynamic_channel_id;
    event.dynamic_priority = dynamic_priority;
    event.name = name;
    event.name_len = name_len;
    event.payload = data;
    event.payload_len = data_len;
    rdp_server_extension_classify_name(name, name_len, &event.family, &event.feature);
    if (event.family == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION)
        rdp_server_classify_device_payload(peer, data, data_len, &event.family, &event.feature);
    event.status = rdp_server_extension_validate(&event);
    if (event.status == LIBRDP_STATUS_OK)
        event.status = rdp_server_update_clipboard_state(peer, &event);
    if (event.status == LIBRDP_STATUS_OK)
        event.status = rdp_server_update_redirected_devices(peer, &event);
    if (event.status == LIBRDP_STATUS_OK)
        rdp_server_extension_state_mark_rx(peer, &event);
    if (event.status == LIBRDP_STATUS_OK && rdp_server_extension_family_valid(event.family))
    {
        librdp_server_extension_callback callback =
            peer->extension_family_callbacks[(size_t)event.family];
        void* user_data = peer->extension_family_user_data[(size_t)event.family];

        if (callback)
            callback(peer, &event, user_data);
    }
    if (event.status == LIBRDP_STATUS_OK &&
        rdp_server_extension_family_valid(event.family) &&
        peer->extension_callback)
        peer->extension_callback(peer, &event, peer->extension_callback_user_data);
    return event.status;
}

int rdp_server_channel_allowed(const librdp_server_peer* peer, uint16_t channel_id)
{
    uint16_t first_static = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    uint16_t last_static = 0;

    if (!peer)
        return 0;
    last_static = (uint16_t)(first_static + peer->advertised_channel_count);
    if (channel_id == peer->user_id || channel_id == RDP_MCS_GLOBAL_CHANNEL_ID)
        return 1;
    if (peer->message_channel_id != 0u &&
        channel_id == peer->message_channel_id)
        return 1;
    return channel_id >= first_static && channel_id < last_static;
}

int rdp_server_static_channel_index(const librdp_server_peer* peer, uint16_t channel_id, uint16_t* index)
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

static librdp_status rdp_server_dispatch_static_channel_payload(
    librdp_server_peer* peer,
    uint16_t channel_index,
    uint16_t channel_id,
    const uint8_t* data,
    size_t data_len)
{
    char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || channel_index >= peer->advertised_channel_count ||
        (!data && data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_copy_channel_name(name,
                                 peer->advertised_channels[channel_index].name);
    if (channel_index == peer->dynamic_channel_static_index)
    {
        return rdp_server_handle_dynamic_channel_message(peer,
                                                         data,
                                                         data_len);
    }
    status = rdp_server_emit_extension_event(peer,
                                             name,
                                             strlen(name),
                                             channel_id,
                                             0u,
                                             0u,
                                             data,
                                             data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_server_metric_add(&peer->metrics.static_channel_in, 1u);
    rdp_server_metric_add(&peer->metrics.static_channel_bytes_in,
                          (uint64_t)data_len);
    if (peer->channel_callback)
    {
        librdp_server_channel_event event;

        memset(&event, 0, sizeof(event));
        event.version = LIBRDP_SERVER_CHANNEL_EVENT_VERSION;
        event.size = (uint32_t)sizeof(event);
        event.type = LIBRDP_SERVER_CHANNEL_EVENT_STATIC_DATA;
        event.channel_id = channel_id;
        event.name = name;
        event.name_len = strlen(name);
        event.data = data;
        event.data_len = data_len;
        peer->channel_callback(peer,
                               &event,
                               peer->channel_callback_user_data);
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Reassemble one static virtual-channel message before domain dispatch. The
 * total length in every fragment is authoritative, while fragment bytes remain
 * borrowed from the peer input buffer until copied into per-channel state.
 */
librdp_status rdp_server_handle_static_channel_message(
    librdp_server_peer* peer,
    uint16_t channel_index,
    uint16_t channel_id,
    const uint8_t* data,
    size_t data_len)
{
    rdp_server_static_channel* channel = NULL;
    rdp_virtual_channel_packet packet;
    uint32_t fragment_flags = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || channel_index >= peer->advertised_channel_count ||
        (!data && data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel = &peer->static_channels[channel_index];
    status = rdp_virtual_channel_parse_packet(data, data_len, &packet);
    if (status != LIBRDP_STATUS_OK ||
        packet.payload_len > data_len - 8u ||
        packet.payload_len + 8u != data_len ||
        packet.length > RDP_SERVER_STATIC_MESSAGE_MAX)
    {
        status = status == LIBRDP_STATUS_OK
                     ? LIBRDP_STATUS_PROTOCOL_ERROR
                     : status;
        goto reset;
    }
    fragment_flags =
        packet.flags &
        (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST);
    if (fragment_flags ==
        (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
    {
        if (channel->fragmenting ||
            packet.payload_len != (size_t)packet.length)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto reset;
        }
        return rdp_server_dispatch_static_channel_payload(peer,
                                                          channel_index,
                                                          channel_id,
                                                          packet.payload,
                                                          packet.payload_len);
    }
    if ((fragment_flags & RDP_VIRTUAL_CHANNEL_FLAG_FIRST) != 0u)
    {
        if (channel->fragmenting || packet.length == 0u ||
            packet.payload_len == 0u ||
            packet.payload_len >= (size_t)packet.length)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto reset;
        }
        rdp_buffer_free(&channel->fragment);
        rdp_buffer_init(&channel->fragment);
        status = rdp_buffer_append(&channel->fragment,
                                   packet.payload,
                                   packet.payload_len);
        if (status != LIBRDP_STATUS_OK)
            goto reset;
        channel->fragment_expected = packet.length;
        channel->fragmenting = 1u;
        return LIBRDP_STATUS_OK;
    }
    if (!channel->fragmenting ||
        channel->fragment_expected != packet.length ||
        packet.payload_len == 0u ||
        channel->fragment.length >
            (size_t)channel->fragment_expected - packet.payload_len)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto reset;
    }
    status = rdp_buffer_append(&channel->fragment,
                               packet.payload,
                               packet.payload_len);
    if (status != LIBRDP_STATUS_OK)
        goto reset;
    if ((fragment_flags & RDP_VIRTUAL_CHANNEL_FLAG_LAST) == 0u)
    {
        if (channel->fragment.length >=
            (size_t)channel->fragment_expected)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto reset;
        }
        return LIBRDP_STATUS_OK;
    }
    if (channel->fragment.length !=
        (size_t)channel->fragment_expected)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto reset;
    }
    status = rdp_server_dispatch_static_channel_payload(
        peer,
        channel_index,
        channel_id,
        channel->fragment.data,
        channel->fragment.length);

reset:
    rdp_buffer_free(&channel->fragment);
    rdp_buffer_init(&channel->fragment);
    channel->fragment_expected = 0u;
    channel->fragmenting = 0u;
    return status;
}

static uint16_t rdp_server_dynamic_static_channel_id(const librdp_server_peer* peer)
{
    if (!peer || peer->dynamic_channel_static_index >= peer->advertised_channel_count)
        return 0;
    return peer->advertised_channel_ids[peer->dynamic_channel_static_index];
}

rdp_server_dynamic_channel* rdp_server_find_dynamic_channel(librdp_server_peer* peer, uint32_t channel_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (peer->dynamic_channels[i].open && peer->dynamic_channels[i].channel_id == channel_id)
            return &peer->dynamic_channels[i];
    }
    return NULL;
}

static rdp_server_dynamic_channel* rdp_server_find_dynamic_channel_any(librdp_server_peer* peer, uint32_t channel_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        rdp_server_dynamic_channel* channel = &peer->dynamic_channels[i];

        if ((channel->open || channel->pending_open || channel->closing) && channel->channel_id == channel_id)
            return channel;
    }
    return NULL;
}

static rdp_server_dynamic_channel* rdp_server_find_pending_dynamic_channel(librdp_server_peer* peer,
                                                                           uint32_t channel_id)
{
    rdp_server_dynamic_channel* channel = rdp_server_find_dynamic_channel_any(peer, channel_id);

    return channel && channel->pending_open ? channel : NULL;
}

static rdp_server_dynamic_channel* rdp_server_allocate_dynamic_channel(librdp_server_peer* peer)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (!peer->dynamic_channels[i].open &&
            !peer->dynamic_channels[i].pending_open &&
            !peer->dynamic_channels[i].closing)
            return &peer->dynamic_channels[i];
    }
    return NULL;
}

static int rdp_server_dynamic_channel_name_valid(const char* name, size_t* name_len)
{
    size_t length = 0;

    if (!name)
        return 0;
    while (name[length] != '\0')
    {
        unsigned char ch = (unsigned char)name[length];

        if (length >= RDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY - 1u || ch < 0x21u || ch > 0x7eu)
            return 0;
        length++;
    }
    if (length == 0)
        return 0;
    if (name_len)
        *name_len = length;
    return 1;
}

static void rdp_server_emit_dynamic_channel_event(librdp_server_peer* peer,
                                                  const rdp_server_dynamic_channel* channel,
                                                  librdp_server_channel_event_type type,
                                                  const uint8_t* data,
                                                  size_t data_len)
{
    librdp_server_channel_event event;

    if (!peer || !channel || !peer->channel_callback)
        return;
    memset(&event, 0, sizeof(event));
    event.version = LIBRDP_SERVER_CHANNEL_EVENT_VERSION;
    event.size = (uint32_t)sizeof(event);
    event.type = type;
    event.channel_id = rdp_server_dynamic_static_channel_id(peer);
    event.dynamic_channel_id = channel->channel_id;
    event.dynamic_priority = channel->priority;
    event.name = channel->name;
    event.name_len = strlen(channel->name);
    event.data = data;
    event.data_len = data_len;
    peer->channel_callback(peer, &event, peer->channel_callback_user_data);
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

uint32_t librdp_server_peer_dynamic_channel_count(const librdp_server_peer* peer)
{
    return peer ? peer->dynamic_channel_count : 0;
}

librdp_status librdp_server_peer_dynamic_channel_at(const librdp_server_peer* peer,
                                                    uint32_t index,
                                                    librdp_server_dynamic_channel_info* info)
{
    uint32_t seen = 0;

    if (!peer || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_server_dynamic_channel_info_init(info) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        const rdp_server_dynamic_channel* channel = &peer->dynamic_channels[i];

        if (!channel->open)
            continue;
        if (seen == index)
        {
            info->channel_id = channel->channel_id;
            info->priority = channel->priority;
            info->open = 1;
            rdp_server_copy_token(info->name, sizeof(info->name), channel->name);
            return LIBRDP_STATUS_OK;
        }
        seen++;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_server_send_static_channel_fragment(
    librdp_server_peer* peer,
    uint16_t channel_id,
    const uint8_t* data,
    size_t data_len,
    size_t total_len,
    uint32_t flags)
{
    rdp_buffer channel_packet;
    rdp_buffer secured;
    rdp_buffer mcs;
    const uint8_t* wire_payload = NULL;
    size_t wire_payload_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    status = rdp_virtual_channel_write_fragment(&channel_packet,
                                                data,
                                                data_len,
                                                total_len,
                                                flags);
    if (status == LIBRDP_STATUS_OK &&
        (channel_packet.length > 0x7fffu ||
         rdp_server_outbound_security_overhead(peer) >
             0x7fffu - channel_packet.length))
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    wire_payload = channel_packet.data;
    wire_payload_len = channel_packet.length;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_prepare_outbound_security_payload(peer,
                                                              &secured,
                                                              &wire_payload,
                                                              &wire_payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_send_data_indication(&mcs,
                                                    peer->user_id,
                                                    channel_id,
                                                    wire_payload,
                                                    wire_payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    rdp_buffer_free(&channel_packet);
    return status;
}

librdp_status librdp_server_peer_send_channel_data(librdp_server_peer* peer,
                                                   uint16_t channel_id,
                                                   const void* data,
                                                   size_t data_len)
{
    const uint8_t* bytes = (const uint8_t*)data;
    uint16_t channel_index = 0;
    size_t offset = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_server_static_channel_index(peer, channel_id, &channel_index) ||
        !peer->advertised_channel_joined[channel_index])
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > RDP_SERVER_STATIC_MESSAGE_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    do
    {
        size_t chunk = data_len - offset;
        uint32_t flags = 0u;

        if (chunk > RDP_SERVER_STATIC_CHANNEL_CHUNK_SIZE)
            chunk = RDP_SERVER_STATIC_CHANNEL_CHUNK_SIZE;
        if (offset == 0u)
            flags |= RDP_VIRTUAL_CHANNEL_FLAG_FIRST;
        if (offset + chunk == data_len)
            flags |= RDP_VIRTUAL_CHANNEL_FLAG_LAST;
        status = rdp_server_send_static_channel_fragment(peer,
                                                         channel_id,
                                                         bytes
                                                             ? bytes + offset
                                                             : NULL,
                                                         chunk,
                                                         data_len,
                                                         flags);
        offset += chunk;
    } while (status == LIBRDP_STATUS_OK && offset < data_len);
    if (status == LIBRDP_STATUS_OK)
    {
        char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        rdp_server_metric_add(&peer->metrics.static_channel_out, 1u);
        rdp_server_metric_add(&peer->metrics.static_channel_bytes_out, (uint64_t)data_len);
        rdp_server_copy_channel_name(name, peer->advertised_channels[channel_index].name);
        rdp_server_extension_classify_name(name, strlen(name), &family, &feature);
        rdp_server_extension_state_mark_tx(peer, family, data_len);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.channel.send",
                                 "static channel send failed");
    return status;
}

static librdp_status rdp_server_send_dynamic_packet(librdp_server_peer* peer, const rdp_buffer* packet)
{
    uint16_t static_channel_id = rdp_server_dynamic_static_channel_id(peer);

    if (!peer || !packet || static_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_peer_send_channel_data(peer, static_channel_id, packet->data, packet->length);
}

librdp_status rdp_server_dynamic_channels_start(librdp_server_peer* peer)
{
    static const uint16_t priority_charge[4] = {
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_0,
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_1,
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_2,
        RDP_DYNAMIC_CHANNEL_PRIORITY_CHARGE_3
    };
    rdp_buffer request;
    uint16_t static_channel_id = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    static_channel_id = rdp_server_dynamic_static_channel_id(peer);
    if (static_channel_id == 0u)
        return LIBRDP_STATUS_OK;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (peer->dynamic_channel_capabilities_sent ||
        peer->dynamic_channels_ready ||
        peer->dynamic_channel_version != 0u)
        return LIBRDP_STATUS_OK;
    rdp_buffer_init(&request);
    status = rdp_dynamic_channel_write_capabilities_request(
        &request,
        3u,
        priority_charge);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_packet(peer, &request);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->dynamic_channel_capabilities_sent = 1;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.drdynvc.capabilities.request",
                        "channel_id=%u version=3",
                        static_channel_id);
    }
    rdp_buffer_free(&request);
    return status;
}

librdp_status librdp_server_peer_open_dynamic_channel(librdp_server_peer* peer,
                                                      uint32_t dynamic_channel_id,
                                                      uint8_t priority,
                                                      const char* name)
{
    rdp_server_dynamic_channel* channel = NULL;
    rdp_buffer packet;
    size_t name_len = 0;
    uint8_t channel_id_bytes = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || dynamic_channel_id == 0 || priority > 3u ||
        !rdp_server_dynamic_channel_name_valid(name, &name_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || !peer->dynamic_channels_ready ||
        rdp_server_dynamic_static_channel_id(peer) == 0)
        return LIBRDP_STATUS_STATE;
    if (rdp_server_find_dynamic_channel_any(peer, dynamic_channel_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel = rdp_server_allocate_dynamic_channel(peer);
    if (!channel)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    channel_id_bytes = rdp_dynamic_channel_select_channel_id_bytes(dynamic_channel_id);
    if (channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&packet);
    status = rdp_dynamic_channel_write_create_request(&packet,
                                                      dynamic_channel_id,
                                                      channel_id_bytes,
                                                      priority,
                                                      name,
                                                      name_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_packet(peer, &packet);
    if (status == LIBRDP_STATUS_OK)
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        memset(channel, 0, sizeof(*channel));
        channel->channel_id = dynamic_channel_id;
        channel->channel_id_bytes = channel_id_bytes;
        channel->priority = priority;
        channel->pending_open = 1;
        memcpy(channel->name, name, name_len);
        channel->name[name_len] = '\0';
        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        rdp_server_extension_state_mark_pending_open(peer, family, dynamic_channel_id, priority);
        rdp_buffer_init(&channel->fragment);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.dvc.open.request",
                        "channel_id=%u name_len=%u priority=%u",
                        dynamic_channel_id,
                        (unsigned)name_len,
                        (unsigned)priority);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.open",
                                 "dynamic channel open request failed");
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Sends application payload on a negotiated dynamic virtual channel.
 * The function fragments oversized messages into DVC DATA_FIRST/DATA PDUs
 * while preserving one logical metrics event for the caller-visible send.
 */
librdp_status librdp_server_peer_send_dynamic_channel_data(librdp_server_peer* peer,
                                                           uint32_t dynamic_channel_id,
                                                           const void* data,
                                                           size_t data_len)
{
    rdp_server_dynamic_channel* channel = NULL;
    const uint8_t* bytes = (const uint8_t*)data;
    rdp_buffer packet;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (data_len > RDP_SERVER_DYNAMIC_MESSAGE_MAX)
    {
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
        rdp_server_record_status(peer,
                                 LIBRDP_STATUS_LIMIT_EXCEEDED,
                                 LIBRDP_ERROR_COMPONENT_CHANNEL,
                                 "server.dvc.flow_control",
                                 "dynamic channel send exceeded flow-control limit");
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);
    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&packet);
    if (data_len <= RDP_DYNAMIC_CHANNEL_SINGLE_MESSAGE_LIMIT)
    {
        status = rdp_dynamic_channel_write_data_ex(&packet,
                                                   dynamic_channel_id,
                                                   channel->channel_id_bytes,
                                                   channel->priority,
                                                   data,
                                                   data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &packet);
    }
    else
    {
        size_t first_capacity = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE -
                                rdp_dynamic_channel_data_first_pdu_header_size(channel->channel_id_bytes,
                                                                               (uint32_t)data_len);
        size_t data_capacity = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE -
                               rdp_dynamic_channel_data_pdu_header_size(channel->channel_id_bytes);
        size_t chunk = data_len < first_capacity ? data_len : first_capacity;

        if (first_capacity == 0 || data_capacity == 0 || data_len > UINT32_MAX)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_data_first_ex(&packet,
                                                             dynamic_channel_id,
                                                             channel->channel_id_bytes,
                                                             channel->priority,
                                                             (uint32_t)data_len,
                                                             bytes,
                                                             chunk);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &packet);
        offset = chunk;
        while (status == LIBRDP_STATUS_OK && offset < data_len)
        {
            chunk = data_len - offset < data_capacity ? data_len - offset : data_capacity;
            packet.length = 0;
            status = rdp_dynamic_channel_write_data_ex(&packet,
                                                       dynamic_channel_id,
                                                       channel->channel_id_bytes,
                                                       channel->priority,
                                                       bytes + offset,
                                                       chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_server_send_dynamic_packet(peer, &packet);
            offset += chunk;
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        rdp_server_metric_add(&peer->metrics.dynamic_channel_out, 1u);
        rdp_server_metric_add(&peer->metrics.dynamic_channel_bytes_out, (uint64_t)data_len);
        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        rdp_server_extension_state_mark_tx(peer, family, data_len);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.send",
                                 "dynamic channel send failed");
    if (status == LIBRDP_STATUS_LIMIT_EXCEEDED)
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Processes one application-owned UDP2 side-transport datagram.
 * The core validates the wrapper and packet, marks UDP2 active only after a
 * complete valid datagram, and returns an ACK datagram for data packets. Socket
 * ownership remains outside the server object so embedders can integrate UDP2
 * with their own transport loop, firewall policy, or gateway binding.
 */
librdp_status librdp_server_peer_process_udp2_datagram(librdp_server_peer* peer,
                                                       const void* datagram,
                                                       size_t datagram_len,
                                                       void* response,
                                                       size_t response_capacity,
                                                       size_t* response_len)
{
    rdp_buffer packet_bytes;
    rdp_buffer response_packet;
    rdp_buffer ack_wire;
    rdp_udp2_prefix prefix;
    rdp_udp2_packet packet;
    rdp_udp2_packet_kind kind = RDP_UDP2_PACKET_KIND_CONTROL;
    uint8_t response_is_ack = 0;
    uint8_t response_is_ack_vector = 0;
    uint8_t next_window_started = 0;
    uint8_t next_fallback_tcp = 0;
    uint8_t next_log_window_size = 0;
    uint16_t next_receive_sequence = 0;
    uint16_t next_last_receive_sequence = 0;
    uint16_t next_last_peer_ack_sequence = 0;
    uint64_t metric_ack_in = 0;
    uint64_t metric_ack_vector_in = 0;
    uint64_t metric_ack_vector_lost = 0;
    uint64_t metric_lost = 0;
    uint64_t metric_reordered = 0;
    uint64_t metric_tcp_fallback = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !datagram || datagram_len == 0 || !response_len ||
        (!response && response_capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *response_len = 0;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if ((peer->requested_features & (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT) == 0 ||
        !peer->multitransport_negotiated)
        return LIBRDP_STATUS_UNSUPPORTED;
    next_window_started = peer->multitransport_udp2_window_started;
    next_fallback_tcp = peer->multitransport_udp2_fallback_tcp;
    next_log_window_size = peer->multitransport_udp2_log_window_size;
    next_receive_sequence = peer->multitransport_udp2_next_receive_sequence;
    next_last_receive_sequence = peer->multitransport_udp2_last_receive_sequence;
    next_last_peer_ack_sequence = peer->multitransport_udp2_last_peer_ack_sequence;

    rdp_buffer_init(&packet_bytes);
    rdp_buffer_init(&response_packet);
    rdp_buffer_init(&ack_wire);
    memset(&prefix, 0, sizeof(prefix));
    memset(&packet, 0, sizeof(packet));

    status = rdp_udp2_unwrap_packet(&packet_bytes, datagram, datagram_len, &prefix);
    if (status == LIBRDP_STATUS_OK && prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
        status = rdp_udp2_parse_packet(packet_bytes.data, packet_bytes.length, &packet);
    if (status == LIBRDP_STATUS_OK && prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
        status = rdp_udp2_classify_packet(&packet, &kind);
    if (status == LIBRDP_STATUS_OK && prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA)
    {
        if (packet.has_ack)
        {
            next_last_peer_ack_sequence = packet.ack.sequence_number;
            metric_ack_in++;
        }
        if (packet.has_ack_vector)
        {
            uint32_t received = 0;
            uint32_t lost = 0;

            status = rdp_udp2_ack_vector_count(&packet.ack_vector, &received, &lost);
            if (status == LIBRDP_STATUS_OK)
            {
                metric_ack_vector_in++;
                metric_ack_vector_lost += lost;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK &&
        (kind == RDP_UDP2_PACKET_KIND_DATA || kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK))
    {
        uint16_t sequence = packet.data_sequence_number;
        uint16_t expected = next_receive_sequence;
        uint16_t distance = next_window_started ? (uint16_t)(sequence - expected) : 0;
        uint32_t window = UINT32_C(1) << packet.header.log_window_size;

        if (window == 0)
            window = 1u;
        next_log_window_size = packet.header.log_window_size;
        if (!next_window_started)
        {
            next_window_started = 1;
            next_receive_sequence = (uint16_t)(sequence + 1u);
            next_last_receive_sequence = sequence;
        }
        else if (distance == 0)
        {
            next_receive_sequence = (uint16_t)(sequence + 1u);
            next_last_receive_sequence = sequence;
        }
        else if (distance < 0x8000u && distance <= window && distance <= RDP_SERVER_UDP2_MAX_REPORTABLE_LOSS)
        {
            uint8_t coded_ack_vector[RDP_SERVER_UDP2_ACK_VECTOR_MAX_BYTES];
            uint16_t base_sequence = expected;
            uint16_t remaining = distance;
            uint8_t count = 0;

            memset(coded_ack_vector, 0, sizeof(coded_ack_vector));
            while (remaining > 0 && count < (uint8_t)sizeof(coded_ack_vector))
            {
                uint8_t run = remaining > RDP_SERVER_UDP2_ACK_VECTOR_MAX_RUN ?
                                  RDP_SERVER_UDP2_ACK_VECTOR_MAX_RUN :
                                  (uint8_t)remaining;
                coded_ack_vector[count] = (uint8_t)(0x80u | (uint8_t)(run - 1u));
                remaining = (uint16_t)(remaining - run);
                count++;
            }
            if (remaining != 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            if (status == LIBRDP_STATUS_OK)
                status = rdp_udp2_write_ack_vector_packet(&response_packet,
                                                          packet.header.log_window_size,
                                                          base_sequence,
                                                          0,
                                                          0,
                                                          0,
                                                          coded_ack_vector,
                                                          count);
            if (status == LIBRDP_STATUS_OK)
            {
                next_receive_sequence = (uint16_t)(sequence + 1u);
                next_last_receive_sequence = sequence;
                metric_lost += distance;
                response_is_ack_vector = 1;
            }
        }
        else if (distance < 0x8000u)
        {
            next_fallback_tcp = 1;
            metric_tcp_fallback++;
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else
        {
            metric_reordered++;
        }
        if (status == LIBRDP_STATUS_OK && response_packet.length == 0)
        {
            status = rdp_udp2_write_ack_packet(&response_packet,
                                               packet.header.log_window_size,
                                               packet.data_sequence_number,
                                               0,
                                               0,
                                               NULL,
                                               0,
                                               0);
            if (status == LIBRDP_STATUS_OK)
                response_is_ack = 1;
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp2_wrap_packet(&ack_wire,
                                          response_packet.data,
                                          response_packet.length,
                                          RDP_UDP2_PACKET_TYPE_DATA);
    }
    if (status == LIBRDP_STATUS_OK && ack_wire.length > response_capacity)
    {
        *response_len = ack_wire.length;
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (ack_wire.length > 0)
            memcpy(response, ack_wire.data, ack_wire.length);
        *response_len = ack_wire.length;
        peer->multitransport_udp2_window_started = next_window_started;
        peer->multitransport_udp2_fallback_tcp = next_fallback_tcp;
        peer->multitransport_udp2_log_window_size = next_log_window_size;
        peer->multitransport_udp2_next_receive_sequence = next_receive_sequence;
        peer->multitransport_udp2_last_receive_sequence = next_last_receive_sequence;
        peer->multitransport_udp2_last_peer_ack_sequence = next_last_peer_ack_sequence;
        peer->multitransport_udp2_active = 1;
        rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
        rdp_server_metric_add(&peer->metrics.udp2_datagrams_in, 1u);
        rdp_server_metric_add(&peer->metrics.udp2_bytes_in, (uint64_t)datagram_len);
        rdp_server_metric_add(&peer->metrics.udp2_ack_in, metric_ack_in);
        rdp_server_metric_add(&peer->metrics.udp2_ack_vector_in, metric_ack_vector_in);
        rdp_server_metric_add(&peer->metrics.udp2_lost_packets, metric_ack_vector_lost + metric_lost);
        rdp_server_metric_add(&peer->metrics.udp2_reordered_packets, metric_reordered);
        if (ack_wire.length > 0)
        {
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
            rdp_server_metric_add(&peer->metrics.udp2_datagrams_out, 1u);
            rdp_server_metric_add(&peer->metrics.udp2_bytes_out, (uint64_t)ack_wire.length);
            if (response_is_ack)
                rdp_server_metric_add(&peer->metrics.udp2_ack_out, 1u);
            if (response_is_ack_vector)
                rdp_server_metric_add(&peer->metrics.udp2_ack_vector_out, 1u);
        }
    }
    else if (metric_tcp_fallback > 0)
    {
        peer->multitransport_udp2_fallback_tcp = next_fallback_tcp;
        rdp_server_metric_add(&peer->metrics.udp2_tcp_fallbacks, metric_tcp_fallback);
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.udp2.datagram",
                                 "UDP2 datagram processing failed");

    rdp_buffer_free(&ack_wire);
    rdp_buffer_free(&response_packet);
    rdp_buffer_free(&packet_bytes);
    return status;
}

static int rdp_server_static_channel_joined_named(const librdp_server_peer* peer,
                                                  uint16_t channel_id,
                                                  const char* expected_name)
{
    char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
    uint16_t index = 0;

    if (!peer || !expected_name ||
        !rdp_server_static_channel_index(peer, channel_id, &index) ||
        !peer->advertised_channel_joined[index])
        return 0;
    rdp_server_copy_channel_name(name, peer->advertised_channels[index].name);
    return rdp_server_name_equals(name, strlen(name), expected_name);
}

int rdp_server_dynamic_channel_open_named(librdp_server_peer* peer,
                                                 uint32_t dynamic_channel_id,
                                                 const char* expected_name)
{
    rdp_server_dynamic_channel* channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);

    if (!channel || !expected_name)
        return 0;
    return rdp_server_name_equals(channel->name, strlen(channel->name), expected_name);
}

static int rdp_server_tunnel_type_present(const uint32_t* tunnel_types, uint32_t tunnel_count, uint32_t tunnel_type)
{
    if (!tunnel_types)
        return 0;
    for (uint32_t i = 0; i < tunnel_count; i++)
    {
        if (tunnel_types[i] == tunnel_type)
            return 1;
    }
    return 0;
}

static int rdp_server_soft_sync_channels_open(librdp_server_peer* peer,
                                              const rdp_dynamic_channel_soft_sync_channel_list* list)
{
    if (!peer || !list)
        return 0;
    for (uint16_t i = 0; i < list->channel_count; i++)
    {
        uint32_t channel_id = 0;

        if (rdp_dynamic_channel_soft_sync_channel_list_get_id(list, i, &channel_id) != LIBRDP_STATUS_OK ||
            !rdp_server_find_dynamic_channel(peer, channel_id))
            return 0;
    }
    return 1;
}

static librdp_status rdp_server_select_soft_sync_tunnels(librdp_server_peer* peer,
                                                         const rdp_dynamic_channel_soft_sync_request* request,
                                                         uint32_t* tunnel_types,
                                                         uint32_t tunnel_capacity,
                                                         uint32_t* tunnel_count)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !request || !tunnel_types || !tunnel_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *tunnel_count = 0;
    if (!peer->multitransport_negotiated ||
        (peer->requested_features & (uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT) == 0)
        return LIBRDP_STATUS_OK;
    for (uint16_t i = 0; i < request->tunnel_count && status == LIBRDP_STATUS_OK; i++)
    {
        rdp_dynamic_channel_soft_sync_channel_list list;

        status = rdp_dynamic_channel_soft_sync_request_get_list(request, i, &list);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (!rdp_server_soft_sync_channels_open(peer, &list))
            continue;
        if (list.tunnel_type != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
            list.tunnel_type != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY)
            continue;
        if (!rdp_server_tunnel_type_present(tunnel_types, *tunnel_count, list.tunnel_type))
        {
            if (*tunnel_count >= tunnel_capacity)
                return LIBRDP_STATUS_LIMIT_EXCEEDED;
            tunnel_types[*tunnel_count] = list.tunnel_type;
            (*tunnel_count)++;
        }
    }
    return status;
}

librdp_status rdp_server_send_static_named_buffer(librdp_server_peer* peer,
                                                        uint16_t channel_id,
                                                        const char* expected_name,
                                                        const rdp_buffer* buffer)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_static_channel_joined_named(peer, channel_id, expected_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_peer_send_channel_data(peer, channel_id, buffer->data, buffer->length);
}

static librdp_status rdp_server_udp_write_ack_vector_response(rdp_buffer* response,
                                                              uint32_t source_ack,
                                                              uint16_t receive_window,
                                                              uint32_t pending_gap)
{
    rdp_udp_fec_header header;
    uint8_t vector[RDP_SERVER_UDP_ACK_VECTOR_MAX_BYTES];
    uint16_t vector_size = 0;
    uint32_t remaining = pending_gap;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!response || pending_gap > RDP_SERVER_UDP_MAX_REPORTABLE_PENDING)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&header, 0, sizeof(header));
    memset(vector, 0, sizeof(vector));
    header.source_ack = source_ack;
    header.receive_window_size = receive_window == 0 ? 1u : receive_window;
    header.flags = RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_SACK_OPTION;
    while (remaining > 0 && vector_size < (uint16_t)sizeof(vector))
    {
        uint8_t run = remaining > RDP_SERVER_UDP_ACK_VECTOR_MAX_RUN ?
                          RDP_SERVER_UDP_ACK_VECTOR_MAX_RUN :
                          (uint8_t)remaining;
        vector[vector_size] = (uint8_t)((RDP_UDP_ACK_VECTOR_STATE_PENDING << 6) |
                                        (uint8_t)(run - 1u));
        remaining -= run;
        vector_size++;
    }
    if (remaining != 0 || vector_size >= (uint16_t)sizeof(vector))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    vector[vector_size] = 0;
    vector_size++;
    status = rdp_udp_write_fec_header(response, &header);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp_write_ack_vector(response, vector, vector_size);
    return status;
}

/*
 * Processes one caller-owned RDPEUDP datagram after dynamic-channel soft-sync
 * selected a UDP tunnel. State commits only after any required SACK response is
 * successfully copied to the caller buffer, so retrying with a larger response
 * buffer cannot create artificial sequence gaps.
 */
librdp_status librdp_server_peer_process_udp_datagram(librdp_server_peer* peer,
                                                      const void* datagram,
                                                      size_t datagram_len,
                                                      void* response,
                                                      size_t response_capacity,
                                                      size_t* response_len)
{
    const uint8_t* bytes = (const uint8_t*)datagram;
    rdp_udp_fec_header header;
    rdp_udp_payload_prefix prefix;
    rdp_udp_source_payload_header source;
    rdp_udp_ack_vector ack_vector;
    rdp_udp_syn_data syn;
    rdp_udp_syn_data_ex syn_ex;
    rdp_udp_ack_of_ack_vector ack_of_ack;
    rdp_buffer response_packet;
    uint8_t next_window_started = 0;
    uint8_t next_fallback_tcp = 0;
    uint16_t next_receive_window = 0;
    uint32_t next_receive_sequence = 0;
    uint32_t next_last_receive_sequence = 0;
    uint64_t metric_ack_vector_in = 0;
    uint64_t metric_pending_from_peer = 0;
    uint64_t metric_pending = 0;
    uint64_t metric_tcp_fallback = 0;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !datagram || datagram_len == 0 || !response_len ||
        (!response && response_capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *response_len = 0;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if ((peer->requested_features & (uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT) == 0 ||
        !peer->multitransport_negotiated)
        return LIBRDP_STATUS_UNSUPPORTED;

    memset(&header, 0, sizeof(header));
    memset(&prefix, 0, sizeof(prefix));
    memset(&source, 0, sizeof(source));
    memset(&ack_vector, 0, sizeof(ack_vector));
    memset(&syn, 0, sizeof(syn));
    memset(&syn_ex, 0, sizeof(syn_ex));
    memset(&ack_of_ack, 0, sizeof(ack_of_ack));
    rdp_buffer_init(&response_packet);
    next_window_started = peer->multitransport_udp_window_started;
    next_fallback_tcp = peer->multitransport_udp_fallback_tcp;
    next_receive_window = peer->multitransport_udp_receive_window;
    next_receive_sequence = peer->multitransport_udp_next_receive_sequence;
    next_last_receive_sequence = peer->multitransport_udp_last_receive_sequence;

    status = rdp_udp_parse_fec_header(datagram, datagram_len, &header);
    if (status == LIBRDP_STATUS_OK)
        offset = 8u;
    if (status == LIBRDP_STATUS_OK)
    {
        uint16_t known_payload_flags = RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_SYNLOSSY |
                                       RDP_UDP_FLAG_SYNEX | RDP_UDP_FLAG_ACK_OF_ACKS |
                                       RDP_UDP_FLAG_SACK_OPTION | RDP_UDP_FLAG_DATA;
        uint16_t payload_flags = (uint16_t)(header.flags & known_payload_flags);

        if ((payload_flags & RDP_UDP_FLAG_DATA) != 0 &&
            (payload_flags & ~(RDP_UDP_FLAG_DATA | RDP_UDP_FLAG_FEC)) != 0)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else if ((payload_flags & RDP_UDP_FLAG_SYNEX) != 0 &&
                 payload_flags != RDP_UDP_FLAG_SYNEX)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else if ((payload_flags & RDP_UDP_FLAG_SACK_OPTION) != 0 &&
                 payload_flags != RDP_UDP_FLAG_SACK_OPTION)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK &&
        (header.flags & (RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_SYNLOSSY)) != 0)
    {
        if (datagram_len - offset != 8u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_udp_parse_syn_data(bytes + offset, datagram_len - offset, &syn);
    }
    else if (status == LIBRDP_STATUS_OK && (header.flags & RDP_UDP_FLAG_SYNEX) != 0)
    {
        status = rdp_udp_parse_syn_data_ex(bytes + offset, datagram_len - offset, &syn_ex);
    }
    else if (status == LIBRDP_STATUS_OK && (header.flags & RDP_UDP_FLAG_ACK_OF_ACKS) != 0)
    {
        if (datagram_len - offset != 4u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_udp_parse_ack_of_ack_vector(bytes + offset, datagram_len - offset, &ack_of_ack);
    }
    else if (status == LIBRDP_STATUS_OK && (header.flags & RDP_UDP_FLAG_SACK_OPTION) != 0)
    {
        uint32_t received = 0;
        uint32_t pending = 0;

        status = rdp_udp_parse_ack_vector(bytes + offset, datagram_len - offset, &ack_vector);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp_ack_vector_count(&ack_vector, &received, &pending);
        if (status == LIBRDP_STATUS_OK)
        {
            metric_ack_vector_in++;
            metric_pending_from_peer += pending;
        }
    }
    else if (status == LIBRDP_STATUS_OK && (header.flags & RDP_UDP_FLAG_DATA) != 0)
    {
        uint32_t sequence = 0;
        uint32_t expected = next_receive_sequence;
        uint32_t distance = 0;
        uint16_t window = header.receive_window_size == 0 ? 1u : header.receive_window_size;

        if (datagram_len - offset < 10u)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp_parse_payload_prefix(bytes + offset, datagram_len - offset, &prefix);
        if (status == LIBRDP_STATUS_OK &&
            (prefix.payload_size < 8u || (size_t)prefix.payload_size > datagram_len - offset - 2u))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp_parse_source_payload_header(bytes + offset + 2u,
                                                         prefix.payload_size,
                                                         &source);
        if (status == LIBRDP_STATUS_OK)
        {
            sequence = source.coded_sequence;
            distance = next_window_started ? sequence - expected : 0;
            next_receive_window = window;
            if (!next_window_started)
            {
                next_window_started = 1;
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
            }
            else if (distance == 0)
            {
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
            }
            else if (distance < 0x80000000u && distance <= window &&
                     distance <= RDP_SERVER_UDP_MAX_REPORTABLE_PENDING)
            {
                next_receive_sequence = sequence + 1u;
                next_last_receive_sequence = sequence;
                metric_pending += distance;
            }
            else if (distance < 0x80000000u)
            {
                next_fallback_tcp = 1;
                metric_tcp_fallback++;
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_udp_write_ack_vector_response(&response_packet,
                                                              sequence,
                                                              window,
                                                              (uint32_t)metric_pending);
    }
    if (status == LIBRDP_STATUS_OK && response_packet.length > response_capacity)
    {
        *response_len = response_packet.length;
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (response_packet.length > 0)
            memcpy(response, response_packet.data, response_packet.length);
        *response_len = response_packet.length;
        peer->multitransport_udp_window_started = next_window_started;
        peer->multitransport_udp_fallback_tcp = next_fallback_tcp;
        peer->multitransport_udp_receive_window = next_receive_window;
        peer->multitransport_udp_next_receive_sequence = next_receive_sequence;
        peer->multitransport_udp_last_receive_sequence = next_last_receive_sequence;
        peer->multitransport_udp_active = 1;
        rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
        rdp_server_metric_add(&peer->metrics.udp_datagrams_in, 1u);
        rdp_server_metric_add(&peer->metrics.udp_bytes_in, (uint64_t)datagram_len);
        rdp_server_metric_add(&peer->metrics.udp_ack_vector_in, metric_ack_vector_in);
        rdp_server_metric_add(&peer->metrics.udp_pending_packets, metric_pending_from_peer + metric_pending);
        if (response_packet.length > 0)
        {
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
            rdp_server_metric_add(&peer->metrics.udp_datagrams_out, 1u);
            rdp_server_metric_add(&peer->metrics.udp_bytes_out, (uint64_t)response_packet.length);
            rdp_server_metric_add(&peer->metrics.udp_ack_vector_out, 1u);
        }
    }
    else if (metric_tcp_fallback > 0)
    {
        peer->multitransport_udp_fallback_tcp = next_fallback_tcp;
        rdp_server_metric_add(&peer->metrics.udp_tcp_fallbacks, metric_tcp_fallback);
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.udp.datagram",
                                 "RDPEUDP datagram processing failed");
    rdp_buffer_free(&response_packet);
    return status;
}

librdp_status librdp_server_peer_get_clipboard_state(const librdp_server_peer* peer,
                                                     librdp_server_clipboard_state* state)
{
    if (!peer || !rdp_server_clipboard_state_valid(state))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    state->monitor_ready_sent = peer->clipboard_monitor_ready_sent;
    state->monitor_ready_received = peer->clipboard_monitor_ready_received;
    state->capabilities_sent = peer->clipboard_capabilities_sent;
    state->capabilities_received = peer->clipboard_capabilities_received;
    state->formats_sent = peer->clipboard_formats_sent;
    state->formats_accepted = peer->clipboard_formats_accepted;
    state->pending_format_request = peer->clipboard_pending_format;
    state->pending_file_request = peer->clipboard_pending_file;
    state->locked = peer->clipboard_locked;
    state->format_count = peer->clipboard_format_count;
    state->pending_format_id = peer->clipboard_pending_format_id;
    state->pending_file_stream_id = peer->clipboard_pending_file_stream_id;
    state->locked_clip_data_id = peer->clipboard_locked_clip_data_id;
    state->reconnect_generation = peer->clipboard_reconnect_generation;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_cancel_clipboard_requests(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (peer->clipboard_pending_format)
    {
        rdp_server_emit_clipboard_cancel(
            peer,
            LIBRDP_SERVER_CLIPBOARD_FORMAT_DATA_RESPONSE,
            peer->clipboard_pending_format_id,
            0u);
    }
    if (peer->clipboard_pending_file)
    {
        rdp_server_emit_clipboard_cancel(
            peer,
            LIBRDP_SERVER_CLIPBOARD_FILE_CONTENTS_RESPONSE,
            0u,
            peer->clipboard_pending_file_stream_id);
    }
    peer->clipboard_pending_format = 0;
    peer->clipboard_pending_file = 0;
    peer->clipboard_pending_format_id = 0;
    peer->clipboard_pending_file_stream_id = 0;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_send_clipboard_monitor_ready(librdp_server_peer* peer, uint16_t channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_monitor_ready(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer)
        peer->clipboard_monitor_ready_sent = 1u;
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_capabilities(librdp_server_peer* peer,
                                                             uint16_t channel_id,
                                                             uint32_t general_flags)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_capabilities(&payload, general_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer)
        peer->clipboard_capabilities_sent = 1u;
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_format_list(
    librdp_server_peer* peer,
    uint16_t channel_id,
    const librdp_server_clipboard_format* formats,
    uint32_t count,
    int long_names)
{
    rdp_clipboard_format_entry* entries = NULL;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!formats && count > 0) || count > RDP_SERVER_MAX_CLIPBOARD_FORMATS)
        return count > RDP_SERVER_MAX_CLIPBOARD_FORMATS ? LIBRDP_STATUS_LIMIT_EXCEEDED :
                                                          LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count > 0)
    {
        entries = (rdp_clipboard_format_entry*)calloc(count, sizeof(*entries));
        if (!entries)
            return LIBRDP_STATUS_NO_MEMORY;
        for (uint32_t i = 0; i < count; i++)
        {
            if (!formats[i].name && formats[i].name_len > 0)
            {
                free(entries);
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            }
            entries[i].format_id = formats[i].format_id;
            entries[i].name = (const uint8_t*)formats[i].name;
            entries[i].name_len = formats[i].name_len;
        }
    }
    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_format_list(&payload, entries, count, long_names ? 1 : 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer)
    {
        peer->clipboard_formats_sent = 1u;
        peer->clipboard_formats_accepted = 0;
        peer->clipboard_format_count = count;
    }
    rdp_buffer_free(&payload);
    free(entries);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_format_list_response(librdp_server_peer* peer,
                                                                    uint16_t channel_id,
                                                                    int ok)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_format_list_response(&payload, ok);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_format_data_request(librdp_server_peer* peer,
                                                                    uint16_t channel_id,
                                                                    uint32_t format_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_format_data_request(&payload, format_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer)
    {
        peer->clipboard_pending_format = 1u;
        peer->clipboard_pending_format_id = format_id;
    }
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_format_data_response(librdp_server_peer* peer,
                                                                     uint16_t channel_id,
                                                                     int ok,
                                                                     const void* data,
                                                                     size_t data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_format_data_response(&payload, ok, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_file_contents_request(
    librdp_server_peer* peer,
    uint16_t channel_id,
    uint32_t stream_id,
    int32_t lindex,
    uint32_t flags,
    uint64_t position,
    uint32_t requested,
    const uint32_t* clip_data_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_file_contents_request(&payload,
                                                       stream_id,
                                                       lindex,
                                                       flags,
                                                       position,
                                                       requested,
                                                       clip_data_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer)
    {
        peer->clipboard_pending_file = 1u;
        peer->clipboard_pending_file_stream_id = stream_id;
    }
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_file_contents_response(
    librdp_server_peer* peer,
    uint16_t channel_id,
    int ok,
    uint32_t stream_id,
    const void* data,
    size_t data_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_file_contents_response(&payload, ok, stream_id, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_lock(librdp_server_peer* peer,
                                                     uint16_t channel_id,
                                                     uint32_t clip_data_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_lock(&payload, clip_data_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer)
    {
        peer->clipboard_locked = 1u;
        peer->clipboard_locked_clip_data_id = clip_data_id;
    }
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_unlock(librdp_server_peer* peer,
                                                       uint16_t channel_id,
                                                       uint32_t clip_data_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_unlock(&payload, clip_data_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    if (status == LIBRDP_STATUS_OK && peer &&
        peer->clipboard_locked_clip_data_id == clip_data_id)
    {
        peer->clipboard_locked = 0;
        peer->clipboard_locked_clip_data_id = 0;
    }
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_close_dynamic_channel(librdp_server_peer* peer, uint32_t dynamic_channel_id)
{
    rdp_server_dynamic_channel* channel = NULL;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);
    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_dynamic_channel_write_close(&packet, dynamic_channel_id, channel->channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_packet(peer, &packet);
    if (status == LIBRDP_STATUS_OK)
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        if (strcmp(channel->name, RDP_GRAPHICS_PIPELINE_CHANNEL_NAME) == 0)
            rdp_server_graphics_frame_state_reset(peer);
        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        channel->open = 0;
        channel->closing = 1;
        peer->dynamic_channel_count--;
        rdp_server_extension_state_mark_close(peer, family);
        rdp_buffer_free(&channel->fragment);
        rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE, NULL, 0);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.close",
                                 "dynamic channel close failed");
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_dynamic_apply_channel_state(librdp_server_peer* peer,
                                                            const rdp_server_dynamic_channel* channel,
                                                            const uint8_t* data,
                                                            size_t data_len)
{
    if (!peer || !channel || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (strcmp(channel->name, RDP_GRAPHICS_PIPELINE_CHANNEL_NAME) == 0)
        return rdp_server_graphics_handle_frame_ack(peer, data, data_len);
    return LIBRDP_STATUS_OK;
}

/*
 * Dispatches one complete DVC message after family-specific decoding. Auth
 * Redirection payloads are unwrapped exactly once and accepted only when they
 * match the pending or retired call; decode and correlation failures stop
 * generic dispatch. Decrypted storage is cleansed on every exit path.
 */
static librdp_status rdp_server_dynamic_emit_reassembled(librdp_server_peer* peer,
                                                         rdp_server_dynamic_channel* channel,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_auth_redirection_response_message auth_response;
    rdp_buffer auth_plaintext;
    const uint8_t* extension_data = data;
    size_t extension_data_len = data_len;
    uint32_t auth_package = RDP_AUTH_REDIRECTION_PACKAGE_UNKNOWN;
    int auth_message = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !channel || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&auth_plaintext);
    memset(&auth_response, 0, sizeof(auth_response));
    auth_message = strcmp(channel->name, RDP_AUTH_REDIRECTION_CHANNEL_NAME) == 0;
    if (auth_message)
    {
        status = rdp_server_auth_redirection_decode(peer,
                                                    data,
                                                    data_len,
                                                    &auth_plaintext,
                                                    &auth_package,
                                                    &extension_data,
                                                    &extension_data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_auth_redirection_parse_response_message(
                extension_data,
                extension_data_len,
                &auth_response);
        if (status == LIBRDP_STATUS_OK &&
            peer->auth_redirection_retired &&
            channel->channel_id == peer->auth_redirection_retired_channel_id &&
            auth_package == peer->auth_redirection_retired_package &&
            auth_response.response.call_id ==
                peer->auth_redirection_retired_call_id)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.auth_redirection.response.late",
                            "dvc_channel_id=%u package=%u call_id=%u",
                            channel->channel_id,
                            auth_package,
                            auth_response.response.call_id);
            peer->auth_redirection_retired = 0u;
            status = LIBRDP_STATUS_AGAIN;
        }
        else if (status == LIBRDP_STATUS_OK &&
                 (!peer->auth_redirection_pending ||
                  channel->channel_id !=
                      peer->auth_redirection_pending_channel_id ||
                  auth_package != peer->auth_redirection_pending_package ||
                  auth_response.response.call_id !=
                      peer->auth_redirection_pending_call_id))
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status == LIBRDP_STATUS_AGAIN)
        {
            rdp_server_metric_add(&peer->metrics.dynamic_channel_in, 1u);
            rdp_server_metric_add(&peer->metrics.dynamic_channel_bytes_in,
                                  (uint64_t)data_len);
            if (auth_plaintext.data && auth_plaintext.capacity > 0u)
                OPENSSL_cleanse(auth_plaintext.data,
                                auth_plaintext.capacity);
            rdp_buffer_free(&auth_plaintext);
            return LIBRDP_STATUS_OK;
        }
        if (status == LIBRDP_STATUS_OK)
        {
            librdp_server_extension_state* state =
                rdp_server_extension_state_mut(
                    peer,
                    LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION);

            peer->auth_redirection_pending_channel_id = 0u;
            peer->auth_redirection_pending_package =
                RDP_AUTH_REDIRECTION_PACKAGE_UNKNOWN;
            peer->auth_redirection_pending_call_id = 0u;
            peer->auth_redirection_pending = 0u;
            if (state && state->pending_requests > 0u)
                state->pending_requests--;
        }
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_dynamic_apply_channel_state(peer,
                                                        channel,
                                                        data,
                                                        data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_emit_extension_event(
            peer,
            channel->name,
            strlen(channel->name),
            rdp_server_dynamic_static_channel_id(peer),
            channel->channel_id,
            channel->priority,
            extension_data,
            extension_data_len);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_server_metric_add(&peer->metrics.dynamic_channel_in, 1u);
        rdp_server_metric_add(&peer->metrics.dynamic_channel_bytes_in,
                              (uint64_t)data_len);
        rdp_server_emit_dynamic_channel_event(
            peer,
            channel,
            LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA,
            data,
            data_len);
    }
    if (auth_plaintext.data && auth_plaintext.capacity > 0u)
        OPENSSL_cleanse(auth_plaintext.data, auth_plaintext.capacity);
    rdp_buffer_free(&auth_plaintext);
    return status;
}

/*
 * Known extension channels require a registered family or feature provider.
 * Unknown application channels retain the explicit accept-callback contract
 * and are not assigned built-in feature state.
 */
static int rdp_server_dynamic_provider_ready(
    const librdp_server_peer* peer,
    librdp_server_extension_family family,
    librdp_feature feature)
{
    if (!peer)
        return 0;
    if (family == LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION &&
        (peer->selected_protocol != RDP_X224_PROTOCOL_NLA ||
         !peer->credssp_security_ready || !peer->nla_authenticated))
        return 0;
    if (family == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return 1;
    if (rdp_server_extension_provider_ready(
            peer->backend_extension_families,
            family))
        return 1;
    return (uint32_t)feature != 0u &&
           (peer->backend_features & (uint32_t)feature) != 0u;
}

/*
 * Validate and answer one client DVC CREATE transaction. Duplicate IDs and
 * malformed names fail the parser path, unavailable known providers receive a
 * not-supported response without invoking application code, and no channel
 * slot becomes visible until every admission check has succeeded.
 */
static librdp_status rdp_server_dynamic_handle_create(librdp_server_peer* peer,
                                                      const uint8_t* data,
                                                      size_t data_len)
{
    rdp_dynamic_channel_create_request request;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_server_extension_family family =
        LIBRDP_SERVER_EXTENSION_UNKNOWN;
    librdp_feature feature = (librdp_feature)0;
    rdp_buffer response;
    uint32_t status_code = RDP_DYNAMIC_CHANNEL_STATUS_OK;
    librdp_status status = LIBRDP_STATUS_OK;
    int accepted = 1;

    memset(&request, 0, sizeof(request));
    rdp_buffer_init(&response);
    status = rdp_dynamic_channel_parse_create_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (status == LIBRDP_STATUS_OK && request.name_len >= RDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK && rdp_server_find_dynamic_channel_any(peer, request.channel_id))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_server_extension_classify_name((const char*)request.name,
                                           request.name_len,
                                           &family,
                                           &feature);
        accepted = rdp_server_dynamic_provider_ready(peer,
                                                     family,
                                                     feature);
        if (!accepted)
            status_code = RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    }
    if (status == LIBRDP_STATUS_OK && accepted &&
        peer->dynamic_channel_accept_callback)
    {
        accepted = peer->dynamic_channel_accept_callback(peer,
                                                         request.channel_id,
                                                         request.priority,
                                                         (const char*)request.name,
                                                         request.name_len,
                                                         peer->dynamic_channel_accept_user_data);
        if (!accepted)
            status_code = RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    }
    if (status == LIBRDP_STATUS_OK && accepted)
    {
        channel = rdp_server_allocate_dynamic_channel(peer);
        if (!channel)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status != LIBRDP_STATUS_OK)
        status_code = RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    if (rdp_dynamic_channel_write_create_response(&response,
                                                  request.channel_id,
                                                  request.channel_id_bytes ? request.channel_id_bytes : 1u,
                                                  status_code) == LIBRDP_STATUS_OK)
        (void)rdp_server_send_dynamic_packet(peer, &response);
    if (status == LIBRDP_STATUS_OK && accepted && channel)
    {
        memset(channel, 0, sizeof(*channel));
        channel->channel_id = request.channel_id;
        channel->channel_id_bytes = request.channel_id_bytes;
        channel->priority = request.priority;
        channel->open = 1;
        memcpy(channel->name, request.name, request.name_len);
        channel->name[request.name_len] = '\0';
        rdp_server_extension_state_mark_open(peer, family, 0, request.channel_id, request.priority);
        rdp_buffer_init(&channel->fragment);
        peer->dynamic_channel_count++;
        rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN, NULL, 0);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.dvc.create",
                        "channel_id=%u name_len=%u",
                        request.channel_id,
                        (unsigned)request.name_len);
    }
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_dynamic_handle_create_response(librdp_server_peer* peer,
                                                               const rdp_dynamic_channel_create_response* response)
{
    rdp_server_dynamic_channel* channel = NULL;

    if (!peer || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel = rdp_server_find_pending_dynamic_channel(peer, response->channel_id);
    if (!channel)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (response->status_code != RDP_DYNAMIC_CHANNEL_STATUS_OK)
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        rdp_server_extension_state_mark_close(peer, family);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.dvc.open.rejected",
                        "channel_id=%u status=0x%08x",
                        response->channel_id,
                        response->status_code);
        rdp_buffer_free(&channel->fragment);
        memset(channel, 0, sizeof(*channel));
        return LIBRDP_STATUS_OK;
    }
    channel->pending_open = 0;
    channel->open = 1;
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        rdp_server_extension_state_mark_open(peer, family, 0, channel->channel_id, channel->priority);
    }
    peer->dynamic_channel_count++;
    rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN, NULL, 0);
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "server.dvc.open.done",
                    "channel_id=%u name_len=%u",
                    channel->channel_id,
                    (unsigned)strlen(channel->name));
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_dynamic_handle_data_first(librdp_server_peer* peer,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_dynamic_channel_data_first_pdu pdu;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_status status = rdp_dynamic_channel_parse_data_first(data, data_len, &pdu);

    if (status != LIBRDP_STATUS_OK)
        return status;
    channel = rdp_server_find_dynamic_channel(peer, pdu.channel_id);
    if (!channel || channel->fragment.length != 0 || pdu.total_length < pdu.data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu.total_length > RDP_SERVER_DYNAMIC_MESSAGE_MAX)
    {
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    channel->fragment_expected = pdu.total_length;
    status = rdp_buffer_append(&channel->fragment, pdu.data, pdu.data_len);
    if (status == LIBRDP_STATUS_OK && channel->fragment.length == channel->fragment_expected)
    {
        status = rdp_server_dynamic_emit_reassembled(peer,
                                                     channel,
                                                     channel->fragment.data,
                                                     channel->fragment.length);
        channel->fragment.length = 0;
        channel->fragment_expected = 0;
    }
    return status;
}

static librdp_status rdp_server_dynamic_handle_data(librdp_server_peer* peer,
                                                    const uint8_t* data,
                                                    size_t data_len)
{
    rdp_dynamic_channel_data_pdu pdu;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_status status = rdp_dynamic_channel_parse_data(data, data_len, &pdu);

    if (status != LIBRDP_STATUS_OK)
        return status;
    channel = rdp_server_find_dynamic_channel(peer, pdu.channel_id);
    if (!channel)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (channel->fragment.length == 0)
        return rdp_server_dynamic_emit_reassembled(peer, channel, pdu.data, pdu.data_len);
    if (channel->fragment.length > (size_t)channel->fragment_expected || pdu.data_len == 0 ||
        pdu.data_len > (size_t)channel->fragment_expected - channel->fragment.length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(&channel->fragment, pdu.data, pdu.data_len);
    if (status == LIBRDP_STATUS_OK && channel->fragment.length == channel->fragment_expected)
    {
        status = rdp_server_dynamic_emit_reassembled(peer,
                                                     channel,
                                                     channel->fragment.data,
                                                     channel->fragment.length);
        channel->fragment.length = 0;
        channel->fragment_expected = 0;
    }
    return status;
}

static librdp_status rdp_server_dynamic_handle_close(librdp_server_peer* peer,
                                                     const uint8_t* data,
                                                     size_t data_len)
{
    rdp_dynamic_channel_close_pdu pdu;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_status status = rdp_dynamic_channel_parse_close(data, data_len, &pdu);

    if (status != LIBRDP_STATUS_OK)
        return status;
    channel = rdp_server_find_dynamic_channel_any(peer, pdu.channel_id);
    if (!channel)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (channel->closing)
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        if (strcmp(channel->name, RDP_GRAPHICS_PIPELINE_CHANNEL_NAME) == 0)
            rdp_server_graphics_frame_state_reset(peer);
        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        rdp_server_extension_state_mark_close(peer, family);
        rdp_buffer_free(&channel->fragment);
        memset(channel, 0, sizeof(*channel));
        return LIBRDP_STATUS_OK;
    }
    if (!channel->open || channel->pending_open)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    channel->open = 0;
    peer->dynamic_channel_count--;
    {
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        rdp_server_extension_classify_name(channel->name, strlen(channel->name), &family, &feature);
        rdp_server_extension_state_mark_close(peer, family);
    }
    if (strcmp(channel->name, RDP_GRAPHICS_PIPELINE_CHANNEL_NAME) == 0)
        rdp_server_graphics_frame_state_reset(peer);
    rdp_buffer_free(&channel->fragment);
    rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE, NULL, 0);
    memset(channel, 0, sizeof(*channel));
    return LIBRDP_STATUS_OK;
}

/*
 * Dispatches the drdynvc control stream after the static channel is joined.
 * Capability negotiation must complete before create/data/close/soft-sync
 * commands are accepted; application payload is emitted only after DVC
 * fragmentation is reassembled and extension headers validate. Soft-Sync
 * tunnel responses are intentionally limited to already-open dynamic channel
 * IDs so the server never advertises a side transport for unknown state.
 */
librdp_status rdp_server_handle_dynamic_channel_message(librdp_server_peer* peer,
                                                               const uint8_t* data,
                                                               size_t data_len)
{
    rdp_dynamic_channel_header header;
    rdp_buffer response;
    librdp_status status = rdp_dynamic_channel_parse_header(data, data_len, &header);

    if (!peer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&response);
    if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES)
    {
        rdp_dynamic_channel_capabilities caps;

        status = rdp_dynamic_channel_parse_capabilities(data, data_len, &caps);
        if (status == LIBRDP_STATUS_OK &&
            (!peer->dynamic_channel_capabilities_sent ||
             caps.has_priority_charges ||
             data_len != 4u ||
             caps.version > 3u))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
        {
            peer->dynamic_channel_version = caps.version;
            peer->dynamic_channels_ready = 1;
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.drdynvc.capabilities.response",
                            "version=%u",
                            caps.version);
        }
    }
    else if (!peer->dynamic_channels_ready)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CREATE)
    {
        rdp_dynamic_channel_create_response create_response;

        memset(&create_response, 0, sizeof(create_response));
        if (rdp_dynamic_channel_parse_create_response(data, data_len, &create_response) == LIBRDP_STATUS_OK &&
            rdp_server_find_pending_dynamic_channel(peer, create_response.channel_id))
            status = rdp_server_dynamic_handle_create_response(peer, &create_response);
        else
            status = rdp_server_dynamic_handle_create(peer, data, data_len);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
        status = rdp_server_dynamic_handle_data_first(peer, data, data_len);
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA)
        status = rdp_server_dynamic_handle_data(peer, data, data_len);
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
        status = rdp_server_dynamic_handle_close(peer, data, data_len);
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST)
    {
        rdp_dynamic_channel_soft_sync_request request;
        uint32_t tunnel_types[2];
        uint32_t tunnel_count = 0;

        memset(tunnel_types, 0, sizeof(tunnel_types));
        status = rdp_dynamic_channel_parse_soft_sync_request(data, data_len, &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_select_soft_sync_tunnels(peer,
                                                         &request,
                                                         tunnel_types,
                                                         (uint32_t)(sizeof(tunnel_types) / sizeof(tunnel_types[0])),
                                                         &tunnel_count);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_soft_sync_response(&response,
                                                                  tunnel_count > 0 ? tunnel_types : NULL,
                                                                  tunnel_count);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &response);
        if (status == LIBRDP_STATUS_OK && tunnel_count > 0)
            peer->multitransport_udp_active = 1;
    }
    else
        status = LIBRDP_STATUS_UNSUPPORTED;
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.dispatch",
                                 "dynamic channel dispatch failed");
    rdp_buffer_free(&response);
    return status;
}

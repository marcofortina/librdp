/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X.224, MCS/GCC, licensing, activation, and runtime PDU dispatch.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_protocol.h"

#include "server/server_channels.h"
#include "server/server_drive.h"
#include "server/server_features.h"
#include "server/server_graphics.h"
#include "server/server_peer.h"
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
 * Validate MCS Connect-Initial, capture client channel declarations, and emit
 * GCC/MCS response data. Standard Security material is generated here because
 * SC_SECURITY must carry the peer-specific random and certificate.
 */
librdp_status rdp_server_handle_mcs_connect_initial(librdp_server_peer* peer, const rdp_tpkt* packet)
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
        int reconnect = peer->advertised_channel_count > 0 ? 1 : 0;

        rdp_server_clipboard_state_reset(peer, peer->advertised_channel_count > 0 ? 1 : 0);
        rdp_server_drive_state_reset(peer, reconnect);
        rdp_server_extension_states_reset(peer, reconnect);
        peer->width = client_data.desktop_width ? client_data.desktop_width : peer->width;
        peer->height = client_data.desktop_height ? client_data.desktop_height : peer->height;
        peer->advertised_channel_count = client_data.channel_count;
        rdp_server_dynamic_channels_reset(peer, peer->dynamic_channel_count > 0 ? 1 : 0);
        memset(peer->advertised_channels, 0, sizeof(peer->advertised_channels));
        memset(peer->advertised_channel_ids, 0, sizeof(peer->advertised_channel_ids));
        memset(peer->advertised_channel_joined, 0, sizeof(peer->advertised_channel_joined));
        for (uint16_t channel_index = 0; channel_index < client_data.channel_count; channel_index++)
        {
            peer->advertised_channels[channel_index] = client_data.channels[channel_index];
            peer->advertised_channel_ids[channel_index] =
                (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u + channel_index);
            if (memcmp(client_data.channels[channel_index].name, "drdynvc", 7u) == 0 &&
                client_data.channels[channel_index].name[7] == '\0')
                peer->dynamic_channel_static_index = channel_index;
        }
        server_config.version = client_data.version ? client_data.version : RDP_GCC_CLIENT_VERSION_5;
        server_config.selected_protocol = peer->selected_protocol;
        server_config.early_capability_flags = client_data.early_capability_flags;
        server_config.mcs_channel_id = (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID;
        server_config.channel_count = client_data.channel_count;
        peer->multitransport_negotiated = 0;
        peer->multitransport_udp_active = 0;
        peer->multitransport_udp2_active = 0;
        peer->multitransport_flags = 0;
        if (client_data.has_multitransport &&
            (peer->requested_features & (uint32_t)LIBRDP_FEATURE_MULTITRANSPORT) != 0 &&
            (peer->requested_features &
             ((uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT | (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT)) != 0)
        {
            uint32_t flags = client_data.multitransport_flags & RDP_GCC_MULTITRANSPORT_SERVER_KNOWN_FLAGS;

            if ((flags & (RDP_GCC_MULTITRANSPORT_UDP_FECR | RDP_GCC_MULTITRANSPORT_UDP_FECL)) ==
                (RDP_GCC_MULTITRANSPORT_UDP_FECR | RDP_GCC_MULTITRANSPORT_UDP_FECL))
            {
                server_config.enable_multitransport = 1;
                server_config.multitransport_flags =
                    flags | RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP;
                peer->multitransport_negotiated = 1;
                peer->multitransport_flags = server_config.multitransport_flags;
            }
        }
        if (rdp_server_uses_standard_security(peer))
        {
            status = rdp_server_prepare_standard_security(peer);
            if (status == LIBRDP_STATUS_OK)
            {
                server_config.encryption_method = RDP_SECURITY_METHOD_128BIT;
                server_config.encryption_level = RDP_SERVER_STANDARD_ENCRYPTION_LEVEL;
                server_config.server_random = peer->standard_server_random;
                server_config.server_random_len = RDP_SECURITY_CLIENT_RANDOM_LEN;
                server_config.server_certificate = peer->standard_certificate.data;
                server_config.server_certificate_len = (uint32_t)peer->standard_certificate.length;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_server_data_blocks(&server_blocks, &server_config);
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
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_MCS_CONNECTED);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_parse_x224_data_packet(const rdp_tpkt* packet, const uint8_t** data, size_t* data_len)
{
    if (!packet || !data || !data_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_x224_parse_data(packet->payload, packet->payload_len, data, data_len);
}

librdp_status rdp_server_handle_erect_domain(librdp_server_peer* peer, const rdp_tpkt* packet)
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
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_DOMAIN_READY);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_server_handle_attach_user(librdp_server_peer* peer, const rdp_tpkt* packet)
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
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_USER_ATTACHED);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_server_send_demand_active(librdp_server_peer* peer)
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
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_ACTIVATING);
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
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_LICENSING);
    }
    return status;
}

size_t rdp_server_channel_name_len(const char name[8])
{
    size_t length = 0;

    while (length < 8u && name[length] != '\0')
        length++;
    return length;
}

void rdp_server_copy_channel_name(char output[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY], const char name[8])
{
    size_t length = rdp_server_channel_name_len(name);

    memset(output, 0, LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY);
    if (length > 0)
        memcpy(output, name, length);
}

void rdp_server_emit_input(librdp_server_peer* peer, const librdp_server_input_event* event)
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
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (event_count > 256u || pad != 0 || rdp_stream_remaining(&stream) != (size_t)event_count * 12u)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.input.header.failed",
                        "event_count=%u pad=%u remaining=%u payload_len=%u",
                        event_count,
                        pad,
                        (unsigned)rdp_stream_remaining(&stream),
                        (unsigned)payload_len);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
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
        if (message_type == 0x0000u)
            event.type = LIBRDP_SERVER_INPUT_SYNCHRONIZE;
        else if (message_type == 0x0004u)
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
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.input.message_type.failed",
                            "message_type=%u flags=%u param1=%u param2=%u",
                            message_type,
                            event.flags,
                            event.param1,
                            event.param2);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        rdp_server_emit_input(peer, &event);
    }
    return LIBRDP_STATUS_OK;
}

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
    if (!peer->updates_suppressed && peer->surface_repaint_pending)
        return rdp_server_surface_flush_repaint(peer);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_server_handle_channel_join(librdp_server_peer* peer, const rdp_tpkt* packet)
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
        char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
        librdp_server_extension_family family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
        librdp_feature feature = (librdp_feature)0;

        (void)rdp_server_static_channel_index(peer, request.channel_id, &channel_index);
        peer->advertised_channel_joined[channel_index] = 1;
        rdp_server_copy_channel_name(name, peer->advertised_channels[channel_index].name);
        rdp_server_extension_classify_name(name, strlen(name), &family, &feature);
        rdp_server_extension_state_mark_open(peer, family, request.channel_id, 0, 0);
        rdp_server_emit_channel_joined_event(peer, request.channel_id);
    }
    peer->joined_channel_count++;
    required_joins = (uint16_t)(peer->advertised_channel_count + 2u);
    if (peer->joined_channel_count >= required_joins)
        return rdp_server_send_valid_client_license(peer);
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    return LIBRDP_STATUS_OK;
}

/*
 * Validate the client-info PDU sent after licensing and before activation.
 * Only field lengths are retained in trace; credentials stay in the borrowed
 * packet memory and are never copied into the server peer.
 */
librdp_status rdp_server_handle_client_info(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_send_data_indication request;
    rdp_client_info_summary summary;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    memset(&request, 0, sizeof(request));
    memset(&summary, 0, sizeof(summary));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_send_data_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK &&
        (request.initiator != peer->user_id || request.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && !peer->standard_security_ready &&
        rdp_server_security_payload_has_flag(request.payload, request.payload_len, RDP_SEC_EXCHANGE_PKT))
        status = rdp_server_handle_security_exchange(peer, request.payload, request.payload_len);
    else if (status == LIBRDP_STATUS_OK)
        status = rdp_server_parse_client_info_security_payload(peer, request.payload, request.payload_len, &summary);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    if (!peer->client_info_seen &&
        rdp_server_security_payload_has_flag(request.payload, request.payload_len, RDP_SEC_EXCHANGE_PKT))
        return LIBRDP_STATUS_OK;
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

/*
 * Dispatch one post-MCS client packet. Global-channel slow-path data drives
 * activation, input, refresh, and output-suppression state; joined static
 * channels are routed to the application callback with borrowed payload
 * views. Malformed runtime input closes the peer because continuing would
 * desynchronize channel and activation state.
 */
librdp_status rdp_server_handle_runtime_data(librdp_server_peer* peer, const rdp_tpkt* packet)
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
        status = rdp_server_unwrap_optional_security_header(peer,
                                                            request.payload,
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
        else if (channel_index == peer->dynamic_channel_static_index)
            status = rdp_server_handle_dynamic_channel_message(peer, runtime_payload, runtime_payload_len);
        else
        {
            char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];

            rdp_server_copy_channel_name(name, peer->advertised_channels[channel_index].name);
            status = rdp_server_emit_extension_event(peer,
                                                     name,
                                                     strlen(name),
                                                     request.channel_id,
                                                     0,
                                                     0,
                                                     runtime_payload,
                                                     runtime_payload_len);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
                rdp_buffer_free(&security_payload);
                return status;
            }
            rdp_server_metric_add(&peer->metrics.static_channel_in, 1u);
            rdp_server_metric_add(&peer->metrics.static_channel_bytes_in, (uint64_t)runtime_payload_len);
            if (peer->channel_callback)
            {
                librdp_server_channel_event event;

                memset(&event, 0, sizeof(event));
                event.version = LIBRDP_SERVER_CHANNEL_EVENT_VERSION;
                event.size = (uint32_t)sizeof(event);
                event.type = LIBRDP_SERVER_CHANNEL_EVENT_STATIC_DATA;
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
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.slowpath.data.failed",
                            "status=%s payload_len=%u",
                            librdp_status_name(status),
                            (unsigned)runtime_payload_len);
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            rdp_buffer_free(&security_payload);
            return status;
        }
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "server.slowpath.data",
                              "pdu_type2=%u payload_len=%u",
                              pdu.pdu_type2,
                              (unsigned)pdu.payload_len);
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
            {
                rdp_server_set_state(peer, LIBRDP_SERVER_PEER_ACTIVE);
                status = rdp_server_surface_flush_repaint(peer);
            }
            else
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            if (status != LIBRDP_STATUS_OK)
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

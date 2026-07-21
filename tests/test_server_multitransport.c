/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server multitransport ownership and reset tests.
 * Coverage: per-peer tunnel selection, reliable/lossy isolation, closed-peer
 * rejection and reconnect invalidation.
 * Bug classes: cross-peer state reuse, stale receive windows, fallback bleed
 * between transport modes and metrics committed to the wrong peer.
 * Determinism: all datagrams are synthetic and no socket is created.
 */

#include "test_server_support.h"
#include "test_server_suites.h"

#include "server/server_channels.h"

#include <string.h>

/* Build one minimal RDPEUDP DATA datagram around a caller-selected sequence. */
static librdp_status server_multitransport_build_data(rdp_buffer* wire,
                                                      uint32_t sequence)
{
    static const uint8_t payload[] = {0x11u, 0x22u, 0x33u};
    rdp_udp_fec_header header;
    rdp_udp_source_payload_header source;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&header, 0, sizeof(header));
    memset(&source, 0, sizeof(source));
    header.receive_window_size = 8u;
    header.flags = RDP_UDP_FLAG_DATA;
    source.coded_sequence = sequence;
    source.source_start = sequence;
    wire->length = 0u;
    status = rdp_udp_write_fec_header(wire, &header);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp_write_payload_prefix(
            wire,
            (uint16_t)(8u + sizeof(payload)));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_udp_write_source_payload_header(wire, &source);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(wire, payload, sizeof(payload));
    return status;
}

/*
 * Model the application-owned secure transport association with the selected
 * mode bits on one peer. A different peer cannot consume the record until its
 * own Soft-Sync selection completes, and reconnect clears every association.
 */
int test_server_multitransport_focused(void)
{
    librdp_server_peer peer;
    librdp_server_peer other_peer;
    librdp_server_metrics metrics;
    rdp_buffer wire;
    uint8_t response[64];
    size_t response_len = 0u;

    memset(&peer, 0, sizeof(peer));
    memset(&other_peer, 0, sizeof(other_peer));
    rdp_buffer_init(&wire);
    peer.state = LIBRDP_SERVER_PEER_ACTIVE;
    peer.requested_features = (uint32_t)LIBRDP_FEATURE_MULTITRANSPORT |
                              (uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT |
                              (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT;
    peer.multitransport_negotiated = 1u;
    peer.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR;
    SCHECK(rdp_server_multitransport_tunnel_allowed(
               &peer,
               RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE));
    SCHECK(!rdp_server_multitransport_tunnel_allowed(
               &peer,
               RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY));
    peer.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECL;
    SCHECK(!rdp_server_multitransport_tunnel_allowed(
               &peer,
               RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE));
    SCHECK(rdp_server_multitransport_tunnel_allowed(
               &peer,
               RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY));
    peer.multitransport_flags = RDP_GCC_MULTITRANSPORT_UDP_FECR |
                                RDP_GCC_MULTITRANSPORT_UDP_FECL;
    peer.multitransport_udp_selected[0] = 1u;
    peer.multitransport_udp_selected[1] = 1u;
    SCHECK(librdp_server_metrics_init(&peer.metrics) == LIBRDP_STATUS_OK);

    other_peer.state = LIBRDP_SERVER_PEER_ACTIVE;
    other_peer.requested_features = peer.requested_features;
    other_peer.multitransport_negotiated = 1u;
    SCHECK(librdp_server_metrics_init(&other_peer.metrics) ==
           LIBRDP_STATUS_OK);
    SCHECK(server_multitransport_build_data(&wire, 100u) ==
           LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_process_udp_datagram(
               &other_peer,
               wire.data,
               wire.length,
               response,
               sizeof(response),
               &response_len) == LIBRDP_STATUS_UNSUPPORTED);
    SCHECK(other_peer.metrics.udp_datagrams_in == 0u);

    response_len = 0u;
    SCHECK(librdp_server_peer_process_udp_datagram(
               &peer,
               wire.data,
               wire.length,
               response,
               sizeof(response),
               &response_len) == LIBRDP_STATUS_OK);
    SCHECK(response_len > 0u && peer.multitransport_udp_window_started[1]);
    SCHECK(!peer.multitransport_udp_window_started[0]);
    SCHECK(server_multitransport_build_data(&wire, 200u) ==
           LIBRDP_STATUS_OK);
    response_len = 0u;
    SCHECK(librdp_server_peer_process_udp_datagram_mode(
               &peer,
               0,
               wire.data,
               wire.length,
               response,
               sizeof(response),
               &response_len) == LIBRDP_STATUS_OK);
    SCHECK(response_len > 0u && peer.multitransport_udp_window_started[0]);
    SCHECK(peer.multitransport_udp_next_receive_sequence[0] == 201u &&
           peer.multitransport_udp_next_receive_sequence[1] == 101u);

    peer.state = LIBRDP_SERVER_PEER_CLOSED;
    response_len = 0u;
    SCHECK(librdp_server_peer_process_udp_datagram_mode(
               &peer,
               0,
               wire.data,
               wire.length,
               response,
               sizeof(response),
               &response_len) == LIBRDP_STATUS_STATE);
    peer.state = LIBRDP_SERVER_PEER_ACTIVE;
    SCHECK(librdp_server_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    SCHECK(librdp_server_peer_get_metrics(&peer, &metrics) ==
           LIBRDP_STATUS_OK);
    SCHECK(metrics.udp_datagrams_in == 2u &&
           metrics.udp_datagrams_out == 2u);

    rdp_server_multitransport_reset(&peer);
    SCHECK(!peer.multitransport_negotiated &&
           !peer.multitransport_udp_selected[0] &&
           !peer.multitransport_udp_selected[1] &&
           !peer.multitransport_udp_window_started[0] &&
           !peer.multitransport_udp_window_started[1] &&
           !peer.multitransport_udp2_window_started);
    response_len = 0u;
    SCHECK(librdp_server_peer_process_udp_datagram(
               &peer,
               wire.data,
               wire.length,
               response,
               sizeof(response),
               &response_len) == LIBRDP_STATUS_UNSUPPORTED);

    rdp_buffer_free(&wire);
    return 0;
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for server-side inbound parser composition.
 * Coverage: feeds arbitrary bytes through the parser families reached by a
 * server peer while accepting RDPBCGR, CredSSP, static channel, DVC, and UDP
 * traffic.
 * Bug classes: malformed handshake framing, nested length disagreement,
 * encrypted-wrapper bounds, channel fragmentation edge cases, and UDP control
 * packet truncation.
 * Determinism: no socket, filesystem, clock, certificate, credential, or host
 * backend dependency is used by the fuzz entrypoint.
 */

#include "channels/dynamic_channel.h"
#include "channels/virtual_channel.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Fuzz target: runs one byte slice through independent server inbound parser
 * paths and selected nested payload paths when outer wrappers are valid.
 * Bug classes: parser over-read, inconsistent nested lengths, sequence-state
 * wrappers seeing malformed input, and cleanup of temporary decoded buffers.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_tpkt tpkt;
    rdp_x224_connection_request x224_request;
    rdp_mcs_connect_initial connect_initial;
    rdp_mcs_channel_join_request join_request;
    rdp_mcs_send_data_indication send_request;
    rdp_slowpath_share_control_header share_header;
    rdp_slowpath_data_pdu data_pdu;
    rdp_virtual_channel_packet virtual_packet;
    rdp_dynamic_channel_header dynamic_header;
    rdp_dynamic_channel_create_response dynamic_create;
    rdp_dynamic_channel_data_pdu dynamic_data;
    rdp_dynamic_channel_data_first_pdu dynamic_first;
    rdp_dynamic_channel_close_pdu dynamic_close;
    rdp_credssp_ts_request ts_request;
    rdp_ntlm_authenticate ntlm_authenticate;
    rdp_license_preamble license_preamble;
    rdp_license_error_alert license_alert;
    rdp_client_info_summary client_info;
    rdp_standard_security_context security;
    rdp_buffer decoded;
    rdp_udp_fec_header udp_header;
    rdp_udp_source_payload_header udp_source;
    rdp_udp2_packet udp2_packet;
    rdp_udp2_packet_kind udp2_kind = RDP_UDP2_PACKET_KIND_CONTROL;
    uint16_t security_flags = 0;
    const uint8_t* x224_payload = NULL;
    size_t x224_payload_len = 0;
    const uint8_t* payload = data;
    size_t payload_len = size;
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN] = {0};
    uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN] = {0};

    rdp_buffer_init(&decoded);
    memset(&security, 0, sizeof(security));

    (void)rdp_tpkt_parse(data, size, &tpkt);
    if (rdp_tpkt_parse(data, size, &tpkt) == LIBRDP_STATUS_OK)
    {
        payload = tpkt.payload;
        payload_len = tpkt.payload_len;
    }

    (void)rdp_x224_parse_connection_request(payload, payload_len, &x224_request);
    if (rdp_x224_parse_data(payload, payload_len, &x224_payload, &x224_payload_len) == LIBRDP_STATUS_OK)
    {
        payload = x224_payload;
        payload_len = x224_payload_len;
    }

    (void)rdp_mcs_parse_connect_initial(payload, payload_len, &connect_initial);
    (void)rdp_mcs_parse_erect_domain_request(payload, payload_len);
    (void)rdp_mcs_parse_attach_user_request(payload, payload_len);
    (void)rdp_mcs_parse_channel_join_request(payload, payload_len, &join_request);
    (void)rdp_mcs_parse_send_data_request(payload, payload_len, &send_request);

    if (rdp_mcs_parse_send_data_request(payload, payload_len, &send_request) == LIBRDP_STATUS_OK)
    {
        payload = send_request.payload;
        payload_len = send_request.payload_len;
    }

    (void)rdp_security_parse_client_info_pdu(payload, payload_len, &client_info);
    if (rdp_security_standard_server_init(&security,
                                          RDP_SECURITY_METHOD_128BIT,
                                          client_random,
                                          server_random) == LIBRDP_STATUS_OK)
    {
        (void)rdp_security_unwrap_pdu(&security, payload, payload_len, &decoded, &security_flags);
        if (decoded.length > 0)
        {
            payload = decoded.data;
            payload_len = decoded.length;
        }
        rdp_security_standard_clear(&security);
    }

    (void)rdp_slowpath_parse_share_control_header(payload, payload_len, &share_header);
    (void)rdp_slowpath_parse_data_pdu(payload, payload_len, &data_pdu);
    (void)rdp_virtual_channel_parse_packet(payload, payload_len, &virtual_packet);
    if (rdp_virtual_channel_parse_packet(payload, payload_len, &virtual_packet) == LIBRDP_STATUS_OK)
    {
        payload = virtual_packet.payload;
        payload_len = virtual_packet.payload_len;
    }

    (void)rdp_dynamic_channel_parse_header(payload, payload_len, &dynamic_header);
    (void)rdp_dynamic_channel_parse_create_response(payload, payload_len, &dynamic_create);
    (void)rdp_dynamic_channel_parse_data(payload, payload_len, &dynamic_data);
    (void)rdp_dynamic_channel_parse_data_first(payload, payload_len, &dynamic_first);
    (void)rdp_dynamic_channel_parse_close(payload, payload_len, &dynamic_close);

    (void)rdp_credssp_parse_ts_request(data, size, &ts_request);
    (void)rdp_credssp_parse_ntlm_authenticate(data, size, &ntlm_authenticate);
    (void)rdp_license_parse_preamble(data, size, &license_preamble);
    (void)rdp_license_parse_error_alert(data, size, &license_alert);
    (void)rdp_udp_parse_fec_header(data, size, &udp_header);
    (void)rdp_udp_parse_source_payload_header(data, size, &udp_source);
    if (rdp_udp2_parse_packet(data, size, &udp2_packet) == LIBRDP_STATUS_OK)
        (void)rdp_udp2_classify_packet(&udp2_packet, &udp2_kind);

    rdp_buffer_free(&decoded);
    return 0;
}

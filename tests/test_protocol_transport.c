/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: protocol transport-channel conformance vectors.
 * Coverage: multitransport and UDP/UDP2 parser/serializer fixtures.
 * Bug classes: malformed transport headers, sequence/window validation, packet
 * wrapping limits, ACK vector bounds, and reorder handling.
 * Determinism: fixtures use synthetic packets and no network sockets.
 */

#include "common/buffer.h"
#include "transport/multitransport.h"
#include "transport/udp_transport.h"

#include <stdio.h>
#include <string.h>

#define PCHECK(expr)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

/*
 * Coverage: validates multitransport request/response vectors and correlation
 * fields without external transport negotiation.
 */
static int test_multitransport(void)
{
    const uint8_t autodetect_payload[] = {0x01u, 0x02u, 0x03u};
    const uint8_t data_payload[] = {0x10u, 0x20u, 0x30u, 0x40u};
    const uint8_t bad_subheader[] = {0x02u, 0xffu};
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH];
    rdp_multitransport_create_request create_request;
    rdp_multitransport_create_response create_response;
    rdp_multitransport_data data_pdu;
    rdp_multitransport_subheader subheader;
    uint16_t subheader_count = 0;
    rdp_buffer buffer;
    rdp_buffer subheaders;
    size_t i = 0;

    for (i = 0; i < sizeof(cookie); i++)
        cookie[i] = (uint8_t)(0x80u + i);

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&subheaders);

    PCHECK(rdp_multitransport_write_create_request(&buffer, 0x11223344u, cookie) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_multitransport_parse_create_request(buffer.data,
                                                   buffer.length,
                                                   &create_request) == LIBRDP_STATUS_OK);
    PCHECK(create_request.header.action == RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST &&
           create_request.request_id == 0x11223344u &&
           memcmp(create_request.security_cookie, cookie, sizeof(cookie)) == 0);
    buffer.data[8] = 1u;
    PCHECK(rdp_multitransport_parse_create_request(buffer.data,
                                                   buffer.length,
                                                   &create_request) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multitransport_write_create_response(&buffer, 0x55667788u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_multitransport_parse_create_response(buffer.data,
                                                    buffer.length,
                                                    &create_response) == LIBRDP_STATUS_OK);
    PCHECK(create_response.header.action == RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE &&
           create_response.hresult == 0x55667788u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multitransport_write_subheader(&subheaders,
                                              RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST,
                                              autodetect_payload,
                                              sizeof(autodetect_payload)) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_multitransport_count_subheaders(subheaders.data,
                                               subheaders.length,
                                               &subheader_count) == LIBRDP_STATUS_OK);
    PCHECK(subheader_count == 1);
    PCHECK(rdp_multitransport_parse_subheader(subheaders.data,
                                              subheaders.length,
                                              &subheader) == LIBRDP_STATUS_OK);
    PCHECK(subheader.type == RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST &&
           subheader.data_len == sizeof(autodetect_payload) &&
           memcmp(subheader.data, autodetect_payload, sizeof(autodetect_payload)) == 0);
    PCHECK(rdp_multitransport_parse_subheader(bad_subheader,
                                              sizeof(bad_subheader),
                                              &subheader) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multitransport_write_header(&buffer,
                                           RDP_MULTITRANSPORT_ACTION_DATA,
                                           autodetect_payload,
                                           (size_t)-1,
                                           sizeof(data_payload)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1u && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_multitransport_write_data(&buffer,
                                         subheaders.data,
                                         subheaders.length,
                                         data_payload,
                                         sizeof(data_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multitransport_parse_data(buffer.data,
                                         buffer.length,
                                         &data_pdu) == LIBRDP_STATUS_OK);
    PCHECK(data_pdu.header.action == RDP_MULTITRANSPORT_ACTION_DATA &&
           data_pdu.header.subheaders_len == subheaders.length &&
           data_pdu.data_len == sizeof(data_payload) &&
           memcmp(data_pdu.data, data_payload, sizeof(data_payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_multitransport_write_data(&buffer,
                                         bad_subheader,
                                         sizeof(bad_subheader),
                                         data_payload,
                                         sizeof(data_payload)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1 && buffer.data[0] == 0xa5u);

    rdp_buffer_free(&subheaders);
    rdp_buffer_free(&buffer);
    return 0;
}

/*
 * Coverage: validates UDP transport packet vectors, sequence state, FEC/ACK
 * framing, and malformed datagram rejection.
 */
static int test_udp_transport(void)
{
    const uint8_t ack_payload[] = {0xaau, 0xbbu, 0xccu};
    const uint8_t udp_ack_vector_payload[] = {0x00u, 0xc1u};
    const uint8_t udp2_ack_vector_payload[] = {0x05u, 0xc2u, 0x81u};
    const uint8_t data_payload[] = {0x10u, 0x20u, 0x30u, 0x40u};
    const uint8_t packet_payload[] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u};
    const uint8_t tiny_payload[] = {0xabu, 0xcdu, 0xefu};
    const uint8_t bad_ack_vector_extra[] = {3u, 0u, 0xaau, 0xbbu, 0xccu, 0u, 0u, 0u, 0u};
    const uint8_t bad_ack_vector_padding[] = {3u, 0u, 0xaau, 0xbbu, 0xccu, 0u, 0u, 1u};
    const uint8_t udp2_empty_data_packet[] = {0x04u, 0x30u, 0x34u, 0x12u};
    uint8_t correlation_id[16];
    uint8_t cookie_hash[32];
    rdp_udp_fec_header fec;
    rdp_udp_syn_data syn;
    rdp_udp_payload_prefix payload_prefix;
    rdp_udp_ack_vector ack_vector;
    rdp_udp_ack_of_ack_vector ack_of_ack;
    rdp_udp_correlation_id correlation;
    rdp_udp_syn_data_ex syn_ex;
    rdp_udp2_header udp2_header;
    rdp_udp2_packet packet;
    rdp_udp2_prefix prefix;
    rdp_udp2_packet_kind packet_kind;
    rdp_buffer buffer;
    rdp_buffer unwrapped;
    uint32_t received = 0;
    uint32_t pending = 0;
    uint32_t lost = 0;
    size_t i = 0;

    for (i = 0; i < sizeof(correlation_id); i++)
        correlation_id[i] = (uint8_t)i;
    for (i = 0; i < sizeof(cookie_hash); i++)
        cookie_hash[i] = (uint8_t)(0x80u + i);

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&unwrapped);

    memset(&fec, 0, sizeof(fec));
    fec.source_ack = 0x11223344u;
    fec.receive_window_size = 64u;
    fec.flags = RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_DATA;
    PCHECK(rdp_udp_write_fec_header(&buffer, &fec) == LIBRDP_STATUS_OK);
    memset(&fec, 0, sizeof(fec));
    PCHECK(rdp_udp_parse_fec_header(buffer.data, buffer.length, &fec) == LIBRDP_STATUS_OK);
    PCHECK(fec.source_ack == 0x11223344u &&
           fec.receive_window_size == 64u &&
           fec.flags == (RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_ACK | RDP_UDP_FLAG_DATA));
    fec.flags = 0x8000u;
    PCHECK(rdp_udp_write_fec_header(&buffer, &fec) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 8u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&syn, 0, sizeof(syn));
    syn.initial_sequence_number = 0x55667788u;
    syn.upstream_mtu = RDP_UDP_MIN_MTU;
    syn.downstream_mtu = RDP_UDP_MAX_MTU;
    PCHECK(rdp_udp_write_syn_data(&buffer, &syn) == LIBRDP_STATUS_OK);
    memset(&syn, 0, sizeof(syn));
    PCHECK(rdp_udp_parse_syn_data(buffer.data, buffer.length, &syn) == LIBRDP_STATUS_OK);
    PCHECK(syn.initial_sequence_number == 0x55667788u &&
           syn.upstream_mtu == RDP_UDP_MIN_MTU &&
           syn.downstream_mtu == RDP_UDP_MAX_MTU);
    syn.upstream_mtu = RDP_UDP_MIN_MTU - 1u;
    PCHECK(rdp_udp_write_syn_data(&buffer, &syn) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 8u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp_write_payload_prefix(&buffer, 0x1234u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp_parse_payload_prefix(buffer.data, buffer.length, &payload_prefix) == LIBRDP_STATUS_OK);
    PCHECK(payload_prefix.payload_size == 0x1234u);
    PCHECK(rdp_udp_write_payload_prefix(NULL, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp_write_ack_vector(&buffer, ack_payload, sizeof(ack_payload)) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 8u);
    PCHECK(rdp_udp_parse_ack_vector(buffer.data, buffer.length, &ack_vector) == LIBRDP_STATUS_OK);
    PCHECK(ack_vector.size == sizeof(ack_payload) &&
           ack_vector.padding_len == 3u &&
           memcmp(ack_vector.vector, ack_payload, sizeof(ack_payload)) == 0);
    PCHECK(rdp_udp_parse_ack_vector(bad_ack_vector_extra,
                                    sizeof(bad_ack_vector_extra),
                                    &ack_vector) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_udp_parse_ack_vector(bad_ack_vector_padding,
                                    sizeof(bad_ack_vector_padding),
                                    &ack_vector) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_udp_write_ack_vector(&buffer, ack_payload, RDP_UDP_ACK_VECTOR_MAX_SIZE + 1u) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 8u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp_write_ack_vector(&buffer,
                                    udp_ack_vector_payload,
                                    sizeof(udp_ack_vector_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp_parse_ack_vector(buffer.data, buffer.length, &ack_vector) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp_ack_vector_count(&ack_vector, &received, &pending) == LIBRDP_STATUS_OK);
    PCHECK(received == 1u && pending == 2u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&ack_of_ack, 0, sizeof(ack_of_ack));
    ack_of_ack.reset_sequence_number = 0x10203040u;
    PCHECK(rdp_udp_write_ack_of_ack_vector(&buffer, &ack_of_ack) == LIBRDP_STATUS_OK);
    memset(&ack_of_ack, 0, sizeof(ack_of_ack));
    PCHECK(rdp_udp_parse_ack_of_ack_vector(buffer.data, buffer.length, &ack_of_ack) ==
           LIBRDP_STATUS_OK);
    PCHECK(ack_of_ack.reset_sequence_number == 0x10203040u);
    PCHECK(rdp_udp_write_ack_of_ack_vector(NULL, &ack_of_ack) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 4u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp_write_correlation_id(&buffer, correlation_id) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp_parse_correlation_id(buffer.data, buffer.length, &correlation) == LIBRDP_STATUS_OK);
    PCHECK(memcmp(correlation.correlation_id, correlation_id, sizeof(correlation_id)) == 0);
    buffer.data[31] = 1u;
    PCHECK(rdp_udp_parse_correlation_id(buffer.data, buffer.length, &correlation) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&syn_ex, 0, sizeof(syn_ex));
    syn_ex.flags = RDP_UDP_SYNEX_VERSION_INFO_VALID;
    syn_ex.udp_version = RDP_UDP_PROTOCOL_VERSION_3;
    syn_ex.has_cookie_hash = 1u;
    memcpy(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash));
    PCHECK(rdp_udp_write_syn_data_ex(&buffer, &syn_ex) == LIBRDP_STATUS_OK);
    memset(&syn_ex, 0, sizeof(syn_ex));
    PCHECK(rdp_udp_parse_syn_data_ex(buffer.data, buffer.length, &syn_ex) == LIBRDP_STATUS_OK);
    PCHECK(syn_ex.udp_version == RDP_UDP_PROTOCOL_VERSION_3 &&
           syn_ex.has_cookie_hash &&
           memcmp(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&syn_ex, 0, sizeof(syn_ex));
    syn_ex.flags = RDP_UDP_SYNEX_VERSION_INFO_VALID;
    syn_ex.udp_version = RDP_UDP_PROTOCOL_VERSION_2;
    PCHECK(rdp_udp_write_syn_data_ex(&buffer, &syn_ex) == LIBRDP_STATUS_OK);
    PCHECK(buffer.length == 4u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    syn_ex.has_cookie_hash = 1u;
    memcpy(syn_ex.cookie_hash, cookie_hash, sizeof(cookie_hash));
    PCHECK(rdp_udp_write_syn_data_ex(&buffer, &syn_ex) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1 && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&udp2_header, 0, sizeof(udp2_header));
    udp2_header.flags = RDP_UDP2_FLAG_ACK | RDP_UDP2_FLAG_ACKVEC;
    udp2_header.log_window_size = 2u;
    PCHECK(rdp_udp2_write_header(&buffer, &udp2_header) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(rdp_udp2_parse_prefix(0x01u, &prefix) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_udp2_parse_prefix(0x00u, &prefix) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_buffer_append_u8(&buffer, 0xa5u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_wrap_packet(&buffer, NULL, 0, RDP_UDP2_PACKET_TYPE_DATA) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1 && buffer.data[0] == 0xa5u);
    PCHECK(rdp_udp2_write_data_packet(&buffer, 3u, 0x1234u, NULL, 0) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1 && buffer.data[0] == 0xa5u);
    PCHECK(rdp_udp2_parse_packet(udp2_empty_data_packet,
                                 sizeof(udp2_empty_data_packet),
                                 &packet) == LIBRDP_STATUS_PROTOCOL_ERROR);
    PCHECK(rdp_udp2_write_data_packet(&buffer,
                                      16u,
                                      0x1234u,
                                      data_payload,
                                      sizeof(data_payload)) == LIBRDP_STATUS_INVALID_ARGUMENT);
    PCHECK(buffer.length == 1 && buffer.data[0] == 0xa5u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp2_write_data_packet(&buffer,
                                      3u,
                                      0x1234u,
                                      data_payload,
                                      sizeof(data_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_validate_packet(&packet) == LIBRDP_STATUS_OK);
    PCHECK(packet.header.flags == RDP_UDP2_FLAG_DATA &&
           packet.header.log_window_size == 3u &&
           packet.data_sequence_number == 0x1234u &&
           packet.data_body_len == sizeof(data_payload) &&
           memcmp(packet.data_body, data_payload, sizeof(data_payload)) == 0);
    PCHECK(rdp_udp2_classify_packet(&packet, &packet_kind) == LIBRDP_STATUS_OK &&
           packet_kind == RDP_UDP2_PACKET_KIND_DATA);
    {
        const uint16_t reordered_sequences[] = {9u, 7u, 8u};
        uint16_t previous_sequence = 0;
        uint32_t reorder_events = 0;

        for (i = 0; i < sizeof(reordered_sequences) / sizeof(reordered_sequences[0]); i++)
        {
            rdp_buffer_free(&buffer);
            rdp_buffer_init(&buffer);
            PCHECK(rdp_udp2_write_data_packet(&buffer,
                                              3u,
                                              reordered_sequences[i],
                                              data_payload,
                                              sizeof(data_payload)) == LIBRDP_STATUS_OK);
            PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
            PCHECK(packet.has_data && packet.data_sequence_number == reordered_sequences[i]);
            if (i > 0 && reordered_sequences[i] < previous_sequence)
                reorder_events++;
            previous_sequence = reordered_sequences[i];
        }
        PCHECK(reorder_events == 1u);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp2_write_ack_packet(&buffer, 1u, 0x2345u, 0x00aabbccu, 9u, ack_payload, 2u, 3u) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_validate_packet(&packet) == LIBRDP_STATUS_OK);
    PCHECK(packet.has_ack &&
           packet.ack.sequence_number == 0x2345u &&
           packet.ack.received_timestamp == 0x00aabbccu &&
           packet.ack.delayed_ack_count == 2u &&
           packet.ack.delayed_ack_time_scale == 3u);
    PCHECK(rdp_udp2_classify_packet(&packet, &packet_kind) == LIBRDP_STATUS_OK &&
           packet_kind == RDP_UDP2_PACKET_KIND_ACK);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp2_write_ack_vector_packet(&buffer,
                                            4u,
                                            0x3456u,
                                            1u,
                                            0x00010203u,
                                            7u,
                                            ack_payload,
                                            sizeof(ack_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_validate_packet(&packet) == LIBRDP_STATUS_OK);
    PCHECK(packet.has_ack_vector &&
           packet.ack_vector.base_sequence_number == 0x3456u &&
           packet.ack_vector.timestamp_present &&
           packet.ack_vector.timestamp == 0x00010203u &&
           packet.ack_vector.coded_ack_vector_size == sizeof(ack_payload));
    PCHECK(rdp_udp2_classify_packet(&packet, &packet_kind) == LIBRDP_STATUS_OK &&
           packet_kind == RDP_UDP2_PACKET_KIND_ACK_VECTOR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp2_write_ack_of_acks_packet(&buffer, 5u, 0x4567u) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_validate_packet(&packet) == LIBRDP_STATUS_OK);
    PCHECK(packet.has_ack_of_acks && packet.ack_of_acks_sequence_number == 0x4567u);
    PCHECK(rdp_udp2_classify_packet(&packet, &packet_kind) == LIBRDP_STATUS_OK &&
           packet_kind == RDP_UDP2_PACKET_KIND_ACK_OF_ACKS);
    packet.has_ack_of_acks = 0;
    PCHECK(rdp_udp2_validate_packet(&packet) == LIBRDP_STATUS_PROTOCOL_ERROR);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp2_write_ack_vector_packet(&buffer,
                                            2u,
                                            0x1000u,
                                            0u,
                                            0u,
                                            0u,
                                            udp2_ack_vector_payload,
                                            sizeof(udp2_ack_vector_payload)) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_ack_vector_count(&packet.ack_vector, &received, &lost) == LIBRDP_STATUS_OK);
    PCHECK(received == 5u && lost == 7u);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&packet, 0, sizeof(packet));
    packet.header.flags = RDP_UDP2_FLAG_ACK | RDP_UDP2_FLAG_AOA | RDP_UDP2_FLAG_DATA;
    packet.header.log_window_size = 6u;
    packet.has_ack = 1u;
    packet.ack.sequence_number = 0x1111u;
    packet.ack.received_timestamp = 0x00020304u;
    packet.ack.send_ack_time_gap_ms = 2u;
    packet.has_ack_of_acks = 1u;
    packet.ack_of_acks_sequence_number = 0x2222u;
    packet.has_data = 1u;
    packet.data_sequence_number = 0x3333u;
    packet.data_body = data_payload;
    packet.data_body_len = sizeof(data_payload);
    PCHECK(rdp_udp2_write_packet(&buffer, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_classify_packet(&packet, &packet_kind) == LIBRDP_STATUS_OK &&
           packet_kind == RDP_UDP2_PACKET_KIND_DATA_WITH_ACK);
    PCHECK(packet.has_ack && packet.has_ack_of_acks && packet.has_data &&
           packet.data_body_len == sizeof(data_payload));
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    memset(&packet, 0, sizeof(packet));
    packet.header.flags = RDP_UDP2_FLAG_OVERHEADSIZE | RDP_UDP2_FLAG_DELAYACKINFO;
    packet.header.log_window_size = 7u;
    packet.has_overhead_size = 1u;
    packet.overhead_size = 8u;
    packet.has_delay_ack_info = 1u;
    packet.max_delayed_acks = 4u;
    packet.delayed_ack_timeout_ms = 20u;
    PCHECK(rdp_udp2_write_packet(&buffer, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_parse_packet(buffer.data, buffer.length, &packet) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_classify_packet(&packet, &packet_kind) == LIBRDP_STATUS_OK &&
           packet_kind == RDP_UDP2_PACKET_KIND_CONTROL);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);

    PCHECK(rdp_udp2_wrap_packet(&buffer,
                                packet_payload,
                                sizeof(packet_payload),
                                RDP_UDP2_PACKET_TYPE_DATA) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &prefix) == LIBRDP_STATUS_OK);
    PCHECK(prefix.packet_type == RDP_UDP2_PACKET_TYPE_DATA &&
           prefix.short_packet_length == 7u &&
           unwrapped.length == sizeof(packet_payload) &&
           memcmp(unwrapped.data, packet_payload, sizeof(packet_payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    rdp_buffer_free(&unwrapped);
    rdp_buffer_init(&unwrapped);

    PCHECK(rdp_udp2_wrap_packet(&buffer,
                                tiny_payload,
                                sizeof(tiny_payload),
                                RDP_UDP2_PACKET_TYPE_DUMMY) == LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &prefix) == LIBRDP_STATUS_OK);
    PCHECK(prefix.packet_type == RDP_UDP2_PACKET_TYPE_DUMMY &&
           prefix.short_packet_length == sizeof(tiny_payload) &&
           unwrapped.length == sizeof(tiny_payload) &&
           memcmp(unwrapped.data, tiny_payload, sizeof(tiny_payload)) == 0);
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    rdp_buffer_free(&unwrapped);
    rdp_buffer_init(&unwrapped);

    PCHECK(rdp_udp2_wrap_packet(&buffer, NULL, 0, RDP_UDP2_PACKET_TYPE_DUMMY) ==
           LIBRDP_STATUS_OK);
    PCHECK(rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &prefix) == LIBRDP_STATUS_OK);
    PCHECK(prefix.packet_type == RDP_UDP2_PACKET_TYPE_DUMMY &&
           prefix.short_packet_length == 0u &&
           unwrapped.length == 0u);
    buffer.length = (size_t)-4;
    PCHECK(rdp_udp2_wrap_packet(&buffer,
                                tiny_payload,
                                sizeof(tiny_payload),
                                RDP_UDP2_PACKET_TYPE_DUMMY) == LIBRDP_STATUS_NO_MEMORY);
    buffer.length = 8u;
    unwrapped.length = (size_t)-2;
    PCHECK(rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &prefix) ==
           LIBRDP_STATUS_INVALID_ARGUMENT);
    unwrapped.length = 0;
    buffer.data[5] = 1u;
    rdp_buffer_free(&unwrapped);
    rdp_buffer_init(&unwrapped);
    PCHECK(rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &prefix) ==
           LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&unwrapped);
    rdp_buffer_free(&buffer);
    return 0;
}

int test_protocol_transport(void)
{
    if (test_multitransport() != 0)
        return 1;
    if (test_udp_transport() != 0)
        return 1;
    return 0;
}

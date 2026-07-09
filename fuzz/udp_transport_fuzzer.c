#include "transport/udp_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_udp_fec_header fec_header;
    rdp_udp_fec_payload_header fec_payload;
    rdp_udp_payload_prefix prefix;
    rdp_udp_source_payload_header source_payload;
    rdp_udp_syn_data syn;
    rdp_udp_ack_of_ack_vector ack_of_ack;
    rdp_udp_ack_vector ack_vector;
    rdp_udp_correlation_id correlation;
    rdp_udp_syn_data_ex syn_ex;
    rdp_udp2_header udp2_header;
    rdp_udp2_packet udp2_packet;
    rdp_udp2_prefix udp2_prefix;
    rdp_buffer buffer;
    uint8_t correlation_id[16] = {0};

    (void)rdp_udp_parse_fec_header(data, size, &fec_header);
    (void)rdp_udp_parse_fec_payload_header(data, size, &fec_payload);
    (void)rdp_udp_parse_payload_prefix(data, size, &prefix);
    (void)rdp_udp_parse_source_payload_header(data, size, &source_payload);
    (void)rdp_udp_parse_syn_data(data, size, &syn);
    (void)rdp_udp_parse_ack_of_ack_vector(data, size, &ack_of_ack);
    (void)rdp_udp_parse_ack_vector(data, size, &ack_vector);
    (void)rdp_udp_parse_correlation_id(data, size, &correlation);
    (void)rdp_udp_parse_syn_data_ex(data, size, &syn_ex);
    (void)rdp_udp2_parse_header(data, size, &udp2_header);
    (void)rdp_udp2_parse_packet(data, size, &udp2_packet);
    if (size > 0)
        (void)rdp_udp2_parse_prefix(data[0], &udp2_prefix);

    rdp_buffer_init(&buffer);
    fec_header.source_ack = 1;
    fec_header.receive_window_size = 64;
    fec_header.flags = RDP_UDP_FLAG_SYN | RDP_UDP_FLAG_SYNEX;
    (void)rdp_udp_write_fec_header(&buffer, &fec_header);
    buffer.length = 0;
    fec_payload.coded_sequence = 1;
    fec_payload.source_start = 2;
    fec_payload.range = 3;
    fec_payload.fec_index = 0;
    fec_payload.padding = 0;
    (void)rdp_udp_write_fec_payload_header(&buffer, &fec_payload);
    buffer.length = 0;
    (void)rdp_udp_write_payload_prefix(&buffer, size < 64u ? (uint16_t)size : 64u);
    buffer.length = 0;
    source_payload.coded_sequence = 1;
    source_payload.source_start = 0;
    (void)rdp_udp_write_source_payload_header(&buffer, &source_payload);
    buffer.length = 0;
    syn.initial_sequence_number = 2;
    syn.upstream_mtu = RDP_UDP_MIN_MTU;
    syn.downstream_mtu = RDP_UDP_MAX_MTU;
    (void)rdp_udp_write_syn_data(&buffer, &syn);
    buffer.length = 0;
    ack_of_ack.reset_sequence_number = 3;
    (void)rdp_udp_write_ack_of_ack_vector(&buffer, &ack_of_ack);
    buffer.length = 0;
    (void)rdp_udp_write_ack_vector(&buffer, data, size < 32u ? (uint16_t)size : 32u);
    buffer.length = 0;
    (void)rdp_udp_write_correlation_id(&buffer, correlation_id);
    buffer.length = 0;
    syn_ex.flags = RDP_UDP_SYNEX_VERSION_INFO_VALID;
    syn_ex.udp_version = RDP_UDP_PROTOCOL_VERSION_2;
    syn_ex.has_cookie_hash = 0;
    (void)rdp_udp_write_syn_data_ex(&buffer, &syn_ex);
    buffer.length = 0;
    (void)rdp_udp2_write_data_packet(&buffer, 4, 3, data, size < 64u ? size : 64u);
    buffer.length = 0;
    (void)rdp_udp2_write_ack_packet(&buffer, 4, 3, 4, 5, data, size < 8u ? (uint8_t)size : 8u, 0);
    buffer.length = 0;
    memset(&udp2_packet, 0, sizeof(udp2_packet));
    udp2_packet.header.flags = RDP_UDP2_FLAG_ACK | RDP_UDP2_FLAG_OVERHEADSIZE |
                               RDP_UDP2_FLAG_DELAYACKINFO | RDP_UDP2_FLAG_AOA |
                               RDP_UDP2_FLAG_DATA;
    udp2_packet.header.log_window_size = 4;
    udp2_packet.has_ack = 1;
    udp2_packet.ack.sequence_number = 3;
    udp2_packet.ack.received_timestamp = 4;
    udp2_packet.ack.send_ack_time_gap_ms = 5;
    udp2_packet.has_overhead_size = 1;
    udp2_packet.overhead_size = 8;
    udp2_packet.has_delay_ack_info = 1;
    udp2_packet.max_delayed_acks = 4;
    udp2_packet.delayed_ack_timeout_ms = 20;
    udp2_packet.has_ack_of_acks = 1;
    udp2_packet.ack_of_acks_sequence_number = 2;
    udp2_packet.has_data = 1;
    udp2_packet.data_sequence_number = 1;
    udp2_packet.data_body = data;
    udp2_packet.data_body_len = size < 32u ? size : 32u;
    (void)rdp_udp2_write_packet(&buffer, &udp2_packet);
    buffer.length = 0;
    (void)rdp_udp2_write_ack_vector_packet(&buffer,
                                           4,
                                           3,
                                           1,
                                           4,
                                           5,
                                           data,
                                           size < 16u ? (uint8_t)size : 16u);
    buffer.length = 0;
    (void)rdp_udp2_write_ack_of_acks_packet(&buffer, 4, 3);
    buffer.length = 0;
    (void)rdp_udp2_wrap_packet(&buffer, data, size < 64u ? size : 64u, RDP_UDP2_PACKET_TYPE_DATA);
    if (buffer.length > 0)
    {
        rdp_buffer unwrapped;

        rdp_buffer_init(&unwrapped);
        (void)rdp_udp2_unwrap_packet(&unwrapped, buffer.data, buffer.length, &udp2_prefix);
        rdp_buffer_free(&unwrapped);
    }
    rdp_buffer_free(&buffer);
    return 0;
}

#include "transport/udp_transport.h"

#include <stddef.h>
#include <stdint.h>

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
    syn.initial_sequence_number = 2;
    syn.upstream_mtu = RDP_UDP_MIN_MTU;
    syn.downstream_mtu = RDP_UDP_MAX_MTU;
    (void)rdp_udp_write_syn_data(&buffer, &syn);
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

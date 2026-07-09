#ifndef RDP_TRANSPORT_UDP_TRANSPORT_H
#define RDP_TRANSPORT_UDP_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_UDP_FLAG_SYN 0x0001u
#define RDP_UDP_FLAG_FIN 0x0002u
#define RDP_UDP_FLAG_ACK 0x0004u
#define RDP_UDP_FLAG_DATA 0x0008u
#define RDP_UDP_FLAG_FEC 0x0010u
#define RDP_UDP_FLAG_CN 0x0020u
#define RDP_UDP_FLAG_CWR 0x0040u
#define RDP_UDP_FLAG_SACK_OPTION 0x0080u
#define RDP_UDP_FLAG_ACK_OF_ACKS 0x0100u
#define RDP_UDP_FLAG_SYNLOSSY 0x0200u
#define RDP_UDP_FLAG_ACKDELAYED 0x0400u
#define RDP_UDP_FLAG_CORRELATION_ID 0x0800u
#define RDP_UDP_FLAG_SYNEX 0x1000u

#define RDP_UDP_PROTOCOL_VERSION_1 0x0001u
#define RDP_UDP_PROTOCOL_VERSION_2 0x0002u
#define RDP_UDP_PROTOCOL_VERSION_3 0x0101u
#define RDP_UDP_SYNEX_VERSION_INFO_VALID 0x0001u
#define RDP_UDP_ACK_VECTOR_MAX_SIZE 2048u
#define RDP_UDP_MIN_MTU 1132u
#define RDP_UDP_MAX_MTU 1232u

#define RDP_UDP2_FLAG_ACK 0x0001u
#define RDP_UDP2_FLAG_DATA 0x0004u
#define RDP_UDP2_FLAG_ACKVEC 0x0008u
#define RDP_UDP2_FLAG_AOA 0x0010u
#define RDP_UDP2_FLAG_OVERHEADSIZE 0x0040u
#define RDP_UDP2_FLAG_DELAYACKINFO 0x0100u
#define RDP_UDP2_KNOWN_FLAGS 0x015du
#define RDP_UDP2_PACKET_TYPE_DATA 0x0u
#define RDP_UDP2_PACKET_TYPE_DUMMY 0x8u

typedef struct rdp_udp_fec_header
{
    uint32_t source_ack;
    uint16_t receive_window_size;
    uint16_t flags;
} rdp_udp_fec_header;

typedef struct rdp_udp_fec_payload_header
{
    uint32_t coded_sequence;
    uint32_t source_start;
    uint8_t range;
    uint8_t fec_index;
    uint16_t padding;
} rdp_udp_fec_payload_header;

typedef struct rdp_udp_payload_prefix
{
    uint16_t payload_size;
} rdp_udp_payload_prefix;

typedef struct rdp_udp_source_payload_header
{
    uint32_t coded_sequence;
    uint32_t source_start;
} rdp_udp_source_payload_header;

typedef struct rdp_udp_syn_data
{
    uint32_t initial_sequence_number;
    uint16_t upstream_mtu;
    uint16_t downstream_mtu;
} rdp_udp_syn_data;

typedef struct rdp_udp_ack_of_ack_vector
{
    uint32_t reset_sequence_number;
} rdp_udp_ack_of_ack_vector;

typedef struct rdp_udp_ack_vector
{
    uint16_t size;
    const uint8_t* vector;
    size_t padding_len;
} rdp_udp_ack_vector;

typedef struct rdp_udp_correlation_id
{
    uint8_t correlation_id[16];
    uint8_t reserved[16];
} rdp_udp_correlation_id;

typedef struct rdp_udp_syn_data_ex
{
    uint16_t flags;
    uint16_t udp_version;
    uint8_t has_cookie_hash;
    uint8_t cookie_hash[32];
} rdp_udp_syn_data_ex;

typedef struct rdp_udp2_header
{
    uint16_t flags;
    uint8_t log_window_size;
} rdp_udp2_header;

typedef struct rdp_udp2_ack
{
    uint16_t sequence_number;
    uint32_t received_timestamp;
    uint8_t send_ack_time_gap_ms;
    uint8_t delayed_ack_count;
    uint8_t delayed_ack_time_scale;
    const uint8_t* delayed_ack_time_additions;
} rdp_udp2_ack;

typedef struct rdp_udp2_ack_vector
{
    uint16_t base_sequence_number;
    uint8_t coded_ack_vector_size;
    uint8_t timestamp_present;
    uint32_t timestamp;
    uint8_t send_ack_time_gap_ms;
    const uint8_t* coded_ack_vector;
} rdp_udp2_ack_vector;

typedef struct rdp_udp2_packet
{
    rdp_udp2_header header;
    uint8_t has_ack;
    rdp_udp2_ack ack;
    uint8_t has_overhead_size;
    uint8_t overhead_size;
    uint8_t has_delay_ack_info;
    uint8_t max_delayed_acks;
    uint16_t delayed_ack_timeout_ms;
    uint8_t has_ack_of_acks;
    uint16_t ack_of_acks_sequence_number;
    uint8_t has_data;
    uint16_t data_sequence_number;
    uint8_t has_ack_vector;
    rdp_udp2_ack_vector ack_vector;
    const uint8_t* data_body;
    size_t data_body_len;
} rdp_udp2_packet;

typedef struct rdp_udp2_prefix
{
    uint8_t packet_type;
    uint8_t short_packet_length;
} rdp_udp2_prefix;

librdp_status rdp_udp_parse_fec_header(const void* data, size_t length, rdp_udp_fec_header* header);
librdp_status rdp_udp_write_fec_header(rdp_buffer* buffer, const rdp_udp_fec_header* header);
librdp_status rdp_udp_parse_fec_payload_header(const void* data,
                                               size_t length,
                                               rdp_udp_fec_payload_header* header);
librdp_status rdp_udp_parse_payload_prefix(const void* data, size_t length, rdp_udp_payload_prefix* prefix);
librdp_status rdp_udp_parse_source_payload_header(const void* data,
                                                  size_t length,
                                                  rdp_udp_source_payload_header* header);
librdp_status rdp_udp_parse_syn_data(const void* data, size_t length, rdp_udp_syn_data* syn);
librdp_status rdp_udp_write_syn_data(rdp_buffer* buffer, const rdp_udp_syn_data* syn);
librdp_status rdp_udp_parse_ack_of_ack_vector(const void* data,
                                              size_t length,
                                              rdp_udp_ack_of_ack_vector* ack);
librdp_status rdp_udp_parse_ack_vector(const void* data, size_t length, rdp_udp_ack_vector* ack_vector);
librdp_status rdp_udp_parse_correlation_id(const void* data,
                                           size_t length,
                                           rdp_udp_correlation_id* correlation);
librdp_status rdp_udp_parse_syn_data_ex(const void* data, size_t length, rdp_udp_syn_data_ex* syn_ex);
librdp_status rdp_udp_write_syn_data_ex(rdp_buffer* buffer, const rdp_udp_syn_data_ex* syn_ex);

librdp_status rdp_udp2_parse_header(const void* data, size_t length, rdp_udp2_header* header);
librdp_status rdp_udp2_write_header(rdp_buffer* buffer, const rdp_udp2_header* header);
librdp_status rdp_udp2_parse_packet(const void* data, size_t length, rdp_udp2_packet* packet);
librdp_status rdp_udp2_write_data_packet(rdp_buffer* buffer,
                                         uint8_t log_window_size,
                                         uint16_t data_sequence_number,
                                         const void* data,
                                         size_t data_len);
librdp_status rdp_udp2_write_ack_packet(rdp_buffer* buffer,
                                        uint8_t log_window_size,
                                        uint16_t sequence_number,
                                        uint32_t received_timestamp,
                                        uint8_t send_ack_time_gap_ms,
                                        const uint8_t* delayed_ack_time_additions,
                                        uint8_t delayed_ack_count,
                                        uint8_t delayed_ack_time_scale);
librdp_status rdp_udp2_parse_prefix(uint8_t value, rdp_udp2_prefix* prefix);
librdp_status rdp_udp2_wrap_packet(rdp_buffer* output,
                                   const void* packet,
                                   size_t packet_len,
                                   uint8_t packet_type);
librdp_status rdp_udp2_unwrap_packet(rdp_buffer* output, const void* wire, size_t wire_len, rdp_udp2_prefix* prefix);

#endif

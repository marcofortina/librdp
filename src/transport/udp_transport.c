#include "transport/udp_transport.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

#define RDP_UDP_KNOWN_FLAGS 0x1fffu
#define RDP_UDP_FEC_HEADER_LENGTH 8u
#define RDP_UDP_FEC_PAYLOAD_HEADER_LENGTH 12u
#define RDP_UDP_SOURCE_PAYLOAD_HEADER_LENGTH 8u
#define RDP_UDP_SYN_DATA_LENGTH 8u
#define RDP_UDP_ACK_OF_ACK_VECTOR_LENGTH 4u
#define RDP_UDP_CORRELATION_ID_LENGTH 32u
#define RDP_UDP_SYN_DATA_EX_BASE_LENGTH 4u
#define RDP_UDP_SYN_DATA_EX_COOKIE_LENGTH 36u
#define RDP_UDP2_HEADER_LENGTH 2u

static int rdp_udp_valid_flags(uint16_t flags)
{
    return (flags & ~RDP_UDP_KNOWN_FLAGS) == 0;
}

static int rdp_udp_valid_mtu(uint16_t mtu)
{
    return mtu >= RDP_UDP_MIN_MTU && mtu <= RDP_UDP_MAX_MTU;
}

static uint32_t rdp_udp_read_u24_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16);
}

static librdp_status rdp_udp_append_u24_le(rdp_buffer* buffer, uint32_t value)
{
    uint8_t bytes[3];

    if (!buffer || value > 0x00ffffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    bytes[2] = (uint8_t)((value >> 16) & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

librdp_status rdp_udp_parse_fec_header(const void* data, size_t length, rdp_udp_fec_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP_FEC_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &header->source_ack) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->receive_window_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_udp_valid_flags(header->flags) ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_udp_write_fec_header(rdp_buffer* buffer, const rdp_udp_fec_header* header)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !header || !rdp_udp_valid_flags(header->flags))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u32_le(buffer, header->source_ack);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, header->receive_window_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, header->flags);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp_parse_fec_payload_header(const void* data,
                                               size_t length,
                                               rdp_udp_fec_payload_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP_FEC_PAYLOAD_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &header->coded_sequence) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->source_start) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->range) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->fec_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->padding) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return header->padding == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_udp_write_fec_payload_header(rdp_buffer* buffer,
                                               const rdp_udp_fec_payload_header* header)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !header || header->padding != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u32_le(buffer, header->coded_sequence);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, header->source_start);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, header->range);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, header->fec_index);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, header->padding);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp_parse_payload_prefix(const void* data, size_t length, rdp_udp_payload_prefix* prefix)
{
    rdp_stream stream;

    if (!data || !prefix)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(prefix, 0, sizeof(*prefix));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &prefix->payload_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_payload_prefix(rdp_buffer* buffer, uint16_t payload_size)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_le(buffer, payload_size);
}

librdp_status rdp_udp_parse_source_payload_header(const void* data,
                                                  size_t length,
                                                  rdp_udp_source_payload_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP_SOURCE_PAYLOAD_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &header->coded_sequence) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->source_start) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_source_payload_header(rdp_buffer* buffer,
                                                  const rdp_udp_source_payload_header* header)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u32_le(buffer, header->coded_sequence);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, header->source_start);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp_parse_syn_data(const void* data, size_t length, rdp_udp_syn_data* syn)
{
    rdp_stream stream;

    if (!data || !syn)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP_SYN_DATA_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(syn, 0, sizeof(*syn));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &syn->initial_sequence_number) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &syn->upstream_mtu) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &syn->downstream_mtu) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_udp_valid_mtu(syn->upstream_mtu) || !rdp_udp_valid_mtu(syn->downstream_mtu))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_syn_data(rdp_buffer* buffer, const rdp_udp_syn_data* syn)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !syn || !rdp_udp_valid_mtu(syn->upstream_mtu) || !rdp_udp_valid_mtu(syn->downstream_mtu))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u32_le(buffer, syn->initial_sequence_number);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, syn->upstream_mtu);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, syn->downstream_mtu);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp_parse_ack_of_ack_vector(const void* data,
                                              size_t length,
                                              rdp_udp_ack_of_ack_vector* ack)
{
    rdp_stream stream;

    if (!data || !ack)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP_ACK_OF_ACK_VECTOR_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(ack, 0, sizeof(*ack));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &ack->reset_sequence_number) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_ack_of_ack_vector(rdp_buffer* buffer,
                                              const rdp_udp_ack_of_ack_vector* ack)
{
    if (!buffer || !ack)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(buffer, ack->reset_sequence_number);
}

librdp_status rdp_udp_parse_ack_vector(const void* data, size_t length, rdp_udp_ack_vector* ack_vector)
{
    rdp_stream stream;
    const uint8_t* pad = NULL;
    size_t used = 0;
    size_t padding = 0;
    size_t i = 0;

    if (!data || !ack_vector)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(ack_vector, 0, sizeof(*ack_vector));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &ack_vector->size) != LIBRDP_STATUS_OK ||
        ack_vector->size > RDP_UDP_ACK_VECTOR_MAX_SIZE ||
        ack_vector->size > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &ack_vector->vector, ack_vector->size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    used = 2u + ack_vector->size;
    padding = (4u - (used % 4u)) % 4u;
    if (rdp_stream_remaining(&stream) != padding ||
        (padding > 0 && rdp_stream_read_bytes(&stream, &pad, padding) != LIBRDP_STATUS_OK))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < padding; i++)
    {
        if (pad[i] != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    ack_vector->padding_len = padding;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_ack_vector(rdp_buffer* buffer, const uint8_t* vector, uint16_t vector_size)
{
    size_t used = 0;
    size_t padding = 0;
    size_t start = 0;
    static const uint8_t zeroes[3] = {0, 0, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!vector && vector_size > 0) || vector_size > RDP_UDP_ACK_VECTOR_MAX_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, vector_size);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, vector, vector_size);
    used = 2u + vector_size;
    padding = (4u - (used % 4u)) % 4u;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, zeroes, padding);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp_ack_vector_decode_entry(uint8_t value, rdp_udp_ack_vector_entry* entry)
{
    uint8_t state = (uint8_t)(value >> 6);
    uint8_t run_length = (uint8_t)(value & 0x3fu);

    if (!entry)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(entry, 0, sizeof(*entry));
    if (state != RDP_UDP_ACK_VECTOR_STATE_RECEIVED &&
        state != RDP_UDP_ACK_VECTOR_STATE_PENDING)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entry->state = state;
    entry->run_length = run_length;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_ack_vector_count(const rdp_udp_ack_vector* ack_vector,
                                       uint32_t* received,
                                       uint32_t* pending)
{
    uint32_t received_count = 0;
    uint32_t pending_count = 0;
    uint16_t i = 0;

    if (!ack_vector || !received || !pending || (!ack_vector->vector && ack_vector->size > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < ack_vector->size; i++)
    {
        rdp_udp_ack_vector_entry entry;
        uint32_t run = 0;
        librdp_status status = rdp_udp_ack_vector_decode_entry(ack_vector->vector[i], &entry);

        if (status != LIBRDP_STATUS_OK)
            return status;
        run = (uint32_t)entry.run_length + 1u;
        if (entry.state == RDP_UDP_ACK_VECTOR_STATE_RECEIVED)
            received_count += run;
        else
            pending_count += run;
    }
    *received = received_count;
    *pending = pending_count;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_parse_correlation_id(const void* data,
                                           size_t length,
                                           rdp_udp_correlation_id* correlation)
{
    rdp_stream stream;
    const uint8_t* id = NULL;
    const uint8_t* reserved = NULL;
    size_t i = 0;

    if (!data || !correlation)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP_CORRELATION_ID_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(correlation, 0, sizeof(*correlation));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_bytes(&stream, &id, 16u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &reserved, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < 16u; i++)
    {
        if (reserved[i] != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    memcpy(correlation->correlation_id, id, 16u);
    memcpy(correlation->reserved, reserved, 16u);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_correlation_id(rdp_buffer* buffer, const uint8_t correlation_id[16])
{
    static const uint8_t reserved[16] = {0};
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !correlation_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append(buffer, correlation_id, 16u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, reserved, sizeof(reserved));
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp_parse_syn_data_ex(const void* data, size_t length, rdp_udp_syn_data_ex* syn_ex)
{
    rdp_stream stream;
    const uint8_t* hash = NULL;

    if (!data || !syn_ex)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_UDP_SYN_DATA_EX_BASE_LENGTH && length != RDP_UDP_SYN_DATA_EX_COOKIE_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(syn_ex, 0, sizeof(*syn_ex));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &syn_ex->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &syn_ex->udp_version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((syn_ex->flags & ~RDP_UDP_SYNEX_VERSION_INFO_VALID) != 0 ||
        (syn_ex->flags & RDP_UDP_SYNEX_VERSION_INFO_VALID) == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_1 &&
        syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_2 &&
        syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_3)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (syn_ex->udp_version == RDP_UDP_PROTOCOL_VERSION_3)
    {
        if (rdp_stream_remaining(&stream) != 32u ||
            rdp_stream_read_bytes(&stream, &hash, 32u) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        memcpy(syn_ex->cookie_hash, hash, 32u);
        syn_ex->has_cookie_hash = 1;
    }
    else if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp_write_syn_data_ex(rdp_buffer* buffer, const rdp_udp_syn_data_ex* syn_ex)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !syn_ex ||
        (syn_ex->flags & ~RDP_UDP_SYNEX_VERSION_INFO_VALID) != 0 ||
        (syn_ex->flags & RDP_UDP_SYNEX_VERSION_INFO_VALID) == 0 ||
        (syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_1 &&
         syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_2 &&
         syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_3) ||
        (syn_ex->udp_version == RDP_UDP_PROTOCOL_VERSION_3 && !syn_ex->has_cookie_hash) ||
        (syn_ex->udp_version != RDP_UDP_PROTOCOL_VERSION_3 && syn_ex->has_cookie_hash))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u16_le(buffer, syn_ex->flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, syn_ex->udp_version);
    if (status == LIBRDP_STATUS_OK && syn_ex->has_cookie_hash)
        status = rdp_buffer_append(buffer, syn_ex->cookie_hash, sizeof(syn_ex->cookie_hash));
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp2_parse_header(const void* data, size_t length, rdp_udp2_header* header)
{
    rdp_stream stream;
    uint16_t raw = 0;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP2_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &raw) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->flags = raw & 0x0fffu;
    header->log_window_size = (uint8_t)(raw >> 12);
    if (header->flags == 0 ||
        (header->flags & ~RDP_UDP2_KNOWN_FLAGS) != 0 ||
        ((header->flags & RDP_UDP2_FLAG_ACK) && (header->flags & RDP_UDP2_FLAG_ACKVEC)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_write_header(rdp_buffer* buffer, const rdp_udp2_header* header)
{
    uint16_t raw = 0;

    if (!buffer || !header || header->log_window_size > 15u ||
        header->flags == 0 ||
        (header->flags & ~RDP_UDP2_KNOWN_FLAGS) != 0 ||
        ((header->flags & RDP_UDP2_FLAG_ACK) && (header->flags & RDP_UDP2_FLAG_ACKVEC)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    raw = (uint16_t)(header->flags | ((uint16_t)header->log_window_size << 12));
    return rdp_buffer_append_u16_le(buffer, raw);
}

static librdp_status rdp_udp2_parse_ack(rdp_stream* stream, rdp_udp2_ack* ack)
{
    const uint8_t* timestamp = NULL;
    uint8_t packed = 0;

    if (!stream || !ack)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(ack, 0, sizeof(*ack));
    if (rdp_stream_remaining(stream) < 7u ||
        rdp_stream_read_u16_le(stream, &ack->sequence_number) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(stream, &timestamp, 3u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &ack->send_ack_time_gap_ms) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &packed) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    ack->received_timestamp = rdp_udp_read_u24_le(timestamp);
    ack->delayed_ack_count = packed & 0x0fu;
    ack->delayed_ack_time_scale = (uint8_t)(packed >> 4);
    if (ack->delayed_ack_count > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, &ack->delayed_ack_time_additions, ack->delayed_ack_count) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_udp2_parse_ack_vector_payload(rdp_stream* stream, rdp_udp2_ack_vector* ack_vector)
{
    uint8_t packed = 0;
    const uint8_t* timestamp = NULL;

    if (!stream || !ack_vector)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(ack_vector, 0, sizeof(*ack_vector));
    if (rdp_stream_remaining(stream) < 3u ||
        rdp_stream_read_u16_le(stream, &ack_vector->base_sequence_number) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &packed) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    ack_vector->coded_ack_vector_size = packed & 0x7fu;
    ack_vector->timestamp_present = (uint8_t)((packed >> 7) & 1u);
    if (ack_vector->timestamp_present)
    {
        if (rdp_stream_remaining(stream) < 4u ||
            rdp_stream_read_bytes(stream, &timestamp, 3u) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(stream, &ack_vector->send_ack_time_gap_ms) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        ack_vector->timestamp = rdp_udp_read_u24_le(timestamp);
    }
    if (ack_vector->coded_ack_vector_size > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, &ack_vector->coded_ack_vector, ack_vector->coded_ack_vector_size) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_validate_packet(const rdp_udp2_packet* packet)
{
    uint16_t expected_flags = 0;

    if (!packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (packet->header.log_window_size > 15u ||
        packet->header.flags == 0 ||
        (packet->header.flags & ~RDP_UDP2_KNOWN_FLAGS) != 0 ||
        ((packet->header.flags & RDP_UDP2_FLAG_ACK) && (packet->header.flags & RDP_UDP2_FLAG_ACKVEC)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->has_ack)
        expected_flags |= RDP_UDP2_FLAG_ACK;
    if (packet->has_overhead_size)
        expected_flags |= RDP_UDP2_FLAG_OVERHEADSIZE;
    if (packet->has_delay_ack_info)
        expected_flags |= RDP_UDP2_FLAG_DELAYACKINFO;
    if (packet->has_ack_of_acks)
        expected_flags |= RDP_UDP2_FLAG_AOA;
    if (packet->has_data)
        expected_flags |= RDP_UDP2_FLAG_DATA;
    if (packet->has_ack_vector)
        expected_flags |= RDP_UDP2_FLAG_ACKVEC;
    if (packet->header.flags != expected_flags)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->has_ack &&
        (packet->ack.received_timestamp > 0x00ffffffu ||
         packet->ack.delayed_ack_count > 15u ||
         packet->ack.delayed_ack_time_scale > 15u ||
         (!packet->ack.delayed_ack_time_additions && packet->ack.delayed_ack_count > 0)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->has_delay_ack_info && packet->max_delayed_acks > 15u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->has_ack_vector &&
        (packet->ack_vector.coded_ack_vector_size > 0x7fu ||
         packet->ack_vector.timestamp_present > 1u ||
         (packet->ack_vector.timestamp_present && packet->ack_vector.timestamp > 0x00ffffffu) ||
         (!packet->ack_vector.coded_ack_vector && packet->ack_vector.coded_ack_vector_size > 0)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!packet->has_data && packet->data_body_len > 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->has_data && !packet->data_body && packet->data_body_len > 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_parse_packet(const void* data, size_t length, rdp_udp2_packet* packet)
{
    rdp_stream stream;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_UDP2_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(packet, 0, sizeof(*packet));
    if (rdp_udp2_parse_header(data, length, &packet->header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, RDP_UDP2_HEADER_LENGTH) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->header.flags & RDP_UDP2_FLAG_ACK)
    {
        packet->has_ack = 1;
        if (rdp_udp2_parse_ack(&stream, &packet->ack) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (packet->header.flags & RDP_UDP2_FLAG_OVERHEADSIZE)
    {
        packet->has_overhead_size = 1;
        if (rdp_stream_read_u8(&stream, &packet->overhead_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (packet->header.flags & RDP_UDP2_FLAG_DELAYACKINFO)
    {
        packet->has_delay_ack_info = 1;
        if (rdp_stream_read_u8(&stream, &packet->max_delayed_acks) != LIBRDP_STATUS_OK ||
            packet->max_delayed_acks > 15u ||
            rdp_stream_read_u16_le(&stream, &packet->delayed_ack_timeout_ms) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (packet->header.flags & RDP_UDP2_FLAG_AOA)
    {
        packet->has_ack_of_acks = 1;
        if (rdp_stream_read_u16_le(&stream, &packet->ack_of_acks_sequence_number) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (packet->header.flags & RDP_UDP2_FLAG_DATA)
    {
        packet->has_data = 1;
        if (rdp_stream_read_u16_le(&stream, &packet->data_sequence_number) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (packet->header.flags & RDP_UDP2_FLAG_ACKVEC)
    {
        packet->has_ack_vector = 1;
        if (rdp_udp2_parse_ack_vector_payload(&stream, &packet->ack_vector) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (packet->has_data)
    {
        packet->data_body = data ? ((const uint8_t*)data + stream.position) : NULL;
        packet->data_body_len = rdp_stream_remaining(&stream);
        return rdp_udp2_validate_packet(packet);
    }
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_udp2_validate_packet(packet);
}

static librdp_status rdp_udp2_write_ack(rdp_buffer* buffer, const rdp_udp2_ack* ack)
{
    uint8_t packed = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !ack || ack->received_timestamp > 0x00ffffffu ||
        ack->delayed_ack_count > 15u ||
        ack->delayed_ack_time_scale > 15u ||
        (!ack->delayed_ack_time_additions && ack->delayed_ack_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, ack->sequence_number);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_udp_append_u24_le(buffer, ack->received_timestamp);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, ack->send_ack_time_gap_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packed = (uint8_t)(ack->delayed_ack_count | (uint8_t)(ack->delayed_ack_time_scale << 4));
    status = rdp_buffer_append_u8(buffer, packed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, ack->delayed_ack_time_additions, ack->delayed_ack_count);
}

static librdp_status rdp_udp2_write_ack_vector_payload(rdp_buffer* buffer,
                                                       const rdp_udp2_ack_vector* ack_vector)
{
    uint8_t packed = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !ack_vector ||
        ack_vector->coded_ack_vector_size > 0x7fu ||
        ack_vector->timestamp_present > 1u ||
        (ack_vector->timestamp_present && ack_vector->timestamp > 0x00ffffffu) ||
        (!ack_vector->coded_ack_vector && ack_vector->coded_ack_vector_size > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, ack_vector->base_sequence_number);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packed = ack_vector->coded_ack_vector_size;
    if (ack_vector->timestamp_present)
        packed = (uint8_t)(packed | 0x80u);
    status = rdp_buffer_append_u8(buffer, packed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (ack_vector->timestamp_present)
    {
        status = rdp_udp_append_u24_le(buffer, ack_vector->timestamp);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u8(buffer, ack_vector->send_ack_time_gap_ms);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return rdp_buffer_append(buffer,
                             ack_vector->coded_ack_vector,
                             ack_vector->coded_ack_vector_size);
}

librdp_status rdp_udp2_write_packet(rdp_buffer* buffer, const rdp_udp2_packet* packet)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_udp2_validate_packet(packet) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_udp2_write_header(buffer, &packet->header);
    if (packet->has_ack)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp2_write_ack(buffer, &packet->ack);
    }
    if (packet->has_overhead_size)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, packet->overhead_size);
    }
    if (packet->has_delay_ack_info)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, packet->max_delayed_acks);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, packet->delayed_ack_timeout_ms);
    }
    if (packet->has_ack_of_acks)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, packet->ack_of_acks_sequence_number);
    }
    if (packet->has_data)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, packet->data_sequence_number);
    }
    if (packet->has_ack_vector)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_udp2_write_ack_vector_payload(buffer, &packet->ack_vector);
    }
    if (status == LIBRDP_STATUS_OK && packet->has_data)
        status = rdp_buffer_append(buffer, packet->data_body, packet->data_body_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_udp2_classify_packet(const rdp_udp2_packet* packet, rdp_udp2_packet_kind* kind)
{
    if (!packet || !kind)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_udp2_validate_packet(packet) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (packet->has_data && packet->has_ack)
        *kind = RDP_UDP2_PACKET_KIND_DATA_WITH_ACK;
    else if (packet->has_data)
        *kind = RDP_UDP2_PACKET_KIND_DATA;
    else if (packet->has_ack_vector)
        *kind = RDP_UDP2_PACKET_KIND_ACK_VECTOR;
    else if (packet->has_ack)
        *kind = RDP_UDP2_PACKET_KIND_ACK;
    else if (packet->has_ack_of_acks)
        *kind = RDP_UDP2_PACKET_KIND_ACK_OF_ACKS;
    else
        *kind = RDP_UDP2_PACKET_KIND_CONTROL;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_ack_vector_decode_entry(uint8_t value, rdp_udp2_ack_vector_entry* entry)
{
    if (!entry)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(entry, 0, sizeof(*entry));
    if ((value & 0x80u) != 0)
    {
        entry->mode = RDP_UDP2_ACK_VECTOR_MODE_RLE;
        entry->state = (value & 0x40u) ? RDP_UDP2_ACK_VECTOR_STATE_RECEIVED : RDP_UDP2_ACK_VECTOR_STATE_LOST;
        entry->run_length = (uint8_t)(value & 0x3fu);
    }
    else
    {
        entry->mode = RDP_UDP2_ACK_VECTOR_MODE_BITMAP;
        entry->bitmap = (uint8_t)(value & 0x7fu);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_ack_vector_count(const rdp_udp2_ack_vector* ack_vector,
                                        uint32_t* received,
                                        uint32_t* lost)
{
    uint32_t received_count = 0;
    uint32_t lost_count = 0;
    uint8_t i = 0;

    if (!ack_vector || !received || !lost ||
        (!ack_vector->coded_ack_vector && ack_vector->coded_ack_vector_size > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < ack_vector->coded_ack_vector_size; i++)
    {
        rdp_udp2_ack_vector_entry entry;
        librdp_status status = rdp_udp2_ack_vector_decode_entry(ack_vector->coded_ack_vector[i], &entry);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (entry.mode == RDP_UDP2_ACK_VECTOR_MODE_RLE)
        {
            uint32_t run = (uint32_t)entry.run_length + 1u;
            if (entry.state == RDP_UDP2_ACK_VECTOR_STATE_RECEIVED)
                received_count += run;
            else
                lost_count += run;
        }
        else
        {
            uint8_t bit = 0;
            for (bit = 0; bit < 7u; bit++)
            {
                if ((entry.bitmap & (uint8_t)(1u << bit)) != 0)
                    received_count++;
                else
                    lost_count++;
            }
        }
    }
    *received = received_count;
    *lost = lost_count;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_write_data_packet(rdp_buffer* buffer,
                                         uint8_t log_window_size,
                                         uint16_t data_sequence_number,
                                         const void* data,
                                         size_t data_len)
{
    rdp_udp2_packet packet;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&packet, 0, sizeof(packet));
    packet.header.flags = RDP_UDP2_FLAG_DATA;
    packet.header.log_window_size = log_window_size;
    packet.has_data = 1;
    packet.data_sequence_number = data_sequence_number;
    packet.data_body = (const uint8_t*)data;
    packet.data_body_len = data_len;
    return rdp_udp2_write_packet(buffer, &packet);
}

librdp_status rdp_udp2_write_ack_packet(rdp_buffer* buffer,
                                        uint8_t log_window_size,
                                        uint16_t sequence_number,
                                        uint32_t received_timestamp,
                                        uint8_t send_ack_time_gap_ms,
                                        const uint8_t* delayed_ack_time_additions,
                                        uint8_t delayed_ack_count,
                                        uint8_t delayed_ack_time_scale)
{
    rdp_udp2_packet packet;

    if (!buffer || received_timestamp > 0x00ffffffu ||
        delayed_ack_count > 15u || delayed_ack_time_scale > 15u ||
        (!delayed_ack_time_additions && delayed_ack_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&packet, 0, sizeof(packet));
    packet.header.flags = RDP_UDP2_FLAG_ACK;
    packet.header.log_window_size = log_window_size;
    packet.has_ack = 1;
    packet.ack.sequence_number = sequence_number;
    packet.ack.received_timestamp = received_timestamp;
    packet.ack.send_ack_time_gap_ms = send_ack_time_gap_ms;
    packet.ack.delayed_ack_time_additions = delayed_ack_time_additions;
    packet.ack.delayed_ack_count = delayed_ack_count;
    packet.ack.delayed_ack_time_scale = delayed_ack_time_scale;
    return rdp_udp2_write_packet(buffer, &packet);
}

librdp_status rdp_udp2_write_ack_vector_packet(rdp_buffer* buffer,
                                               uint8_t log_window_size,
                                               uint16_t base_sequence_number,
                                               uint8_t timestamp_present,
                                               uint32_t timestamp,
                                               uint8_t send_ack_time_gap_ms,
                                               const uint8_t* coded_ack_vector,
                                               uint8_t coded_ack_vector_size)
{
    rdp_udp2_packet packet;

    if (!buffer || timestamp_present > 1u ||
        (timestamp_present && timestamp > 0x00ffffffu) ||
        (!coded_ack_vector && coded_ack_vector_size > 0) ||
        coded_ack_vector_size > 0x7fu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&packet, 0, sizeof(packet));
    packet.header.flags = RDP_UDP2_FLAG_ACKVEC;
    packet.header.log_window_size = log_window_size;
    packet.has_ack_vector = 1;
    packet.ack_vector.base_sequence_number = base_sequence_number;
    packet.ack_vector.timestamp_present = timestamp_present;
    packet.ack_vector.timestamp = timestamp;
    packet.ack_vector.send_ack_time_gap_ms = send_ack_time_gap_ms;
    packet.ack_vector.coded_ack_vector = coded_ack_vector;
    packet.ack_vector.coded_ack_vector_size = coded_ack_vector_size;
    return rdp_udp2_write_packet(buffer, &packet);
}

librdp_status rdp_udp2_write_ack_of_acks_packet(rdp_buffer* buffer,
                                                uint8_t log_window_size,
                                                uint16_t sequence_number)
{
    rdp_udp2_packet packet;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&packet, 0, sizeof(packet));
    packet.header.flags = RDP_UDP2_FLAG_AOA;
    packet.header.log_window_size = log_window_size;
    packet.has_ack_of_acks = 1;
    packet.ack_of_acks_sequence_number = sequence_number;
    return rdp_udp2_write_packet(buffer, &packet);
}

librdp_status rdp_udp2_parse_prefix(uint8_t value, rdp_udp2_prefix* prefix)
{
    if (!prefix)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(prefix, 0, sizeof(*prefix));
    if ((value & 0x01u) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    prefix->packet_type = (uint8_t)((value & 0x1eu) >> 1);
    prefix->short_packet_length = (uint8_t)(value >> 5);
    if (prefix->packet_type != RDP_UDP2_PACKET_TYPE_DATA &&
        prefix->packet_type != RDP_UDP2_PACKET_TYPE_DUMMY)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_wrap_packet(rdp_buffer* output,
                                   const void* packet,
                                   size_t packet_len,
                                   uint8_t packet_type)
{
    const uint8_t* bytes = (const uint8_t*)packet;
    uint8_t prefix = 0;
    uint8_t short_len = 0;
    size_t padded_len = 0;
    size_t output_len = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || (!packet && packet_len > 0) ||
        (packet_type != RDP_UDP2_PACKET_TYPE_DATA && packet_type != RDP_UDP2_PACKET_TYPE_DUMMY) ||
        packet_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    padded_len = packet_len < 7u ? 7u : packet_len;
    short_len = packet_len < 7u ? (uint8_t)packet_len : 7u;
    prefix = (uint8_t)((packet_type << 1) | (short_len << 5));
    output_len = padded_len + 1u;
    if (output_len > SIZE_MAX - output->length)
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_buffer_reserve(output, output->length + output_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < output_len; i++)
        output->data[output->length + i] = 0;
    output->data[output->length] = prefix;
    if (packet_len > 0)
        memcpy(output->data + output->length + 1u, bytes, packet_len);
    output->data[output->length] = output->data[output->length + 7u];
    output->data[output->length + 7u] = prefix;
    output->length += output_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_udp2_unwrap_packet(rdp_buffer* output, const void* wire, size_t wire_len, rdp_udp2_prefix* prefix)
{
    const uint8_t* bytes = (const uint8_t*)wire;
    uint8_t prefix_byte = 0;
    size_t layout_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !wire || wire_len <= 7u || !prefix)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    prefix_byte = bytes[7];
    status = rdp_udp2_parse_prefix(prefix_byte, prefix);
    if (status != LIBRDP_STATUS_OK)
        return status;
    layout_len = wire_len - 1u;
    if (prefix->short_packet_length > 0 && prefix->short_packet_length < 7u)
    {
        size_t i = 0;

        if (wire_len != 8u || bytes[0] != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = (size_t)prefix->short_packet_length + 1u; i < 7u; i++)
        {
            if (bytes[i] != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        layout_len = prefix->short_packet_length;
    }
    else if (prefix->short_packet_length == 0 && wire_len == 8u && bytes[0] == 0)
    {
        size_t i = 0;

        for (i = 1u; i < 7u; i++)
        {
            if (bytes[i] != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        layout_len = 0;
    }
    if (layout_len > SIZE_MAX - output->length)
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_buffer_reserve(output, output->length + layout_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (layout_len <= 6u)
        memcpy(output->data + output->length, bytes + 1u, layout_len);
    else
    {
        memcpy(output->data + output->length, bytes + 1u, 6u);
        output->data[output->length + 6u] = bytes[0];
        if (layout_len > 7u)
            memcpy(output->data + output->length + 7u, bytes + 8u, layout_len - 7u);
    }
    output->length += layout_len;
    return LIBRDP_STATUS_OK;
}

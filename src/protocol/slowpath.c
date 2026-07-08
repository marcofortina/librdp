#include "protocol/slowpath.h"

#include "common/stream.h"

#include <stdlib.h>
#include <string.h>

librdp_status rdp_slowpath_parse_share_control_header(const void* data,
                                                      size_t length,
                                                      rdp_slowpath_share_control_header* header)
{
    rdp_stream stream;

    if (!data || !header || length < 6)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->total_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->channel_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->total_length < 6 || header->total_length > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static uint16_t rdp_slowpath_base_type(uint16_t pdu_type)
{
    return (uint16_t)(pdu_type & 0x000fu);
}

#define RDP_CONFIRM_ACTIVE_CAPABILITY_COUNT 16u

static librdp_status rdp_slowpath_append_zeros(rdp_buffer* buffer, size_t count)
{
    static const uint8_t zeros[64] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (count > 0)
    {
        size_t chunk = count > sizeof(zeros) ? sizeof(zeros) : count;
        status = rdp_buffer_append(buffer, zeros, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_slowpath_append_u16s(rdp_buffer* buffer, const uint16_t* values, size_t count)
{
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!values && count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < count; i++)
    {
        status = rdp_buffer_append_u16_le(buffer, values[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_slowpath_write_capability_header(rdp_buffer* buffer, uint16_t type, uint16_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || length < 4)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, length);
    return status;
}

librdp_status rdp_slowpath_parse_demand_active(const void* data,
                                               size_t length,
                                               rdp_slowpath_demand_active* demand)
{
    rdp_stream stream;
    const uint8_t* capabilities = NULL;
    uint16_t capabilities_len = 0;
    uint16_t source_len = 0;
    uint16_t pad = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !demand)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(demand, 0, sizeof(*demand));
    status = rdp_slowpath_parse_share_control_header(data, length, &demand->header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_slowpath_base_type(demand->header.pdu_type) != RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, demand->header.total_length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &demand->share_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &source_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &capabilities_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (source_len == 0 || capabilities_len < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) < (size_t)source_len + capabilities_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &demand->source_descriptor, source_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &capabilities, capabilities_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    demand->source_descriptor_len = source_len;
    status = rdp_capabilities_parse(capabilities, capabilities_len, &demand->capabilities);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_remaining(&stream) >= 4)
        (void)rdp_stream_read_u16_le(&stream, &pad);
    (void)pad;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_slowpath_write_general_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {
        1, 3, 0x0200u, 0, 0, 0x0404u, 0, 0, 0
    };
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_GENERAL, 24);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 1);
    return status;
}

static librdp_status rdp_slowpath_write_bitmap_capability(rdp_buffer* buffer, uint16_t width, uint16_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_BITMAP, 28);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 32);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    return status;
}

static librdp_status rdp_slowpath_write_order_capability(rdp_buffer* buffer)
{
    const uint16_t first_fields[] = {1, 20, 0, 1, 0, 0x002au};
    const uint16_t last_fields[] = {0, 0, 65001u, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_ORDER, 88);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_zeros(buffer, 16);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, first_fields, sizeof(first_fields) / sizeof(first_fields[0]));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_zeros(buffer, 32);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 230400u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, last_fields, sizeof(last_fields) / sizeof(last_fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_bitmap_cache_v2_capability(rdp_buffer* buffer)
{
    const uint32_t cell_info[] = {600u, 600u, 2048u, 4096u, 2048u};
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_BITMAP_CACHE_V2, 40);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0x0002u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 5);
    for (i = 0; status == LIBRDP_STATUS_OK && i < sizeof(cell_info) / sizeof(cell_info[0]); i++)
        status = rdp_buffer_append_u32_le(buffer, cell_info[i]);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_zeros(buffer, 12);
    return status;
}

static librdp_status rdp_slowpath_write_pointer_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {1, 128, 128};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_POINTER, 10);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_large_pointer_capability(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_LARGE_POINTER, 6);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    return status;
}

static librdp_status rdp_slowpath_write_input_capability(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;
    const uint16_t input_flags = 0x0001u | 0x0004u | 0x0010u | 0x0100u;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_INPUT, 88);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, input_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0x00000409u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 12);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_zeros(buffer, 64);
    return status;
}

static librdp_status rdp_slowpath_write_u32_capability(rdp_buffer* buffer, uint16_t type, uint32_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, type, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, value);
    return status;
}

static librdp_status rdp_slowpath_write_glyph_cache_capability(rdp_buffer* buffer)
{
    const uint16_t cell_sizes[] = {4, 4, 8, 8, 16, 32, 64, 128, 256, 256};
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_GLYPH_CACHE, 52);
    for (i = 0; status == LIBRDP_STATUS_OK && i < sizeof(cell_sizes) / sizeof(cell_sizes[0]); i++)
    {
        status = rdp_buffer_append_u16_le(buffer, 254);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, cell_sizes[i]);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 256);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 256);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    return status;
}

static librdp_status rdp_slowpath_write_virtual_channel_capability(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_VIRTUAL_CHANNEL, 12);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 1600);
    return status;
}

static librdp_status rdp_slowpath_write_sound_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {0, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_SOUND, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_share_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {0, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_SHARE, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_font_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {1, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_FONT, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_control_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {0, 0, 2, 2};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_CONTROL, 12);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_color_cache_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {6, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_COLOR_CACHE, 8);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_activation_capability(rdp_buffer* buffer)
{
    const uint16_t fields[] = {0, 0, 0, 0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_slowpath_write_capability_header(buffer, RDP_CAPABILITY_TYPE_ACTIVATION, 12);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_append_u16s(buffer, fields, sizeof(fields) / sizeof(fields[0]));
    return status;
}

static librdp_status rdp_slowpath_write_data_pdu(rdp_buffer* buffer,
                                                 uint32_t share_id,
                                                 uint16_t channel_id,
                                                 uint8_t pdu_type2,
                                                 const void* payload,
                                                 size_t payload_len)
{
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) || payload_len > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = 18u + payload_len;
    if (total > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u16_le(buffer, (uint16_t)total);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_DATA));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, channel_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, share_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, pdu_type2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}

librdp_status rdp_slowpath_write_confirm_active(rdp_buffer* buffer,
                                                uint32_t share_id,
                                                uint16_t channel_id,
                                                uint16_t width,
                                                uint16_t height,
                                                const char* source_descriptor)
{
    rdp_buffer capabilities;
    size_t source_len = 0;
    size_t combined_len = 0;
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !source_descriptor || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    source_len = strlen(source_descriptor);
    if (source_len == 0 || source_len > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&capabilities);
    status = rdp_buffer_append_u16_le(&capabilities, RDP_CONFIRM_ACTIVE_CAPABILITY_COUNT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&capabilities, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_general_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_bitmap_capability(&capabilities, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_order_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_bitmap_cache_v2_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_pointer_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_large_pointer_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_input_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_u32_capability(&capabilities, RDP_CAPABILITY_TYPE_BRUSH, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_glyph_cache_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_virtual_channel_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_sound_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_share_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_font_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_control_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_color_cache_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_activation_capability(&capabilities);
    combined_len = capabilities.length;
    total = 6u + 4u + 2u + 2u + 2u + source_len + combined_len;
    if (status == LIBRDP_STATUS_OK && total > 0xffffu)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)total);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(RDP_SLOWPATH_PDU_VERSION | RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, channel_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, share_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1002);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)source_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)combined_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, source_descriptor, source_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, capabilities.data, capabilities.length);

    rdp_buffer_free(&capabilities);
    return status;
}

librdp_status rdp_slowpath_write_client_synchronize(rdp_buffer* buffer,
                                                    uint32_t share_id,
                                                    uint16_t channel_id)
{
    uint8_t payload[4];

    payload[0] = 1;
    payload[1] = 0;
    payload[2] = (uint8_t)(channel_id & 0xffu);
    payload[3] = (uint8_t)((channel_id >> 8) & 0xffu);
    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE,
                                       payload,
                                       sizeof(payload));
}

librdp_status rdp_slowpath_write_client_control(rdp_buffer* buffer,
                                                uint32_t share_id,
                                                uint16_t channel_id,
                                                uint16_t action)
{
    uint8_t payload[8];

    if (action != 1u && action != 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    payload[0] = (uint8_t)(action & 0xffu);
    payload[1] = (uint8_t)((action >> 8) & 0xffu);
    payload[2] = 0;
    payload[3] = 0;
    payload[4] = 0;
    payload[5] = 0;
    payload[6] = 0;
    payload[7] = 0;
    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_CONTROL,
                                       payload,
                                       sizeof(payload));
}

librdp_status rdp_slowpath_write_client_font_list(rdp_buffer* buffer,
                                                  uint32_t share_id,
                                                  uint16_t channel_id)
{
    static const uint8_t payload[8] = {0, 0, 0, 0, 3, 0, 50, 0};

    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_FONT_LIST,
                                       payload,
                                       sizeof(payload));
}

librdp_status rdp_slowpath_write_client_persistent_key_list(rdp_buffer* buffer,
                                                            uint32_t share_id,
                                                            uint16_t channel_id)
{
    uint8_t payload[24] = {0};

    payload[20] = 3;
    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_BITMAP_CACHE_PERSISTENT_LIST,
                                       payload,
                                       sizeof(payload));
}

static librdp_status rdp_slowpath_write_client_input_event(rdp_buffer* buffer,
                                                           uint32_t share_id,
                                                           uint16_t channel_id,
                                                           uint16_t message_type,
                                                           uint16_t flags,
                                                           uint16_t param1,
                                                           uint16_t param2)
{
    uint8_t payload[16];

    payload[0] = 1;
    payload[1] = 0;
    payload[2] = 0;
    payload[3] = 0;
    payload[4] = 0;
    payload[5] = 0;
    payload[6] = 0;
    payload[7] = 0;
    payload[8] = (uint8_t)(message_type & 0xffu);
    payload[9] = (uint8_t)((message_type >> 8) & 0xffu);
    payload[10] = (uint8_t)(flags & 0xffu);
    payload[11] = (uint8_t)((flags >> 8) & 0xffu);
    payload[12] = (uint8_t)(param1 & 0xffu);
    payload[13] = (uint8_t)((param1 >> 8) & 0xffu);
    payload[14] = (uint8_t)(param2 & 0xffu);
    payload[15] = (uint8_t)((param2 >> 8) & 0xffu);
    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_INPUT,
                                       payload,
                                       sizeof(payload));
}

librdp_status rdp_slowpath_write_client_keyboard_input(rdp_buffer* buffer,
                                                       uint32_t share_id,
                                                       uint16_t channel_id,
                                                       uint16_t flags,
                                                       uint16_t scancode)
{
    if (scancode > 0xffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_slowpath_write_client_input_event(buffer, share_id, channel_id, 0x0004u, flags, scancode, 0);
}

librdp_status rdp_slowpath_write_client_unicode_keyboard_input(rdp_buffer* buffer,
                                                               uint32_t share_id,
                                                               uint16_t channel_id,
                                                               uint16_t flags,
                                                               uint16_t code)
{
    return rdp_slowpath_write_client_input_event(buffer, share_id, channel_id, 0x0005u, flags, code, 0);
}

librdp_status rdp_slowpath_write_client_mouse_input(rdp_buffer* buffer,
                                                    uint32_t share_id,
                                                    uint16_t channel_id,
                                                    uint16_t flags,
                                                    uint16_t x,
                                                    uint16_t y)
{
    return rdp_slowpath_write_client_input_event(buffer, share_id, channel_id, 0x8001u, flags, x, y);
}

librdp_status rdp_slowpath_write_client_extended_mouse_input(rdp_buffer* buffer,
                                                             uint32_t share_id,
                                                             uint16_t channel_id,
                                                             uint16_t flags,
                                                             uint16_t x,
                                                             uint16_t y)
{
    return rdp_slowpath_write_client_input_event(buffer, share_id, channel_id, 0x8002u, flags, x, y);
}

librdp_status rdp_slowpath_write_client_refresh_rect(rdp_buffer* buffer,
                                                     uint32_t share_id,
                                                     uint16_t channel_id,
                                                     uint16_t x,
                                                     uint16_t y,
                                                     uint16_t width,
                                                     uint16_t height)
{
    uint32_t right = 0;
    uint32_t bottom = 0;
    uint8_t payload[12];

    if (!buffer || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    right = (uint32_t)x + width - 1u;
    bottom = (uint32_t)y + height - 1u;
    if (right > 0xffffu || bottom > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    payload[0] = 1;
    payload[1] = 0;
    payload[2] = 0;
    payload[3] = 0;
    payload[4] = (uint8_t)(x & 0xffu);
    payload[5] = (uint8_t)((x >> 8) & 0xffu);
    payload[6] = (uint8_t)(y & 0xffu);
    payload[7] = (uint8_t)((y >> 8) & 0xffu);
    payload[8] = (uint8_t)(right & 0xffu);
    payload[9] = (uint8_t)((right >> 8) & 0xffu);
    payload[10] = (uint8_t)(bottom & 0xffu);
    payload[11] = (uint8_t)((bottom >> 8) & 0xffu);
    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_REFRESH_RECT,
                                       payload,
                                       sizeof(payload));
}

librdp_status rdp_slowpath_write_client_suppress_output(rdp_buffer* buffer,
                                                        uint32_t share_id,
                                                        uint16_t channel_id,
                                                        int allow_updates,
                                                        uint16_t x,
                                                        uint16_t y,
                                                        uint16_t width,
                                                        uint16_t height)
{
    uint32_t right = 0;
    uint32_t bottom = 0;
    uint8_t payload[12];
    size_t payload_len = 4;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(payload, 0, sizeof(payload));
    payload[0] = allow_updates ? 1 : 0;
    if (allow_updates)
    {
        if (width == 0 || height == 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        right = (uint32_t)x + width - 1u;
        bottom = (uint32_t)y + height - 1u;
        if (right > 0xffffu || bottom > 0xffffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        payload[4] = (uint8_t)(x & 0xffu);
        payload[5] = (uint8_t)((x >> 8) & 0xffu);
        payload[6] = (uint8_t)(y & 0xffu);
        payload[7] = (uint8_t)((y >> 8) & 0xffu);
        payload[8] = (uint8_t)(right & 0xffu);
        payload[9] = (uint8_t)((right >> 8) & 0xffu);
        payload[10] = (uint8_t)(bottom & 0xffu);
        payload[11] = (uint8_t)((bottom >> 8) & 0xffu);
        payload_len = 12;
    }

    return rdp_slowpath_write_data_pdu(buffer,
                                       share_id,
                                       channel_id,
                                       RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT,
                                       payload,
                                       payload_len);
}

librdp_status rdp_slowpath_parse_data_pdu(const void* data, size_t length, rdp_slowpath_data_pdu* pdu)
{
    rdp_stream stream;
    uint8_t pad = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pdu, 0, sizeof(*pdu));
    status = rdp_slowpath_parse_share_control_header(data, length, &pdu->header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_slowpath_base_type(pdu->header.pdu_type) != RDP_SLOWPATH_PDU_TYPE_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu->header.total_length < 18)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, pdu->header.total_length);
    if (rdp_stream_skip(&stream, 6) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->share_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pdu->stream_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pdu->uncompressed_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pdu->pdu_type2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pdu->compressed_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pdu->compressed_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;

    pdu->payload_len = rdp_stream_remaining(&stream);
    if (pdu->payload_len > 0 &&
        rdp_stream_read_bytes(&stream, &pdu->payload, pdu->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_slowpath_parse_font_map(const void* data, size_t length, rdp_slowpath_font_map* font_map)
{
    rdp_stream stream;

    if (!data || !font_map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 8)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(font_map, 0, sizeof(*font_map));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &font_map->number_entries) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &font_map->total_entries) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &font_map->map_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &font_map->entry_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_slowpath_parse_set_error_info(const void* data, size_t length, uint32_t* error_info)
{
    rdp_stream stream;

    if (!data || !error_info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    *error_info = 0;
    rdp_stream_init(&stream, data, length);
    return rdp_stream_read_u32_le(&stream, error_info);
}

librdp_status rdp_slowpath_parse_save_session_info(const void* data,
                                                   size_t length,
                                                   rdp_slowpath_save_session_info* info)
{
    rdp_stream stream;

    if (!data || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(info, 0, sizeof(*info));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &info->info_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    info->data_len = rdp_stream_remaining(&stream);
    if (info->data_len > 0 &&
        rdp_stream_read_bytes(&stream, &info->data, info->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

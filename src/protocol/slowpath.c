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
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 24);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 3);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0x0200u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0x040du);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
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
    status = rdp_buffer_append_u16_le(buffer, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 28);
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
    status = rdp_buffer_append_u16_le(&capabilities, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&capabilities, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_general_capability(&capabilities);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_bitmap_capability(&capabilities, width, height);
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

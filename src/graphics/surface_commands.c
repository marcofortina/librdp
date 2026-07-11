#include "graphics/surface_commands.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_surface_commands_read_u64_le(rdp_stream* stream, uint64_t* value)
{
    uint32_t low = 0;
    uint32_t high = 0;

    if (!stream || !value)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &low) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &high) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = (uint64_t)low | ((uint64_t)high << 32u);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_surface_commands_write_u64_le(rdp_buffer* buffer, uint64_t value)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, (uint32_t)(value & 0xffffffffu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, (uint32_t)(value >> 32u));
}

static librdp_status rdp_surface_commands_parse_bits(rdp_stream* stream,
                                                     uint16_t command_type,
                                                     rdp_surface_bits* bits)
{
    rdp_surface_bits parsed;
    uint8_t reserved = 0;

    if (!stream || !bits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_remaining(stream) < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    parsed.command_type = command_type;
    if (rdp_stream_read_u16_le(stream, &parsed.dest_left) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &parsed.dest_top) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &parsed.dest_right) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &parsed.dest_bottom) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &parsed.bpp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &parsed.codec_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &parsed.width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &parsed.height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &parsed.bitmap_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (reserved != 0 ||
        (parsed.flags & (uint8_t)~RDP_SURFACE_BITS_FLAG_EXTENDED_HEADER) != 0 ||
        parsed.dest_left >= parsed.dest_right ||
        parsed.dest_top >= parsed.dest_bottom ||
        parsed.width == 0 ||
        parsed.height == 0 ||
        parsed.bpp == 0 ||
        parsed.bpp > 32u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if ((parsed.flags & RDP_SURFACE_BITS_FLAG_EXTENDED_HEADER) != 0)
    {
        if (rdp_stream_remaining(stream) < 24u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.has_extended_header = 1;
        if (rdp_stream_read_u32_le(stream, &parsed.high_unique_id) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(stream, &parsed.low_unique_id) != LIBRDP_STATUS_OK ||
            rdp_surface_commands_read_u64_le(stream, &parsed.timestamp_ms) != LIBRDP_STATUS_OK ||
            rdp_surface_commands_read_u64_le(stream, &parsed.timestamp_s) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    if (parsed.bitmap_data_length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &parsed.bitmap_data, parsed.bitmap_data_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *bits = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_surface_commands_parse(const void* data,
                                         size_t length,
                                         rdp_surface_command_list* list)
{
    rdp_surface_command_list parsed;
    rdp_stream stream;

    if ((!data && length > 0) || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (length == 0)
    {
        *list = parsed;
        return LIBRDP_STATUS_OK;
    }

    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) > 0)
    {
        uint16_t command_type = 0;
        rdp_surface_command* command = NULL;

        if (parsed.count >= RDP_SURFACE_COMMAND_MAX_COMMANDS)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_u16_le(&stream, &command_type) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        command = &parsed.commands[parsed.count];
        if (command_type == RDP_SURFACE_COMMAND_SET_BITS ||
            command_type == RDP_SURFACE_COMMAND_STREAM_BITS)
        {
            command->kind = RDP_SURFACE_COMMAND_KIND_BITS;
            if (rdp_surface_commands_parse_bits(&stream, command_type, &command->bits) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (command_type == RDP_SURFACE_COMMAND_FRAME_MARKER)
        {
            command->kind = RDP_SURFACE_COMMAND_KIND_FRAME_MARKER;
            if (rdp_stream_read_u16_le(&stream, &command->frame_marker.action) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &command->frame_marker.frame_id) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            command->frame_marker.has_frame_id = 1;
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        parsed.count++;
    }
    *list = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_surface_commands_write_bits(rdp_buffer* buffer,
                                              const rdp_surface_bits* bits)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !bits || (!bits->bitmap_data && bits->bitmap_data_length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (bits->command_type != RDP_SURFACE_COMMAND_SET_BITS &&
        bits->command_type != RDP_SURFACE_COMMAND_STREAM_BITS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((bits->flags & (uint8_t)~RDP_SURFACE_BITS_FLAG_EXTENDED_HEADER) != 0 ||
        bits->dest_left >= bits->dest_right ||
        bits->dest_top >= bits->dest_bottom ||
        bits->width == 0 ||
        bits->height == 0 ||
        bits->bpp == 0 ||
        bits->bpp > 32u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u16_le(buffer, bits->command_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, bits->dest_left);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, bits->dest_top);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, bits->dest_right);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, bits->dest_bottom);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, bits->bpp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, bits->flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, bits->codec_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, bits->width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, bits->height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, bits->bitmap_data_length);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if ((bits->flags & RDP_SURFACE_BITS_FLAG_EXTENDED_HEADER) != 0)
    {
        status = rdp_buffer_append_u32_le(buffer, bits->high_unique_id);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, bits->low_unique_id);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_surface_commands_write_u64_le(buffer, bits->timestamp_ms);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_surface_commands_write_u64_le(buffer, bits->timestamp_s);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }

    return rdp_buffer_append(buffer, bits->bitmap_data, bits->bitmap_data_length);
}

librdp_status rdp_surface_commands_write_frame_marker(rdp_buffer* buffer,
                                                      uint16_t action,
                                                      uint32_t frame_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, RDP_SURFACE_COMMAND_FRAME_MARKER);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, action);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, frame_id);
    return status;
}

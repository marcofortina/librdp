#include "channels/mouse_cursor.h"

#include "common/stream.h"

#include <string.h>

#define RDP_MOUSE_CURSOR_MAX_DIMENSION 512u

static librdp_status rdp_mouse_cursor_parse_capset(rdp_stream* stream, rdp_mouse_cursor_capset* capset)
{
    if (!stream || !capset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u32_le(stream, &capset->signature) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &capset->version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &capset->size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (capset->signature != RDP_MOUSE_CURSOR_CAPSET_SIGNATURE ||
        capset->version != RDP_MOUSE_CURSOR_CAPSET_VERSION1 ||
        capset->size != RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1)
        return LIBRDP_STATUS_UNSUPPORTED;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_mouse_cursor_parse_pointer_attributes(rdp_stream* stream,
                                                              int large_lengths,
                                                              rdp_pointer_update* update)
{
    uint32_t and_len32 = 0;
    uint32_t xor_len32 = 0;
    uint16_t and_len16 = 0;
    uint16_t xor_len16 = 0;

    if (!stream || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u16_le(stream, &update->xor_bpp) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &update->cache_index) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &update->hot_x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &update->hot_y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &update->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &update->height) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (large_lengths)
    {
        if (rdp_stream_read_u32_le(stream, &and_len32) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(stream, &xor_len32) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->and_mask_len = and_len32;
        update->xor_mask_len = xor_len32;
    }
    else
    {
        if (rdp_stream_read_u16_le(stream, &and_len16) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &xor_len16) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->and_mask_len = and_len16;
        update->xor_mask_len = xor_len16;
    }

    if (update->width == 0 || update->height == 0 ||
        update->width > RDP_MOUSE_CURSOR_MAX_DIMENSION ||
        update->height > RDP_MOUSE_CURSOR_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update->hot_x >= update->width || update->hot_y >= update->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update->and_mask_len > rdp_stream_remaining(stream) ||
        update->xor_mask_len > rdp_stream_remaining(stream) - update->and_mask_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &update->xor_mask, update->xor_mask_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(stream, &update->and_mask, update->and_mask_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    update->kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mouse_cursor_write_caps_advertise(rdp_buffer* buffer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_MOUSE_CURSOR_PDU_CS_CAPS_ADVERTISE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, RDP_MOUSE_CURSOR_CAPSET_SIGNATURE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, RDP_MOUSE_CURSOR_CAPSET_VERSION1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, RDP_MOUSE_CURSOR_CAPSET_SIZE_VERSION1);
    return status;
}

librdp_status rdp_mouse_cursor_parse_header(const void* data, size_t length, rdp_mouse_cursor_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &header->pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->update_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->reserved) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mouse_cursor_parse_caps_confirm(const void* data,
                                                  size_t length,
                                                  rdp_mouse_cursor_capset* capset)
{
    rdp_stream stream;
    rdp_mouse_cursor_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !capset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(capset, 0, sizeof(*capset));
    status = rdp_mouse_cursor_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.pdu_type != RDP_MOUSE_CURSOR_PDU_SC_CAPS_CONFIRM || header.update_type != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_mouse_cursor_parse_capset(&stream, capset);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mouse_cursor_parse_update(const void* data, size_t length, rdp_pointer_update* update)
{
    rdp_stream stream;
    rdp_mouse_cursor_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
    status = rdp_mouse_cursor_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.pdu_type != RDP_MOUSE_CURSOR_PDU_SC_MOUSEPTR_UPDATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_NULL)
    {
        if (rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->kind = RDP_POINTER_UPDATE_KIND_NULL;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_DEFAULT)
    {
        if (rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_POSITION)
    {
        if (rdp_stream_read_u16_le(&stream, &update->x) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &update->y) != LIBRDP_STATUS_OK ||
            rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->kind = RDP_POINTER_UPDATE_KIND_POSITION;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_CACHED)
    {
        if (rdp_stream_read_u16_le(&stream, &update->cache_index) != LIBRDP_STATUS_OK ||
            rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        update->kind = RDP_POINTER_UPDATE_KIND_CACHED;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_POINTER)
        return rdp_mouse_cursor_parse_pointer_attributes(&stream, 0, update);
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_LARGE_POINTER)
        return rdp_mouse_cursor_parse_pointer_attributes(&stream, 1, update);
    return LIBRDP_STATUS_UNSUPPORTED;
}

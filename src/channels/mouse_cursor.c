/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: mouse cursor channel parsing and cache support.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/mouse_cursor.h"

#include "common/stream.h"

#include <string.h>

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

/*
 * Parse pointer attributes from the mouse cursor virtual channel. Dimension,
 * hotspot, stride, and mask-length invariants are checked before borrowed
 * pixel/mask slices are returned to cursor-cache code.
 */
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
        update->width > RDP_POINTER_MAX_DIMENSION ||
        update->height > RDP_POINTER_MAX_DIMENSION)
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

static librdp_status rdp_mouse_cursor_write_header(rdp_buffer* buffer, uint8_t update_type)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_MOUSE_CURSOR_PDU_SC_MOUSEPTR_UPDATE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, update_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    return status;
}

/*
 * Serialize a normalized pointer update for the Mouse Cursor virtual channel.
 * Shape payloads are accepted only after hotspot, dimension, length and
 * mask-pointer invariants match the parser, keeping cache state symmetric
 * between server tests and client cursor handling.
 */
librdp_status rdp_mouse_cursor_write_update(rdp_buffer* buffer, const rdp_pointer_update* update)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t update_type = 0;
    int large_lengths = 0;

    if (!buffer || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (update->kind)
    {
        case RDP_POINTER_UPDATE_KIND_NULL:
            return rdp_mouse_cursor_write_header(buffer, RDP_MOUSE_CURSOR_UPDATE_NULL);
        case RDP_POINTER_UPDATE_KIND_DEFAULT:
            return rdp_mouse_cursor_write_header(buffer, RDP_MOUSE_CURSOR_UPDATE_DEFAULT);
        case RDP_POINTER_UPDATE_KIND_POSITION:
            status = rdp_mouse_cursor_write_header(buffer, RDP_MOUSE_CURSOR_UPDATE_POSITION);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, update->x);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, update->y);
            return status;
        case RDP_POINTER_UPDATE_KIND_CACHED:
            status = rdp_mouse_cursor_write_header(buffer, RDP_MOUSE_CURSOR_UPDATE_CACHED);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, update->cache_index);
            return status;
        case RDP_POINTER_UPDATE_KIND_SHAPE:
            break;
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }

    if (update->width == 0 || update->height == 0 ||
        update->width > RDP_POINTER_MAX_DIMENSION ||
        update->height > RDP_POINTER_MAX_DIMENSION ||
        update->hot_x >= update->width || update->hot_y >= update->height ||
        (!update->xor_mask && update->xor_mask_len > 0) ||
        (!update->and_mask && update->and_mask_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    large_lengths = update->xor_mask_len > 0xffffu || update->and_mask_len > 0xffffu;
    if (!large_lengths && (update->xor_mask_len > 0xffffu || update->and_mask_len > 0xffffu))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->xor_mask_len > UINT32_MAX || update->and_mask_len > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    update_type = large_lengths ? RDP_MOUSE_CURSOR_UPDATE_LARGE_POINTER :
                                  RDP_MOUSE_CURSOR_UPDATE_POINTER;
    status = rdp_mouse_cursor_write_header(buffer, update_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, update->xor_bpp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, update->cache_index);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, update->hot_x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, update->hot_y);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, update->width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, update->height);
    if (large_lengths)
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, (uint32_t)update->and_mask_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u32_le(buffer, (uint32_t)update->xor_mask_len);
    }
    else
    {
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, (uint16_t)update->and_mask_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u16_le(buffer, (uint16_t)update->xor_mask_len);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, update->xor_mask, update->xor_mask_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, update->and_mask, update->and_mask_len);
    return status;
}

librdp_status rdp_mouse_cursor_parse_header(const void* data, size_t length, rdp_mouse_cursor_header* header)
{
    rdp_stream stream;
    rdp_mouse_cursor_header parsed;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.pdu_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.update_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.reserved) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mouse_cursor_parse_caps_confirm(const void* data,
                                                  size_t length,
                                                  rdp_mouse_cursor_capset* capset)
{
    rdp_stream stream;
    rdp_mouse_cursor_header header;
    rdp_mouse_cursor_capset parsed;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !capset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    status = rdp_mouse_cursor_parse_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.pdu_type != RDP_MOUSE_CURSOR_PDU_SC_CAPS_CONFIRM || header.update_type != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_mouse_cursor_parse_capset(&stream, &parsed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *capset = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_mouse_cursor_parse_update(const void* data, size_t length, rdp_pointer_update* update)
{
    rdp_stream stream;
    rdp_mouse_cursor_header header;
    rdp_pointer_update parsed;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
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
        parsed.kind = RDP_POINTER_UPDATE_KIND_NULL;
        *update = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_DEFAULT)
    {
        if (rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
        *update = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_POSITION)
    {
        if (rdp_stream_read_u16_le(&stream, &parsed.x) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &parsed.y) != LIBRDP_STATUS_OK ||
            rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.kind = RDP_POINTER_UPDATE_KIND_POSITION;
        *update = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_CACHED)
    {
        if (rdp_stream_read_u16_le(&stream, &parsed.cache_index) != LIBRDP_STATUS_OK ||
            rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.kind = RDP_POINTER_UPDATE_KIND_CACHED;
        *update = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_POINTER)
    {
        status = rdp_mouse_cursor_parse_pointer_attributes(&stream, 0, &parsed);
        if (status == LIBRDP_STATUS_OK)
        {
            parsed.shape_format = RDP_POINTER_SHAPE_FORMAT_NEW;
            *update = parsed;
        }
        return status;
    }
    if (header.update_type == RDP_MOUSE_CURSOR_UPDATE_LARGE_POINTER)
    {
        status = rdp_mouse_cursor_parse_pointer_attributes(&stream, 1, &parsed);
        if (status == LIBRDP_STATUS_OK)
        {
            parsed.shape_format = RDP_POINTER_SHAPE_FORMAT_LARGE;
            *update = parsed;
        }
        return status;
    }
    return LIBRDP_STATUS_UNSUPPORTED;
}

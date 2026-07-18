/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: pointer shape decoding and cache support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


#include "protocol/pointer.h"

#include "common/stream.h"
#include "protocol/fastpath.h"

#include <limits.h>
#include <string.h>

static size_t rdp_pointer_mask_stride(uint16_t width)
{
    return (((size_t)width + 15u) / 16u) * 2u;
}

static size_t rdp_pointer_xor_stride(uint16_t width, uint16_t bpp)
{
    return ((((size_t)width * bpp) + 15u) / 16u) * 2u;
}

static int rdp_pointer_mask_bit(const uint8_t* data, size_t stride, uint16_t width, uint16_t height, uint16_t x, uint16_t y)
{
    size_t row = (size_t)(height - 1u - y);
    size_t offset = row * stride + ((size_t)x / 8u);
    uint8_t mask = (uint8_t)(0x80u >> (x % 8u));

    if (!data || x >= width || y >= height)
        return 0;
    return (data[offset] & mask) != 0;
}

static int rdp_pointer_color_nonzero(const uint8_t* pixel)
{
    return pixel && (pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0);
}

static void rdp_pointer_write_invert_approximation(uint8_t* dst)
{
    dst[0] = 0x00u;
    dst[1] = 0x00u;
    dst[2] = 0x00u;
    dst[3] = 0xffu;
}

static uint8_t rdp_pointer_scale_5_to_8(uint16_t value)
{
    return (uint8_t)((value * 255u + 15u) / 31u);
}

static uint8_t rdp_pointer_scale_6_to_8(uint16_t value)
{
    return (uint8_t)((value * 255u + 31u) / 63u);
}

static librdp_status rdp_pointer_parse_color_attributes(rdp_stream* stream,
                                                        uint16_t bpp,
                                                        int large_lengths,
                                                        rdp_pointer_update* update)
{
    uint16_t and_len16 = 0;
    uint16_t xor_len16 = 0;
    uint32_t and_len32 = 0;
    uint32_t xor_len32 = 0;

    if (!stream || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (rdp_stream_read_u16_le(stream, &update->cache_index) != LIBRDP_STATUS_OK ||
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
        update->width > RDP_POINTER_MAX_DIMENSION || update->height > RDP_POINTER_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update->hot_x >= update->width || update->hot_y >= update->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update->and_mask_len > rdp_stream_remaining(stream) ||
        update->xor_mask_len > rdp_stream_remaining(stream) - update->and_mask_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &update->xor_mask, update->xor_mask_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(stream, &update->and_mask, update->and_mask_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    update->kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    update->xor_bpp = bpp;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pointer_parse_fastpath(uint8_t update_code,
                                         const void* data,
                                         size_t length,
                                         rdp_pointer_update* update)
{
    rdp_stream stream;
    rdp_pointer_update parsed;

    if (!update || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    switch (update_code)
    {
        case RDP_FASTPATH_UPDATE_POINTER_NULL:
            if (length != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.kind = RDP_POINTER_UPDATE_KIND_NULL;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_DEFAULT:
            if (length != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_POSITION:
            if (rdp_stream_read_u16_le(&stream, &parsed.x) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &parsed.y) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.kind = RDP_POINTER_UPDATE_KIND_POSITION;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_CACHED:
            if (rdp_stream_read_u16_le(&stream, &parsed.cache_index) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.kind = RDP_POINTER_UPDATE_KIND_CACHED;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_COLOR:
        {
            librdp_status status = rdp_pointer_parse_color_attributes(&stream, 24, 0, &parsed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        case RDP_FASTPATH_UPDATE_POINTER_NEW:
        {
            librdp_status status = LIBRDP_STATUS_OK;
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_pointer_parse_color_attributes(&stream, bpp, 0, &parsed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        case RDP_FASTPATH_UPDATE_POINTER_LARGE:
        {
            librdp_status status = LIBRDP_STATUS_OK;
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_pointer_parse_color_attributes(&stream, bpp, 1, &parsed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

/*
 * Parse slow-path pointer updates into a single normalized pointer event.
 * The function keeps all decoded fields local until message type, payload
 * length, dimensions, hotspots, and mask bounds are accepted, so malformed
 * cursor PDUs cannot replace the caller's last valid pointer state.
 */
librdp_status rdp_pointer_parse_slowpath(const void* data, size_t length, rdp_pointer_update* update)
{
    rdp_stream stream;
    rdp_pointer_update parsed;
    uint16_t message_type = 0;

    if (!update || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &message_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    switch (message_type)
    {
        case RDP_POINTER_MESSAGE_TYPE_SYSTEM:
        {
            uint32_t pointer_type = 0;
            if (rdp_stream_read_u32_le(&stream, &pointer_type) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (pointer_type == RDP_POINTER_SYSTEM_NULL)
                parsed.kind = RDP_POINTER_UPDATE_KIND_NULL;
            else if (pointer_type == RDP_POINTER_SYSTEM_DEFAULT)
                parsed.kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
            else
                return LIBRDP_STATUS_UNSUPPORTED;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        case RDP_POINTER_MESSAGE_TYPE_POSITION:
            if (rdp_stream_read_u16_le(&stream, &parsed.x) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &parsed.y) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.kind = RDP_POINTER_UPDATE_KIND_POSITION;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_MESSAGE_TYPE_COLOR:
        {
            librdp_status status = rdp_pointer_parse_color_attributes(&stream, 24, 0, &parsed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        case RDP_POINTER_MESSAGE_TYPE_CACHED:
            if (rdp_stream_read_u16_le(&stream, &parsed.cache_index) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed.kind = RDP_POINTER_UPDATE_KIND_CACHED;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_MESSAGE_TYPE_POINTER:
        {
            librdp_status status = LIBRDP_STATUS_OK;
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_pointer_parse_color_attributes(&stream, bpp, 0, &parsed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        case RDP_POINTER_MESSAGE_TYPE_LARGE:
        {
            librdp_status status = LIBRDP_STATUS_OK;
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_pointer_parse_color_attributes(&stream, bpp, 1, &parsed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            *update = parsed;
            return LIBRDP_STATUS_OK;
        }
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

/*
 * Serialize one normalized pointer update without the enclosing Update Data
 * PDU. Attribute lengths select the standard or large pointer message, and a
 * failed append restores the caller's original buffer length.
 */
librdp_status rdp_pointer_write_slowpath(
    rdp_buffer* buffer,
    const rdp_pointer_update* update)
{
    size_t original_length = 0u;
    uint16_t message_type = 0u;
    int large_lengths = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    original_length = buffer->length;
    switch (update->kind)
    {
        case RDP_POINTER_UPDATE_KIND_NULL:
        case RDP_POINTER_UPDATE_KIND_DEFAULT:
            status = rdp_buffer_append_u16_le(
                buffer,
                RDP_POINTER_MESSAGE_TYPE_SYSTEM);
            if (status == LIBRDP_STATUS_OK)
            {
                status = rdp_buffer_append_u32_le(
                    buffer,
                    update->kind == RDP_POINTER_UPDATE_KIND_NULL
                        ? RDP_POINTER_SYSTEM_NULL
                        : RDP_POINTER_SYSTEM_DEFAULT);
            }
            break;
        case RDP_POINTER_UPDATE_KIND_POSITION:
            status = rdp_buffer_append_u16_le(
                buffer,
                RDP_POINTER_MESSAGE_TYPE_POSITION);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, update->x);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, update->y);
            break;
        case RDP_POINTER_UPDATE_KIND_CACHED:
            status = rdp_buffer_append_u16_le(
                buffer,
                RDP_POINTER_MESSAGE_TYPE_CACHED);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer,
                                                  update->cache_index);
            break;
        case RDP_POINTER_UPDATE_KIND_SHAPE:
            if (update->width == 0u || update->height == 0u ||
                update->width > RDP_POINTER_MAX_DIMENSION ||
                update->height > RDP_POINTER_MAX_DIMENSION ||
                update->hot_x >= update->width ||
                update->hot_y >= update->height ||
                (update->xor_bpp != 1u && update->xor_bpp != 15u &&
                 update->xor_bpp != 16u && update->xor_bpp != 24u &&
                 update->xor_bpp != 32u) ||
                (!update->xor_mask && update->xor_mask_len > 0u) ||
                (!update->and_mask && update->and_mask_len > 0u) ||
                update->xor_mask_len > UINT32_MAX ||
                update->and_mask_len > UINT32_MAX)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            large_lengths = update->xor_mask_len > UINT16_MAX ||
                            update->and_mask_len > UINT16_MAX;
            message_type = large_lengths
                               ? RDP_POINTER_MESSAGE_TYPE_LARGE
                               : RDP_POINTER_MESSAGE_TYPE_POINTER;
            status = rdp_buffer_append_u16_le(buffer, message_type);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer, update->xor_bpp);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_buffer_append_u16_le(buffer,
                                                  update->cache_index);
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
                {
                    status = rdp_buffer_append_u32_le(
                        buffer,
                        (uint32_t)update->and_mask_len);
                }
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_buffer_append_u32_le(
                        buffer,
                        (uint32_t)update->xor_mask_len);
                }
            }
            else
            {
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_buffer_append_u16_le(
                        buffer,
                        (uint16_t)update->and_mask_len);
                }
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_buffer_append_u16_le(
                        buffer,
                        (uint16_t)update->xor_mask_len);
                }
            }
            if (status == LIBRDP_STATUS_OK)
            {
                status = rdp_buffer_append(buffer,
                                           update->xor_mask,
                                           update->xor_mask_len);
            }
            if (status == LIBRDP_STATUS_OK)
            {
                status = rdp_buffer_append(buffer,
                                           update->and_mask,
                                           update->and_mask_len);
            }
            break;
        default:
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (status != LIBRDP_STATUS_OK)
        buffer->length = original_length;
    return status;
}

/*
 * Decode a pointer shape into BGRA pixels using the supplied color and mask
 * planes. All stride and mask offsets are checked before composing pixels so
 * malformed cursors cannot corrupt caller output.
 */
librdp_status rdp_pointer_decode_bgra32(const rdp_pointer_update* update, rdp_buffer* output, size_t* stride)
{
    uint16_t y = 0;
    uint16_t x = 0;
    size_t and_stride = 0;
    size_t xor_stride = 0;
    size_t dst_stride = 0;
    size_t dst_size = 0;
    int has_alpha = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!update || !output || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->kind != RDP_POINTER_UPDATE_KIND_SHAPE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->xor_bpp != 1u && update->xor_bpp != 15u && update->xor_bpp != 16u &&
        update->xor_bpp != 24u && update->xor_bpp != 32u)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (update->width == 0 || update->height == 0 ||
        update->width > RDP_POINTER_MAX_DIMENSION || update->height > RDP_POINTER_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    and_stride = rdp_pointer_mask_stride(update->width);
    xor_stride = rdp_pointer_xor_stride(update->width, update->xor_bpp);
    if (and_stride == 0 || xor_stride == 0 ||
        (size_t)update->height > SIZE_MAX / and_stride ||
        (size_t)update->height > SIZE_MAX / xor_stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->and_mask_len < and_stride * update->height ||
        update->xor_mask_len < xor_stride * update->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    dst_stride = (size_t)update->width * 4u;
    if ((size_t)update->height > SIZE_MAX / dst_stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    dst_size = dst_stride * update->height;
    status = rdp_buffer_reserve(output, dst_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    output->length = dst_size;

    if (update->xor_bpp == 32u)
    {
        size_t i = 0;
        for (i = 3; i < update->xor_mask_len; i += 4)
        {
            if (update->xor_mask[i] != 0)
            {
                has_alpha = 1;
                break;
            }
        }
    }

    for (y = 0; y < update->height; y++)
    {
        const uint8_t* src = update->xor_mask + ((size_t)(update->height - 1u - y) * xor_stride);
        uint8_t* dst = output->data + ((size_t)y * dst_stride);

        for (x = 0; x < update->width; x++)
        {
            size_t dst_pos = (size_t)x * 4u;
            int transparent = rdp_pointer_mask_bit(update->and_mask,
                                                   and_stride,
                                                   update->width,
                                                   update->height,
                                                   x,
                                                   y);

            if (update->xor_bpp == 32u)
            {
                const uint8_t* pixel = src + ((size_t)x * 4u);
                int alpha_visible = has_alpha && pixel[3] != 0;

                if (transparent && !has_alpha && rdp_pointer_color_nonzero(pixel))
                {
                    rdp_pointer_write_invert_approximation(dst + dst_pos);
                }
                else
                {
                    dst[dst_pos + 0u] = pixel[0];
                    dst[dst_pos + 1u] = pixel[1];
                    dst[dst_pos + 2u] = pixel[2];
                    dst[dst_pos + 3u] = transparent && !alpha_visible ? 0u : (has_alpha ? pixel[3] : 0xffu);
                }
            }
            else if (update->xor_bpp == 24u)
            {
                const uint8_t* pixel = src + ((size_t)x * 3u);
                if (transparent && rdp_pointer_color_nonzero(pixel))
                {
                    rdp_pointer_write_invert_approximation(dst + dst_pos);
                }
                else
                {
                    dst[dst_pos + 0u] = pixel[0];
                    dst[dst_pos + 1u] = pixel[1];
                    dst[dst_pos + 2u] = pixel[2];
                    dst[dst_pos + 3u] = transparent ? 0u : 0xffu;
                }
            }
            else if (update->xor_bpp == 15u)
            {
                const uint8_t* pixel = src + ((size_t)x * 2u);
                uint16_t raw = (uint16_t)(pixel[0] | ((uint16_t)pixel[1] << 8));
                int nonzero = raw != 0;

                if (transparent && nonzero)
                {
                    rdp_pointer_write_invert_approximation(dst + dst_pos);
                }
                else
                {
                    dst[dst_pos + 0u] = rdp_pointer_scale_5_to_8((uint16_t)(raw & 0x001fu));
                    dst[dst_pos + 1u] = rdp_pointer_scale_5_to_8((uint16_t)((raw >> 5) & 0x001fu));
                    dst[dst_pos + 2u] = rdp_pointer_scale_5_to_8((uint16_t)((raw >> 10) & 0x001fu));
                    dst[dst_pos + 3u] = transparent ? 0u : 0xffu;
                }
            }
            else if (update->xor_bpp == 16u)
            {
                const uint8_t* pixel = src + ((size_t)x * 2u);
                uint16_t raw = (uint16_t)(pixel[0] | ((uint16_t)pixel[1] << 8));
                int nonzero = raw != 0;

                if (transparent && nonzero)
                {
                    rdp_pointer_write_invert_approximation(dst + dst_pos);
                }
                else
                {
                    dst[dst_pos + 0u] = rdp_pointer_scale_5_to_8((uint16_t)(raw & 0x001fu));
                    dst[dst_pos + 1u] = rdp_pointer_scale_6_to_8((uint16_t)((raw >> 5) & 0x003fu));
                    dst[dst_pos + 2u] = rdp_pointer_scale_5_to_8((uint16_t)((raw >> 11) & 0x001fu));
                    dst[dst_pos + 3u] = transparent ? 0u : 0xffu;
                }
            }
            else
            {
                int xor_bit = rdp_pointer_mask_bit(update->xor_mask,
                                                   xor_stride,
                                                   update->width,
                                                   update->height,
                                                   x,
                                                   y);
                uint8_t color = xor_bit ? 0xffu : 0x00u;

                if (transparent && xor_bit)
                {
                    rdp_pointer_write_invert_approximation(dst + dst_pos);
                }
                else
                {
                    dst[dst_pos + 0u] = color;
                    dst[dst_pos + 1u] = color;
                    dst[dst_pos + 2u] = color;
                    dst[dst_pos + 3u] = transparent ? 0u : 0xffu;
                }
            }
        }
    }

    *stride = dst_stride;
    return LIBRDP_STATUS_OK;
}

#include "graphics/bitmap.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static librdp_status rdp_bitmap_parse_rectangles(rdp_stream* stream, uint16_t count, rdp_bitmap_update* update)
{
    uint16_t i = 0;

    if (!stream || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (count > RDP_BITMAP_MAX_RECTS)
        return LIBRDP_STATUS_UNSUPPORTED;

    for (i = 0; i < count; i++)
    {
        rdp_bitmap_rect* rect = &update->rects[i];

        if (rdp_stream_read_u16_le(stream, &rect->dest_left) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->dest_top) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->dest_right) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->dest_bottom) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->width) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->height) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->bits_per_pixel) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(stream, &rect->flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(stream, &rect->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rect->width == 0 || rect->height == 0 || rect->dest_right < rect->dest_left ||
            rect->dest_bottom < rect->dest_top)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rect->data_len > rdp_stream_remaining(stream))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_bytes(stream, &rect->data, rect->data_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    update->count = count;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_parse_update_header(const void* data, size_t length, rdp_bitmap_update_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &header->update_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &header->count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_parse_update(const void* data, size_t length, rdp_bitmap_update* update)
{
    rdp_stream stream;
    rdp_bitmap_update_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
    status = rdp_bitmap_parse_update_header(data, length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.update_type != RDP_UPDATE_TYPE_BITMAP)
        return LIBRDP_STATUS_UNSUPPORTED;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 4) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_bitmap_parse_rectangles(&stream, header.count, update);
}

librdp_status rdp_bitmap_parse_fastpath_update(const void* data, size_t length, rdp_bitmap_update* update)
{
    rdp_stream stream;
    uint16_t count = 0;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_bitmap_parse_rectangles(&stream, count, update);
}

static librdp_status rdp_bitmap_validate_rect(const rdp_bitmap_rect* rect)
{
    if (!rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->width == 0 || rect->height == 0 || rect->dest_right < rect->dest_left ||
        rect->dest_bottom < rect->dest_top || rect->bits_per_pixel == 0 ||
        (!rect->data && rect->data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_write_rect(rdp_buffer* buffer, const rdp_bitmap_rect* rect)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_bitmap_validate_rect(rect);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->dest_left);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->dest_top);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->dest_right);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->dest_bottom);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->width);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->bits_per_pixel);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, rect->flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, rect->data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, rect->data, rect->data_len);
}

static librdp_status rdp_bitmap_write_rects(rdp_buffer* buffer, const rdp_bitmap_rect* rects, uint16_t count)
{
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!rects && count > 0) || count > RDP_BITMAP_MAX_RECTS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < count; i++)
    {
        status = rdp_bitmap_write_rect(buffer, &rects[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_write_update(rdp_buffer* buffer, const rdp_bitmap_rect* rects, uint16_t count)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!rects && count > 0) || count > RDP_BITMAP_MAX_RECTS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, RDP_UPDATE_TYPE_BITMAP);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_bitmap_write_rects(buffer, rects, count);
}

librdp_status rdp_bitmap_write_fastpath_update(rdp_buffer* buffer, const rdp_bitmap_rect* rects, uint16_t count)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!rects && count > 0) || count > RDP_BITMAP_MAX_RECTS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_bitmap_write_rects(buffer, rects, count);
}

static uint8_t rdp_scale_5_to_8(uint16_t value)
{
    return (uint8_t)((value * 255u + 15u) / 31u);
}

static uint8_t rdp_scale_6_to_8(uint16_t value)
{
    return (uint8_t)((value * 255u + 31u) / 63u);
}

librdp_status rdp_bitmap_decode_rect_bgra32(const rdp_bitmap_rect* rect, rdp_buffer* output, size_t* stride)
{
    uint16_t row = 0;
    uint16_t column = 0;
    size_t src_stride = 0;
    size_t dst_stride = 0;
    size_t dst_size = 0;
    uint16_t bytes_per_pixel = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rect || !output || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->flags != 0 || (rect->bits_per_pixel != 16 && rect->bits_per_pixel != 24 && rect->bits_per_pixel != 32))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (rect->width == 0 || rect->height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    bytes_per_pixel = (uint16_t)(rect->bits_per_pixel / 8u);
    if ((size_t)rect->width > SIZE_MAX / bytes_per_pixel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    src_stride = (size_t)rect->width * bytes_per_pixel;
    if ((size_t)rect->height > SIZE_MAX / src_stride || rect->data_len < src_stride * rect->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    dst_stride = (size_t)rect->width * 4u;
    if ((size_t)rect->height > SIZE_MAX / dst_stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    dst_size = dst_stride * rect->height;

    status = rdp_buffer_reserve(output, dst_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    output->length = dst_size;

    for (row = 0; row < rect->height; row++)
    {
        const uint8_t* src = rect->data + ((size_t)(rect->height - 1u - row) * src_stride);
        uint8_t* dst = output->data + ((size_t)row * dst_stride);

        if (rect->bits_per_pixel == 32)
        {
            memcpy(dst, src, dst_stride);
        }
        else if (rect->bits_per_pixel == 24)
        {
            for (column = 0; column < rect->width; column++)
            {
                dst[(size_t)column * 4u + 0u] = src[(size_t)column * 3u + 0u];
                dst[(size_t)column * 4u + 1u] = src[(size_t)column * 3u + 1u];
                dst[(size_t)column * 4u + 2u] = src[(size_t)column * 3u + 2u];
                dst[(size_t)column * 4u + 3u] = 0xffu;
            }
        }
        else
        {
            for (column = 0; column < rect->width; column++)
            {
                uint16_t pixel = (uint16_t)(src[(size_t)column * 2u] | ((uint16_t)src[(size_t)column * 2u + 1u] << 8));
                dst[(size_t)column * 4u + 0u] = rdp_scale_5_to_8((uint16_t)(pixel & 0x001fu));
                dst[(size_t)column * 4u + 1u] = rdp_scale_6_to_8((uint16_t)((pixel >> 5) & 0x003fu));
                dst[(size_t)column * 4u + 2u] = rdp_scale_5_to_8((uint16_t)((pixel >> 11) & 0x001fu));
                dst[(size_t)column * 4u + 3u] = 0xffu;
            }
        }
    }

    *stride = dst_stride;
    return LIBRDP_STATUS_OK;
}

#include "graphics/bitmap.h"

#include "common/stream.h"

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

librdp_status rdp_bitmap_parse_update(const void* data, size_t length, rdp_bitmap_update* update)
{
    rdp_stream stream;
    uint16_t update_type = 0;
    uint16_t count = 0;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &update_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update_type != RDP_UPDATE_TYPE_BITMAP)
        return LIBRDP_STATUS_UNSUPPORTED;
    return rdp_bitmap_parse_rectangles(&stream, count, update);
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

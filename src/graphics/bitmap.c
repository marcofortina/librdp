#include "graphics/bitmap.h"

#include "common/stream.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define RDP_BITMAP_FLAG_COMPRESSED 0x0001u
#define RDP_BITMAP_FLAG_NO_COMPRESSION_HEADER 0x0400u
#define RDP_BITMAP_RLE_BG_RUN 0x00u
#define RDP_BITMAP_RLE_FG_RUN 0x01u
#define RDP_BITMAP_RLE_FGBG_IMAGE 0x02u
#define RDP_BITMAP_RLE_COLOR_RUN 0x03u
#define RDP_BITMAP_RLE_COLOR_IMAGE 0x04u
#define RDP_BITMAP_RLE_SET_FG_FG_RUN 0x0cu
#define RDP_BITMAP_RLE_SET_FG_FGBG_IMAGE 0x0du
#define RDP_BITMAP_RLE_DITHERED_RUN 0x0eu
#define RDP_BITMAP_RLE_MEGA_BG_RUN 0xf0u
#define RDP_BITMAP_RLE_MEGA_FG_RUN 0xf1u
#define RDP_BITMAP_RLE_MEGA_FGBG_IMAGE 0xf2u
#define RDP_BITMAP_RLE_MEGA_COLOR_RUN 0xf3u
#define RDP_BITMAP_RLE_MEGA_COLOR_IMAGE 0xf4u
#define RDP_BITMAP_RLE_MEGA_SET_FG_RUN 0xf6u
#define RDP_BITMAP_RLE_MEGA_SET_FG_FGBG_IMAGE 0xf7u
#define RDP_BITMAP_RLE_MEGA_DITHERED_RUN 0xf8u
#define RDP_BITMAP_RLE_SPECIAL_FGBG_1 0xf9u
#define RDP_BITMAP_RLE_SPECIAL_FGBG_2 0xfau
#define RDP_BITMAP_RLE_SPECIAL_WHITE 0xfdu
#define RDP_BITMAP_RLE_SPECIAL_BLACK 0xfeu

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
    uint16_t first = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = first;
    status = rdp_bitmap_parse_rectangles(&stream, count, update);
    if (status == LIBRDP_STATUS_OK || first != RDP_UPDATE_TYPE_BITMAP)
        return status;

    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 2) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_bitmap_parse_rectangles(&stream, count, update);
}

static librdp_status rdp_bitmap_parse_palette_body(rdp_stream* stream, rdp_palette_update* palette)
{
    uint16_t pad = 0;
    uint32_t count = 0;
    uint32_t i = 0;

    if (!stream || !palette)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u16_le(stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (count > RDP_BITMAP_PALETTE_MAX_ENTRIES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(stream) < (size_t)count * 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(palette, 0, sizeof(*palette));
    palette->count = count;
    for (i = 0; i < count; i++)
    {
        if (rdp_stream_read_u8(stream, &palette->entries[i].red) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(stream, &palette->entries[i].green) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(stream, &palette->entries[i].blue) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    (void)pad;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_parse_palette_update(const void* data, size_t length, rdp_palette_update* palette)
{
    rdp_stream stream;
    uint16_t update_type = 0;

    if (!data || !palette)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &update_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (update_type != RDP_UPDATE_TYPE_PALETTE)
        return LIBRDP_STATUS_UNSUPPORTED;
    return rdp_bitmap_parse_palette_body(&stream, palette);
}

librdp_status rdp_bitmap_parse_fastpath_palette_update(const void* data, size_t length, rdp_palette_update* palette)
{
    rdp_stream stream;
    uint16_t first = 0;

    if (!data || !palette)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (first == RDP_UPDATE_TYPE_PALETTE)
        return rdp_bitmap_parse_palette_body(&stream, palette);
    rdp_stream_init(&stream, data, length);
    return rdp_bitmap_parse_palette_body(&stream, palette);
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

librdp_status rdp_bitmap_write_palette_update(rdp_buffer* buffer, const rdp_palette_update* palette)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || !palette || palette->count > RDP_BITMAP_PALETTE_MAX_ENTRIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, RDP_UPDATE_TYPE_PALETTE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, palette->count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < palette->count; i++)
    {
        status = rdp_buffer_append_u8(buffer, palette->entries[i].red);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, palette->entries[i].green);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, palette->entries[i].blue);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_write_fastpath_palette_update(rdp_buffer* buffer, const rdp_palette_update* palette)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || !palette || palette->count > RDP_BITMAP_PALETTE_MAX_ENTRIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, palette->count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0; i < palette->count; i++)
    {
        status = rdp_buffer_append_u8(buffer, palette->entries[i].red);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, palette->entries[i].green);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append_u8(buffer, palette->entries[i].blue);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static uint8_t rdp_scale_5_to_8(uint16_t value)
{
    return (uint8_t)((value * 255u + 15u) / 31u);
}

static uint8_t rdp_scale_6_to_8(uint16_t value)
{
    return (uint8_t)((value * 255u + 31u) / 63u);
}

typedef struct rdp_bitmap_rle_reader
{
    const uint8_t* current;
    const uint8_t* end;
    uint32_t* pixels;
    size_t position;
    size_t total;
    uint16_t width;
    uint16_t bits_per_pixel;
    uint32_t foreground;
    uint8_t insert_foreground;
} rdp_bitmap_rle_reader;

static uint8_t rdp_bitmap_rle_bytes_per_pixel(uint16_t bits_per_pixel)
{
    if (bits_per_pixel == 8u)
        return 1;
    if (bits_per_pixel == 15u)
        return 2;
    if (bits_per_pixel == 16u)
        return 2;
    if (bits_per_pixel == 24u)
        return 3;
    if (bits_per_pixel == 32u)
        return 4;
    return 0;
}

static uint32_t rdp_bitmap_rle_white(uint16_t bits_per_pixel)
{
    if (bits_per_pixel == 8u)
        return 0xffu;
    if (bits_per_pixel == 15u)
        return 0x7fffu;
    if (bits_per_pixel == 16u)
        return 0xffffu;
    return 0x00ffffffu;
}

static uint8_t rdp_bitmap_rle_code(uint8_t header)
{
    if ((header & 0xc0u) != 0xc0u)
        return (uint8_t)(header >> 5);
    if ((header & 0xf0u) == 0xf0u)
        return header;
    return (uint8_t)(header >> 4);
}

static librdp_status rdp_bitmap_rle_read_pixel(rdp_bitmap_rle_reader* reader, uint32_t* pixel)
{
    uint8_t bytes = 0;

    if (!reader || !pixel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    bytes = rdp_bitmap_rle_bytes_per_pixel(reader->bits_per_pixel);
    if (bytes == 0 || (size_t)(reader->end - reader->current) < bytes)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (reader->bits_per_pixel == 15u || reader->bits_per_pixel == 16u)
    {
        *pixel = (uint32_t)reader->current[0] | ((uint32_t)reader->current[1] << 8);
    }
    else if (reader->bits_per_pixel == 8u)
    {
        *pixel = reader->current[0];
    }
    else
    {
        *pixel = (uint32_t)reader->current[0] | ((uint32_t)reader->current[1] << 8) |
                 ((uint32_t)reader->current[2] << 16);
    }
    reader->current += bytes;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_rle_write_pixel(rdp_bitmap_rle_reader* reader, uint32_t pixel)
{
    if (!reader || !reader->pixels || reader->position >= reader->total)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    reader->pixels[reader->position++] = pixel;
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_bitmap_rle_previous_pixel(const rdp_bitmap_rle_reader* reader)
{
    if (!reader || reader->position < reader->width)
        return 0;
    return reader->pixels[reader->position - reader->width];
}

static librdp_status rdp_bitmap_rle_repeat(rdp_bitmap_rle_reader* reader, uint32_t pixel, uint32_t count)
{
    uint32_t i = 0;

    for (i = 0; i < count; i++)
    {
        librdp_status status = rdp_bitmap_rle_write_pixel(reader, pixel);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_rle_write_background(rdp_bitmap_rle_reader* reader, uint32_t count)
{
    uint32_t i = 0;

    for (i = 0; i < count; i++)
    {
        uint32_t pixel = reader->position < reader->width ? 0 : rdp_bitmap_rle_previous_pixel(reader);
        librdp_status status = rdp_bitmap_rle_write_pixel(reader, pixel);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_rle_write_foreground(rdp_bitmap_rle_reader* reader, uint32_t count)
{
    uint32_t i = 0;

    for (i = 0; i < count; i++)
    {
        uint32_t pixel = reader->position < reader->width ?
                         reader->foreground :
                         rdp_bitmap_rle_previous_pixel(reader) ^ reader->foreground;
        librdp_status status = rdp_bitmap_rle_write_pixel(reader, pixel);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_rle_run_length(const rdp_bitmap_rle_reader* reader,
                                               uint8_t code,
                                               uint32_t* run_length,
                                               size_t* consumed)
{
    const uint8_t* order = NULL;
    uint8_t low = 0;

    if (!reader || !run_length || !consumed || reader->current >= reader->end)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    order = reader->current;
    *consumed = 1;
    if (code == RDP_BITMAP_RLE_MEGA_BG_RUN || code == RDP_BITMAP_RLE_MEGA_FG_RUN ||
        code == RDP_BITMAP_RLE_MEGA_SET_FG_RUN || code == RDP_BITMAP_RLE_MEGA_DITHERED_RUN ||
        code == RDP_BITMAP_RLE_MEGA_COLOR_RUN || code == RDP_BITMAP_RLE_MEGA_FGBG_IMAGE ||
        code == RDP_BITMAP_RLE_MEGA_SET_FG_FGBG_IMAGE || code == RDP_BITMAP_RLE_MEGA_COLOR_IMAGE)
    {
        if ((size_t)(reader->end - order) < 3u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *run_length = (uint32_t)order[1] | ((uint32_t)order[2] << 8);
        *consumed = 3;
        return *run_length == 0 ? LIBRDP_STATUS_PROTOCOL_ERROR : LIBRDP_STATUS_OK;
    }
    if (code == RDP_BITMAP_RLE_FGBG_IMAGE)
    {
        low = (uint8_t)(order[0] & 0x1fu);
        if (low == 0)
        {
            if ((size_t)(reader->end - order) < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            *run_length = (uint32_t)order[1] + 1u;
            *consumed = 2;
        }
        else
        {
            *run_length = (uint32_t)low * 8u;
        }
        return LIBRDP_STATUS_OK;
    }
    if (code == RDP_BITMAP_RLE_SET_FG_FGBG_IMAGE)
    {
        low = (uint8_t)(order[0] & 0x0fu);
        if (low == 0)
        {
            if ((size_t)(reader->end - order) < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            *run_length = (uint32_t)order[1] + 1u;
            *consumed = 2;
        }
        else
        {
            *run_length = (uint32_t)low * 8u;
        }
        return LIBRDP_STATUS_OK;
    }
    if (code == RDP_BITMAP_RLE_SET_FG_FG_RUN || code == RDP_BITMAP_RLE_DITHERED_RUN)
    {
        low = (uint8_t)(order[0] & 0x0fu);
        if (low == 0)
        {
            if ((size_t)(reader->end - order) < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            *run_length = (uint32_t)order[1] + 16u;
            *consumed = 2;
        }
        else
        {
            *run_length = low;
        }
        return LIBRDP_STATUS_OK;
    }
    if (code == RDP_BITMAP_RLE_BG_RUN || code == RDP_BITMAP_RLE_FG_RUN ||
        code == RDP_BITMAP_RLE_COLOR_RUN || code == RDP_BITMAP_RLE_COLOR_IMAGE)
    {
        low = (uint8_t)(order[0] & 0x1fu);
        if (low == 0)
        {
            if ((size_t)(reader->end - order) < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            *run_length = (uint32_t)order[1] + 32u;
            *consumed = 2;
        }
        else
        {
            *run_length = low;
        }
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_bitmap_rle_write_fgbg(rdp_bitmap_rle_reader* reader,
                                               uint8_t mask,
                                               uint32_t count)
{
    uint32_t bit = 0;

    if (!reader || count > 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (bit = 0; bit < count; bit++)
    {
        uint32_t pixel = 0;

        if (reader->position < reader->width)
            pixel = (mask & (uint8_t)(1u << bit)) ? reader->foreground : 0;
        else
            pixel = (mask & (uint8_t)(1u << bit)) ? (rdp_bitmap_rle_previous_pixel(reader) ^ reader->foreground) :
                                                     rdp_bitmap_rle_previous_pixel(reader);
        if (rdp_bitmap_rle_write_pixel(reader, pixel) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_rle_decode_stream(const uint8_t* data,
                                                  size_t length,
                                                  uint16_t width,
                                                  uint16_t height,
                                                  uint16_t bits_per_pixel,
                                                  uint32_t* pixels)
{
    rdp_bitmap_rle_reader reader;

    if (!data || !pixels || width == 0 || height == 0 || !rdp_bitmap_rle_bytes_per_pixel(bits_per_pixel))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((size_t)width > SIZE_MAX / height)
        return LIBRDP_STATUS_NO_MEMORY;
    memset(&reader, 0, sizeof(reader));
    reader.current = data;
    reader.end = data + length;
    reader.pixels = pixels;
    reader.total = (size_t)width * height;
    reader.width = width;
    reader.bits_per_pixel = bits_per_pixel;
    reader.foreground = rdp_bitmap_rle_white(bits_per_pixel);

    while (reader.current < reader.end)
    {
        uint8_t code = rdp_bitmap_rle_code(*reader.current);
        uint32_t run = 0;
        size_t consumed = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (code == RDP_BITMAP_RLE_BG_RUN || code == RDP_BITMAP_RLE_MEGA_BG_RUN)
        {
            status = rdp_bitmap_rle_run_length(&reader, code, &run, &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.current += consumed;
            if (reader.insert_foreground)
            {
                if (run == 0)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                status = rdp_bitmap_rle_write_foreground(&reader, 1);
                if (status != LIBRDP_STATUS_OK)
                    return status;
                run--;
            }
            status = rdp_bitmap_rle_write_background(&reader, run);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.insert_foreground = 1;
            continue;
        }

        reader.insert_foreground = 0;
        if (code == RDP_BITMAP_RLE_FG_RUN || code == RDP_BITMAP_RLE_MEGA_FG_RUN ||
            code == RDP_BITMAP_RLE_SET_FG_FG_RUN || code == RDP_BITMAP_RLE_MEGA_SET_FG_RUN)
        {
            status = rdp_bitmap_rle_run_length(&reader, code, &run, &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.current += consumed;
            if (code == RDP_BITMAP_RLE_SET_FG_FG_RUN || code == RDP_BITMAP_RLE_MEGA_SET_FG_RUN)
            {
                status = rdp_bitmap_rle_read_pixel(&reader, &reader.foreground);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
            status = rdp_bitmap_rle_write_foreground(&reader, run);
        }
        else if (code == RDP_BITMAP_RLE_DITHERED_RUN || code == RDP_BITMAP_RLE_MEGA_DITHERED_RUN)
        {
            uint32_t a = 0;
            uint32_t b = 0;
            uint32_t i = 0;

            status = rdp_bitmap_rle_run_length(&reader, code, &run, &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.current += consumed;
            status = rdp_bitmap_rle_read_pixel(&reader, &a);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_bitmap_rle_read_pixel(&reader, &b);
            if (status != LIBRDP_STATUS_OK)
                return status;
            for (i = 0; i < run; i++)
            {
                status = rdp_bitmap_rle_write_pixel(&reader, a);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_bitmap_rle_write_pixel(&reader, b);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
        }
        else if (code == RDP_BITMAP_RLE_COLOR_RUN || code == RDP_BITMAP_RLE_MEGA_COLOR_RUN)
        {
            uint32_t color = 0;

            status = rdp_bitmap_rle_run_length(&reader, code, &run, &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.current += consumed;
            status = rdp_bitmap_rle_read_pixel(&reader, &color);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_bitmap_rle_repeat(&reader, color, run);
        }
        else if (code == RDP_BITMAP_RLE_FGBG_IMAGE || code == RDP_BITMAP_RLE_MEGA_FGBG_IMAGE ||
                 code == RDP_BITMAP_RLE_SET_FG_FGBG_IMAGE || code == RDP_BITMAP_RLE_MEGA_SET_FG_FGBG_IMAGE)
        {
            status = rdp_bitmap_rle_run_length(&reader, code, &run, &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.current += consumed;
            if (code == RDP_BITMAP_RLE_SET_FG_FGBG_IMAGE || code == RDP_BITMAP_RLE_MEGA_SET_FG_FGBG_IMAGE)
            {
                status = rdp_bitmap_rle_read_pixel(&reader, &reader.foreground);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
            while (run > 8u)
            {
                if (reader.current >= reader.end)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                status = rdp_bitmap_rle_write_fgbg(&reader, *reader.current++, 8);
                if (status != LIBRDP_STATUS_OK)
                    return status;
                run -= 8u;
            }
            if (run > 0)
            {
                if (reader.current >= reader.end)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                status = rdp_bitmap_rle_write_fgbg(&reader, *reader.current++, run);
            }
        }
        else if (code == RDP_BITMAP_RLE_COLOR_IMAGE || code == RDP_BITMAP_RLE_MEGA_COLOR_IMAGE)
        {
            uint32_t i = 0;

            status = rdp_bitmap_rle_run_length(&reader, code, &run, &consumed);
            if (status != LIBRDP_STATUS_OK)
                return status;
            reader.current += consumed;
            for (i = 0; i < run; i++)
            {
                uint32_t color = 0;

                status = rdp_bitmap_rle_read_pixel(&reader, &color);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_bitmap_rle_write_pixel(&reader, color);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
        }
        else if (code == RDP_BITMAP_RLE_SPECIAL_FGBG_1 || code == RDP_BITMAP_RLE_SPECIAL_FGBG_2)
        {
            uint8_t mask = code == RDP_BITMAP_RLE_SPECIAL_FGBG_1 ? 0x03u : 0x05u;

            reader.current++;
            status = rdp_bitmap_rle_write_fgbg(&reader, mask, 8);
        }
        else if (code == RDP_BITMAP_RLE_SPECIAL_WHITE || code == RDP_BITMAP_RLE_SPECIAL_BLACK)
        {
            reader.current++;
            status = rdp_bitmap_rle_write_pixel(
                &reader,
                code == RDP_BITMAP_RLE_SPECIAL_WHITE ? rdp_bitmap_rle_white(bits_per_pixel) : 0);
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return reader.position == reader.total ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_bitmap_indexed_pixel_to_bgra(uint32_t pixel,
                                                      const rdp_palette_update* palette,
                                                      uint8_t* dst)
{
    const rdp_palette_entry* entry = NULL;

    if (!palette || !dst || pixel >= palette->count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    entry = &palette->entries[pixel];
    dst[0] = entry->blue;
    dst[1] = entry->green;
    dst[2] = entry->red;
    dst[3] = 0xffu;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_raw_pixel_to_bgra(uint32_t pixel,
                                                  uint16_t bits_per_pixel,
                                                  const rdp_palette_update* palette,
                                                  uint8_t* dst)
{
    if (bits_per_pixel == 8u)
    {
        return rdp_bitmap_indexed_pixel_to_bgra(pixel, palette, dst);
    }
    if (bits_per_pixel == 15u)
    {
        dst[0] = rdp_scale_5_to_8((uint16_t)(pixel & 0x001fu));
        dst[1] = rdp_scale_5_to_8((uint16_t)((pixel >> 5) & 0x001fu));
        dst[2] = rdp_scale_5_to_8((uint16_t)((pixel >> 10) & 0x001fu));
    }
    else if (bits_per_pixel == 16u)
    {
        dst[0] = rdp_scale_5_to_8((uint16_t)(pixel & 0x001fu));
        dst[1] = rdp_scale_6_to_8((uint16_t)((pixel >> 5) & 0x003fu));
        dst[2] = rdp_scale_5_to_8((uint16_t)((pixel >> 11) & 0x001fu));
    }
    else
    {
        dst[0] = (uint8_t)(pixel & 0xffu);
        dst[1] = (uint8_t)((pixel >> 8) & 0xffu);
        dst[2] = (uint8_t)((pixel >> 16) & 0xffu);
    }
    dst[3] = 0xffu;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_compressed_payload(const rdp_bitmap_rect* rect,
                                                   const uint8_t** payload,
                                                   size_t* payload_len)
{
    uint16_t body_len = 0;

    if (!rect || !payload || !payload_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((rect->flags & RDP_BITMAP_FLAG_NO_COMPRESSION_HEADER) != 0)
    {
        *payload = rect->data;
        *payload_len = rect->data_len;
        return LIBRDP_STATUS_OK;
    }
    if (rect->data_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    body_len = (uint16_t)(rect->data[2] | ((uint16_t)rect->data[3] << 8));
    if (body_len == 0)
        body_len = (uint16_t)(rect->data_len - 8u);
    if ((size_t)body_len > rect->data_len - 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *payload = rect->data + 8u;
    *payload_len = body_len;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_bitmap_decode_compressed_bgra32(const rdp_bitmap_rect* rect,
                                                         const rdp_palette_update* palette,
                                                         rdp_buffer* output,
                                                         size_t* stride)
{
    const uint8_t* payload = NULL;
    size_t payload_len = 0;
    uint32_t* pixels = NULL;
    size_t pixel_count = 0;
    size_t dst_stride = 0;
    size_t dst_size = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rect || !output || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((rect->flags & ~(RDP_BITMAP_FLAG_COMPRESSED | RDP_BITMAP_FLAG_NO_COMPRESSION_HEADER)) != 0)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (rect->width == 0 || rect->height == 0 ||
        (rect->bits_per_pixel != 8 && rect->bits_per_pixel != 15 && rect->bits_per_pixel != 16 &&
         rect->bits_per_pixel != 24 && rect->bits_per_pixel != 32))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rect->bits_per_pixel == 8u && !palette)
        return LIBRDP_STATUS_UNSUPPORTED;
    if ((size_t)rect->width > SIZE_MAX / rect->height)
        return LIBRDP_STATUS_NO_MEMORY;
    pixel_count = (size_t)rect->width * rect->height;
    if (pixel_count > SIZE_MAX / sizeof(uint32_t))
        return LIBRDP_STATUS_NO_MEMORY;
    dst_stride = (size_t)rect->width * 4u;
    if ((size_t)rect->height > SIZE_MAX / dst_stride)
        return LIBRDP_STATUS_NO_MEMORY;
    dst_size = dst_stride * rect->height;

    status = rdp_bitmap_compressed_payload(rect, &payload, &payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    pixels = (uint32_t*)calloc(pixel_count, sizeof(uint32_t));
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_bitmap_rle_decode_stream(payload, payload_len, rect->width, rect->height, rect->bits_per_pixel, pixels);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    status = rdp_buffer_reserve(output, dst_size);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    output->length = dst_size;
    for (i = 0; i < pixel_count; i++)
    {
        status = rdp_bitmap_raw_pixel_to_bgra(pixels[i], rect->bits_per_pixel, palette, output->data + (i * 4u));
        if (status != LIBRDP_STATUS_OK)
            goto out;
    }
    *stride = dst_stride;

out:
    free(pixels);
    return status;
}

static int rdp_bitmap_stride_aligned(size_t stride, size_t alignment, size_t* aligned)
{
    size_t rem = 0;

    if (!aligned || alignment == 0)
        return 0;
    rem = stride % alignment;
    if (rem == 0)
    {
        *aligned = stride;
        return 1;
    }
    if (stride > SIZE_MAX - (alignment - rem))
        return 0;
    *aligned = stride + alignment - rem;
    return 1;
}

librdp_status rdp_bitmap_decode_rect_bgra32_with_palette(const rdp_bitmap_rect* rect,
                                                         const rdp_palette_update* palette,
                                                         rdp_buffer* output,
                                                         size_t* stride)
{
    uint16_t row = 0;
    uint16_t column = 0;
    size_t src_stride = 0;
    size_t aligned_src_stride = 0;
    size_t dst_stride = 0;
    size_t dst_size = 0;
    uint16_t bytes_per_pixel = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rect || !output || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((rect->flags & RDP_BITMAP_FLAG_COMPRESSED) != 0)
        return rdp_bitmap_decode_compressed_bgra32(rect, palette, output, stride);
    if (rect->flags != 0 ||
        (rect->bits_per_pixel != 1 && rect->bits_per_pixel != 4 &&
         rect->bits_per_pixel != 8 && rect->bits_per_pixel != 15 && rect->bits_per_pixel != 16 &&
         rect->bits_per_pixel != 24 && rect->bits_per_pixel != 32))
        return LIBRDP_STATUS_UNSUPPORTED;
    if ((rect->bits_per_pixel == 1u || rect->bits_per_pixel == 4u || rect->bits_per_pixel == 8u) &&
        !palette)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (rect->width == 0 || rect->height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rect->bits_per_pixel == 1u)
    {
        src_stride = ((size_t)rect->width + 7u) / 8u;
    }
    else if (rect->bits_per_pixel == 4u)
    {
        src_stride = ((size_t)rect->width + 1u) / 2u;
    }
    else
    {
        bytes_per_pixel = rect->bits_per_pixel == 15u ? 2u : (uint16_t)(rect->bits_per_pixel / 8u);
        if ((size_t)rect->width > SIZE_MAX / bytes_per_pixel)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        src_stride = (size_t)rect->width * bytes_per_pixel;
    }
    if (!rdp_bitmap_stride_aligned(src_stride, 4u, &aligned_src_stride))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((size_t)rect->height > SIZE_MAX / src_stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->data_len < src_stride * rect->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (aligned_src_stride > src_stride &&
        (size_t)rect->height <= SIZE_MAX / aligned_src_stride &&
        rect->data_len >= aligned_src_stride * rect->height)
        src_stride = aligned_src_stride;
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
        else if (rect->bits_per_pixel == 1)
        {
            for (column = 0; column < rect->width; column++)
            {
                uint32_t pixel = (src[column / 8u] >> (7u - (column % 8u))) & 0x01u;

                status = rdp_bitmap_indexed_pixel_to_bgra(pixel, palette, dst + ((size_t)column * 4u));
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
        }
        else if (rect->bits_per_pixel == 4)
        {
            for (column = 0; column < rect->width; column++)
            {
                uint8_t packed = src[column / 2u];
                uint32_t pixel = (column & 1u) ? (uint32_t)(packed & 0x0fu) : (uint32_t)(packed >> 4u);

                status = rdp_bitmap_indexed_pixel_to_bgra(pixel, palette, dst + ((size_t)column * 4u));
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
        }
        else if (rect->bits_per_pixel == 8)
        {
            for (column = 0; column < rect->width; column++)
            {
                status = rdp_bitmap_indexed_pixel_to_bgra(src[column], palette, dst + ((size_t)column * 4u));
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
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
        else if (rect->bits_per_pixel == 16)
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
        else
        {
            for (column = 0; column < rect->width; column++)
            {
                uint16_t pixel = (uint16_t)(src[(size_t)column * 2u] | ((uint16_t)src[(size_t)column * 2u + 1u] << 8));
                dst[(size_t)column * 4u + 0u] = rdp_scale_5_to_8((uint16_t)(pixel & 0x001fu));
                dst[(size_t)column * 4u + 1u] = rdp_scale_5_to_8((uint16_t)((pixel >> 5) & 0x001fu));
                dst[(size_t)column * 4u + 2u] = rdp_scale_5_to_8((uint16_t)((pixel >> 10) & 0x001fu));
                dst[(size_t)column * 4u + 3u] = 0xffu;
            }
        }
    }

    *stride = dst_stride;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_bitmap_decode_rect_bgra32(const rdp_bitmap_rect* rect, rdp_buffer* output, size_t* stride)
{
    return rdp_bitmap_decode_rect_bgra32_with_palette(rect, NULL, output, stride);
}

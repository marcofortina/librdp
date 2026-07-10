#include "graphics/clearcodec.h"

#include "common/stream.h"

#include <stdlib.h>
#include <string.h>

#define RDP_CLEARCODEC_VBAR_STRIDE (RDP_CLEARCODEC_MAX_BAND_HEIGHT * 4u)

typedef struct rdp_clearcodec_band
{
    uint16_t x_start;
    uint16_t x_end;
    uint16_t y_start;
    uint16_t y_end;
    uint8_t b;
    uint8_t g;
    uint8_t r;
} rdp_clearcodec_band;

void rdp_clearcodec_context_init(rdp_clearcodec_context* context)
{
    if (!context)
        return;
    memset(context, 0, sizeof(*context));
    rdp_nscodec_context_init(&context->nscodec);
}

void rdp_clearcodec_context_reset(rdp_clearcodec_context* context)
{
    size_t i = 0;

    if (!context)
        return;
    if (context->vbar_lengths)
        memset(context->vbar_lengths, 0, RDP_CLEARCODEC_VBAR_STORAGE_ENTRIES);
    if (context->short_vbar_lengths)
        memset(context->short_vbar_lengths, 0, RDP_CLEARCODEC_SHORT_VBAR_STORAGE_ENTRIES);
    context->vbar_cursor = 0;
    context->short_vbar_cursor = 0;
    rdp_nscodec_context_reset(&context->nscodec);
    for (i = 0; i < RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES; i++)
    {
        context->glyphs[i].pixel_count = 0;
        context->glyphs[i].pixels.length = 0;
    }
}

static librdp_status rdp_clearcodec_copy_glyph(const rdp_clearcodec_glyph* glyph,
                                               uint16_t width,
                                               uint16_t height,
                                               rdp_buffer* pixels,
                                               size_t* stride)
{
    size_t row_stride = 0;
    size_t size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!glyph || !pixels || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((size_t)width > ((size_t)-1) / (size_t)height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = (size_t)width * (size_t)height;
    if (size > ((size_t)-1) / 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (glyph->pixel_count < size || glyph->pixels.length < size * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    row_stride = (size_t)width * 4u;
    size *= 4u;
    status = rdp_buffer_reserve(pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memcpy(pixels->data, glyph->pixels.data, size);
    pixels->length = size;
    *stride = row_stride;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_store_glyph(rdp_clearcodec_context* context,
                                                uint16_t glyph_index,
                                                uint16_t width,
                                                uint16_t height,
                                                const rdp_buffer* pixels)
{
    rdp_clearcodec_glyph* glyph = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !pixels || glyph_index >= RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    glyph = &context->glyphs[glyph_index];
    status = rdp_buffer_reserve(&glyph->pixels, pixels->length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memcpy(glyph->pixels.data, pixels->data, pixels->length);
    glyph->pixels.length = pixels->length;
    glyph->pixel_count = (size_t)width * (size_t)height;
    return LIBRDP_STATUS_OK;
}

void rdp_clearcodec_context_free(rdp_clearcodec_context* context)
{
    size_t i = 0;

    if (!context)
        return;
    free(context->vbar_storage);
    free(context->short_vbar_storage);
    free(context->vbar_lengths);
    free(context->short_vbar_lengths);
    rdp_nscodec_context_free(&context->nscodec);
    for (i = 0; i < RDP_CLEARCODEC_GLYPH_STORAGE_ENTRIES; i++)
        rdp_buffer_free(&context->glyphs[i].pixels);
    memset(context, 0, sizeof(*context));
}

static librdp_status rdp_clearcodec_context_ensure_bands(rdp_clearcodec_context* context)
{
    if (!context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!context->vbar_storage)
    {
        context->vbar_storage = (uint8_t*)calloc(RDP_CLEARCODEC_VBAR_STORAGE_ENTRIES, RDP_CLEARCODEC_VBAR_STRIDE);
        if (!context->vbar_storage)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    if (!context->short_vbar_storage)
    {
        context->short_vbar_storage =
            (uint8_t*)calloc(RDP_CLEARCODEC_SHORT_VBAR_STORAGE_ENTRIES, RDP_CLEARCODEC_VBAR_STRIDE);
        if (!context->short_vbar_storage)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    if (!context->vbar_lengths)
    {
        context->vbar_lengths = (uint8_t*)calloc(RDP_CLEARCODEC_VBAR_STORAGE_ENTRIES, 1);
        if (!context->vbar_lengths)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    if (!context->short_vbar_lengths)
    {
        context->short_vbar_lengths = (uint8_t*)calloc(RDP_CLEARCODEC_SHORT_VBAR_STORAGE_ENTRIES, 1);
        if (!context->short_vbar_lengths)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_read_run_length(rdp_stream* stream, uint32_t* run_length)
{
    uint8_t factor1 = 0;

    if (!stream || !run_length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &factor1) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (factor1 < 0xffu)
    {
        *run_length = factor1;
        return LIBRDP_STATUS_OK;
    }
    {
        uint16_t factor2 = 0;

        if (rdp_stream_read_u16_le(stream, &factor2) != LIBRDP_STATUS_OK || factor2 == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (factor2 < 0xffffu)
        {
            *run_length = factor2;
            return LIBRDP_STATUS_OK;
        }
    }
    if (rdp_stream_read_u32_le(stream, run_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static uint8_t rdp_clearcodec_low_mask(uint8_t bits)
{
    if (bits == 0)
        return 0;
    if (bits >= 8)
        return 0xffu;
    return (uint8_t)((1u << bits) - 1u);
}

static uint8_t rdp_clearcodec_log2_floor_u8(uint8_t value)
{
    uint8_t shift = 0;

    while (value > 1u)
    {
        value = (uint8_t)(value >> 1u);
        shift++;
    }
    return shift;
}

static uint8_t* rdp_clearcodec_vbar_slot(rdp_clearcodec_context* context, uint16_t index)
{
    return context->vbar_storage + ((size_t)index * RDP_CLEARCODEC_VBAR_STRIDE);
}

static uint8_t* rdp_clearcodec_short_vbar_slot(rdp_clearcodec_context* context, uint16_t index)
{
    return context->short_vbar_storage + ((size_t)index * RDP_CLEARCODEC_VBAR_STRIDE);
}

static void rdp_clearcodec_advance_vbar_cursor(rdp_clearcodec_context* context)
{
    context->vbar_cursor++;
    if (context->vbar_cursor == RDP_CLEARCODEC_VBAR_STORAGE_ENTRIES)
        context->vbar_cursor = 0;
}

static void rdp_clearcodec_advance_short_vbar_cursor(rdp_clearcodec_context* context)
{
    context->short_vbar_cursor++;
    if (context->short_vbar_cursor == RDP_CLEARCODEC_SHORT_VBAR_STORAGE_ENTRIES)
        context->short_vbar_cursor = 0;
}

static void rdp_clearcodec_fill_vbar(uint8_t* vbar,
                                     uint8_t b,
                                     uint8_t g,
                                     uint8_t r,
                                     uint8_t y_on,
                                     const uint8_t* short_pixels,
                                     uint8_t short_count,
                                     uint8_t height)
{
    uint8_t y = 0;

    if (y_on > height)
        y_on = height;
    if (short_count > height - y_on)
        short_count = (uint8_t)(height - y_on);
    for (y = 0; y < height; y++)
    {
        uint8_t* pixel = vbar + ((size_t)y * 4u);

        pixel[0] = b;
        pixel[1] = g;
        pixel[2] = r;
        pixel[3] = 0xffu;
    }
    for (y = 0; y < short_count; y++)
    {
        uint8_t* pixel = vbar + ((size_t)(y_on + y) * 4u);
        const uint8_t* source = short_pixels + ((size_t)y * 4u);

        pixel[0] = source[0];
        pixel[1] = source[1];
        pixel[2] = source[2];
        pixel[3] = 0xffu;
    }
}

static void rdp_clearcodec_normalize_vbar(uint8_t* vbar, uint8_t* length, uint8_t height)
{
    uint8_t old_length = 0;

    if (!vbar || !length)
        return;
    old_length = *length;
    if (old_length < height)
        memset(vbar + ((size_t)old_length * 4u), 0, (size_t)(height - old_length) * 4u);
    *length = height;
}

static void rdp_clearcodec_copy_vbar_to_pixels(const uint8_t* vbar,
                                               uint16_t x,
                                               uint16_t y_start,
                                               uint8_t height,
                                               uint8_t* pixels,
                                               size_t stride)
{
    uint8_t y = 0;

    for (y = 0; y < height; y++)
    {
        memcpy(pixels + ((size_t)(y_start + y) * stride) + ((size_t)x * 4u),
               vbar + ((size_t)y * 4u),
               4);
    }
}

static void rdp_clearcodec_store_short_vbar(rdp_clearcodec_context* context,
                                            const uint8_t* pixels,
                                            uint8_t count)
{
    uint8_t* slot = rdp_clearcodec_short_vbar_slot(context, context->short_vbar_cursor);
    uint8_t i = 0;

    for (i = 0; i < count; i++)
    {
        slot[((size_t)i * 4u) + 0u] = pixels[((size_t)i * 3u) + 0u];
        slot[((size_t)i * 4u) + 1u] = pixels[((size_t)i * 3u) + 1u];
        slot[((size_t)i * 4u) + 2u] = pixels[((size_t)i * 3u) + 2u];
        slot[((size_t)i * 4u) + 3u] = 0xffu;
    }
    context->short_vbar_lengths[context->short_vbar_cursor] = count;
    rdp_clearcodec_advance_short_vbar_cursor(context);
}

static void rdp_clearcodec_store_vbar(rdp_clearcodec_context* context, const uint8_t* vbar, uint8_t height)
{
    memcpy(rdp_clearcodec_vbar_slot(context, context->vbar_cursor), vbar, (size_t)height * 4u);
    context->vbar_lengths[context->vbar_cursor] = height;
    rdp_clearcodec_advance_vbar_cursor(context);
}

static librdp_status rdp_clearcodec_read_band(rdp_stream* stream, rdp_clearcodec_band* band)
{
    if (!stream || !band)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u16_le(stream, &band->x_start) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &band->x_end) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &band->y_start) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &band->y_end) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &band->b) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &band->g) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(stream, &band->r) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (band->x_end < band->x_start || band->y_end < band->y_start)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((uint32_t)band->y_end - band->y_start + 1u > RDP_CLEARCODEC_MAX_BAND_HEIGHT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_decode_band_vbar(rdp_clearcodec_context* context,
                                                     rdp_stream* stream,
                                                     const rdp_clearcodec_band* band,
                                                     uint16_t x,
                                                     uint8_t band_height,
                                                     uint8_t* pixels,
                                                     size_t stride)
{
    uint16_t header = 0;
    uint8_t vbar[RDP_CLEARCODEC_VBAR_STRIDE];

    if (rdp_stream_read_u16_le(stream, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((header & 0x8000u) != 0)
    {
        uint16_t index = (uint16_t)(header & 0x7fffu);

        if (context->vbar_lengths[index] != band_height)
            rdp_clearcodec_normalize_vbar(rdp_clearcodec_vbar_slot(context, index),
                                          &context->vbar_lengths[index],
                                          band_height);
        rdp_clearcodec_copy_vbar_to_pixels(rdp_clearcodec_vbar_slot(context, index),
                                           x,
                                           band->y_start,
                                           band_height,
                                           pixels,
                                           stride);
        return LIBRDP_STATUS_OK;
    }
    if ((header & 0xc000u) == 0x4000u)
    {
        uint16_t index = (uint16_t)(header & 0x3fffu);
        uint8_t y_on = 0;
        uint8_t short_count = 0;

        if (rdp_stream_read_u8(stream, &y_on) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        short_count = context->short_vbar_lengths[index];
        if (y_on > band_height)
            y_on = band_height;
        if (short_count > band_height - y_on)
            short_count = (uint8_t)(band_height - y_on);
        rdp_clearcodec_fill_vbar(vbar,
                                 band->b,
                                 band->g,
                                 band->r,
                                 y_on,
                                 rdp_clearcodec_short_vbar_slot(context, index),
                                 short_count,
                                 band_height);
        rdp_clearcodec_store_vbar(context, vbar, band_height);
        rdp_clearcodec_copy_vbar_to_pixels(vbar, x, band->y_start, band_height, pixels, stride);
        return LIBRDP_STATUS_OK;
    }
    if ((header & 0xc000u) == 0)
    {
        uint8_t y_on = (uint8_t)(header & 0xffu);
        uint8_t y_off = (uint8_t)((header >> 8) & 0x3fu);
        uint8_t short_count = 0;
        const uint8_t* short_pixels = NULL;
        uint8_t converted[RDP_CLEARCODEC_VBAR_STRIDE];
        uint8_t i = 0;

        if (y_off < y_on || y_off > band_height)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        short_count = (uint8_t)(y_off - y_on);
        if (rdp_stream_read_bytes(stream, &short_pixels, (size_t)short_count * 3u) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_clearcodec_store_short_vbar(context, short_pixels, short_count);
        for (i = 0; i < short_count; i++)
        {
            converted[((size_t)i * 4u) + 0u] = short_pixels[((size_t)i * 3u) + 0u];
            converted[((size_t)i * 4u) + 1u] = short_pixels[((size_t)i * 3u) + 1u];
            converted[((size_t)i * 4u) + 2u] = short_pixels[((size_t)i * 3u) + 2u];
            converted[((size_t)i * 4u) + 3u] = 0xffu;
        }
        rdp_clearcodec_fill_vbar(vbar, band->b, band->g, band->r, y_on, converted, short_count, band_height);
        rdp_clearcodec_store_vbar(context, vbar, band_height);
        rdp_clearcodec_copy_vbar_to_pixels(vbar, x, band->y_start, band_height, pixels, stride);
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_clearcodec_decode_bands(rdp_clearcodec_context* context,
                                                 const uint8_t* data,
                                                 size_t length,
                                                 uint16_t width,
                                                 uint16_t height,
                                                 uint8_t* pixels,
                                                 size_t stride)
{
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || (!data && length > 0) || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_clearcodec_context_ensure_bands(context);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) > 0)
    {
        rdp_clearcodec_band band;
        uint8_t band_height = 0;
        uint16_t x = 0;

        status = rdp_clearcodec_read_band(&stream, &band);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (band.x_end >= width || band.y_end >= height)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        band_height = (uint8_t)(band.y_end - band.y_start + 1u);
        for (x = band.x_start; x <= band.x_end; x++)
        {
            status = rdp_clearcodec_decode_band_vbar(context, &stream, &band, x, band_height, pixels, stride);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_decode_residual(const uint8_t* data,
                                                    size_t length,
                                                    uint16_t width,
                                                    uint16_t height,
                                                    uint8_t* pixels,
                                                    size_t stride)
{
    rdp_stream stream;
    uint32_t pixel_count = (uint32_t)width * (uint32_t)height;
    uint32_t offset = 0;

    if ((!data && length > 0) || !pixels || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    while (rdp_stream_remaining(&stream) > 0)
    {
        uint8_t b = 0;
        uint8_t g = 0;
        uint8_t r = 0;
        uint32_t run = 0;
        uint32_t i = 0;

        if (rdp_stream_read_u8(&stream, &b) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &g) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &r) != LIBRDP_STATUS_OK ||
            rdp_clearcodec_read_run_length(&stream, &run) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (run > pixel_count - offset)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (i = 0; i < run; i++)
        {
            uint32_t position = offset + i;
            uint8_t* pixel = pixels + ((size_t)(position / width) * stride) + ((size_t)(position % width) * 4u);

            pixel[0] = b;
            pixel[1] = g;
            pixel[2] = r;
            pixel[3] = 0xffu;
        }
        offset += run;
    }
    if (offset != pixel_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_write_rlex_pixel(uint8_t* pixels,
                                                     size_t stride,
                                                     uint16_t dest_x,
                                                     uint16_t dest_y,
                                                     uint16_t width,
                                                     uint32_t pixel_index,
                                                     const uint8_t* color)
{
    uint16_t x = 0;
    uint16_t y = 0;
    uint8_t* pixel = NULL;

    if (!pixels || !color || width == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    x = (uint16_t)(pixel_index % width);
    y = (uint16_t)(pixel_index / width);
    pixel = pixels + ((size_t)(dest_y + y) * stride) + ((size_t)(dest_x + x) * 4u);
    pixel[0] = color[0];
    pixel[1] = color[1];
    pixel[2] = color[2];
    pixel[3] = 0xffu;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_decode_rlex_subcodec(const rdp_clearcodec_subcodec* subcodec,
                                                         uint16_t width,
                                                         uint16_t height,
                                                         uint8_t* pixels,
                                                         size_t stride)
{
    const uint8_t* data = NULL;
    uint8_t palette[128u][4u];
    uint8_t palette_count = 0;
    uint8_t index_bits = 0;
    uint8_t index_mask = 0;
    uint8_t suite_mask = 0;
    uint32_t pixel_count = 0;
    uint32_t pixel_index = 0;
    size_t offset = 0;

    if (!subcodec || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (subcodec->width == 0 || subcodec->height == 0 ||
        subcodec->x > width || subcodec->y > height ||
        subcodec->width > width - subcodec->x || subcodec->height > height - subcodec->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!subcodec->bitmap_data || subcodec->bitmap_data_len < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    data = subcodec->bitmap_data;
    palette_count = data[offset++];
    if (palette_count == 0 || palette_count > 127u ||
        subcodec->bitmap_data_len < 1u + ((uint32_t)palette_count * 3u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(palette, 0, sizeof(palette));
    for (uint8_t i = 0; i < palette_count; i++)
    {
        palette[i][0] = data[offset++];
        palette[i][1] = data[offset++];
        palette[i][2] = data[offset++];
        palette[i][3] = 0xffu;
    }

    index_bits = (uint8_t)(rdp_clearcodec_log2_floor_u8((uint8_t)(palette_count - 1u)) + 1u);
    index_mask = rdp_clearcodec_low_mask(index_bits);
    suite_mask = rdp_clearcodec_low_mask((uint8_t)(8u - index_bits));
    pixel_count = (uint32_t)subcodec->width * (uint32_t)subcodec->height;
    while (offset < subcodec->bitmap_data_len)
    {
        uint8_t token = 0;
        uint8_t run_factor1 = 0;
        uint8_t stop_index = 0;
        uint8_t suite_depth = 0;
        uint8_t start_index = 0;
        uint32_t run_length = 0;

        if (subcodec->bitmap_data_len - offset < 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        token = data[offset++];
        run_factor1 = data[offset++];
        if (run_factor1 < 0xffu)
        {
            run_length = run_factor1;
        }
        else
        {
            if (subcodec->bitmap_data_len - offset < 2u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            run_length = (uint32_t)data[offset] | ((uint32_t)data[offset + 1u] << 8u);
            offset += 2u;
            if (run_length >= 0xffffu)
            {
                if (subcodec->bitmap_data_len - offset < 4u)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                run_length = (uint32_t)data[offset] |
                             ((uint32_t)data[offset + 1u] << 8u) |
                             ((uint32_t)data[offset + 2u] << 16u) |
                             ((uint32_t)data[offset + 3u] << 24u);
                offset += 4u;
            }
        }
        suite_depth = (uint8_t)((token >> index_bits) & suite_mask);
        stop_index = (uint8_t)(token & index_mask);
        if (suite_depth > stop_index)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        start_index = (uint8_t)(stop_index - suite_depth);
        if (start_index >= palette_count || stop_index >= palette_count)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (run_length > pixel_count - pixel_index)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < run_length; i++)
        {
            librdp_status status = rdp_clearcodec_write_rlex_pixel(pixels,
                                                                   stride,
                                                                   subcodec->x,
                                                                   subcodec->y,
                                                                   subcodec->width,
                                                                   pixel_index++,
                                                                   palette[start_index]);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        if ((uint32_t)suite_depth + 1u > pixel_count - pixel_index)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (uint8_t i = 0; i <= suite_depth; i++)
        {
            uint8_t palette_index = (uint8_t)(start_index + i);
            librdp_status status = LIBRDP_STATUS_OK;

            if (palette_index >= palette_count)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_clearcodec_write_rlex_pixel(pixels,
                                                     stride,
                                                     subcodec->x,
                                                     subcodec->y,
                                                     subcodec->width,
                                                     pixel_index++,
                                                     palette[palette_index]);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    return pixel_index == pixel_count ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_clearcodec_decode_nsc_subcodec(rdp_clearcodec_context* context,
                                                        const rdp_clearcodec_subcodec* subcodec,
                                                        uint16_t width,
                                                        uint16_t height,
                                                        uint8_t* pixels,
                                                        size_t stride)
{
    if (!context || !subcodec || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (subcodec->width == 0 || subcodec->height == 0 ||
        subcodec->x > width || subcodec->y > height ||
        subcodec->width > width - subcodec->x || subcodec->height > height - subcodec->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_nscodec_decode_region_bgra32(&context->nscodec,
                                            subcodec->bitmap_data,
                                            subcodec->bitmap_data_len,
                                            subcodec->width,
                                            subcodec->height,
                                            pixels,
                                            stride,
                                            subcodec->x,
                                            subcodec->y,
                                            width,
                                            height);
}

static librdp_status rdp_clearcodec_apply_raw_subcodec(const rdp_clearcodec_subcodec* subcodec,
                                                       uint16_t width,
                                                       uint16_t height,
                                                       uint8_t* pixels,
                                                       size_t stride)
{
    uint16_t row = 0;

    if (!subcodec || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (subcodec->width == 0 || subcodec->height == 0 ||
        subcodec->x > width || subcodec->y > height ||
        subcodec->width > width - subcodec->x || subcodec->height > height - subcodec->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (subcodec->bitmap_data_len != (uint32_t)subcodec->width * (uint32_t)subcodec->height * 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (row = 0; row < subcodec->height; row++)
    {
        uint16_t column = 0;
        const uint8_t* source = subcodec->bitmap_data + ((size_t)row * (size_t)subcodec->width * 3u);
        uint8_t* dest = pixels + ((size_t)(subcodec->y + row) * stride) + ((size_t)subcodec->x * 4u);

        for (column = 0; column < subcodec->width; column++)
        {
            dest[0] = source[0];
            dest[1] = source[1];
            dest[2] = source[2];
            dest[3] = 0xffu;
            source += 3;
            dest += 4;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_clearcodec_decode_subcodecs(rdp_clearcodec_context* context,
                                                     const uint8_t* data,
                                                     size_t length,
                                                     uint16_t width,
                                                     uint16_t height,
                                                     uint8_t* pixels,
                                                     size_t stride)
{
    size_t offset = 0;

    if (!context || (!data && length > 0) || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (offset < length)
    {
        rdp_clearcodec_subcodec subcodec;
        librdp_status status = rdp_clearcodec_parse_subcodec(data + offset, length - offset, &subcodec);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RAW)
            status = rdp_clearcodec_apply_raw_subcodec(&subcodec, width, height, pixels, stride);
        else if (subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_NSCODEC)
            status = rdp_clearcodec_decode_nsc_subcodec(context, &subcodec, width, height, pixels, stride);
        else if (subcodec.subcodec_id == RDP_CLEARCODEC_SUBCODEC_RLEX)
            status = rdp_clearcodec_decode_rlex_subcodec(&subcodec, width, height, pixels, stride);
        else
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status != LIBRDP_STATUS_OK)
            return status;
        offset += subcodec.total_len;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clearcodec_parse_stream(const void* data, size_t length, rdp_clearcodec_stream* stream)
{
    rdp_stream input;

    if (!data || !stream || length < 2u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(stream, 0, sizeof(*stream));
    rdp_stream_init(&input, data, length);
    if (rdp_stream_read_u8(&input, &stream->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&input, &stream->seq_number) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((stream->flags & ~(RDP_CLEARCODEC_FLAG_GLYPH_INDEX |
                           RDP_CLEARCODEC_FLAG_GLYPH_HIT |
                           RDP_CLEARCODEC_FLAG_CACHE_RESET)) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((stream->flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0 &&
        (stream->flags & RDP_CLEARCODEC_FLAG_GLYPH_INDEX) == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((stream->flags & RDP_CLEARCODEC_FLAG_GLYPH_INDEX) != 0)
    {
        stream->has_glyph_index = 1;
        if (rdp_stream_read_u16_le(&input, &stream->glyph_index) != LIBRDP_STATUS_OK ||
            stream->glyph_index > 3999u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    stream->payload_len = rdp_stream_remaining(&input);
    if ((stream->flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0 && stream->payload_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (stream->payload_len > 0 &&
        rdp_stream_read_bytes(&input, &stream->payload, stream->payload_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clearcodec_parse_composite_payload(const void* data,
                                                     size_t length,
                                                     rdp_clearcodec_composite_payload* payload)
{
    rdp_stream stream;
    uint64_t total = 0;

    if (!data || !payload || length < 12u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(payload, 0, sizeof(*payload));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &payload->residual_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &payload->bands_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &payload->subcodec_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = 12ull + payload->residual_len + payload->bands_len + payload->subcodec_len;
    if (total != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (payload->residual_len > 0 &&
        rdp_stream_read_bytes(&stream, &payload->residual, payload->residual_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (payload->bands_len > 0 &&
        rdp_stream_read_bytes(&stream, &payload->bands, payload->bands_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (payload->subcodec_len > 0 &&
        rdp_stream_read_bytes(&stream, &payload->subcodec, payload->subcodec_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clearcodec_parse_subcodec(const void* data,
                                            size_t length,
                                            rdp_clearcodec_subcodec* subcodec)
{
    rdp_stream stream;

    if (!data || !subcodec || length < 13u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(subcodec, 0, sizeof(*subcodec));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &subcodec->x) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &subcodec->y) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &subcodec->width) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &subcodec->height) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &subcodec->bitmap_data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &subcodec->subcodec_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (subcodec->width == 0 || subcodec->height == 0 ||
        rdp_stream_remaining(&stream) < subcodec->bitmap_data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &subcodec->bitmap_data, subcodec->bitmap_data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    subcodec->total_len = 13u + subcodec->bitmap_data_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clearcodec_decode_bitmap(rdp_clearcodec_context* context,
                                           const void* data,
                                           size_t length,
                                           uint16_t width,
                                           uint16_t height,
                                           rdp_buffer* pixels,
                                           size_t* stride)
{
    rdp_clearcodec_stream stream;
    rdp_clearcodec_composite_payload payload;
    size_t row_stride = 0;
    size_t size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !data || !pixels || !stride || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_clearcodec_parse_stream(data, length, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((stream.flags & RDP_CLEARCODEC_FLAG_CACHE_RESET) != 0)
        rdp_clearcodec_context_reset(context);
    if ((stream.flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0)
        return rdp_clearcodec_copy_glyph(&context->glyphs[stream.glyph_index], width, height, pixels, stride);
    if (stream.payload_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_clearcodec_parse_composite_payload(stream.payload, stream.payload_len, &payload);
    if (status != LIBRDP_STATUS_OK)
        return status;

    row_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / row_stride)
        return LIBRDP_STATUS_NO_MEMORY;
    size = row_stride * (size_t)height;
    status = rdp_buffer_reserve(pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(pixels->data, 0, size);
    pixels->length = size;

    if (payload.residual_len > 0)
    {
        status = rdp_clearcodec_decode_residual(payload.residual,
                                                payload.residual_len,
                                                width,
                                                height,
                                                pixels->data,
                                                row_stride);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (payload.bands_len > 0)
    {
        status = rdp_clearcodec_decode_bands(context,
                                             payload.bands,
                                             payload.bands_len,
                                             width,
                                             height,
                                             pixels->data,
                                             row_stride);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (payload.subcodec_len > 0)
    {
        status = rdp_clearcodec_decode_subcodecs(context,
                                                 payload.subcodec,
                                                 payload.subcodec_len,
                                                 width,
                                                 height,
                                                 pixels->data,
                                                 row_stride);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (stream.has_glyph_index)
    {
        status = rdp_clearcodec_store_glyph(context, stream.glyph_index, width, height, pixels);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    *stride = row_stride;
    return LIBRDP_STATUS_OK;
}

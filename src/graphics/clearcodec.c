#include "graphics/clearcodec.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_clearcodec_read_run_length(rdp_stream* stream, uint32_t* run_length)
{
    uint8_t factor1 = 0;

    if (!stream || !run_length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &factor1) != LIBRDP_STATUS_OK || factor1 == 0)
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
    if (rdp_stream_read_u32_le(stream, run_length) != LIBRDP_STATUS_OK || *run_length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
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
    return LIBRDP_STATUS_OK;
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

static librdp_status rdp_clearcodec_decode_subcodecs(const uint8_t* data,
                                                     size_t length,
                                                     uint16_t width,
                                                     uint16_t height,
                                                     uint8_t* pixels,
                                                     size_t stride)
{
    size_t offset = 0;

    if ((!data && length > 0) || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (offset < length)
    {
        rdp_clearcodec_subcodec subcodec;
        librdp_status status = rdp_clearcodec_parse_subcodec(data + offset, length - offset, &subcodec);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (subcodec.subcodec_id != RDP_CLEARCODEC_SUBCODEC_RAW)
            return LIBRDP_STATUS_UNSUPPORTED;
        status = rdp_clearcodec_apply_raw_subcodec(&subcodec, width, height, pixels, stride);
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
        subcodec->bitmap_data_len > (uint32_t)subcodec->width * (uint32_t)subcodec->height * 3u ||
        rdp_stream_remaining(&stream) < subcodec->bitmap_data_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &subcodec->bitmap_data, subcodec->bitmap_data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    subcodec->total_len = 13u + subcodec->bitmap_data_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_clearcodec_decode_bitmap(const void* data,
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

    if (!data || !pixels || !stride || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_clearcodec_parse_stream(data, length, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((stream.flags & RDP_CLEARCODEC_FLAG_GLYPH_HIT) != 0 || stream.payload_len == 0)
        return LIBRDP_STATUS_UNSUPPORTED;
    status = rdp_clearcodec_parse_composite_payload(stream.payload, stream.payload_len, &payload);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (payload.bands_len != 0)
        return LIBRDP_STATUS_UNSUPPORTED;

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
    if (payload.subcodec_len > 0)
    {
        status = rdp_clearcodec_decode_subcodecs(payload.subcodec,
                                                 payload.subcodec_len,
                                                 width,
                                                 height,
                                                 pixels->data,
                                                 row_stride);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    *stride = row_stride;
    return LIBRDP_STATUS_OK;
}

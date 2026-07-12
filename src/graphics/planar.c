/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: planar bitmap decoding support.
 * Invariants: rectangles, strides, cache keys, and pixel formats are validated
 * before any surface mutation.
 * Ownership: decoded pixels and cache entries are owned by the caller or
 * session surface selected by the API.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: codec payloads, rectangles, and cache references are
 * untrusted server data.
 */


#include "graphics/planar.h"

#include <stdint.h>

static uint8_t rdp_planar_clip_i32(int32_t value)
{
    if (value < 0)
        return 0;
    if (value > 255)
        return 255;
    return (uint8_t)value;
}

static int16_t rdp_planar_decode_chroma(uint8_t value, uint8_t cll)
{
    uint8_t shifted = (uint8_t)(value << (cll - 1u));
    return (int16_t)(int8_t)shifted;
}

static int16_t rdp_planar_decode_rle_delta(uint8_t value)
{
    if ((value & 1u) != 0)
        return (int16_t)-(int16_t)((value >> 1u) + 1u);
    return (int16_t)(value >> 1u);
}

static librdp_status rdp_planar_decode_rle_plane(const uint8_t* data,
                                                 size_t length,
                                                 size_t width,
                                                 size_t height,
                                                 uint8_t* output,
                                                 size_t* consumed)
{
    const uint8_t* previous = NULL;
    size_t position = 0;
    size_t y = 0;

    if (!data || !output || !consumed || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (y = 0; y < height; y++)
    {
        uint8_t* current = output + (y * width);
        int16_t value = 0;
        size_t x = 0;

        while (x < width)
        {
            uint8_t control = 0;
            size_t run_count = 0;
            size_t raw_count = 0;

            if (position >= length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            control = data[position++];
            if (control == 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            run_count = (size_t)(control & 0x0fu);
            raw_count = (size_t)(control >> 4u);
            if (run_count == 1u)
            {
                run_count = raw_count + 16u;
                raw_count = 0;
            }
            else if (run_count == 2u)
            {
                run_count = raw_count + 32u;
                raw_count = 0;
            }
            if (raw_count + run_count > width - x || raw_count > length - position)
                return LIBRDP_STATUS_PROTOCOL_ERROR;

            while (raw_count > 0)
            {
                if (previous)
                {
                    value = rdp_planar_decode_rle_delta(data[position++]);
                    current[x] = rdp_planar_clip_i32((int32_t)previous[x] + value);
                }
                else
                {
                    value = (int16_t)data[position++];
                    current[x] = rdp_planar_clip_i32(value);
                }
                raw_count--;
                x++;
            }
            while (run_count > 0)
            {
                if (previous)
                    current[x] = rdp_planar_clip_i32((int32_t)previous[x] + value);
                else
                    current[x] = rdp_planar_clip_i32(value);
                run_count--;
                x++;
            }
        }
        previous = current;
    }

    *consumed = position;
    return LIBRDP_STATUS_OK;
}

/*
 * Planar decoding converts optional RLE planes, chroma subsampling, color-loss
 * deltas, and alpha into one BGRA buffer. Keep plane sizing and expansion
 * checks centralized here because malformed dimensions can otherwise turn into
 * mismatched chroma indexes later in the conversion loop.
 */
librdp_status rdp_planar_decode_argb(const void* data,
                                     size_t length,
                                     uint32_t width,
                                     uint32_t height,
                                     rdp_buffer* pixels,
                                     size_t* stride)
{
    const uint8_t* bytes = (const uint8_t*)data;
    const uint8_t* alpha = NULL;
    const uint8_t* plane0 = NULL;
    const uint8_t* plane1 = NULL;
    const uint8_t* plane2 = NULL;
    uint8_t header = 0;
    uint8_t cll = 0;
    int chroma_subsampled = 0;
    int rle = 0;
    int has_alpha = 0;
    size_t pixel_count = 0;
    size_t chroma_width = 0;
    size_t chroma_height = 0;
    size_t chroma_count = 0;
    size_t payload_size = 0;
    size_t expected = 0;
    size_t output_stride = 0;
    size_t output_size = 0;
    size_t i = 0;
    rdp_buffer decoded_planes;
    rdp_buffer output;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !pixels || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&decoded_planes);
    rdp_buffer_init(&output);
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length < 1u || width > SIZE_MAX / height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    header = bytes[0];
    if ((header & RDP_PLANAR_FORMAT_RESERVED_MASK) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    cll = (uint8_t)(header & RDP_PLANAR_FORMAT_CLL_MASK);
    if ((header & RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING) != 0 && cll == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rle = (header & RDP_PLANAR_FORMAT_RLE) != 0;

    pixel_count = (size_t)width * (size_t)height;
    chroma_subsampled = (header & RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING) != 0;
    chroma_width = chroma_subsampled ? (((size_t)width + 1u) / 2u) : (size_t)width;
    chroma_height = chroma_subsampled ? (((size_t)height + 1u) / 2u) : (size_t)height;
    if (chroma_width == 0 || chroma_height == 0 || chroma_width > SIZE_MAX / chroma_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    chroma_count = chroma_width * chroma_height;
    has_alpha = (header & RDP_PLANAR_FORMAT_NO_ALPHA) == 0;
    if (cll == 0)
    {
        if (pixel_count > (SIZE_MAX - 1u) / (has_alpha ? 4u : 3u))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        payload_size = pixel_count * (has_alpha ? 4u : 3u);
    }
    else
    {
        if (chroma_count > (SIZE_MAX - pixel_count) / 2u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        payload_size = pixel_count + (chroma_count * 2u);
        if (has_alpha)
        {
            if (payload_size > SIZE_MAX - pixel_count)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            payload_size += pixel_count;
        }
    }
    if (payload_size > SIZE_MAX - 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rle)
    {
        expected = 1u + payload_size;
        if (length != expected && length != expected + 1u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
#if SIZE_MAX < UINT64_MAX
    if ((size_t)width > SIZE_MAX / 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#endif
    output_stride = (size_t)width * 4u;
    if (height > SIZE_MAX / output_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_size = (size_t)height * output_stride;

    status = rdp_buffer_reserve(&output, output_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    output.length = output_size;

    if (rle)
    {
        uint8_t* write = NULL;
        size_t position = 1u;
        size_t consumed = 0;

        status = rdp_buffer_reserve(&decoded_planes, payload_size);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&output);
            return status;
        }
        decoded_planes.length = payload_size;
        write = decoded_planes.data;
        if (has_alpha)
        {
            status = rdp_planar_decode_rle_plane(bytes + position,
                                                 length - position,
                                                 (size_t)width,
                                                 (size_t)height,
                                                 write,
                                                 &consumed);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&output);
                rdp_buffer_free(&decoded_planes);
                return status;
            }
            alpha = write;
            write += pixel_count;
            position += consumed;
        }
        status = rdp_planar_decode_rle_plane(bytes + position,
                                             length - position,
                                             (size_t)width,
                                             (size_t)height,
                                             write,
                                             &consumed);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&output);
            rdp_buffer_free(&decoded_planes);
            return status;
        }
        plane0 = write;
        write += pixel_count;
        position += consumed;
        status = rdp_planar_decode_rle_plane(bytes + position,
                                             length - position,
                                             chroma_width,
                                             chroma_height,
                                             write,
                                             &consumed);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&output);
            rdp_buffer_free(&decoded_planes);
            return status;
        }
        plane1 = write;
        write += chroma_count;
        position += consumed;
        status = rdp_planar_decode_rle_plane(bytes + position,
                                             length - position,
                                             chroma_width,
                                             chroma_height,
                                             write,
                                             &consumed);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&output);
            rdp_buffer_free(&decoded_planes);
            return status;
        }
        plane2 = write;
        position += consumed;
        if (position != length)
        {
            rdp_buffer_free(&output);
            rdp_buffer_free(&decoded_planes);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    else
    {
        alpha = has_alpha ? bytes + 1u : NULL;
        plane0 = bytes + 1u + (has_alpha ? pixel_count : 0u);
        plane1 = plane0 + pixel_count;
        plane2 = plane1 + (cll == 0 ? pixel_count : chroma_count);
    }

    for (i = 0; i < pixel_count; i++)
    {
        uint8_t* dest = output.data + (i * 4u);

        if (cll == 0)
        {
            dest[0] = plane2[i];
            dest[1] = plane1[i];
            dest[2] = plane0[i];
        }
        else
        {
            size_t x = i % (size_t)width;
            size_t y = i / (size_t)width;
            size_t chroma_index = chroma_subsampled ? ((y / 2u) * chroma_width) + (x / 2u) : i;
            int16_t co = rdp_planar_decode_chroma(plane1[chroma_index], cll);
            int16_t cg = rdp_planar_decode_chroma(plane2[chroma_index], cll);
            int16_t yy = (int16_t)plane0[i];
            int16_t t = (int16_t)(yy - cg);

            dest[0] = rdp_planar_clip_i32((int32_t)t + co);
            dest[1] = rdp_planar_clip_i32((int32_t)yy + cg);
            dest[2] = rdp_planar_clip_i32((int32_t)t - co);
        }
        dest[3] = has_alpha ? alpha[i] : 0xffu;
    }
    rdp_buffer_free(&decoded_planes);
    rdp_buffer_free(pixels);
    *pixels = output;
    *stride = output_stride;
    return LIBRDP_STATUS_OK;
}

#include "graphics/nscodec.h"

#include "common/stream.h"

#include <stdlib.h>
#include <string.h>

static int rdp_nscodec_round_up(size_t value, size_t alignment, size_t* rounded)
{
    size_t remainder = 0;

    if (!rounded)
        return 0;
    if (alignment == 0)
    {
        *rounded = value;
        return 1;
    }
    remainder = value % alignment;
    if (remainder == 0)
    {
        *rounded = value;
        return 1;
    }
    if (value > ((size_t)-1) - (alignment - remainder))
        return 0;
    *rounded = value + alignment - remainder;
    return 1;
}

static uint8_t rdp_nscodec_clamp_i32(int32_t value)
{
    if (value < 0)
        return 0;
    if (value > 255)
        return 255;
    return (uint8_t)value;
}

static int32_t rdp_nscodec_recover_chroma(uint8_t value, uint8_t color_loss_level)
{
    uint8_t shifted = (uint8_t)(value << (color_loss_level - 1u));
    return (int32_t)(int8_t)shifted;
}

void rdp_nscodec_context_init(rdp_nscodec_context* context)
{
    if (!context)
        return;
    memset(context, 0, sizeof(*context));
}

void rdp_nscodec_context_reset(rdp_nscodec_context* context)
{
    (void)context;
}

void rdp_nscodec_context_free(rdp_nscodec_context* context)
{
    size_t i = 0;

    if (!context)
        return;
    for (i = 0; i < 4u; i++)
        free(context->planes[i]);
    memset(context, 0, sizeof(*context));
}

static librdp_status rdp_nscodec_ensure_planes(rdp_nscodec_context* context, size_t capacity)
{
    size_t old_capacity = 0;
    size_t i = 0;
    uint8_t* resized[4] = {0};

    if (!context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capacity <= context->plane_capacity)
        return LIBRDP_STATUS_OK;
    old_capacity = context->plane_capacity;
    for (i = 0; i < 4u; i++)
    {
        resized[i] = (uint8_t*)malloc(capacity);
        if (!resized[i])
        {
            size_t j = 0;

            for (j = 0; j < i; j++)
                free(resized[j]);
            return LIBRDP_STATUS_NO_MEMORY;
        }
        if (old_capacity > 0 && context->planes[i])
            memcpy(resized[i], context->planes[i], old_capacity);
        if (capacity > old_capacity)
            memset(resized[i] + old_capacity, 0, capacity - old_capacity);
    }
    for (i = 0; i < 4u; i++)
    {
        free(context->planes[i]);
        context->planes[i] = resized[i];
    }
    context->plane_capacity = capacity;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_nscodec_parse_capability(const void* data, size_t length, rdp_nscodec_capability* capability)
{
    rdp_nscodec_capability parsed;
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_NSCODEC_CAPABILITY_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    parsed.allow_dynamic_fidelity = bytes[0];
    parsed.allow_subsampling = bytes[1];
    parsed.color_loss_level = bytes[2];
    if (parsed.allow_dynamic_fidelity > 1u ||
        parsed.allow_subsampling > 1u ||
        parsed.color_loss_level < 1u ||
        parsed.color_loss_level > 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *capability = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_nscodec_write_capability(rdp_buffer* buffer, const rdp_nscodec_capability* capability)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !capability)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (capability->allow_dynamic_fidelity > 1u ||
        capability->allow_subsampling > 1u ||
        capability->color_loss_level < 1u ||
        capability->color_loss_level > 7u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, capability->allow_dynamic_fidelity);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, capability->allow_subsampling);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, capability->color_loss_level);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

static librdp_status rdp_nscodec_plane_size(size_t width, size_t height, size_t* size)
{
    if (!size || width == 0 || height == 0 || width > ((size_t)-1) / height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *size = width * height;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_nscodec_parse_stream(const void* data,
                                       size_t length,
                                       uint32_t width,
                                       uint32_t height,
                                       rdp_nscodec_stream* stream)
{
    rdp_nscodec_stream parsed;
    rdp_stream input;
    const uint8_t* planes = NULL;
    uint16_t reserved = 0;
    size_t luma_expected = 0;
    size_t chroma_expected = 0;
    size_t alpha_expected = 0;
    size_t total = 0;
    size_t rounded_width = 0;
    size_t rounded_height = 0;

    if (!data || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0 || length < RDP_NSCODEC_STREAM_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&input, data, length);
    if (rdp_stream_read_u32_le(&input, &parsed.luma_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&input, &parsed.orange_chroma_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&input, &parsed.green_chroma_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&input, &parsed.alpha_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&input, &parsed.color_loss_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&input, &parsed.chroma_subsampling_level) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&input, &reserved) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)reserved;

    if (parsed.luma_len == 0 ||
        parsed.orange_chroma_len == 0 ||
        parsed.green_chroma_len == 0 ||
        parsed.color_loss_level < 1u ||
        parsed.color_loss_level > 7u ||
        parsed.chroma_subsampling_level > 1u ||
        reserved != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!rdp_nscodec_round_up((size_t)width, 8u, &rounded_width) ||
        !rdp_nscodec_round_up((size_t)height, 2u, &rounded_height) ||
        rounded_width < width || rounded_height < height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (parsed.chroma_subsampling_level)
    {
        parsed.luma_width = rounded_width;
        parsed.luma_height = height;
        parsed.chroma_width = rounded_width / 2u;
        parsed.chroma_height = rounded_height / 2u;
    }
    else
    {
        parsed.luma_width = width;
        parsed.luma_height = height;
        parsed.chroma_width = width;
        parsed.chroma_height = height;
    }
    parsed.alpha_width = width;
    parsed.alpha_height = height;

    if (rdp_nscodec_plane_size(parsed.luma_width, parsed.luma_height, &luma_expected) != LIBRDP_STATUS_OK ||
        rdp_nscodec_plane_size(parsed.chroma_width, parsed.chroma_height, &chroma_expected) != LIBRDP_STATUS_OK ||
        rdp_nscodec_plane_size(parsed.alpha_width, parsed.alpha_height, &alpha_expected) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (parsed.luma_len > luma_expected ||
        parsed.orange_chroma_len > chroma_expected ||
        parsed.green_chroma_len > chroma_expected ||
        parsed.alpha_len > alpha_expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    total = (size_t)parsed.luma_len;
    if ((size_t)parsed.orange_chroma_len > ((size_t)-1) - total)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total += (size_t)parsed.orange_chroma_len;
    if ((size_t)parsed.green_chroma_len > ((size_t)-1) - total)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total += (size_t)parsed.green_chroma_len;
    if ((size_t)parsed.alpha_len > ((size_t)-1) - total)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total += (size_t)parsed.alpha_len;
    if (total != length - RDP_NSCODEC_STREAM_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_stream_read_bytes(&input, &planes, total) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.luma = planes;
    parsed.orange_chroma = parsed.luma + parsed.luma_len;
    parsed.green_chroma = parsed.orange_chroma + parsed.orange_chroma_len;
    parsed.alpha = parsed.alpha_len > 0 ? parsed.green_chroma + parsed.green_chroma_len : NULL;
    *stream = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_nscodec_decode_rle_plane(const uint8_t* input,
                                           size_t input_len,
                                           uint8_t* output,
                                           size_t output_len)
{
    size_t in_offset = 0;
    size_t out_offset = 0;
    size_t left = output_len;

    if (!input || !output || output_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (output_len <= 4u)
    {
        if (input_len != output_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        memcpy(output, input, output_len);
        return LIBRDP_STATUS_OK;
    }

    while (left > 4u)
    {
        uint8_t value = 0;
        size_t run = 0;

        if (in_offset >= input_len)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        value = input[in_offset++];
        if (left == 5u)
        {
            output[out_offset++] = value;
            left--;
        }
        else if (in_offset >= input_len)
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (value == input[in_offset])
        {
            in_offset++;
            if (in_offset >= input_len)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (input[in_offset] < 0xffu)
            {
                run = (size_t)input[in_offset++] + 2u;
            }
            else
            {
                in_offset++;
                if (input_len - in_offset < 4u)
                    return LIBRDP_STATUS_PROTOCOL_ERROR;
                run = (size_t)input[in_offset] |
                      ((size_t)input[in_offset + 1u] << 8u) |
                      ((size_t)input[in_offset + 2u] << 16u) |
                      ((size_t)input[in_offset + 3u] << 24u);
                in_offset += 4u;
            }
            if (run == 0 || run > left || run > output_len - out_offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            memset(output + out_offset, value, run);
            out_offset += run;
            left -= run;
        }
        else
        {
            output[out_offset++] = value;
            left--;
        }
    }

    if (left != 4u || input_len - in_offset != 4u || output_len - out_offset < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(output + out_offset, input + in_offset, 4u);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_nscodec_decode_plane(const uint8_t* encoded,
                                              size_t encoded_len,
                                              size_t expected_len,
                                              uint8_t* decoded)
{
    if (!encoded || !decoded || expected_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (encoded_len == expected_len)
    {
        memcpy(decoded, encoded, expected_len);
        return LIBRDP_STATUS_OK;
    }
    if (encoded_len > expected_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_nscodec_decode_rle_plane(encoded, encoded_len, decoded, expected_len);
}

static librdp_status rdp_nscodec_decode_planes(rdp_nscodec_context* context,
                                               const rdp_nscodec_stream* stream,
                                               size_t width,
                                               size_t height)
{
    size_t luma_expected = 0;
    size_t chroma_expected = 0;
    size_t alpha_expected = 0;
    size_t capacity = 0;
    uint8_t* planes[4] = {NULL, NULL, NULL, NULL};
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_nscodec_plane_size(stream->luma_width, stream->luma_height, &luma_expected) != LIBRDP_STATUS_OK ||
        rdp_nscodec_plane_size(stream->chroma_width, stream->chroma_height, &chroma_expected) != LIBRDP_STATUS_OK ||
        rdp_nscodec_plane_size(width, height, &alpha_expected) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    capacity = luma_expected;
    if (chroma_expected > capacity)
        capacity = chroma_expected;
    if (alpha_expected > capacity)
        capacity = alpha_expected;

    for (i = 0; i < 4u; i++)
    {
        planes[i] = (uint8_t*)malloc(capacity);
        if (!planes[i])
        {
            status = LIBRDP_STATUS_NO_MEMORY;
            goto out;
        }
    }

    status = rdp_nscodec_decode_plane(stream->luma, stream->luma_len, luma_expected, planes[0]);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    status = rdp_nscodec_decode_plane(stream->orange_chroma,
                                      stream->orange_chroma_len,
                                      chroma_expected,
                                      planes[1]);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    status = rdp_nscodec_decode_plane(stream->green_chroma,
                                      stream->green_chroma_len,
                                      chroma_expected,
                                      planes[2]);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    if (stream->alpha_len == 0)
    {
        memset(planes[3], 0xffu, alpha_expected);
    }
    else
    {
        status = rdp_nscodec_decode_plane(stream->alpha, stream->alpha_len, alpha_expected, planes[3]);
        if (status != LIBRDP_STATUS_OK)
            goto out;
    }

    status = rdp_nscodec_ensure_planes(context, capacity);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    memcpy(context->planes[0], planes[0], luma_expected);
    memcpy(context->planes[1], planes[1], chroma_expected);
    memcpy(context->planes[2], planes[2], chroma_expected);
    memcpy(context->planes[3], planes[3], alpha_expected);

out:
    for (i = 0; i < 4u; i++)
        free(planes[i]);
    return status;
}

librdp_status rdp_nscodec_decode_region_bgra32(rdp_nscodec_context* context,
                                               const void* data,
                                               size_t length,
                                               uint32_t width,
                                               uint32_t height,
                                               uint8_t* dest,
                                               size_t dest_stride,
                                               uint32_t dest_x,
                                               uint32_t dest_y,
                                               uint32_t dest_width,
                                               uint32_t dest_height)
{
    rdp_nscodec_stream stream;
    size_t min_stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !data || !dest)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0 ||
        dest_width == 0 || dest_height == 0 ||
        dest_x > dest_width ||
        dest_y > dest_height ||
        width > dest_width - dest_x ||
        height > dest_height - dest_y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#if SIZE_MAX < UINT32_MAX
    if ((size_t)dest_width > ((size_t)-1) / 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#endif
    min_stride = (size_t)dest_width * 4u;
    if (dest_stride < min_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    status = rdp_nscodec_parse_stream(data, length, width, height, &stream);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_nscodec_decode_planes(context, &stream, width, height);
    if (status != LIBRDP_STATUS_OK)
        return status;

    for (uint32_t y = 0; y < height; y++)
    {
        const uint8_t* y_plane = context->planes[0] + ((size_t)y * stream.luma_width);
        const uint8_t* co_plane = NULL;
        const uint8_t* cg_plane = NULL;
        const uint8_t* alpha_plane = context->planes[3] + ((size_t)y * (size_t)width);
        uint8_t* row = dest + ((size_t)(dest_y + y) * dest_stride) + ((size_t)dest_x * 4u);

        if (stream.chroma_subsampling_level)
        {
            co_plane = context->planes[1] + ((size_t)(y / 2u) * stream.chroma_width);
            cg_plane = context->planes[2] + ((size_t)(y / 2u) * stream.chroma_width);
        }
        else
        {
            co_plane = context->planes[1] + ((size_t)y * stream.chroma_width);
            cg_plane = context->planes[2] + ((size_t)y * stream.chroma_width);
        }

        for (uint32_t x = 0; x < width; x++)
        {
            size_t chroma_x = stream.chroma_subsampling_level ? (size_t)(x / 2u) : (size_t)x;
            int32_t y_value = (int32_t)y_plane[x];
            int32_t co_value = rdp_nscodec_recover_chroma(co_plane[chroma_x], stream.color_loss_level);
            int32_t cg_value = rdp_nscodec_recover_chroma(cg_plane[chroma_x], stream.color_loss_level);
            uint8_t* pixel = row + ((size_t)x * 4u);

            pixel[0] = rdp_nscodec_clamp_i32(y_value - co_value - cg_value);
            pixel[1] = rdp_nscodec_clamp_i32(y_value + cg_value);
            pixel[2] = rdp_nscodec_clamp_i32(y_value + co_value - cg_value);
            pixel[3] = alpha_plane[x];
        }
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_nscodec_decode_bgra32(rdp_nscodec_context* context,
                                        const void* data,
                                        size_t length,
                                        uint32_t width,
                                        uint32_t height,
                                        rdp_buffer* pixels,
                                        size_t* stride)
{
    size_t output_stride = 0;
    size_t output_size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !data || !pixels || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#if SIZE_MAX < UINT32_MAX
    if ((size_t)width > ((size_t)-1) / 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#endif
    output_stride = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / output_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_size = (size_t)height * output_stride;
    status = rdp_buffer_reserve(pixels, output_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_nscodec_decode_region_bgra32(context,
                                              data,
                                              length,
                                              width,
                                              height,
                                              pixels->data,
                                              output_stride,
                                              0,
                                              0,
                                              width,
                                              height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    pixels->length = output_size;
    *stride = output_stride;
    return LIBRDP_STATUS_OK;
}

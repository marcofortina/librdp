#include "protocol/pointer.h"

#include "common/stream.h"
#include "protocol/fastpath.h"

#include <limits.h>
#include <string.h>

#define RDP_POINTER_MAX_DIMENSION 512u

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

    if (!update || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
    rdp_stream_init(&stream, data, length);
    switch (update_code)
    {
        case RDP_FASTPATH_UPDATE_POINTER_NULL:
            if (length != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            update->kind = RDP_POINTER_UPDATE_KIND_NULL;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_DEFAULT:
            if (length != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            update->kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_POSITION:
            if (rdp_stream_read_u16_le(&stream, &update->x) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &update->y) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            update->kind = RDP_POINTER_UPDATE_KIND_POSITION;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_CACHED:
            if (rdp_stream_read_u16_le(&stream, &update->cache_index) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            update->kind = RDP_POINTER_UPDATE_KIND_CACHED;
            return LIBRDP_STATUS_OK;
        case RDP_FASTPATH_UPDATE_POINTER_COLOR:
            return rdp_pointer_parse_color_attributes(&stream, 24, 0, update);
        case RDP_FASTPATH_UPDATE_POINTER_NEW:
        {
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            return rdp_pointer_parse_color_attributes(&stream, bpp, 0, update);
        }
        case RDP_FASTPATH_UPDATE_POINTER_LARGE:
        {
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            return rdp_pointer_parse_color_attributes(&stream, bpp, 1, update);
        }
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_pointer_parse_slowpath(const void* data, size_t length, rdp_pointer_update* update)
{
    rdp_stream stream;
    uint16_t message_type = 0;

    if (!update || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(update, 0, sizeof(*update));
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
                update->kind = RDP_POINTER_UPDATE_KIND_NULL;
            else if (pointer_type == RDP_POINTER_SYSTEM_DEFAULT)
                update->kind = RDP_POINTER_UPDATE_KIND_DEFAULT;
            else
                return LIBRDP_STATUS_UNSUPPORTED;
            return LIBRDP_STATUS_OK;
        }
        case RDP_POINTER_MESSAGE_TYPE_POSITION:
            if (rdp_stream_read_u16_le(&stream, &update->x) != LIBRDP_STATUS_OK ||
                rdp_stream_read_u16_le(&stream, &update->y) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            update->kind = RDP_POINTER_UPDATE_KIND_POSITION;
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_MESSAGE_TYPE_COLOR:
            return rdp_pointer_parse_color_attributes(&stream, 24, 0, update);
        case RDP_POINTER_MESSAGE_TYPE_CACHED:
            if (rdp_stream_read_u16_le(&stream, &update->cache_index) != LIBRDP_STATUS_OK ||
                rdp_stream_remaining(&stream) != 0)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            update->kind = RDP_POINTER_UPDATE_KIND_CACHED;
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_MESSAGE_TYPE_POINTER:
        {
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            return rdp_pointer_parse_color_attributes(&stream, bpp, 0, update);
        }
        case RDP_POINTER_MESSAGE_TYPE_LARGE:
        {
            uint16_t bpp = 0;
            if (rdp_stream_read_u16_le(&stream, &bpp) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            return rdp_pointer_parse_color_attributes(&stream, bpp, 1, update);
        }
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

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
    if (update->xor_bpp != 1u && update->xor_bpp != 24u && update->xor_bpp != 32u)
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

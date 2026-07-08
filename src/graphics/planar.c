#include "graphics/planar.h"

#include <stdint.h>

librdp_status rdp_planar_decode_argb(const void* data,
                                     size_t length,
                                     uint32_t width,
                                     uint32_t height,
                                     rdp_buffer* pixels,
                                     size_t* stride)
{
    const uint8_t* bytes = (const uint8_t*)data;
    const uint8_t* alpha = NULL;
    const uint8_t* red = NULL;
    const uint8_t* green = NULL;
    const uint8_t* blue = NULL;
    uint8_t header = 0;
    uint8_t cll = 0;
    int has_alpha = 0;
    size_t pixel_count = 0;
    size_t plane_count = 0;
    size_t expected = 0;
    size_t output_stride = 0;
    size_t output_size = 0;
    size_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !pixels || !stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
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
    if (cll != 0 || (header & RDP_PLANAR_FORMAT_CHROMA_SUBSAMPLING) != 0 ||
        (header & RDP_PLANAR_FORMAT_RLE) != 0)
        return LIBRDP_STATUS_UNSUPPORTED;

    pixel_count = (size_t)width * (size_t)height;
    has_alpha = (header & RDP_PLANAR_FORMAT_NO_ALPHA) == 0;
    plane_count = has_alpha ? 4u : 3u;
    if (pixel_count > (SIZE_MAX - 1u) / plane_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    expected = 1u + (pixel_count * plane_count);
    if (length != expected && length != expected + 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#if SIZE_MAX < UINT64_MAX
    if ((size_t)width > SIZE_MAX / 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
#endif
    output_stride = (size_t)width * 4u;
    if (height > SIZE_MAX / output_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_size = (size_t)height * output_stride;

    status = rdp_buffer_reserve(pixels, output_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    pixels->length = output_size;
    *stride = output_stride;

    alpha = has_alpha ? bytes + 1u : NULL;
    red = bytes + 1u + (has_alpha ? pixel_count : 0u);
    green = red + pixel_count;
    blue = green + pixel_count;

    for (i = 0; i < pixel_count; i++)
    {
        uint8_t* dest = pixels->data + (i * 4u);

        dest[0] = blue[i];
        dest[1] = green[i];
        dest[2] = red[i];
        dest[3] = has_alpha ? alpha[i] : 0xffu;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: portable compressed image decoding for GDI+ Image objects.
 * Invariants: decoded dimensions, row sizes and allocations are bounded before
 * codec libraries receive output storage.
 * Ownership: encoded input is borrowed; decoded pixels are returned to the
 * caller and released by rdp_gdi_image_clear().
 * Threading: each decode owns its codec state and is reentrant.
 * Trust boundary: all encoded bytes and image metadata are remote input.
 */

#include "graphics/gdi_image.h"

#include <limits.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#if defined(RDP_HAVE_PNG)
#include <png.h>
#endif

#if defined(RDP_HAVE_JPEG)
#include <jpeglib.h>
#endif

#define RDP_GDI_IMAGE_MAX_DIMENSION 16384u
#define RDP_GDI_IMAGE_MAX_PIXELS (RDP_GDI_IMAGE_MAX_DIMENSION * RDP_GDI_IMAGE_MAX_DIMENSION)

#if !defined(RDP_HAVE_QUARTZ)
static int rdp_gdi_image_is_png(const uint8_t* data, size_t length)
{
    static const uint8_t signature[] = {0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au};

    return data && length >= sizeof(signature) && memcmp(data, signature, sizeof(signature)) == 0;
}

static int rdp_gdi_image_is_jpeg(const uint8_t* data, size_t length)
{
    return data && length >= 3u && data[0] == 0xffu && data[1] == 0xd8u && data[2] == 0xffu;
}

#if defined(RDP_HAVE_PNG) || defined(RDP_HAVE_JPEG)
static librdp_status rdp_gdi_image_allocate(rdp_gdi_image* image,
                                            uint32_t width,
                                            uint32_t height)
{
    size_t stride = 0u;
    size_t bytes = 0u;

    if (!image || width == 0u || height == 0u ||
        width > RDP_GDI_IMAGE_MAX_DIMENSION || height > RDP_GDI_IMAGE_MAX_DIMENSION ||
        (uint64_t)width * (uint64_t)height > RDP_GDI_IMAGE_MAX_PIXELS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stride = (size_t)width * 4u;
    if ((size_t)height > SIZE_MAX / stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    bytes = (size_t)height * stride;
    image->pixels = (uint8_t*)malloc(bytes);
    if (!image->pixels)
        return LIBRDP_STATUS_NO_MEMORY;
    image->width = width;
    image->height = height;
    image->stride = stride;
    return LIBRDP_STATUS_OK;
}
#endif
#endif

void rdp_gdi_image_init(rdp_gdi_image* image)
{
    if (image)
        memset(image, 0, sizeof(*image));
}

void rdp_gdi_image_clear(rdp_gdi_image* image)
{
    if (!image)
        return;
    free(image->pixels);
    memset(image, 0, sizeof(*image));
}

#if !defined(RDP_HAVE_QUARTZ)
#if defined(RDP_HAVE_PNG)
/*
 * Decodes a PNG through libpng's bounded simplified API. Codec failures are
 * reported as malformed remote payloads and never leave partial image state.
 */
static librdp_status rdp_gdi_image_decode_png(const uint8_t* data,
                                              size_t length,
                                              rdp_gdi_image* image)
{
    png_image png;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&png, 0, sizeof(png));
    png.version = PNG_IMAGE_VERSION;
    if (!png_image_begin_read_from_memory(&png, data, length))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_gdi_image_allocate(image, png.width, png.height);
    if (status != LIBRDP_STATUS_OK)
    {
        png_image_free(&png);
        return status;
    }
    png.format = PNG_FORMAT_BGRA;
    if (image->stride > (size_t)INT32_MAX ||
        !png_image_finish_read(&png, NULL, image->pixels, (png_int_32)image->stride, NULL))
    {
        png_image_free(&png);
        rdp_gdi_image_clear(image);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    png_image_free(&png);
    return LIBRDP_STATUS_OK;
}
#endif

#if defined(RDP_HAVE_JPEG)
typedef struct rdp_gdi_jpeg_error
{
    struct jpeg_error_mgr base;
    jmp_buf jump;
} rdp_gdi_jpeg_error;

static void rdp_gdi_image_jpeg_error_exit(j_common_ptr codec)
{
    rdp_gdi_jpeg_error* error = (rdp_gdi_jpeg_error*)codec->err;

    longjmp(error->jump, 1);
}

/*
 * Decodes JPEG scanlines through libjpeg and normalizes RGB output to BGRA32.
 * setjmp is required by libjpeg's error contract; all allocations are owned by
 * this frame and cleared after a codec failure.
 */
static librdp_status rdp_gdi_image_decode_jpeg(const uint8_t* data,
                                               size_t length,
                                               rdp_gdi_image* image)
{
    struct jpeg_decompress_struct codec;
    rdp_gdi_jpeg_error error;
    uint8_t* row = NULL;
    size_t row_bytes = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (length > (size_t)ULONG_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&codec, 0, sizeof(codec));
    codec.err = jpeg_std_error(&error.base);
    error.base.error_exit = rdp_gdi_image_jpeg_error_exit;
    if (setjmp(error.jump) != 0)
    {
        jpeg_destroy_decompress(&codec);
        free(row);
        rdp_gdi_image_clear(image);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    jpeg_create_decompress(&codec);
    jpeg_mem_src(&codec, data, (unsigned long)length);
    if (jpeg_read_header(&codec, TRUE) != JPEG_HEADER_OK)
    {
        jpeg_destroy_decompress(&codec);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    codec.out_color_space = JCS_RGB;
    if (!jpeg_start_decompress(&codec) || codec.output_components != 3u)
    {
        jpeg_destroy_decompress(&codec);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    status = rdp_gdi_image_allocate(image, codec.output_width, codec.output_height);
    if (status != LIBRDP_STATUS_OK)
    {
        jpeg_destroy_decompress(&codec);
        return status;
    }
    row_bytes = (size_t)codec.output_width * 3u;
    row = (uint8_t*)malloc(row_bytes);
    if (!row)
    {
        jpeg_destroy_decompress(&codec);
        rdp_gdi_image_clear(image);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    while (codec.output_scanline < codec.output_height)
    {
        JSAMPROW rows[1];
        uint32_t y = codec.output_scanline;
        uint32_t x = 0u;

        rows[0] = row;
        if (jpeg_read_scanlines(&codec, rows, 1u) != 1u)
        {
            jpeg_destroy_decompress(&codec);
            free(row);
            rdp_gdi_image_clear(image);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        for (x = 0u; x < image->width; x++)
        {
            uint8_t* pixel = image->pixels + ((size_t)y * image->stride) + ((size_t)x * 4u);
            const uint8_t* rgb = row + ((size_t)x * 3u);

            pixel[0] = rgb[2];
            pixel[1] = rgb[1];
            pixel[2] = rgb[0];
            pixel[3] = 0xffu;
        }
    }
    if (!jpeg_finish_decompress(&codec))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    jpeg_destroy_decompress(&codec);
    free(row);
    if (status != LIBRDP_STATUS_OK)
        rdp_gdi_image_clear(image);
    return status;
}
#endif
#endif

librdp_status rdp_gdi_image_decode(const uint8_t* data,
                                   size_t length,
                                   rdp_gdi_image* image)
{
    if ((!data && length > 0u) || !image)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_gdi_image_clear(image);
#if defined(RDP_HAVE_QUARTZ)
    return rdp_gdi_image_decode_quartz(data, length, image);
#else
    if (rdp_gdi_image_is_png(data, length))
    {
#if defined(RDP_HAVE_PNG)
        return rdp_gdi_image_decode_png(data, length, image);
#else
        return LIBRDP_STATUS_UNSUPPORTED;
#endif
    }
    if (rdp_gdi_image_is_jpeg(data, length))
    {
#if defined(RDP_HAVE_JPEG)
        return rdp_gdi_image_decode_jpeg(data, length, image);
#else
        return LIBRDP_STATUS_UNSUPPORTED;
#endif
    }
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

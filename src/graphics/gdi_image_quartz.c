/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: ImageIO decoder for GDI+ compressed Image objects on Apple systems.
 * Invariants: ImageIO output is normalized into a bounded top-left BGRA32
 * buffer before it reaches the common scaler.
 * Ownership: Core Foundation and Core Graphics objects remain local; decoded
 * pixels are transferred through rdp_gdi_image.
 * Threading: no shared contexts are retained.
 * Trust boundary: encoded image bytes are remote input.
 */

#include "graphics/gdi_image.h"

#if defined(RDP_HAVE_QUARTZ)

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>

#include <limits.h>
#include <stdlib.h>

#define RDP_GDI_IMAGE_QUARTZ_MAX_DIMENSION 16384u

librdp_status rdp_gdi_image_decode_quartz(const uint8_t* data,
                                          size_t length,
                                          rdp_gdi_image* image)
{
    CFDataRef encoded = NULL;
    CGImageSourceRef source = NULL;
    CGImageRef cg_image = NULL;
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    size_t width = 0u;
    size_t height = 0u;
    size_t stride = 0u;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if ((!data && length > 0u) || !image || length > (size_t)LONG_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    encoded = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)length);
    if (!encoded)
        return LIBRDP_STATUS_NO_MEMORY;
    source = CGImageSourceCreateWithData(encoded, NULL);
    if (!source)
        goto cleanup;
    cg_image = CGImageSourceCreateImageAtIndex(source, 0u, NULL);
    if (!cg_image)
        goto cleanup;
    width = CGImageGetWidth(cg_image);
    height = CGImageGetHeight(cg_image);
    if (width == 0u || height == 0u ||
        width > RDP_GDI_IMAGE_QUARTZ_MAX_DIMENSION ||
        height > RDP_GDI_IMAGE_QUARTZ_MAX_DIMENSION ||
        width > SIZE_MAX / 4u)
        goto cleanup;
    stride = width * 4u;
    if (height > SIZE_MAX / stride)
        goto cleanup;
    image->pixels = (uint8_t*)calloc(height, stride);
    if (!image->pixels)
    {
        status = LIBRDP_STATUS_NO_MEMORY;
        goto cleanup;
    }
    color_space = CGColorSpaceCreateDeviceRGB();
    if (!color_space)
    {
        status = LIBRDP_STATUS_NO_MEMORY;
        goto cleanup;
    }
    context = CGBitmapContextCreate(image->pixels,
                                    width,
                                    height,
                                    8u,
                                    stride,
                                    color_space,
                                    (CGBitmapInfo)(kCGBitmapByteOrder32Little |
                                                   kCGImageAlphaPremultipliedFirst));
    if (!context)
    {
        status = LIBRDP_STATUS_NO_MEMORY;
        goto cleanup;
    }
    CGContextTranslateCTM(context, 0.0, (CGFloat)height);
    CGContextScaleCTM(context, 1.0, -1.0);
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0.0, 0.0, (CGFloat)width, (CGFloat)height), cg_image);
    image->width = (uint32_t)width;
    image->height = (uint32_t)height;
    image->stride = stride;
    status = LIBRDP_STATUS_OK;

cleanup:
    if (context)
        CGContextRelease(context);
    if (color_space)
        CGColorSpaceRelease(color_space);
    if (cg_image)
        CGImageRelease(cg_image);
    if (source)
        CFRelease(source);
    CFRelease(encoded);
    if (status != LIBRDP_STATUS_OK)
        rdp_gdi_image_clear(image);
    return status;
}

#endif

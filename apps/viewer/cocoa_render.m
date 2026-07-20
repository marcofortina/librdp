/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: CoreGraphics presentation for the Cocoa viewer.
 * Invariants: each frame is mapped read-only, validated, drawn synchronously,
 * and unmapped after all data-provider users have been released.
 * Ownership: the caller owns the context and surface; this module owns only
 * temporary color-space, provider, and image objects.
 * Threading: presentation runs on the AppKit event thread.
 * Trust boundary: surface metadata originates in protocol processing and is
 * rejected before size arithmetic or CoreGraphics allocation when malformed.
 */

#include "cocoa_render.h"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Draw a mapped BGRA32 frame with replacement semantics. CoreGraphics consumes
 * the borrowed bytes synchronously before the provider and mapping are closed.
 */
librdp_status cocoa_render_surface(CGContextRef context,
                                   librdp_surface* surface,
                                   CGRect destination)
{
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGDataProviderRef provider = NULL;
    CGImageRef image = NULL;
    CGBitmapInfo bitmap_info =
        (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                       (uint32_t)kCGImageAlphaNoneSkipFirst);
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;
    size_t data_size = 0u;

    if (!context || !surface ||
        !isfinite(destination.origin.x) ||
        !isfinite(destination.origin.y) ||
        !isfinite(destination.size.width) ||
        !isfinite(destination.size.height) ||
        destination.size.width <= 0.0 ||
        destination.size.height <= 0.0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_mapping_init(&mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_surface_map(
        surface,
        LIBRDP_SURFACE_ACCESS_READ,
        &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!mapping.pixels ||
        mapping.format != LIBRDP_PIXEL_FORMAT_BGRA32 ||
        mapping.width == 0u ||
        mapping.height == 0u ||
        mapping.width > (uint32_t)(SIZE_MAX / 4u) ||
        mapping.stride < (size_t)mapping.width * 4u ||
        mapping.stride > SIZE_MAX / (size_t)mapping.height)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
    {
        data_size = mapping.stride * (size_t)mapping.height;
        color_space = CGColorSpaceCreateDeviceRGB();
        if (color_space)
        {
            provider = CGDataProviderCreateWithData(
                NULL,
                mapping.pixels,
                data_size,
                NULL);
        }
        if (provider)
        {
            image = CGImageCreate(
                mapping.width,
                mapping.height,
                8u,
                32u,
                mapping.stride,
                color_space,
                bitmap_info,
                provider,
                NULL,
                false,
                kCGRenderingIntentDefault);
        }
        if (!color_space || !provider || !image)
        {
            status = LIBRDP_STATUS_NO_MEMORY;
        }
        else
        {
            CGContextSaveGState(context);
            CGContextSetBlendMode(context, kCGBlendModeCopy);
            CGContextSetInterpolationQuality(
                context,
                kCGInterpolationNone);
            CGContextDrawImage(context, destination, image);
            CGContextRestoreGState(context);
        }
    }
    if (image)
        CGImageRelease(image);
    if (provider)
        CGDataProviderRelease(provider);
    if (color_space)
        CGColorSpaceRelease(color_space);
    unmap_status = librdp_surface_unmap(surface, &mapping);
    if (status == LIBRDP_STATUS_OK)
        status = unmap_status;
    return status;
}

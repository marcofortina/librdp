/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Quartz/CoreGraphics-backed GDI raster primitives.
 * Invariants: CoreGraphics receives mapped BGRA32 buffers with little-endian
 * premultiplied-first layout, matching the public surface storage.
 * Ownership: color spaces and bitmap contexts are created per operation and
 * released before the surface is unmapped.
 * Threading: callers serialize surface access; no CoreGraphics object is
 * shared across calls.
 * Trust boundary: geometry comes from decoded RDP orders and is checked before
 * native drawing.
 */

#include "graphics/gdi_backend.h"

#if defined(RDP_HAVE_QUARTZ)
#include <CoreGraphics/CoreGraphics.h>
#endif

librdp_status rdp_gdi_backend_quartz_query(rdp_gdi_backend_caps* caps)
{
    if (!caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#if defined(RDP_HAVE_QUARTZ)
    caps->name = "quartz";
    caps->caps = RDP_GDI_BACKEND_CAP_FILL_RECT;
    return LIBRDP_STATUS_OK;
#else
    caps->name = "quartz";
    caps->caps = 0;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

librdp_status rdp_gdi_backend_quartz_fill_rect(librdp_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height,
                                               uint32_t color)
{
#if defined(RDP_HAVE_QUARTZ)
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;
    CGFloat b = (CGFloat)(color & 0xffu) / (CGFloat)255.0;
    CGFloat g = (CGFloat)((color >> 8u) & 0xffu) / (CGFloat)255.0;
    CGFloat r = (CGFloat)((color >> 16u) & 0xffu) / (CGFloat)255.0;

    if (!surface)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;

    color_space = CGColorSpaceCreateDeviceRGB();
    if (!color_space)
        status = LIBRDP_STATUS_NO_MEMORY;
    if (status == LIBRDP_STATUS_OK)
    {
        context = CGBitmapContextCreate(mapping.writable_pixels,
                                        mapping.width,
                                        mapping.height,
                                        8,
                                        mapping.stride,
                                        color_space,
                                        kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst);
        if (!context)
            status = LIBRDP_STATUS_NO_MEMORY;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        CGContextSetRGBFillColor(context, r, g, b, (CGFloat)1.0);
        CGContextFillRect(context,
                          CGRectMake((CGFloat)x, (CGFloat)y, (CGFloat)width, (CGFloat)height));
        CGContextFlush(context);
    }
    if (context)
        CGContextRelease(context);
    if (color_space)
        CGColorSpaceRelease(color_space);

    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
#else
    (void)surface;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)color;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

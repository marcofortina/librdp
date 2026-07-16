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

#if defined(RDP_HAVE_QUARTZ)
static uint32_t rdp_gdi_backend_quartz_caps(void)
{
    return RDP_GDI_BACKEND_CAP_FILL_RECT |
           RDP_GDI_BACKEND_CAP_BLIT_BGRA32 |
           RDP_GDI_BACKEND_CAP_COPY_RECT |
           RDP_GDI_BACKEND_CAP_DRAW_LINE |
           RDP_GDI_BACKEND_CAP_FILL_POLYGON |
           RDP_GDI_BACKEND_CAP_FILL_ELLIPSE |
           RDP_GDI_BACKEND_CAP_DRAW_ELLIPSE |
           RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM;
}

static void rdp_gdi_backend_quartz_set_color(CGContextRef context, uint32_t color)
{
    CGFloat b = (CGFloat)(color & 0xffu) / (CGFloat)255.0;
    CGFloat g = (CGFloat)((color >> 8u) & 0xffu) / (CGFloat)255.0;
    CGFloat r = (CGFloat)((color >> 16u) & 0xffu) / (CGFloat)255.0;

    CGContextSetRGBFillColor(context, r, g, b, (CGFloat)1.0);
    CGContextSetRGBStrokeColor(context, r, g, b, (CGFloat)1.0);
}

static void rdp_gdi_backend_quartz_prepare_top_left(CGContextRef context, uint32_t height)
{
    CGContextTranslateCTM(context, 0.0, (CGFloat)height);
    CGContextScaleCTM(context, 1.0, -1.0);
}

static void rdp_gdi_backend_quartz_clip(CGContextRef context, const rdp_gdi_backend_clip* clip)
{
    if (!context || !clip || !clip->present)
        return;
    CGContextClipToRect(context,
                        CGRectMake((CGFloat)clip->left,
                                   (CGFloat)clip->top,
                                   (CGFloat)(clip->right - clip->left + 1),
                                   (CGFloat)(clip->bottom - clip->top + 1)));
}
#endif

librdp_status rdp_gdi_backend_quartz_query(rdp_gdi_backend_caps* caps)
{
    if (!caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#if defined(RDP_HAVE_QUARTZ)
    caps->name = "quartz";
    caps->caps = rdp_gdi_backend_quartz_caps();
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
        rdp_gdi_backend_quartz_prepare_top_left(context, mapping.height);
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        rdp_gdi_backend_quartz_set_color(context, color);
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

librdp_status rdp_gdi_backend_quartz_blit_bgra32(librdp_surface* surface,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 const uint8_t* pixels,
                                                 size_t stride)
{
    return rdp_gdi_backend_blit_bgra32(RDP_GDI_BACKEND_SOFTWARE,
                                       surface,
                                       x,
                                       y,
                                       width,
                                       height,
                                       pixels,
                                       stride);
}

librdp_status rdp_gdi_backend_quartz_copy_rect(librdp_surface* surface,
                                               uint32_t src_x,
                                               uint32_t src_y,
                                               uint32_t dst_x,
                                               uint32_t dst_y,
                                               uint32_t width,
                                               uint32_t height)
{
    return rdp_gdi_backend_copy_rect(RDP_GDI_BACKEND_SOFTWARE,
                                     surface,
                                     src_x,
                                     src_y,
                                     dst_x,
                                     dst_y,
                                     width,
                                     height);
}

/*
 * Draws a top-left-coordinate source-copy line into a Quartz bitmap context.
 * The context transform is set to match the librdp surface memory layout before
 * any drawing operation touches the mapped buffer.
 */
librdp_status rdp_gdi_backend_quartz_draw_line(librdp_surface* surface,
                                               int32_t x0,
                                               int32_t y0,
                                               int32_t x1,
                                               int32_t y1,
                                               uint32_t pen_width,
                                               uint32_t color,
                                               const rdp_gdi_backend_clip* clip,
                                               uint32_t* dirty_left,
                                               uint32_t* dirty_top,
                                               uint32_t* dirty_right,
                                               uint32_t* dirty_bottom)
{
#if defined(RDP_HAVE_QUARTZ)
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;
    int32_t left = x0 < x1 ? x0 : x1;
    int32_t top = y0 < y1 ? y0 : y1;
    int32_t right = x0 > x1 ? x0 : x1;
    int32_t bottom = y0 > y1 ? y0 : y1;
    int32_t half = (int32_t)((pen_width == 0 ? 1u : pen_width) / 2u) + 1;

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
        rdp_gdi_backend_quartz_prepare_top_left(context, mapping.height);
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        CGContextSetShouldAntialias(context, 0);
        rdp_gdi_backend_quartz_clip(context, clip);
        rdp_gdi_backend_quartz_set_color(context, color);
        CGContextSetLineWidth(context, (CGFloat)(pen_width == 0 ? 1u : pen_width));
        CGContextSetLineCap(context, kCGLineCapSquare);
        CGContextMoveToPoint(context, (CGFloat)x0 + (CGFloat)0.5, (CGFloat)y0 + (CGFloat)0.5);
        CGContextAddLineToPoint(context, (CGFloat)x1 + (CGFloat)0.5, (CGFloat)y1 + (CGFloat)0.5);
        CGContextStrokePath(context);
        CGContextFlush(context);
    }
    if (context)
        CGContextRelease(context);
    if (color_space)
        CGColorSpaceRelease(color_space);
    unmap_status = librdp_surface_unmap(surface, &mapping);
    if (status == LIBRDP_STATUS_OK)
        status = unmap_status;
    if (status == LIBRDP_STATUS_OK)
    {
        if (left - half < 0)
            left = 0;
        else
            left -= half;
        if (top - half < 0)
            top = 0;
        else
            top -= half;
        right += half;
        bottom += half;
        if (dirty_left && (uint32_t)left < *dirty_left)
            *dirty_left = (uint32_t)left;
        if (dirty_top && (uint32_t)top < *dirty_top)
            *dirty_top = (uint32_t)top;
        if (dirty_right && (uint32_t)right > *dirty_right)
            *dirty_right = (uint32_t)right;
        if (dirty_bottom && (uint32_t)bottom > *dirty_bottom)
            *dirty_bottom = (uint32_t)bottom;
    }
    return status;
#else
    (void)surface;
    (void)x0;
    (void)y0;
    (void)x1;
    (void)y1;
    (void)pen_width;
    (void)color;
    (void)clip;
    (void)dirty_left;
    (void)dirty_top;
    (void)dirty_right;
    (void)dirty_bottom;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

/*
 * Fills a solid-color polygon through Quartz after flipping the bitmap context
 * into RDP coordinates. Complex brush and raster-operation semantics are kept
 * outside this native path.
 */
librdp_status rdp_gdi_backend_quartz_fill_polygon(librdp_surface* surface,
                                                  const rdp_gdi_backend_point* points,
                                                  uint32_t count,
                                                  uint32_t fill_mode,
                                                  uint32_t color,
                                                  const rdp_gdi_backend_clip* clip,
                                                  uint32_t* dirty_left,
                                                  uint32_t* dirty_top,
                                                  uint32_t* dirty_right,
                                                  uint32_t* dirty_bottom)
{
#if defined(RDP_HAVE_QUARTZ)
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    uint32_t i = 0;
    int32_t left = INT32_MAX;
    int32_t top = INT32_MAX;
    int32_t right = INT32_MIN;
    int32_t bottom = INT32_MIN;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || !points || count < 3)
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
        rdp_gdi_backend_quartz_prepare_top_left(context, mapping.height);
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        CGContextSetShouldAntialias(context, 0);
        rdp_gdi_backend_quartz_clip(context, clip);
        rdp_gdi_backend_quartz_set_color(context, color);
        CGContextMoveToPoint(context, (CGFloat)points[0].x, (CGFloat)points[0].y);
        for (i = 1; i < count; i++)
            CGContextAddLineToPoint(context, (CGFloat)points[i].x, (CGFloat)points[i].y);
        CGContextClosePath(context);
        if (fill_mode == 2u)
            CGContextFillPath(context);
        else
            CGContextEOFillPath(context);
        CGContextFlush(context);
    }
    if (context)
        CGContextRelease(context);
    if (color_space)
        CGColorSpaceRelease(color_space);
    unmap_status = librdp_surface_unmap(surface, &mapping);
    if (status == LIBRDP_STATUS_OK)
        status = unmap_status;
    if (status == LIBRDP_STATUS_OK)
    {
        for (i = 0; i < count; i++)
        {
            if (points[i].x < left)
                left = points[i].x;
            if (points[i].y < top)
                top = points[i].y;
            if (points[i].x > right)
                right = points[i].x;
            if (points[i].y > bottom)
                bottom = points[i].y;
        }
        if (left < 0)
            left = 0;
        if (top < 0)
            top = 0;
        if (dirty_left && (uint32_t)left < *dirty_left)
            *dirty_left = (uint32_t)left;
        if (dirty_top && (uint32_t)top < *dirty_top)
            *dirty_top = (uint32_t)top;
        if (right < 0)
            right = 0;
        if (bottom < 0)
            bottom = 0;
        if (dirty_right && (uint32_t)(right + 1) > *dirty_right)
            *dirty_right = (uint32_t)(right + 1);
        if (dirty_bottom && (uint32_t)(bottom + 1) > *dirty_bottom)
            *dirty_bottom = (uint32_t)(bottom + 1);
    }
    return status;
#else
    (void)surface;
    (void)points;
    (void)count;
    (void)fill_mode;
    (void)color;
    (void)clip;
    (void)dirty_left;
    (void)dirty_top;
    (void)dirty_right;
    (void)dirty_bottom;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

librdp_status rdp_gdi_backend_quartz_fill_ellipse(librdp_surface* surface,
                                                  int32_t x,
                                                  int32_t y,
                                                  uint32_t width,
                                                  uint32_t height,
                                                  uint32_t color,
                                                  const rdp_gdi_backend_clip* clip)
{
#if defined(RDP_HAVE_QUARTZ)
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || width == 0 || height == 0)
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
        rdp_gdi_backend_quartz_prepare_top_left(context, mapping.height);
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        CGContextSetShouldAntialias(context, 0);
        rdp_gdi_backend_quartz_clip(context, clip);
        rdp_gdi_backend_quartz_set_color(context, color);
        CGContextFillEllipseInRect(context,
                                   CGRectMake((CGFloat)x,
                                              (CGFloat)y,
                                              (CGFloat)width,
                                              (CGFloat)height));
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
    (void)clip;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

librdp_status rdp_gdi_backend_quartz_draw_ellipse(librdp_surface* surface,
                                                  int32_t x,
                                                  int32_t y,
                                                  uint32_t width,
                                                  uint32_t height,
                                                  uint32_t pen_width,
                                                  uint32_t color,
                                                  const rdp_gdi_backend_clip* clip)
{
#if defined(RDP_HAVE_QUARTZ)
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGContextRef context = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || width == 0 || height == 0)
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
        rdp_gdi_backend_quartz_prepare_top_left(context, mapping.height);
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        CGContextSetShouldAntialias(context, 0);
        rdp_gdi_backend_quartz_clip(context, clip);
        rdp_gdi_backend_quartz_set_color(context, color);
        CGContextSetLineWidth(context, (CGFloat)(pen_width == 0 ? 1u : pen_width));
        CGContextStrokeEllipseInRect(context,
                                     CGRectMake((CGFloat)x,
                                                (CGFloat)y,
                                                (CGFloat)width,
                                                (CGFloat)height));
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
    (void)pen_width;
    (void)color;
    (void)clip;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

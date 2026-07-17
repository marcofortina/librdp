/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: portable GDI raster backend dispatcher.
 * Invariants: software fallback and native backends share the same surface
 * bounds checks and BGRA color contract.
 * Ownership: mapped surface memory remains owned by librdp_surface and is
 * unmapped before returning to the caller.
 * Threading: callers must serialize surface access.
 * Trust boundary: order coordinates are untrusted and rejected before mapping.
 */

#include "graphics/gdi_backend.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int rdp_gdi_backend_rect_valid(const librdp_surface* surface,
                                      uint32_t x,
                                      uint32_t y,
                                      uint32_t width,
                                      uint32_t height)
{
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;

    if (!surface || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32 ||
        width == 0 || height == 0)
        return 0;
    surface_width = librdp_surface_width(surface);
    surface_height = librdp_surface_height(surface);
    return x <= surface_width && y <= surface_height &&
           width <= surface_width - x && height <= surface_height - y;
}

static uint32_t rdp_gdi_backend_caps_all(void)
{
    return RDP_GDI_BACKEND_CAP_FILL_RECT |
           RDP_GDI_BACKEND_CAP_BLIT_BGRA32 |
           RDP_GDI_BACKEND_CAP_COPY_RECT |
           RDP_GDI_BACKEND_CAP_DRAW_LINE |
           RDP_GDI_BACKEND_CAP_FILL_POLYGON |
           RDP_GDI_BACKEND_CAP_FILL_ELLIPSE |
           RDP_GDI_BACKEND_CAP_DRAW_ELLIPSE |
           RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM |
           RDP_GDI_BACKEND_CAP_GDIPLUS_COMPLETE_VISUALS;
}

static uint16_t rdp_gdi_backend_read_u16_le(const uint8_t* data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8u);
}

static int16_t rdp_gdi_backend_read_i16_le(const uint8_t* data)
{
    return (int16_t)rdp_gdi_backend_read_u16_le(data);
}

static uint32_t rdp_gdi_backend_read_u32_le(const uint8_t* data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8u) |
           ((uint32_t)data[2] << 16u) |
           ((uint32_t)data[3] << 24u);
}

static float rdp_gdi_backend_read_float_le(const uint8_t* data)
{
    uint32_t bits = rdp_gdi_backend_read_u32_le(data);
    float value = 0.0f;

    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint32_t rdp_gdi_backend_argb_to_color(uint32_t argb)
{
    return argb;
}

static uint8_t rdp_gdi_backend_color_alpha(uint32_t color)
{
    uint8_t alpha = (uint8_t)((color >> 24u) & 0xffu);

    return alpha == 0u ? 0xffu : alpha;
}

static uint8_t rdp_gdi_backend_blend_channel(uint8_t source, uint8_t destination, uint8_t alpha)
{
    uint32_t blended = ((uint32_t)source * (uint32_t)alpha) +
                       ((uint32_t)destination * (uint32_t)(255u - alpha)) +
                       127u;

    return (uint8_t)(blended / 255u);
}

static uint32_t rdp_gdi_backend_float_to_pen_width(float width)
{
    if (width <= 1.0f)
        return 1u;
    if (width >= 256.0f)
        return 256u;
    return (uint32_t)(width + 0.5f);
}

static int rdp_gdi_backend_point_visible(const librdp_surface* surface,
                                         int32_t x,
                                         int32_t y,
                                         const rdp_gdi_backend_clip* clip)
{
    uint32_t width = librdp_surface_width(surface);
    uint32_t height = librdp_surface_height(surface);

    if (!surface || x < 0 || y < 0 || x >= (int32_t)width || y >= (int32_t)height)
        return 0;
    if (clip && clip->present &&
        (x < clip->left || y < clip->top || x > clip->right || y > clip->bottom))
        return 0;
    return 1;
}

static void rdp_gdi_backend_expand_dirty(uint32_t x,
                                         uint32_t y,
                                         uint32_t* dirty_left,
                                         uint32_t* dirty_top,
                                         uint32_t* dirty_right,
                                         uint32_t* dirty_bottom)
{
    if (dirty_left && x < *dirty_left)
        *dirty_left = x;
    if (dirty_top && y < *dirty_top)
        *dirty_top = y;
    if (dirty_right && x + 1u > *dirty_right)
        *dirty_right = x + 1u;
    if (dirty_bottom && y + 1u > *dirty_bottom)
        *dirty_bottom = y + 1u;
}

static void rdp_gdi_backend_put_pixel(uint8_t* pixels,
                                      size_t stride,
                                      uint32_t x,
                                      uint32_t y,
                                      uint32_t color)
{
    uint8_t* pixel = pixels + ((size_t)y * stride) + ((size_t)x * 4u);
    uint8_t alpha = rdp_gdi_backend_color_alpha(color);

    if (alpha != 0xffu)
    {
        pixel[0] = rdp_gdi_backend_blend_channel((uint8_t)(color & 0xffu), pixel[0], alpha);
        pixel[1] = rdp_gdi_backend_blend_channel((uint8_t)((color >> 8u) & 0xffu), pixel[1], alpha);
        pixel[2] = rdp_gdi_backend_blend_channel((uint8_t)((color >> 16u) & 0xffu), pixel[2], alpha);
        pixel[3] = 0xffu;
        return;
    }
    pixel[0] = (uint8_t)(color & 0xffu);
    pixel[1] = (uint8_t)((color >> 8u) & 0xffu);
    pixel[2] = (uint8_t)((color >> 16u) & 0xffu);
    pixel[3] = 0xffu;
}

static int rdp_gdi_backend_abs_i32(int32_t value)
{
    return value < 0 ? -value : value;
}

rdp_gdi_backend_kind rdp_gdi_backend_default(void)
{
#if defined(__APPLE__) && defined(RDP_HAVE_QUARTZ)
    return RDP_GDI_BACKEND_QUARTZ;
#elif defined(RDP_HAVE_CAIRO)
    return RDP_GDI_BACKEND_CAIRO;
#else
    return RDP_GDI_BACKEND_SOFTWARE;
#endif
}

static librdp_status rdp_gdi_backend_software_query(rdp_gdi_backend_caps* caps)
{
    if (!caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    caps->name = "software";
    caps->caps = rdp_gdi_backend_caps_all();
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_software_fill_rect(librdp_surface* surface,
                                                        uint32_t x,
                                                        uint32_t y,
                                                        uint32_t width,
                                                        uint32_t height,
                                                        uint32_t color)
{
    librdp_surface_mapping mapping;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;
    uint8_t b = (uint8_t)(color & 0xffu);
    uint8_t g = (uint8_t)((color >> 8u) & 0xffu);
    uint8_t r = (uint8_t)((color >> 16u) & 0xffu);
    uint8_t alpha = rdp_gdi_backend_color_alpha(color);
    uint32_t row = 0;

    if (!rdp_gdi_backend_rect_valid(surface, x, y, width, height))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;

    for (row = 0; row < height; row++)
    {
        uint8_t* pixel = mapping.writable_pixels + ((size_t)(y + row) * mapping.stride) +
                         ((size_t)x * 4u);
        uint32_t column = 0;

        for (column = 0; column < width; column++)
        {
            if (alpha == 0xffu)
            {
                pixel[0] = b;
                pixel[1] = g;
                pixel[2] = r;
                pixel[3] = 0xffu;
            }
            else
            {
                pixel[0] = rdp_gdi_backend_blend_channel(b, pixel[0], alpha);
                pixel[1] = rdp_gdi_backend_blend_channel(g, pixel[1], alpha);
                pixel[2] = rdp_gdi_backend_blend_channel(r, pixel[2], alpha);
                pixel[3] = 0xffu;
            }
            pixel += 4u;
        }
    }

    unmap_status = librdp_surface_unmap(surface, &mapping);
    return unmap_status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_OK : unmap_status;
}

static librdp_status rdp_gdi_backend_software_blit_bgra32(librdp_surface* surface,
                                                          uint32_t x,
                                                          uint32_t y,
                                                          uint32_t width,
                                                          uint32_t height,
                                                          const uint8_t* pixels,
                                                          size_t stride)
{
    return librdp_surface_blit_bgra32(surface, x, y, width, height, pixels, stride);
}

static librdp_status rdp_gdi_backend_software_copy_rect(librdp_surface* surface,
                                                        uint32_t src_x,
                                                        uint32_t src_y,
                                                        uint32_t dst_x,
                                                        uint32_t dst_y,
                                                        uint32_t width,
                                                        uint32_t height)
{
    librdp_surface_mapping mapping;
    uint8_t* temp = NULL;
    size_t row_bytes = 0;
    size_t size = 0;
    uint32_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!rdp_gdi_backend_rect_valid(surface, src_x, src_y, width, height) ||
        !rdp_gdi_backend_rect_valid(surface, dst_x, dst_y, width, height))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    row_bytes = (size_t)width * 4u;
    if ((size_t)height > ((size_t)-1) / row_bytes)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    size = row_bytes * (size_t)height;
    temp = (uint8_t*)malloc(size);
    if (!temp)
        return LIBRDP_STATUS_NO_MEMORY;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
    {
        free(temp);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
    {
        free(temp);
        return status;
    }
    for (row = 0; row < height; row++)
        memcpy(temp + ((size_t)row * row_bytes),
               mapping.pixels + ((size_t)(src_y + row) * mapping.stride) + ((size_t)src_x * 4u),
               row_bytes);
    for (row = 0; row < height; row++)
        memcpy(mapping.writable_pixels + ((size_t)(dst_y + row) * mapping.stride) + ((size_t)dst_x * 4u),
               temp + ((size_t)row * row_bytes),
               row_bytes);
    unmap_status = librdp_surface_unmap(surface, &mapping);
    free(temp);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

/*
 * Draws a solid source-copy line using the same Bresenham and square-pen
 * contract expected by the GDI session renderer. Native backends may delegate
 * here when exact pixel compatibility is more important than acceleration.
 */
static librdp_status rdp_gdi_backend_software_draw_line(librdp_surface* surface,
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
    librdp_surface_mapping mapping;
    int32_t dx = 0;
    int32_t dy = 0;
    int32_t sx = 0;
    int32_t sy = 0;
    int32_t err = 0;
    int32_t start = 0;
    int32_t end = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pen_width == 0)
        pen_width = 1;
    start = -(int32_t)(pen_width / 2u);
    end = start + (int32_t)pen_width;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    dx = rdp_gdi_backend_abs_i32(x1 - x0);
    dy = -rdp_gdi_backend_abs_i32(y1 - y0);
    sx = x0 < x1 ? 1 : -1;
    sy = y0 < y1 ? 1 : -1;
    err = dx + dy;
    for (;;)
    {
        int32_t px = 0;
        int32_t py = 0;
        int32_t e2 = 0;

        for (py = start; py < end; py++)
        {
            for (px = start; px < end; px++)
            {
                int32_t draw_x = x0 + px;
                int32_t draw_y = y0 + py;

                if (!rdp_gdi_backend_point_visible(surface, draw_x, draw_y, clip))
                    continue;
                rdp_gdi_backend_put_pixel(mapping.writable_pixels,
                                          mapping.stride,
                                          (uint32_t)draw_x,
                                          (uint32_t)draw_y,
                                          color);
                rdp_gdi_backend_expand_dirty((uint32_t)draw_x,
                                             (uint32_t)draw_y,
                                             dirty_left,
                                             dirty_top,
                                             dirty_right,
                                             dirty_bottom);
            }
        }
        if (x0 == x1 && y0 == y1)
            break;
        e2 = 2 * err;
        if (e2 >= dy)
        {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y0 += sy;
        }
    }
    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

static int rdp_gdi_backend_polygon_inside(const rdp_gdi_backend_point* points,
                                          uint32_t count,
                                          int32_t x,
                                          int32_t y,
                                          uint32_t fill_mode)
{
    uint32_t i = 0;
    uint32_t j = 0;
    int alternate = 0;
    int winding = 0;
    int64_t px2 = ((int64_t)x * 2) + 1;
    int64_t py2 = ((int64_t)y * 2) + 1;

    if (!points || count < 3)
        return 0;
    j = count - 1u;
    for (i = 0; i < count; i++)
    {
        int64_t xi2 = (int64_t)points[i].x * 2;
        int64_t yi2 = (int64_t)points[i].y * 2;
        int64_t xj2 = (int64_t)points[j].x * 2;
        int64_t yj2 = (int64_t)points[j].y * 2;

        if ((yi2 > py2) != (yj2 > py2))
        {
            int64_t lhs = (px2 - xi2) * (yj2 - yi2);
            int64_t rhs = (xj2 - xi2) * (py2 - yi2);
            int crosses = yj2 > yi2 ? lhs < rhs : lhs > rhs;

            if (crosses)
            {
                alternate = !alternate;
                winding += yj2 > yi2 ? 1 : -1;
            }
        }
        j = i;
    }
    if (fill_mode == 2u)
        return winding != 0;
    return alternate;
}

static librdp_status rdp_gdi_backend_software_fill_polygon(librdp_surface* surface,
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
    librdp_surface_mapping mapping;
    uint32_t i = 0;
    int32_t x = 0;
    int32_t y = 0;
    int32_t min_x = INT32_MAX;
    int32_t min_y = INT32_MAX;
    int32_t max_x = INT32_MIN;
    int32_t max_y = INT32_MIN;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || !points || count < 3 || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < count; i++)
    {
        if (points[i].x < min_x)
            min_x = points[i].x;
        if (points[i].x > max_x)
            max_x = points[i].x;
        if (points[i].y < min_y)
            min_y = points[i].y;
        if (points[i].y > max_y)
            max_y = points[i].y;
    }
    if (min_x < 0)
        min_x = 0;
    if (min_y < 0)
        min_y = 0;
    if (max_x >= (int32_t)librdp_surface_width(surface))
        max_x = (int32_t)librdp_surface_width(surface) - 1;
    if (max_y >= (int32_t)librdp_surface_height(surface))
        max_y = (int32_t)librdp_surface_height(surface) - 1;
    if (min_x > max_x || min_y > max_y)
        return LIBRDP_STATUS_OK;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (y = min_y; y <= max_y; y++)
    {
        for (x = min_x; x <= max_x; x++)
        {
            if (!rdp_gdi_backend_point_visible(surface, x, y, clip) ||
                !rdp_gdi_backend_polygon_inside(points, count, x, y, fill_mode))
                continue;
            rdp_gdi_backend_put_pixel(mapping.writable_pixels, mapping.stride, (uint32_t)x, (uint32_t)y, color);
            rdp_gdi_backend_expand_dirty((uint32_t)x,
                                         (uint32_t)y,
                                         dirty_left,
                                         dirty_top,
                                         dirty_right,
                                         dirty_bottom);
        }
    }
    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

static librdp_status rdp_gdi_backend_software_fill_ellipse(librdp_surface* surface,
                                                           int32_t x,
                                                           int32_t y,
                                                           uint32_t width,
                                                           uint32_t height,
                                                           uint32_t color,
                                                           const rdp_gdi_backend_clip* clip)
{
    librdp_surface_mapping mapping;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t px = 0;
    uint32_t py = 0;
    double ellipse_width = 0.0;
    double ellipse_height = 0.0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || width == 0 || height == 0 || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(surface);
    surface_height = librdp_surface_height(surface);
    if (x >= (int32_t)surface_width || y >= (int32_t)surface_height ||
        (int64_t)x + width <= 0 || (int64_t)y + height <= 0)
        return LIBRDP_STATUS_OK;
    ellipse_width = (double)width;
    ellipse_height = (double)height;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (py = 0; py < height; py++)
    {
        for (px = 0; px < width; px++)
        {
            int32_t absolute_x = x + (int32_t)px;
            int32_t absolute_y = y + (int32_t)py;
            double dx = (((double)absolute_x - (double)x) + 0.5) * 2.0 - ellipse_width;
            double dy = (((double)absolute_y - (double)y) + 0.5) * 2.0 - ellipse_height;

            if (!rdp_gdi_backend_point_visible(surface, absolute_x, absolute_y, clip) ||
                ((dx * dx) / (ellipse_width * ellipse_width) +
                 (dy * dy) / (ellipse_height * ellipse_height)) > 0.25)
                continue;
            rdp_gdi_backend_put_pixel(mapping.writable_pixels,
                                      mapping.stride,
                                      (uint32_t)absolute_x,
                                      (uint32_t)absolute_y,
                                      color);
        }
    }
    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

/*
 * Draws an ellipse outline by evaluating a bounded annulus inside the decoded
 * rectangle. This keeps the software backend deterministic and avoids platform
 * drawing differences for fallback paths.
 */
static librdp_status rdp_gdi_backend_software_draw_ellipse(librdp_surface* surface,
                                                           int32_t x,
                                                           int32_t y,
                                                           uint32_t width,
                                                           uint32_t height,
                                                           uint32_t pen_width,
                                                           uint32_t color,
                                                           const rdp_gdi_backend_clip* clip)
{
    librdp_surface_mapping mapping;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;
    uint32_t px = 0;
    uint32_t py = 0;
    double ellipse_width = 0.0;
    double ellipse_height = 0.0;
    double tolerance = 0.0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || width == 0 || height == 0 || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(surface);
    surface_height = librdp_surface_height(surface);
    if (x >= (int32_t)surface_width || y >= (int32_t)surface_height ||
        (int64_t)x + width <= 0 || (int64_t)y + height <= 0)
        return LIBRDP_STATUS_OK;
    if (pen_width == 0)
        pen_width = 1;
    ellipse_width = (double)width;
    ellipse_height = (double)height;
    tolerance = (double)pen_width / (double)(width < height ? width : height);
    if (tolerance < 0.02)
        tolerance = 0.02;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (py = 0; py < height; py++)
    {
        for (px = 0; px < width; px++)
        {
            int32_t absolute_x = x + (int32_t)px;
            int32_t absolute_y = y + (int32_t)py;
            double dx = (((double)absolute_x - (double)x) + 0.5) * 2.0 - ellipse_width;
            double dy = (((double)absolute_y - (double)y) + 0.5) * 2.0 - ellipse_height;
            double distance = (dx * dx) / (ellipse_width * ellipse_width) +
                              (dy * dy) / (ellipse_height * ellipse_height);
            double delta = distance - 0.25;

            if (delta < 0.0)
                delta = -delta;
            if (!rdp_gdi_backend_point_visible(surface, absolute_x, absolute_y, clip) ||
                delta > tolerance)
                continue;
            rdp_gdi_backend_put_pixel(mapping.writable_pixels,
                                      mapping.stride,
                                      (uint32_t)absolute_x,
                                      (uint32_t)absolute_y,
                                      color);
        }
    }
    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

librdp_status rdp_gdi_backend_query(rdp_gdi_backend_kind backend, rdp_gdi_backend_caps* caps)
{
    if (!caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(caps, 0, sizeof(*caps));
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_query(caps);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_query(caps);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_query(caps);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_gdi_backend_fill_rect(rdp_gdi_backend_kind backend,
                                        librdp_surface* surface,
                                        uint32_t x,
                                        uint32_t y,
                                        uint32_t width,
                                        uint32_t height,
                                        uint32_t color)
{
    if (!rdp_gdi_backend_rect_valid(surface, x, y, width, height))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_fill_rect(surface, x, y, width, height, color);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_fill_rect(surface, x, y, width, height, color);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_fill_rect(surface, x, y, width, height, color);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_gdi_backend_blit_bgra32(rdp_gdi_backend_kind backend,
                                          librdp_surface* surface,
                                          uint32_t x,
                                          uint32_t y,
                                          uint32_t width,
                                          uint32_t height,
                                          const uint8_t* pixels,
                                          size_t stride)
{
    if (!rdp_gdi_backend_rect_valid(surface, x, y, width, height) ||
        !pixels || stride < (size_t)width * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_blit_bgra32(surface, x, y, width, height, pixels, stride);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_blit_bgra32(surface, x, y, width, height, pixels, stride);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_blit_bgra32(surface, x, y, width, height, pixels, stride);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_gdi_backend_copy_rect(rdp_gdi_backend_kind backend,
                                        librdp_surface* surface,
                                        uint32_t src_x,
                                        uint32_t src_y,
                                        uint32_t dst_x,
                                        uint32_t dst_y,
                                        uint32_t width,
                                        uint32_t height)
{
    if (!rdp_gdi_backend_rect_valid(surface, src_x, src_y, width, height) ||
        !rdp_gdi_backend_rect_valid(surface, dst_x, dst_y, width, height))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_copy_rect(surface, src_x, src_y, dst_x, dst_y, width, height);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_copy_rect(surface, src_x, src_y, dst_x, dst_y, width, height);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_copy_rect(surface, src_x, src_y, dst_x, dst_y, width, height);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_gdi_backend_draw_line(rdp_gdi_backend_kind backend,
                                        librdp_surface* surface,
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
    if (!surface || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_draw_line(surface,
                                                      x0,
                                                      y0,
                                                      x1,
                                                      y1,
                                                      pen_width,
                                                      color,
                                                      clip,
                                                      dirty_left,
                                                      dirty_top,
                                                      dirty_right,
                                                      dirty_bottom);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_draw_line(surface,
                                                   x0,
                                                   y0,
                                                   x1,
                                                   y1,
                                                   pen_width,
                                                   color,
                                                   clip,
                                                   dirty_left,
                                                   dirty_top,
                                                   dirty_right,
                                                   dirty_bottom);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_draw_line(surface,
                                                    x0,
                                                    y0,
                                                    x1,
                                                    y1,
                                                    pen_width,
                                                    color,
                                                    clip,
                                                    dirty_left,
                                                    dirty_top,
                                                    dirty_right,
                                                    dirty_bottom);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_gdi_backend_fill_polygon(rdp_gdi_backend_kind backend,
                                           librdp_surface* surface,
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
    if (!surface || !points || count < 3 || librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_fill_polygon(surface,
                                                         points,
                                                         count,
                                                         fill_mode,
                                                         color,
                                                         clip,
                                                         dirty_left,
                                                         dirty_top,
                                                         dirty_right,
                                                         dirty_bottom);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_fill_polygon(surface,
                                                      points,
                                                      count,
                                                      fill_mode,
                                                      color,
                                                      clip,
                                                      dirty_left,
                                                      dirty_top,
                                                      dirty_right,
                                                      dirty_bottom);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_fill_polygon(surface,
                                                       points,
                                                       count,
                                                       fill_mode,
                                                       color,
                                                       clip,
                                                       dirty_left,
                                                       dirty_top,
                                                       dirty_right,
                                                       dirty_bottom);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

librdp_status rdp_gdi_backend_fill_ellipse(rdp_gdi_backend_kind backend,
                                           librdp_surface* surface,
                                           int32_t x,
                                           int32_t y,
                                           uint32_t width,
                                           uint32_t height,
                                           uint32_t color,
                                           const rdp_gdi_backend_clip* clip)
{
    if (!surface || width == 0 || height == 0 ||
        librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_fill_ellipse(surface, x, y, width, height, color, clip);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_fill_ellipse(surface, x, y, width, height, color, clip);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_fill_ellipse(surface, x, y, width, height, color, clip);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

/*
 * Dispatches an outline ellipse to the selected backend. The public session
 * renderer uses this only for source-copy vector records, so unsupported native
 * paths can cleanly fall back to the deterministic software backend.
 */
librdp_status rdp_gdi_backend_draw_ellipse(rdp_gdi_backend_kind backend,
                                           librdp_surface* surface,
                                           int32_t x,
                                           int32_t y,
                                           uint32_t width,
                                           uint32_t height,
                                           uint32_t pen_width,
                                           uint32_t color,
                                           const rdp_gdi_backend_clip* clip)
{
    if (!surface || width == 0 || height == 0 ||
        librdp_surface_format(surface) != LIBRDP_PIXEL_FORMAT_BGRA32)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (backend)
    {
        case RDP_GDI_BACKEND_SOFTWARE:
            return rdp_gdi_backend_software_draw_ellipse(surface, x, y, width, height, pen_width, color, clip);
        case RDP_GDI_BACKEND_CAIRO:
            return rdp_gdi_backend_cairo_draw_ellipse(surface, x, y, width, height, pen_width, color, clip);
        case RDP_GDI_BACKEND_QUARTZ:
            return rdp_gdi_backend_quartz_draw_ellipse(surface, x, y, width, height, pen_width, color, clip);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

static librdp_status rdp_gdi_backend_gdiplus_read_rect(const uint8_t* data,
                                                       size_t length,
                                                       int compressed,
                                                       int32_t* x,
                                                       int32_t* y,
                                                       uint32_t* width,
                                                       uint32_t* height,
                                                       size_t* used)
{
    if (!data || !x || !y || !width || !height || !used)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (compressed)
    {
        int16_t raw_width = 0;
        int16_t raw_height = 0;

        if (length < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        raw_width = rdp_gdi_backend_read_i16_le(data + 4u);
        raw_height = rdp_gdi_backend_read_i16_le(data + 6u);
        if (raw_width <= 0 || raw_height <= 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *x = rdp_gdi_backend_read_i16_le(data);
        *y = rdp_gdi_backend_read_i16_le(data + 2u);
        *width = (uint32_t)raw_width;
        *height = (uint32_t)raw_height;
        *used = 8u;
        return LIBRDP_STATUS_OK;
    }
    else
    {
        float raw_x = 0.0f;
        float raw_y = 0.0f;
        float raw_width = 0.0f;
        float raw_height = 0.0f;

        if (length < 16u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        raw_x = rdp_gdi_backend_read_float_le(data);
        raw_y = rdp_gdi_backend_read_float_le(data + 4u);
        raw_width = rdp_gdi_backend_read_float_le(data + 8u);
        raw_height = rdp_gdi_backend_read_float_le(data + 12u);
        if (raw_width <= 0.0f || raw_height <= 0.0f ||
            raw_width > 2147483647.0f || raw_height > 2147483647.0f ||
            raw_x < -2147483648.0f || raw_x > 2147483647.0f ||
            raw_y < -2147483648.0f || raw_y > 2147483647.0f)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *x = (int32_t)raw_x;
        *y = (int32_t)raw_y;
        *width = (uint32_t)raw_width;
        *height = (uint32_t)raw_height;
        *used = 16u;
        return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_gdi_backend_gdiplus_read_point(const uint8_t* data,
                                                        size_t length,
                                                        int compressed,
                                                        rdp_gdi_backend_point* point,
                                                        size_t* used)
{
    if (!data || !point || !used)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (compressed)
    {
        if (length < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        point->x = rdp_gdi_backend_read_i16_le(data);
        point->y = rdp_gdi_backend_read_i16_le(data + 2u);
        *used = 4u;
        return LIBRDP_STATUS_OK;
    }
    else
    {
        float raw_x = 0.0f;
        float raw_y = 0.0f;

        if (length < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        raw_x = rdp_gdi_backend_read_float_le(data);
        raw_y = rdp_gdi_backend_read_float_le(data + 4u);
        if (raw_x < -2147483648.0f || raw_x > 2147483647.0f ||
            raw_y < -2147483648.0f || raw_y > 2147483647.0f)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        point->x = (int32_t)raw_x;
        point->y = (int32_t)raw_y;
        *used = 8u;
        return LIBRDP_STATUS_OK;
    }
}

#define RDP_GDIPLUS_OBJECT_TABLE_SIZE 64u
#define RDP_GDIPLUS_OBJECT_MAX_BYTES (1024u * 1024u)
#define RDP_GDIPLUS_OBJECT_KIND_BRUSH 1u
#define RDP_GDIPLUS_OBJECT_KIND_PEN 2u
#define RDP_GDIPLUS_OBJECT_KIND_GENERIC 3u
#define RDP_GDIPLUS_OBJECT_TYPE_BRUSH 1u
#define RDP_GDIPLUS_OBJECT_TYPE_PEN 2u
#define RDP_GDIPLUS_OBJECT_TYPE_PATH 3u
#define RDP_GDIPLUS_OBJECT_TYPE_REGION 4u
#define RDP_GDIPLUS_OBJECT_TYPE_IMAGE 5u
#define RDP_GDIPLUS_OBJECT_TYPE_FONT 6u
#define RDP_GDIPLUS_OBJECT_TYPE_STRING_FORMAT 7u
#define RDP_GDIPLUS_OBJECT_TYPE_IMAGE_ATTRIBUTES 8u
#define RDP_GDIPLUS_BRUSH_SOLID_COLOR 0u
#define RDP_GDIPLUS_BRUSH_HATCH_FILL 1u
#define RDP_GDIPLUS_BRUSH_TEXTURE_FILL 2u
#define RDP_GDIPLUS_BRUSH_PATH_GRADIENT 3u
#define RDP_GDIPLUS_BRUSH_LINEAR_GRADIENT 4u

#define RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE 0x00000800u
#define RDP_GDIPLUS_PATH_POINT_FLAGS_COMPRESSED 0x00004000u
#define RDP_GDIPLUS_PATH_POINT_TYPE_START 0x00u
#define RDP_GDIPLUS_PATH_POINT_TYPE_LINE 0x01u
#define RDP_GDIPLUS_PATH_POINT_TYPE_BEZIER 0x03u
#define RDP_GDIPLUS_PATH_POINT_TYPE_CLOSE 0x80u
#define RDP_GDIPLUS_REGION_NODE_EMPTY 0x10000000u
#define RDP_GDIPLUS_REGION_NODE_INFINITE 0x10000001u
#define RDP_GDIPLUS_REGION_NODE_RECT 0x10000002u
#define RDP_GDIPLUS_REGION_NODE_PATH 0x10000003u
#define RDP_GDIPLUS_IMAGE_TYPE_BITMAP 1u
#define RDP_GDIPLUS_BITMAP_DATA_PIXEL 0u
#define RDP_GDIPLUS_PIXEL_FORMAT_32BPP_ARGB 0x0026200au
#define RDP_GDIPLUS_PIXEL_FORMAT_32BPP_PARGB 0x000e200bu
#define RDP_GDIPLUS_PIXEL_FORMAT_32BPP_RGB 0x00022009u
#define RDP_GDIPLUS_MAX_PATH_POINTS 4096u
#define RDP_GDIPLUS_MAX_FLATTENED_POINTS (RDP_GDIPLUS_MAX_PATH_POINTS * 16u)
#define RDP_GDIPLUS_STATE_STACK_SIZE 16u
#define RDP_GDIPLUS_TEXT_CELL_WIDTH 6u
#define RDP_GDIPLUS_TEXT_CELL_HEIGHT 8u

#define RDP_GDIPLUS_RECORD_HEADER 0x4001u
#define RDP_GDIPLUS_RECORD_END_OF_FILE 0x4002u
#define RDP_GDIPLUS_RECORD_COMMENT 0x4003u
#define RDP_GDIPLUS_RECORD_GET_DC 0x4004u
#define RDP_GDIPLUS_RECORD_MULTIFORMAT_START 0x4005u
#define RDP_GDIPLUS_RECORD_MULTIFORMAT_SECTION 0x4006u
#define RDP_GDIPLUS_RECORD_MULTIFORMAT_END 0x4007u
#define RDP_GDIPLUS_RECORD_OBJECT 0x4008u
#define RDP_GDIPLUS_RECORD_CLEAR 0x4009u
#define RDP_GDIPLUS_RECORD_FILL_RECTS 0x400au
#define RDP_GDIPLUS_RECORD_DRAW_RECTS 0x400bu
#define RDP_GDIPLUS_RECORD_FILL_POLYGON 0x400cu
#define RDP_GDIPLUS_RECORD_DRAW_LINES 0x400du
#define RDP_GDIPLUS_RECORD_FILL_ELLIPSE 0x400eu
#define RDP_GDIPLUS_RECORD_DRAW_ELLIPSE 0x400fu
#define RDP_GDIPLUS_RECORD_FILL_PIE 0x4010u
#define RDP_GDIPLUS_RECORD_DRAW_PIE 0x4011u
#define RDP_GDIPLUS_RECORD_DRAW_ARC 0x4012u
#define RDP_GDIPLUS_RECORD_FILL_REGION 0x4013u
#define RDP_GDIPLUS_RECORD_FILL_PATH 0x4014u
#define RDP_GDIPLUS_RECORD_DRAW_PATH 0x4015u
#define RDP_GDIPLUS_RECORD_FILL_CLOSED_CURVE 0x4016u
#define RDP_GDIPLUS_RECORD_DRAW_CLOSED_CURVE 0x4017u
#define RDP_GDIPLUS_RECORD_DRAW_CURVE 0x4018u
#define RDP_GDIPLUS_RECORD_DRAW_BEZIERS 0x4019u
#define RDP_GDIPLUS_RECORD_DRAW_IMAGE 0x401au
#define RDP_GDIPLUS_RECORD_DRAW_IMAGE_POINTS 0x401bu
#define RDP_GDIPLUS_RECORD_DRAW_STRING 0x401cu
#define RDP_GDIPLUS_RECORD_SET_RENDERING_ORIGIN 0x401du
#define RDP_GDIPLUS_RECORD_SET_ANTI_ALIAS_MODE 0x401eu
#define RDP_GDIPLUS_RECORD_SET_TEXT_RENDERING_HINT 0x401fu
#define RDP_GDIPLUS_RECORD_SET_TEXT_CONTRAST 0x4020u
#define RDP_GDIPLUS_RECORD_SET_INTERPOLATION_MODE 0x4021u
#define RDP_GDIPLUS_RECORD_SET_PIXEL_OFFSET_MODE 0x4022u
#define RDP_GDIPLUS_RECORD_SET_COMPOSITING_MODE 0x4023u
#define RDP_GDIPLUS_RECORD_SET_COMPOSITING_QUALITY 0x4024u
#define RDP_GDIPLUS_RECORD_SAVE 0x4025u
#define RDP_GDIPLUS_RECORD_RESTORE 0x4026u
#define RDP_GDIPLUS_RECORD_BEGIN_CONTAINER 0x4027u
#define RDP_GDIPLUS_RECORD_BEGIN_CONTAINER_NO_PARAMS 0x4028u
#define RDP_GDIPLUS_RECORD_END_CONTAINER 0x4029u
#define RDP_GDIPLUS_RECORD_SET_WORLD_TRANSFORM 0x402au
#define RDP_GDIPLUS_RECORD_RESET_WORLD_TRANSFORM 0x402bu
#define RDP_GDIPLUS_RECORD_MULTIPLY_WORLD_TRANSFORM 0x402cu
#define RDP_GDIPLUS_RECORD_TRANSLATE_WORLD_TRANSFORM 0x402du
#define RDP_GDIPLUS_RECORD_SCALE_WORLD_TRANSFORM 0x402eu
#define RDP_GDIPLUS_RECORD_ROTATE_WORLD_TRANSFORM 0x402fu
#define RDP_GDIPLUS_RECORD_SET_PAGE_TRANSFORM 0x4030u
#define RDP_GDIPLUS_RECORD_RESET_CLIP 0x4031u
#define RDP_GDIPLUS_RECORD_SET_CLIP_RECT 0x4032u
#define RDP_GDIPLUS_RECORD_SET_CLIP_PATH 0x4033u
#define RDP_GDIPLUS_RECORD_SET_CLIP_REGION 0x4034u
#define RDP_GDIPLUS_RECORD_OFFSET_CLIP 0x4035u
#define RDP_GDIPLUS_RECORD_DRAW_DRIVER_STRING 0x4036u
#define RDP_GDIPLUS_RECORD_STROKE_FILL_PATH 0x4037u
#define RDP_GDIPLUS_RECORD_SERIALIZABLE_OBJECT 0x4038u
#define RDP_GDIPLUS_RECORD_SET_TS_GRAPHICS 0x4039u
#define RDP_GDIPLUS_RECORD_SET_TS_CLIP 0x403au
#define RDP_GDIPLUS_RECORD_FLAG_DIRECT_COLOR 0x8000u
#define RDP_GDIPLUS_RECORD_FLAG_COMPRESSED_POINTS 0x4000u
#define RDP_GDIPLUS_RECORD_FLAG_CLOSE_OR_WINDING 0x2000u

typedef struct rdp_gdi_backend_gdiplus_object
{
    uint8_t active;
    uint8_t kind;
    uint8_t object_type;
    uint32_t color;
    uint32_t secondary_color;
    uint32_t pen_width;
    uint32_t brush_type;
    uint32_t hatch_style;
    float brush_rect_x;
    float brush_rect_y;
    float brush_rect_width;
    float brush_rect_height;
    float brush_center_x;
    float brush_center_y;
    uint32_t pen_flags;
    uint32_t pen_start_cap;
    uint32_t pen_end_cap;
    uint32_t pen_line_join;
    uint32_t pen_dash_style;
    uint32_t pen_dash_cap;
    uint32_t pen_alignment;
    uint32_t pen_miter_limit;
    uint32_t font_style;
    float font_size;
    uint32_t string_format_flags;
    uint32_t image_width;
    uint32_t image_height;
    int32_t image_stride;
    uint32_t image_pixel_format;
    uint32_t image_bitmap_type;
    size_t image_pixels_offset;
    uint32_t image_attr_flags;
    uint8_t* data;
    size_t data_len;
} rdp_gdi_backend_gdiplus_object;

typedef struct rdp_gdi_backend_gdiplus_partial_object
{
    uint8_t active;
    uint8_t object_id;
    uint8_t object_type;
    uint32_t expected_size;
    size_t length;
    uint8_t* data;
} rdp_gdi_backend_gdiplus_partial_object;

typedef struct rdp_gdi_backend_gdiplus_state
{
    float transform[6];
    rdp_gdi_backend_clip clip;
    int32_t rendering_origin_x;
    int32_t rendering_origin_y;
    uint32_t anti_alias_mode;
    uint32_t text_rendering_hint;
    uint32_t text_contrast;
    uint32_t interpolation_mode;
    uint32_t pixel_offset_mode;
    uint32_t compositing_mode;
    uint32_t compositing_quality;
    uint32_t page_unit;
    float page_scale;
} rdp_gdi_backend_gdiplus_state;

typedef struct rdp_gdi_backend_gdiplus_context
{
    rdp_gdi_backend_gdiplus_object objects[RDP_GDIPLUS_OBJECT_TABLE_SIZE];
    rdp_gdi_backend_gdiplus_partial_object partial;
    float transform[6];
    rdp_gdi_backend_clip clip;
    int32_t rendering_origin_x;
    int32_t rendering_origin_y;
    uint32_t anti_alias_mode;
    uint32_t text_rendering_hint;
    uint32_t text_contrast;
    uint32_t interpolation_mode;
    uint32_t pixel_offset_mode;
    uint32_t compositing_mode;
    uint32_t compositing_quality;
    uint32_t page_unit;
    float page_scale;
    rdp_gdi_backend_gdiplus_state stack[RDP_GDIPLUS_STATE_STACK_SIZE];
    uint32_t stack_depth;
} rdp_gdi_backend_gdiplus_context;

typedef struct rdp_gdi_backend_gdiplus_path
{
    uint32_t count;
    rdp_gdi_backend_point* points;
    uint8_t* types;
} rdp_gdi_backend_gdiplus_path;

static void rdp_gdi_backend_gdiplus_apply_compositing(
    const rdp_gdi_backend_gdiplus_context* context,
    uint32_t* color);

static void rdp_gdi_backend_gdiplus_transform_identity(float transform[6])
{
    if (!transform)
        return;
    transform[0] = 1.0f;
    transform[1] = 0.0f;
    transform[2] = 0.0f;
    transform[3] = 1.0f;
    transform[4] = 0.0f;
    transform[5] = 0.0f;
}

static void rdp_gdi_backend_gdiplus_object_clear(rdp_gdi_backend_gdiplus_object* object)
{
    if (!object)
        return;
    free(object->data);
    memset(object, 0, sizeof(*object));
}

static void rdp_gdi_backend_gdiplus_context_free(rdp_gdi_backend_gdiplus_context* context)
{
    size_t i = 0;

    if (!context)
        return;
    for (i = 0; i < RDP_GDIPLUS_OBJECT_TABLE_SIZE; i++)
        rdp_gdi_backend_gdiplus_object_clear(&context->objects[i]);
    free(context->partial.data);
    memset(context, 0, sizeof(*context));
}

static void rdp_gdi_backend_gdiplus_context_init(rdp_gdi_backend_gdiplus_context* context)
{
    if (!context)
        return;
    memset(context, 0, sizeof(*context));
    rdp_gdi_backend_gdiplus_transform_identity(context->transform);
    context->page_scale = 1.0f;
}

static void rdp_gdi_backend_gdiplus_state_capture(const rdp_gdi_backend_gdiplus_context* context,
                                                  rdp_gdi_backend_gdiplus_state* state)
{
    if (!context || !state)
        return;
    memcpy(state->transform, context->transform, sizeof(state->transform));
    state->clip = context->clip;
    state->rendering_origin_x = context->rendering_origin_x;
    state->rendering_origin_y = context->rendering_origin_y;
    state->anti_alias_mode = context->anti_alias_mode;
    state->text_rendering_hint = context->text_rendering_hint;
    state->text_contrast = context->text_contrast;
    state->interpolation_mode = context->interpolation_mode;
    state->pixel_offset_mode = context->pixel_offset_mode;
    state->compositing_mode = context->compositing_mode;
    state->compositing_quality = context->compositing_quality;
    state->page_unit = context->page_unit;
    state->page_scale = context->page_scale;
}

static void rdp_gdi_backend_gdiplus_state_restore(rdp_gdi_backend_gdiplus_context* context,
                                                  const rdp_gdi_backend_gdiplus_state* state)
{
    if (!context || !state)
        return;
    memcpy(context->transform, state->transform, sizeof(context->transform));
    context->clip = state->clip;
    context->rendering_origin_x = state->rendering_origin_x;
    context->rendering_origin_y = state->rendering_origin_y;
    context->anti_alias_mode = state->anti_alias_mode;
    context->text_rendering_hint = state->text_rendering_hint;
    context->text_contrast = state->text_contrast;
    context->interpolation_mode = state->interpolation_mode;
    context->pixel_offset_mode = state->pixel_offset_mode;
    context->compositing_mode = state->compositing_mode;
    context->compositing_quality = state->compositing_quality;
    context->page_unit = state->page_unit;
    context->page_scale = state->page_scale;
}

static void rdp_gdi_backend_gdiplus_path_free(rdp_gdi_backend_gdiplus_path* path)
{
    if (!path)
        return;
    free(path->points);
    free(path->types);
    memset(path, 0, sizeof(*path));
}

static int rdp_gdi_backend_gdiplus_object_fields(uint16_t flags,
                                                 uint8_t* object_id,
                                                 uint8_t* object_type)
{
    uint16_t raw_id = flags & 0x00ffu;

    if (!object_id || !object_type || raw_id >= RDP_GDIPLUS_OBJECT_TABLE_SIZE)
        return 0;
    *object_id = (uint8_t)raw_id;
    *object_type = (uint8_t)((flags >> 8u) & 0x7fu);
    return 1;
}

static int rdp_gdi_backend_gdiplus_parse_solid_brush(const uint8_t* data,
                                                     size_t length,
                                                     uint32_t* color)
{
    uint32_t brush_type = 0;

    if (!data || !color || length < 12u)
        return 0;
    brush_type = rdp_gdi_backend_read_u32_le(data + 4u);
    if (brush_type != 0)
        return 0;
    *color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(data + 8u));
    return 1;
}

static void rdp_gdi_backend_gdiplus_parse_brush_object(rdp_gdi_backend_gdiplus_object* object)
{
    uint32_t brush_type = 0u;

    if (!object || !object->data || object->data_len < 12u)
        return;
    brush_type = rdp_gdi_backend_read_u32_le(object->data + 4u);
    object->kind = RDP_GDIPLUS_OBJECT_KIND_BRUSH;
    object->brush_type = brush_type;
    object->pen_width = 1u;
    object->secondary_color = object->color;
    if (brush_type == RDP_GDIPLUS_BRUSH_SOLID_COLOR)
    {
        object->color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 8u));
        object->secondary_color = object->color;
        return;
    }
    if (brush_type == RDP_GDIPLUS_BRUSH_HATCH_FILL && object->data_len >= 20u)
    {
        object->hatch_style = rdp_gdi_backend_read_u32_le(object->data + 8u);
        object->color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 12u));
        object->secondary_color =
            rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 16u));
        return;
    }
    if (brush_type == RDP_GDIPLUS_BRUSH_TEXTURE_FILL)
    {
        if (object->data_len >= 20u)
        {
            object->hatch_style = rdp_gdi_backend_read_u32_le(object->data + 8u);
            object->color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 12u));
            object->secondary_color =
                rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 16u));
        }
        else
        {
            object->color = 0xff808080u;
            object->secondary_color = 0xffffffffu;
        }
        return;
    }
    if (brush_type == RDP_GDIPLUS_BRUSH_PATH_GRADIENT && object->data_len >= 32u)
    {
        object->hatch_style = rdp_gdi_backend_read_u32_le(object->data + 8u);
        object->color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 12u));
        object->brush_center_x = rdp_gdi_backend_read_float_le(object->data + 16u);
        object->brush_center_y = rdp_gdi_backend_read_float_le(object->data + 20u);
        object->secondary_color =
            rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 28u));
        return;
    }
    if (brush_type == RDP_GDIPLUS_BRUSH_LINEAR_GRADIENT && object->data_len >= 36u)
    {
        object->hatch_style = rdp_gdi_backend_read_u32_le(object->data + 8u);
        object->brush_rect_x = rdp_gdi_backend_read_float_le(object->data + 12u);
        object->brush_rect_y = rdp_gdi_backend_read_float_le(object->data + 16u);
        object->brush_rect_width = rdp_gdi_backend_read_float_le(object->data + 20u);
        object->brush_rect_height = rdp_gdi_backend_read_float_le(object->data + 24u);
        object->color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 28u));
        object->secondary_color =
            rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + 32u));
        return;
    }
    object->color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(object->data + object->data_len - 4u));
    object->secondary_color = object->color ^ 0x00ffffffu;
}

/*
 * Purpose: normalize an EMF+ pen object into the internal pen metadata used by
 * line and outline renderers. Invariants: every optional pen block advances the
 * brush offset only after its declared length is validated. Failure policy:
 * malformed flags, dash arrays, compound arrays or embedded brushes leave the
 * object untyped so callers can count an unsupported object without reading
 * past the untrusted payload.
 */
static int rdp_gdi_backend_gdiplus_parse_solid_pen(const uint8_t* data,
                                                   size_t length,
                                                   rdp_gdi_backend_gdiplus_object* object)
{
    uint32_t object_type = 0;
    uint32_t pen_flags = 0;
    float width = 0.0f;
    size_t brush_offset = 20u;
    uint32_t color = 0u;

    if (!data || !object || length < brush_offset + 12u)
        return 0;
    object_type = rdp_gdi_backend_read_u32_le(data + 4u);
    pen_flags = rdp_gdi_backend_read_u32_le(data + 8u);
    if (object_type != 0)
        return 0;
    object->pen_flags = pen_flags;
    if ((pen_flags & 0x00000001u) != 0)
    {
        if (length < brush_offset + 24u)
            return 0;
        object->pen_start_cap = rdp_gdi_backend_read_u32_le(data + brush_offset);
        object->pen_end_cap = rdp_gdi_backend_read_u32_le(data + brush_offset + 4u);
        object->pen_line_join = rdp_gdi_backend_read_u32_le(data + brush_offset + 8u);
        brush_offset += 24u;
    }
    if ((pen_flags & 0x00000002u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_miter_limit = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000004u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_line_join = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000008u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_start_cap = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000010u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_end_cap = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000020u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_dash_cap = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000040u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_dash_style = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000080u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_alignment = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000100u) != 0)
    {
        uint32_t dash_count = 0u;

        if (length < brush_offset + 4u)
            return 0;
        dash_count = rdp_gdi_backend_read_u32_le(data + brush_offset);
        if (dash_count > 64u || length - brush_offset < 4u + ((size_t)dash_count * 4u))
            return 0;
        brush_offset += 4u + ((size_t)dash_count * 4u);
    }
    if ((pen_flags & 0x00000200u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00000400u) != 0)
    {
        uint32_t compound_count = 0u;

        if (length < brush_offset + 4u)
            return 0;
        compound_count = rdp_gdi_backend_read_u32_le(data + brush_offset);
        if (compound_count > 64u || length - brush_offset < 4u + ((size_t)compound_count * 4u))
            return 0;
        brush_offset += 4u + ((size_t)compound_count * 4u);
    }
    if ((pen_flags & 0x00000800u) != 0)
    {
        if (length < brush_offset + 4u)
            return 0;
        object->pen_dash_style = rdp_gdi_backend_read_u32_le(data + brush_offset);
        brush_offset += 4u;
    }
    if ((pen_flags & 0x00001000u) != 0)
    {
        uint32_t custom_count = 0u;

        if (length < brush_offset + 4u)
            return 0;
        custom_count = rdp_gdi_backend_read_u32_le(data + brush_offset);
        if (custom_count > 64u || length - brush_offset < 4u + ((size_t)custom_count * 4u))
            return 0;
        brush_offset += 4u + ((size_t)custom_count * 4u);
    }
    if (brush_offset > length || length - brush_offset < 12u)
        return 0;
    width = rdp_gdi_backend_read_float_le(data + 16u);
    if (!rdp_gdi_backend_gdiplus_parse_solid_brush(data + brush_offset, length - brush_offset, &color))
    {
        rdp_gdi_backend_gdiplus_object brush;

        memset(&brush, 0, sizeof(brush));
        brush.data = (uint8_t*)(data + brush_offset);
        brush.data_len = length - brush_offset;
        rdp_gdi_backend_gdiplus_parse_brush_object(&brush);
        color = brush.color;
    }
    object->kind = RDP_GDIPLUS_OBJECT_KIND_PEN;
    object->color = color;
    object->secondary_color = color;
    object->pen_width = rdp_gdi_backend_float_to_pen_width(width);
    return 1;
}

static void rdp_gdi_backend_gdiplus_parse_image_object(rdp_gdi_backend_gdiplus_object* object)
{
    uint32_t image_type = 0u;

    if (!object || !object->data || object->data_len < 28u)
        return;
    image_type = rdp_gdi_backend_read_u32_le(object->data + 4u);
    if (image_type != RDP_GDIPLUS_IMAGE_TYPE_BITMAP)
        return;
    object->image_width = rdp_gdi_backend_read_u32_le(object->data + 8u);
    object->image_height = rdp_gdi_backend_read_u32_le(object->data + 12u);
    object->image_stride = (int32_t)rdp_gdi_backend_read_u32_le(object->data + 16u);
    object->image_pixel_format = rdp_gdi_backend_read_u32_le(object->data + 20u);
    object->image_bitmap_type = rdp_gdi_backend_read_u32_le(object->data + 24u);
    object->image_pixels_offset = 28u;
}

static int rdp_gdi_backend_gdiplus_validate_simple_object(rdp_gdi_backend_gdiplus_object* object)
{
    if (!object || !object->data)
        return 0;
    if (object->object_type == RDP_GDIPLUS_OBJECT_TYPE_FONT)
    {
        if (object->data_len < 20u)
            return 0;
        object->font_size = rdp_gdi_backend_read_float_le(object->data + 12u);
        object->font_style = rdp_gdi_backend_read_u32_le(object->data + 16u);
        return object->font_size > 0.0f && object->font_size <= 1024.0f;
    }
    if (object->object_type == RDP_GDIPLUS_OBJECT_TYPE_STRING_FORMAT)
    {
        if (object->data_len < 12u)
            return 0;
        object->string_format_flags = rdp_gdi_backend_read_u32_le(object->data + 8u);
        return 1;
    }
    if (object->object_type == RDP_GDIPLUS_OBJECT_TYPE_IMAGE_ATTRIBUTES)
    {
        if (object->data_len < 8u)
            return 0;
        object->image_attr_flags = rdp_gdi_backend_read_u32_le(object->data + 4u);
        return 1;
    }
    return 1;
}

static int rdp_gdi_backend_gdiplus_store_object_bytes(rdp_gdi_backend_gdiplus_object* object,
                                                      const uint8_t* data,
                                                      size_t length)
{
    if (!object || (!data && length > 0u) || length > RDP_GDIPLUS_OBJECT_MAX_BYTES)
        return 0;
    free(object->data);
    object->data = NULL;
    object->data_len = 0u;
    if (length == 0u)
        return 1;
    object->data = (uint8_t*)malloc(length);
    if (!object->data)
        return 0;
    memcpy(object->data, data, length);
    object->data_len = length;
    return 1;
}

static int rdp_gdi_backend_gdiplus_store_complete_object(rdp_gdi_backend_gdiplus_context* context,
                                                         uint8_t object_id,
                                                         uint8_t object_type,
                                                         const uint8_t* data,
                                                         size_t length)
{
    rdp_gdi_backend_gdiplus_object* object = NULL;
    uint32_t color = 0;

    if (!context || object_id >= RDP_GDIPLUS_OBJECT_TABLE_SIZE || !data ||
        length > RDP_GDIPLUS_OBJECT_MAX_BYTES)
        return 0;
    object = &context->objects[object_id];
    rdp_gdi_backend_gdiplus_object_clear(object);
    if (!rdp_gdi_backend_gdiplus_store_object_bytes(object, data, length))
        return 0;
    object->object_type = object_type;
    object->pen_width = 1u;
    if (object_type == RDP_GDIPLUS_OBJECT_TYPE_BRUSH)
    {
        (void)rdp_gdi_backend_gdiplus_parse_solid_brush(data, length, &color);
        rdp_gdi_backend_gdiplus_parse_brush_object(object);
        object->active = 1u;
        return 1;
    }
    if (object_type == RDP_GDIPLUS_OBJECT_TYPE_PEN)
    {
        if (!rdp_gdi_backend_gdiplus_parse_solid_pen(data, length, object))
        {
            object->kind = RDP_GDIPLUS_OBJECT_KIND_GENERIC;
            object->color = 0;
            object->pen_width = 1u;
            object->active = 1u;
            return 1;
        }
        object->active = 1u;
        return 1;
    }
    if (object_type == RDP_GDIPLUS_OBJECT_TYPE_IMAGE)
    {
        object->kind = RDP_GDIPLUS_OBJECT_KIND_GENERIC;
        rdp_gdi_backend_gdiplus_parse_image_object(object);
        object->active = 1u;
        return 1;
    }
    if (object_type == RDP_GDIPLUS_OBJECT_TYPE_FONT ||
        object_type == RDP_GDIPLUS_OBJECT_TYPE_STRING_FORMAT ||
        object_type == RDP_GDIPLUS_OBJECT_TYPE_IMAGE_ATTRIBUTES)
    {
        if (!rdp_gdi_backend_gdiplus_validate_simple_object(object))
            return 0;
        object->kind = RDP_GDIPLUS_OBJECT_KIND_GENERIC;
        object->active = 1u;
        return 1;
    }
    object->kind = RDP_GDIPLUS_OBJECT_KIND_GENERIC;
    object->color = 0;
    object->pen_width = 1u;
    object->active = 1u;
    return 1;
}

static librdp_status rdp_gdi_backend_gdiplus_partial_append(rdp_gdi_backend_gdiplus_partial_object* partial,
                                                            const uint8_t* payload,
                                                            uint32_t data_size)
{
    if (!partial || !partial->active || (!payload && data_size > 0u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((size_t)data_size > (size_t)partial->expected_size - partial->length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (data_size > 0u)
        memcpy(partial->data + partial->length, payload, data_size);
    partial->length += data_size;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_render_gdiplus_object(rdp_gdi_backend_gdiplus_context* context,
                                                           uint16_t flags,
                                                           const uint8_t* payload,
                                                           uint32_t data_size,
                                                           uint32_t total_object_size,
                                                           int continued,
                                                           uint32_t* unsupported)
{
    uint8_t object_id = 0;
    uint8_t object_type = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || (!payload && data_size > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_gdi_backend_gdiplus_object_fields(flags, &object_id, &object_type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (data_size > RDP_GDIPLUS_OBJECT_MAX_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (continued || context->partial.active)
    {
        if (!context->partial.active)
        {
            if (total_object_size == 0u || total_object_size > RDP_GDIPLUS_OBJECT_MAX_BYTES ||
                data_size > total_object_size)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            context->partial.data = (uint8_t*)malloc(total_object_size);
            if (!context->partial.data)
                return LIBRDP_STATUS_NO_MEMORY;
            context->partial.active = 1u;
            context->partial.object_id = object_id;
            context->partial.object_type = object_type;
            context->partial.expected_size = total_object_size;
            context->partial.length = 0u;
        }
        if (context->partial.object_id != object_id || context->partial.object_type != object_type)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_gdi_backend_gdiplus_partial_append(&context->partial, payload, data_size);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (continued)
            return LIBRDP_STATUS_OK;
        if (context->partial.length != context->partial.expected_size)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (!rdp_gdi_backend_gdiplus_store_complete_object(context,
                                                           object_id,
                                                           object_type,
                                                           context->partial.data,
                                                           context->partial.length) &&
            unsupported)
            (*unsupported)++;
        free(context->partial.data);
        memset(&context->partial, 0, sizeof(context->partial));
        return LIBRDP_STATUS_OK;
    }
    if (!rdp_gdi_backend_gdiplus_store_complete_object(context, object_id, object_type, payload, data_size) &&
        unsupported)
        (*unsupported)++;
    return LIBRDP_STATUS_OK;
}

static void rdp_gdi_backend_gdiplus_apply_compositing(const rdp_gdi_backend_gdiplus_context* context,
                                                      uint32_t* color)
{
    if (!context || !color)
        return;
    if (context->compositing_mode == 1u)
        *color = 0xff000000u | (*color & 0x00ffffffu);
}

static int rdp_gdi_backend_gdiplus_resolve_draw_color(const rdp_gdi_backend_gdiplus_context* context,
                                                      uint16_t flags,
                                                      uint32_t token,
                                                      uint8_t expected_kind,
                                                      uint32_t* color,
                                                      uint32_t* pen_width)
{
    int direct_color = (flags & 0x8000u) != 0;
    uint32_t object_id = token & 0xffu;
    const rdp_gdi_backend_gdiplus_object* object = NULL;

    if (!color || !pen_width)
        return 0;
    if (direct_color)
    {
        *color = rdp_gdi_backend_argb_to_color(token);
        *pen_width = 1u;
        rdp_gdi_backend_gdiplus_apply_compositing(context, color);
        return 1;
    }
    if (!context || object_id >= RDP_GDIPLUS_OBJECT_TABLE_SIZE)
        return 0;
    object = &context->objects[object_id];
    if (!object->active)
        return 0;
    if (object->kind != expected_kind)
    {
        *color = object->color;
        *pen_width = object->pen_width == 0u ? 1u : object->pen_width;
        rdp_gdi_backend_gdiplus_apply_compositing(context, color);
        return object->kind == RDP_GDIPLUS_OBJECT_KIND_GENERIC;
    }
    *color = object->color;
    *pen_width = object->pen_width == 0u ? 1u : object->pen_width;
    rdp_gdi_backend_gdiplus_apply_compositing(context, color);
    return 1;
}

static const rdp_gdi_backend_gdiplus_object* rdp_gdi_backend_gdiplus_get_object(
    const rdp_gdi_backend_gdiplus_context* context,
    uint32_t object_id,
    uint8_t object_type)
{
    const rdp_gdi_backend_gdiplus_object* object = NULL;

    if (!context || object_id >= RDP_GDIPLUS_OBJECT_TABLE_SIZE)
        return NULL;
    object = &context->objects[object_id];
    if (!object->active || object->object_type != object_type)
        return NULL;
    return object;
}

static int32_t rdp_gdi_backend_gdiplus_round_i32(float value)
{
    if (value >= 2147483647.0f)
        return INT32_MAX;
    if (value <= -2147483648.0f)
        return INT32_MIN;
    return value >= 0.0f ? (int32_t)(value + 0.5f) : (int32_t)(value - 0.5f);
}

static void rdp_gdi_backend_gdiplus_transform_point(const float transform[6],
                                                    rdp_gdi_backend_point* point)
{
    float x = 0.0f;
    float y = 0.0f;

    if (!transform || !point)
        return;
    x = ((float)point->x * transform[0]) + ((float)point->y * transform[2]) + transform[4];
    y = ((float)point->x * transform[1]) + ((float)point->y * transform[3]) + transform[5];
    point->x = rdp_gdi_backend_gdiplus_round_i32(x);
    point->y = rdp_gdi_backend_gdiplus_round_i32(y);
}

static void rdp_gdi_backend_gdiplus_transform_context_point(
    const rdp_gdi_backend_gdiplus_context* context,
    rdp_gdi_backend_point* point)
{
    float scale = 1.0f;

    if (!point)
        return;
    if (!context)
        return;
    rdp_gdi_backend_gdiplus_transform_point(context->transform, point);
    scale = context->page_scale > 0.0f ? context->page_scale : 1.0f;
    if (scale != 1.0f)
    {
        point->x = rdp_gdi_backend_gdiplus_round_i32((float)point->x * scale);
        point->y = rdp_gdi_backend_gdiplus_round_i32((float)point->y * scale);
    }
    if (context->pixel_offset_mode == 3u || context->pixel_offset_mode == 4u)
    {
        if (point->x < INT32_MAX)
            point->x++;
        if (point->y < INT32_MAX)
            point->y++;
    }
}

static librdp_status rdp_gdi_backend_gdiplus_transform_rect(const rdp_gdi_backend_gdiplus_context* context,
                                                            int32_t* x,
                                                            int32_t* y,
                                                            uint32_t* width,
                                                            uint32_t* height)
{
    rdp_gdi_backend_point points[4];
    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 0;
    int32_t bottom = 0;
    uint32_t i = 0;

    if (!x || !y || !width || !height || *width == 0u || *height == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    points[0].x = *x;
    points[0].y = *y;
    points[1].x = *x + (int32_t)(*width - 1u);
    points[1].y = *y;
    points[2].x = *x;
    points[2].y = *y + (int32_t)(*height - 1u);
    points[3].x = *x + (int32_t)(*width - 1u);
    points[3].y = *y + (int32_t)(*height - 1u);
    for (i = 0; i < 4u; i++)
        rdp_gdi_backend_gdiplus_transform_context_point(context, &points[i]);
    left = points[0].x;
    right = points[0].x;
    top = points[0].y;
    bottom = points[0].y;
    for (i = 1u; i < 4u; i++)
    {
        if (points[i].x < left)
            left = points[i].x;
        if (points[i].x > right)
            right = points[i].x;
        if (points[i].y < top)
            top = points[i].y;
        if (points[i].y > bottom)
            bottom = points[i].y;
    }
    if (right < left || bottom < top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *x = left;
    *y = top;
    *width = (uint32_t)(right - left + 1);
    *height = (uint32_t)(bottom - top + 1);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_fill_rect_clipped(rdp_gdi_backend_kind backend,
                                                       librdp_surface* surface,
                                                       int32_t x,
                                                       int32_t y,
                                                       uint32_t width,
                                                       uint32_t height,
                                                       uint32_t color,
                                                       const rdp_gdi_backend_clip* clip)
{
    int32_t left = x;
    int32_t top = y;
    int32_t right = 0;
    int32_t bottom = 0;
    uint32_t surface_width = 0;
    uint32_t surface_height = 0;

    if (!surface || width == 0u || height == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(surface);
    surface_height = librdp_surface_height(surface);
    if (width > (uint32_t)INT32_MAX || height > (uint32_t)INT32_MAX ||
        x > INT32_MAX - (int32_t)width || y > INT32_MAX - (int32_t)height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    right = x + (int32_t)width;
    bottom = y + (int32_t)height;
    if (left < 0)
        left = 0;
    if (top < 0)
        top = 0;
    if (right > (int32_t)surface_width)
        right = (int32_t)surface_width;
    if (bottom > (int32_t)surface_height)
        bottom = (int32_t)surface_height;
    if (clip && clip->present)
    {
        if (left < clip->left)
            left = clip->left;
        if (top < clip->top)
            top = clip->top;
        if (right > clip->right + 1)
            right = clip->right + 1;
        if (bottom > clip->bottom + 1)
            bottom = clip->bottom + 1;
    }
    if (left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    return rdp_gdi_backend_fill_rect(backend,
                                     surface,
                                     (uint32_t)left,
                                     (uint32_t)top,
                                     (uint32_t)(right - left),
                                     (uint32_t)(bottom - top),
                                     color);
}

static uint8_t rdp_gdi_backend_gdiplus_mix_u8(uint8_t a, uint8_t b, uint32_t weight)
{
    if (weight > 255u)
        weight = 255u;
    return (uint8_t)((((uint32_t)a * (255u - weight)) + ((uint32_t)b * weight) + 127u) / 255u);
}

static uint32_t rdp_gdi_backend_gdiplus_mix_color(uint32_t start, uint32_t end, uint32_t weight)
{
    uint8_t a = rdp_gdi_backend_gdiplus_mix_u8((uint8_t)((start >> 24u) & 0xffu),
                                               (uint8_t)((end >> 24u) & 0xffu),
                                               weight);
    uint8_t r = rdp_gdi_backend_gdiplus_mix_u8((uint8_t)((start >> 16u) & 0xffu),
                                               (uint8_t)((end >> 16u) & 0xffu),
                                               weight);
    uint8_t g = rdp_gdi_backend_gdiplus_mix_u8((uint8_t)((start >> 8u) & 0xffu),
                                               (uint8_t)((end >> 8u) & 0xffu),
                                               weight);
    uint8_t b = rdp_gdi_backend_gdiplus_mix_u8((uint8_t)(start & 0xffu),
                                               (uint8_t)(end & 0xffu),
                                               weight);

    return ((uint32_t)a << 24u) | ((uint32_t)r << 16u) | ((uint32_t)g << 8u) | (uint32_t)b;
}

/*
 * Purpose: evaluate non-solid EMF+ brushes at a destination pixel. Invariants:
 * hatch and texture phases include the active rendering origin, and gradients
 * clamp interpolation to the stored brush geometry. Failure policy: unknown
 * brush types produce the validated representative color instead of failing
 * mid-fill.
 */
static uint32_t rdp_gdi_backend_gdiplus_sample_brush(
    const rdp_gdi_backend_gdiplus_context* context,
    const rdp_gdi_backend_gdiplus_object* brush,
    int32_t x,
    int32_t y)
{
    int32_t origin_x = context ? context->rendering_origin_x : 0;
    int32_t origin_y = context ? context->rendering_origin_y : 0;
    int32_t sx = x + origin_x;
    int32_t sy = y + origin_y;
    uint32_t weight = 0u;

    if (!brush)
        return 0xff000000u;
    if (brush->brush_type == RDP_GDIPLUS_BRUSH_SOLID_COLOR)
        return brush->color;
    if (brush->brush_type == RDP_GDIPLUS_BRUSH_HATCH_FILL)
    {
        uint32_t style = brush->hatch_style % 8u;
        int foreground = 0;

        if (style == 0u)
            foreground = (sy & 3) == 0;
        else if (style == 1u)
            foreground = (sx & 3) == 0;
        else if (style == 2u)
            foreground = ((sx + sy) & 7) == 0;
        else if (style == 3u)
            foreground = ((sx - sy) & 7) == 0;
        else if (style == 4u)
            foreground = ((sx & 3) == 0) || ((sy & 3) == 0);
        else
            foreground = (((sx >> 2) ^ (sy >> 2) ^ (int32_t)style) & 1) == 0;
        return foreground ? brush->color : brush->secondary_color;
    }
    if (brush->brush_type == RDP_GDIPLUS_BRUSH_TEXTURE_FILL)
    {
        uint32_t cell_x = (uint32_t)((sx >= 0 ? sx : -sx) & 7);
        uint32_t cell_y = (uint32_t)((sy >= 0 ? sy : -sy) & 7);

        return ((cell_x ^ cell_y ^ brush->hatch_style) & 1u) != 0u ? brush->color :
                                                                     brush->secondary_color;
    }
    if (brush->brush_type == RDP_GDIPLUS_BRUSH_LINEAR_GRADIENT)
    {
        float span = brush->brush_rect_width;
        float position = (float)x - brush->brush_rect_x;

        if (!(span > 0.0f))
            span = brush->brush_rect_height;
        if (!(span > 0.0f))
            span = 1.0f;
        if (brush->brush_rect_width <= 0.0f)
            position = (float)y - brush->brush_rect_y;
        if (position <= 0.0f)
            weight = 0u;
        else if (position >= span)
            weight = 255u;
        else
            weight = (uint32_t)((position * 255.0f) / span);
        return rdp_gdi_backend_gdiplus_mix_color(brush->color, brush->secondary_color, weight);
    }
    if (brush->brush_type == RDP_GDIPLUS_BRUSH_PATH_GRADIENT)
    {
        float dx = (float)x - brush->brush_center_x;
        float dy = (float)y - brush->brush_center_y;
        float distance = (dx < 0.0f ? -dx : dx) + (dy < 0.0f ? -dy : dy);

        if (distance >= 64.0f)
            weight = 255u;
        else
            weight = (uint32_t)((distance * 255.0f) / 64.0f);
        return rdp_gdi_backend_gdiplus_mix_color(brush->color, brush->secondary_color, weight);
    }
    return brush->color;
}

/*
 * Purpose: fill a clipped rectangle with a sampled EMF+ brush through the
 * software pixel path. Invariants: destination bounds are clipped before the
 * surface is mapped, and compositing mode is applied to every sampled color.
 * Failure policy: invalid rectangles fail before mapping, while fully clipped
 * rectangles are successful no-ops.
 */
static librdp_status rdp_gdi_backend_fill_rect_brush_clipped(
    librdp_surface* surface,
    int32_t x,
    int32_t y,
    uint32_t width,
    uint32_t height,
    const rdp_gdi_backend_gdiplus_context* context,
    const rdp_gdi_backend_gdiplus_object* brush)
{
    librdp_surface_mapping mapping;
    uint32_t surface_width = 0u;
    uint32_t surface_height = 0u;
    int32_t left = x;
    int32_t top = y;
    int32_t right = 0;
    int32_t bottom = 0;
    int32_t py = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (!surface || !brush || width == 0u || height == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(surface);
    surface_height = librdp_surface_height(surface);
    if (width > (uint32_t)INT32_MAX || height > (uint32_t)INT32_MAX ||
        x > INT32_MAX - (int32_t)width || y > INT32_MAX - (int32_t)height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    right = x + (int32_t)width;
    bottom = y + (int32_t)height;
    if (left < 0)
        left = 0;
    if (top < 0)
        top = 0;
    if (right > (int32_t)surface_width)
        right = (int32_t)surface_width;
    if (bottom > (int32_t)surface_height)
        bottom = (int32_t)surface_height;
    if (context && context->clip.present)
    {
        if (left < context->clip.left)
            left = context->clip.left;
        if (top < context->clip.top)
            top = context->clip.top;
        if (right > context->clip.right + 1)
            right = context->clip.right + 1;
        if (bottom > context->clip.bottom + 1)
            bottom = context->clip.bottom + 1;
    }
    if (left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (py = top; py < bottom; py++)
    {
        int32_t px = 0;

        for (px = left; px < right; px++)
        {
            uint32_t color = rdp_gdi_backend_gdiplus_sample_brush(context, brush, px, py);

            rdp_gdi_backend_gdiplus_apply_compositing(context, &color);
            rdp_gdi_backend_put_pixel(mapping.writable_pixels,
                                      mapping.stride,
                                      (uint32_t)px,
                                      (uint32_t)py,
                                      color);
        }
    }
    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

static librdp_status rdp_gdi_backend_gdiplus_parse_path_object(
    const rdp_gdi_backend_gdiplus_object* object,
    rdp_gdi_backend_gdiplus_path* path)
{
    const uint8_t* data = NULL;
    size_t length = 0;
    uint32_t count = 0;
    uint32_t flags = 0;
    size_t offset = 12u;
    size_t point_size = 0u;
    uint32_t i = 0;
    int32_t current_x = 0;
    int32_t current_y = 0;

    if (!object || !path || object->object_type != RDP_GDIPLUS_OBJECT_TYPE_PATH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    data = object->data;
    length = object->data_len;
    if (!data || length < 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = rdp_gdi_backend_read_u32_le(data + 4u);
    flags = rdp_gdi_backend_read_u32_le(data + 8u);
    if (count == 0u || count > RDP_GDIPLUS_MAX_PATH_POINTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE) != 0u)
        point_size = 2u;
    else
        point_size = (flags & RDP_GDIPLUS_PATH_POINT_FLAGS_COMPRESSED) != 0u ? 4u : 8u;
    if (point_size > (size_t)-1 / count || length < offset + ((size_t)count * point_size) + count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    path->points = (rdp_gdi_backend_point*)calloc(count, sizeof(*path->points));
    path->types = (uint8_t*)calloc(count, sizeof(*path->types));
    if (!path->points || !path->types)
    {
        rdp_gdi_backend_gdiplus_path_free(path);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    path->count = count;
    for (i = 0; i < count; i++)
    {
        if ((flags & RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE) != 0u)
        {
            current_x += (int8_t)data[offset + ((size_t)i * point_size)];
            current_y += (int8_t)data[offset + ((size_t)i * point_size) + 1u];
            path->points[i].x = current_x;
            path->points[i].y = current_y;
        }
        else
        {
            size_t used = 0u;
            librdp_status status =
                rdp_gdi_backend_gdiplus_read_point(data + offset + ((size_t)i * point_size),
                                                   point_size,
                                                   (flags & RDP_GDIPLUS_PATH_POINT_FLAGS_COMPRESSED) != 0u,
                                                   &path->points[i],
                                                   &used);

            if (status != LIBRDP_STATUS_OK)
            {
                rdp_gdi_backend_gdiplus_path_free(path);
                return status;
            }
            (void)used;
        }
    }
    offset += (size_t)count * point_size;
    memcpy(path->types, data + offset, count);
    return LIBRDP_STATUS_OK;
}

static int rdp_gdi_backend_gdiplus_append_flattened_point(rdp_gdi_backend_point* points,
                                                          uint32_t* count,
                                                          uint32_t capacity,
                                                          rdp_gdi_backend_point point)
{
    if (!points || !count || *count >= capacity)
        return 0;
    points[*count] = point;
    (*count)++;
    return 1;
}

/*
 * Purpose: convert an EMF+ path object into the backend polyline/polygon form.
 * Invariants: input points are bounded by the object parser and the output is
 * capped by RDP_GDIPLUS_MAX_FLATTENED_POINTS. Failure policy: malformed or
 * overlarge paths fail before any caller-visible drawing is attempted.
 */
static int rdp_gdi_backend_gdiplus_flatten_path(const rdp_gdi_backend_gdiplus_path* path,
                                                const rdp_gdi_backend_gdiplus_context* context,
                                                rdp_gdi_backend_point** flattened,
                                                uint32_t* flattened_count)
{
    rdp_gdi_backend_point* out = NULL;
    uint32_t out_count = 0u;
    uint32_t i = 0u;
    rdp_gdi_backend_point current;
    rdp_gdi_backend_point subpath_start;
    int have_current = 0;

    if (!path || !flattened || !flattened_count || path->count == 0u ||
        path->count > RDP_GDIPLUS_MAX_PATH_POINTS)
        return 0;
    out = (rdp_gdi_backend_point*)calloc(RDP_GDIPLUS_MAX_FLATTENED_POINTS, sizeof(*out));
    if (!out)
        return 0;
    memset(&current, 0, sizeof(current));
    memset(&subpath_start, 0, sizeof(subpath_start));
    while (i < path->count)
    {
        uint8_t type = path->types[i] & 0x07u;
        uint8_t close = path->types[i] & RDP_GDIPLUS_PATH_POINT_TYPE_CLOSE;
        rdp_gdi_backend_point point = path->points[i];

        rdp_gdi_backend_gdiplus_transform_context_point(context, &point);
        if (type == RDP_GDIPLUS_PATH_POINT_TYPE_START || !have_current)
        {
            current = point;
            subpath_start = point;
            have_current = 1;
            if (!rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                               &out_count,
                                                               RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                               point))
                break;
        }
        else if (type == RDP_GDIPLUS_PATH_POINT_TYPE_BEZIER && i + 2u < path->count)
        {
            rdp_gdi_backend_point p0 = current;
            rdp_gdi_backend_point p1 = point;
            rdp_gdi_backend_point p2 = path->points[i + 1u];
            rdp_gdi_backend_point p3 = path->points[i + 2u];
            uint32_t step = 0u;

            rdp_gdi_backend_gdiplus_transform_context_point(context, &p2);
            rdp_gdi_backend_gdiplus_transform_context_point(context, &p3);
            for (step = 1u; step <= 16u; step++)
            {
                float t = (float)step / 16.0f;
                float mt = 1.0f - t;
                float x = (mt * mt * mt * (float)p0.x) +
                          (3.0f * mt * mt * t * (float)p1.x) +
                          (3.0f * mt * t * t * (float)p2.x) +
                          (t * t * t * (float)p3.x);
                float y = (mt * mt * mt * (float)p0.y) +
                          (3.0f * mt * mt * t * (float)p1.y) +
                          (3.0f * mt * t * t * (float)p2.y) +
                          (t * t * t * (float)p3.y);
                rdp_gdi_backend_point curve_point;

                curve_point.x = rdp_gdi_backend_gdiplus_round_i32(x);
                curve_point.y = rdp_gdi_backend_gdiplus_round_i32(y);
                if (!rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                                   &out_count,
                                                                   RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                                   curve_point))
                    break;
            }
            current = p3;
            close = path->types[i + 2u] & RDP_GDIPLUS_PATH_POINT_TYPE_CLOSE;
            i += 2u;
        }
        else
        {
            if (!rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                               &out_count,
                                                               RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                               point))
                break;
            current = point;
        }
        if (close != 0u && have_current)
        {
            if (!rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                               &out_count,
                                                               RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                               subpath_start))
                break;
            current = subpath_start;
        }
        i++;
    }
    if (out_count == 0u)
    {
        free(out);
        return 0;
    }
    *flattened = out;
    *flattened_count = out_count;
    return 1;
}

static librdp_status rdp_gdi_backend_draw_rect_outline(rdp_gdi_backend_kind backend,
                                                       librdp_surface* surface,
                                                       int32_t x,
                                                       int32_t y,
                                                       uint32_t width,
                                                       uint32_t height,
                                                       uint32_t pen_width,
                                                       uint32_t color,
                                                       const rdp_gdi_backend_clip* clip)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t dirty_left = UINT32_MAX;
    uint32_t dirty_top = UINT32_MAX;
    uint32_t dirty_right = 0;
    uint32_t dirty_bottom = 0;

    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    status = rdp_gdi_backend_draw_line(backend,
                                       surface,
                                       x,
                                       y,
                                       x + (int32_t)(width - 1u),
                                       y,
                                       pen_width,
                                       color,
                                       clip,
                                       &dirty_left,
                                       &dirty_top,
                                       &dirty_right,
                                       &dirty_bottom);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_gdi_backend_draw_line(backend,
                                       surface,
                                       x,
                                       y + (int32_t)(height - 1u),
                                       x + (int32_t)(width - 1u),
                                       y + (int32_t)(height - 1u),
                                       pen_width,
                                       color,
                                       clip,
                                       &dirty_left,
                                       &dirty_top,
                                       &dirty_right,
                                       &dirty_bottom);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_gdi_backend_draw_line(backend,
                                       surface,
                                       x,
                                       y,
                                       x,
                                       y + (int32_t)(height - 1u),
                                       pen_width,
                                       color,
                                       clip,
                                       &dirty_left,
                                       &dirty_top,
                                       &dirty_right,
                                       &dirty_bottom);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_gdi_backend_draw_line(backend,
                                     surface,
                                     x + (int32_t)(width - 1u),
                                     y,
                                     x + (int32_t)(width - 1u),
                                     y + (int32_t)(height - 1u),
                                     pen_width,
                                     color,
                                     clip,
                                     &dirty_left,
                                     &dirty_top,
                                     &dirty_right,
                                     &dirty_bottom);
}

static librdp_status rdp_gdi_backend_render_gdiplus_clear(rdp_gdi_backend_kind backend,
                                                          librdp_surface* surface,
                                                          const uint8_t* payload,
                                                          uint32_t data_size,
                                                          uint32_t* rasterized)
{
    uint32_t color = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (data_size != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    color = rdp_gdi_backend_argb_to_color(rdp_gdi_backend_read_u32_le(payload));
    status = rdp_gdi_backend_fill_rect(backend,
                                       surface,
                                       0,
                                       0,
                                       librdp_surface_width(surface),
                                       librdp_surface_height(surface),
                                       color);
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

static size_t rdp_gdi_backend_gdiplus_point_record_size(uint16_t flags)
{
    if ((flags & RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE) != 0u)
        return 2u;
    return (flags & RDP_GDIPLUS_RECORD_FLAG_COMPRESSED_POINTS) != 0u ? 4u : 8u;
}

/*
 * Purpose: decode a bounded EMF+ point array shared by line, curve and Bezier
 * records. Invariants: relative deltas are accumulated before any transform,
 * and padding is limited to EMF+ record alignment. Failure policy: malformed
 * point counts fail before allocating or drawing.
 */
static librdp_status rdp_gdi_backend_gdiplus_read_point_array(const uint8_t* data,
                                                              size_t length,
                                                              uint16_t flags,
                                                              uint32_t count,
                                                              rdp_gdi_backend_point** points)
{
    rdp_gdi_backend_point* decoded = NULL;
    size_t point_size = rdp_gdi_backend_gdiplus_point_record_size(flags);
    size_t total_size = 0u;
    uint32_t i = 0u;
    int32_t current_x = 0;
    int32_t current_y = 0;

    if (!points || (!data && length > 0u) || count == 0u ||
        count > RDP_GDIPLUS_MAX_PATH_POINTS || point_size > (size_t)-1 / count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total_size = point_size * count;
    if (length < total_size || length - total_size > 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    decoded = (rdp_gdi_backend_point*)calloc(count, sizeof(*decoded));
    if (!decoded)
        return LIBRDP_STATUS_NO_MEMORY;
    for (i = 0u; i < count; i++)
    {
        if ((flags & RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE) != 0u)
        {
            current_x += (int8_t)data[(size_t)i * point_size];
            current_y += (int8_t)data[((size_t)i * point_size) + 1u];
            decoded[i].x = current_x;
            decoded[i].y = current_y;
        }
        else
        {
            size_t used = 0u;
            librdp_status status =
                rdp_gdi_backend_gdiplus_read_point(data + ((size_t)i * point_size),
                                                   point_size,
                                                   (flags & RDP_GDIPLUS_RECORD_FLAG_COMPRESSED_POINTS) != 0u,
                                                   &decoded[i],
                                                   &used);

            if (status != LIBRDP_STATUS_OK)
            {
                free(decoded);
                return status;
            }
            (void)used;
        }
    }
    *points = decoded;
    return LIBRDP_STATUS_OK;
}

static void rdp_gdi_backend_gdiplus_transform_points(const rdp_gdi_backend_gdiplus_context* context,
                                                     rdp_gdi_backend_point* points,
                                                     uint32_t count)
{
    uint32_t i = 0u;

    if (!points)
        return;
    for (i = 0u; i < count; i++)
        rdp_gdi_backend_gdiplus_transform_context_point(context, &points[i]);
}

/*
 * Purpose: render transformed EMF+ line strips and optional closing segments.
 * Invariants: each segment is clipped through the backend line primitive, and
 * anti-alias coverage is emitted only after the main segment succeeds. Failure
 * policy: the first backend drawing error stops the polyline so callers never
 * count a partially failed visual record as fully rasterized.
 */
static librdp_status rdp_gdi_backend_gdiplus_draw_polyline(rdp_gdi_backend_kind backend,
                                                           librdp_surface* surface,
                                                           const rdp_gdi_backend_gdiplus_context* context,
                                                           const rdp_gdi_backend_point* points,
                                                           uint32_t count,
                                                           uint32_t pen_width,
                                                           uint32_t color,
                                                           int close,
                                                           uint32_t* rasterized)
{
    uint32_t i = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!points || count < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 1u; i < count && status == LIBRDP_STATUS_OK; i++)
    {
        uint32_t dirty_left = UINT32_MAX;
        uint32_t dirty_top = UINT32_MAX;
        uint32_t dirty_right = 0u;
        uint32_t dirty_bottom = 0u;

        status = rdp_gdi_backend_draw_line(backend,
                                           surface,
                                           points[i - 1u].x,
                                           points[i - 1u].y,
                                           points[i].x,
                                           points[i].y,
                                           pen_width,
                                           color,
                                           context ? &context->clip : NULL,
                                           &dirty_left,
                                           &dirty_top,
                                           &dirty_right,
                                           &dirty_bottom);
        if (status == LIBRDP_STATUS_OK && context && context->anti_alias_mode != 0u && pen_width <= 2u)
        {
            uint32_t aa_color = 0x40000000u | (color & 0x00ffffffu);

            status = rdp_gdi_backend_draw_line(backend,
                                               surface,
                                               points[i - 1u].x,
                                               points[i - 1u].y + 1,
                                               points[i].x,
                                               points[i].y + 1,
                                               1u,
                                               aa_color,
                                               &context->clip,
                                               &dirty_left,
                                               &dirty_top,
                                               &dirty_right,
                                               &dirty_bottom);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_gdi_backend_draw_line(backend,
                                                   surface,
                                                   points[i - 1u].x + 1,
                                                   points[i - 1u].y,
                                                   points[i].x + 1,
                                                   points[i].y,
                                                   1u,
                                                   aa_color,
                                                   &context->clip,
                                                   &dirty_left,
                                                   &dirty_top,
                                                   &dirty_right,
                                                   &dirty_bottom);
        }
    }
    if (close && status == LIBRDP_STATUS_OK)
    {
        uint32_t dirty_left = UINT32_MAX;
        uint32_t dirty_top = UINT32_MAX;
        uint32_t dirty_right = 0u;
        uint32_t dirty_bottom = 0u;

        status = rdp_gdi_backend_draw_line(backend,
                                           surface,
                                           points[count - 1u].x,
                                           points[count - 1u].y,
                                           points[0].x,
                                           points[0].y,
                                           pen_width,
                                           color,
                                           context ? &context->clip : NULL,
                                           &dirty_left,
                                           &dirty_top,
                                           &dirty_right,
                                           &dirty_bottom);
    }
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

static int rdp_gdi_backend_gdiplus_append_curve_point(rdp_gdi_backend_point* points,
                                                      uint32_t* count,
                                                      uint32_t capacity,
                                                      float x,
                                                      float y)
{
    rdp_gdi_backend_point point;

    point.x = rdp_gdi_backend_gdiplus_round_i32(x);
    point.y = rdp_gdi_backend_gdiplus_round_i32(y);
    return rdp_gdi_backend_gdiplus_append_flattened_point(points, count, capacity, point);
}

/*
 * Purpose: flatten EMF+ cardinal spline records before software/native line
 * dispatch. Invariants: offset and segment count select only valid adjacent
 * point ranges; the generated point array is bounded. Failure policy: invalid
 * curve ranges fail the stream instead of falling back to a misleading polyline.
 */
static int rdp_gdi_backend_gdiplus_flatten_cardinal_curve(const rdp_gdi_backend_point* source,
                                                          uint32_t count,
                                                          float tension,
                                                          int closed,
                                                          uint32_t offset,
                                                          uint32_t segment_count,
                                                          rdp_gdi_backend_point** flattened,
                                                          uint32_t* flattened_count)
{
    rdp_gdi_backend_point* out = NULL;
    uint32_t out_count = 0u;
    uint32_t segment = 0u;
    uint32_t max_segments = closed ? count : count - 1u;

    if (!source || !flattened || !flattened_count || count < 2u ||
        count > RDP_GDIPLUS_MAX_PATH_POINTS || offset >= max_segments ||
        segment_count == 0u || segment_count > max_segments - offset)
        return 0;
    out = (rdp_gdi_backend_point*)calloc(RDP_GDIPLUS_MAX_FLATTENED_POINTS, sizeof(*out));
    if (!out)
        return 0;
    if (tension < 0.0001f)
    {
        for (segment = 0u; segment <= segment_count; segment++)
        {
            uint32_t index = closed ? ((offset + segment) % count) : offset + segment;

            if (!rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                               &out_count,
                                                               RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                               source[index]))
                break;
        }
    }
    else
    {
        for (segment = offset; segment < offset + segment_count; segment++)
        {
            uint32_t step = 0u;
            uint32_t p1_index = closed ? (segment % count) : segment;
            uint32_t p2_index = closed ? ((segment + 1u) % count) : segment + 1u;
            uint32_t p0_index = 0u;
            uint32_t p3_index = 0u;
            rdp_gdi_backend_point p0;
            rdp_gdi_backend_point p1 = source[p1_index];
            rdp_gdi_backend_point p2 = source[p2_index];
            rdp_gdi_backend_point p3;

            if (closed)
            {
                p0_index = segment == 0u ? count - 1u : segment - 1u;
                p3_index = (segment + 2u) % count;
            }
            else
            {
                p0_index = segment == 0u ? p1_index : segment - 1u;
                p3_index = segment + 2u < count ? segment + 2u : p2_index;
            }
            p0 = source[p0_index];
            p3 = source[p3_index];
            if (out_count == 0u &&
                !rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                               &out_count,
                                                               RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                               p1))
                break;
            for (step = 1u; step <= 16u; step++)
            {
                float t = (float)step / 16.0f;
                float t2 = t * t;
                float t3 = t2 * t;
                float h1 = (2.0f * t3) - (3.0f * t2) + 1.0f;
                float h2 = (-2.0f * t3) + (3.0f * t2);
                float h3 = t3 - (2.0f * t2) + t;
                float h4 = t3 - t2;
                float m1x = tension * (float)(p2.x - p0.x);
                float m1y = tension * (float)(p2.y - p0.y);
                float m2x = tension * (float)(p3.x - p1.x);
                float m2y = tension * (float)(p3.y - p1.y);
                float x = (h1 * (float)p1.x) + (h2 * (float)p2.x) + (h3 * m1x) + (h4 * m2x);
                float y = (h1 * (float)p1.y) + (h2 * (float)p2.y) + (h3 * m1y) + (h4 * m2y);

                if (!rdp_gdi_backend_gdiplus_append_curve_point(out,
                                                               &out_count,
                                                               RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                               x,
                                                               y))
                    break;
            }
        }
    }
    if (out_count < 2u)
    {
        free(out);
        return 0;
    }
    *flattened = out;
    *flattened_count = out_count;
    return 1;
}

static int rdp_gdi_backend_gdiplus_flatten_beziers(const rdp_gdi_backend_point* source,
                                                   uint32_t count,
                                                   rdp_gdi_backend_point** flattened,
                                                   uint32_t* flattened_count)
{
    rdp_gdi_backend_point* out = NULL;
    uint32_t out_count = 0u;
    uint32_t i = 0u;

    if (!source || !flattened || !flattened_count || count < 4u ||
        ((count - 1u) % 3u) != 0u || count > RDP_GDIPLUS_MAX_PATH_POINTS)
        return 0;
    out = (rdp_gdi_backend_point*)calloc(RDP_GDIPLUS_MAX_FLATTENED_POINTS, sizeof(*out));
    if (!out)
        return 0;
    if (!rdp_gdi_backend_gdiplus_append_flattened_point(out,
                                                       &out_count,
                                                       RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                       source[0]))
    {
        free(out);
        return 0;
    }
    for (i = 0u; i + 3u < count; i += 3u)
    {
        uint32_t step = 0u;
        rdp_gdi_backend_point p0 = source[i];
        rdp_gdi_backend_point p1 = source[i + 1u];
        rdp_gdi_backend_point p2 = source[i + 2u];
        rdp_gdi_backend_point p3 = source[i + 3u];

        for (step = 1u; step <= 16u; step++)
        {
            float t = (float)step / 16.0f;
            float mt = 1.0f - t;
            float x = (mt * mt * mt * (float)p0.x) +
                      (3.0f * mt * mt * t * (float)p1.x) +
                      (3.0f * mt * t * t * (float)p2.x) +
                      (t * t * t * (float)p3.x);
            float y = (mt * mt * mt * (float)p0.y) +
                      (3.0f * mt * mt * t * (float)p1.y) +
                      (3.0f * mt * t * t * (float)p2.y) +
                      (t * t * t * (float)p3.y);

            if (!rdp_gdi_backend_gdiplus_append_curve_point(out,
                                                           &out_count,
                                                           RDP_GDIPLUS_MAX_FLATTENED_POINTS,
                                                           x,
                                                           y))
                break;
        }
    }
    if (out_count < 2u)
    {
        free(out);
        return 0;
    }
    *flattened = out;
    *flattened_count = out_count;
    return 1;
}

static librdp_status rdp_gdi_backend_render_gdiplus_draw_rects(rdp_gdi_backend_kind backend,
                                                               librdp_surface* surface,
                                                               const rdp_gdi_backend_gdiplus_context* context,
                                                               uint16_t flags,
                                                               const uint8_t* payload,
                                                               uint32_t data_size,
                                                               uint32_t* rasterized,
                                                               uint32_t* unsupported)
{
    uint32_t pen = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    int compressed = (flags & 0x4000u) != 0;
    size_t rect_size = compressed ? 8u : 16u;

    if (data_size < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pen = rdp_gdi_backend_read_u32_le(payload);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    pen,
                                                    RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    count = rdp_gdi_backend_read_u32_le(payload + 4u);
    if (count == 0 || count > 4096u || rect_size > (size_t)-1 / count ||
        data_size != (uint32_t)(8u + (count * rect_size)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        int32_t x = 0;
        int32_t y = 0;
        uint32_t width = 0;
        uint32_t height = 0;
        size_t used = 0;
        librdp_status status = rdp_gdi_backend_gdiplus_read_rect(payload + 8u + ((size_t)i * rect_size),
                                                                 rect_size,
                                                                 compressed,
                                                                 &x,
                                                                 &y,
                                                                 &width,
                                                                 &height,
                                                                 &used);

        if (status != LIBRDP_STATUS_OK)
            return status;
        (void)used;
        status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_gdi_backend_draw_rect_outline(backend,
                                                   surface,
                                                   x,
                                                   y,
                                                   width,
                                                   height,
                                                   pen_width,
                                                   color,
                                                   context ? &context->clip : NULL);
        if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
            continue;
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (rasterized)
            (*rasterized)++;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Purpose: render EMF+ FillRects records using either the fast solid-color
 * path or sampled brush fills. Invariants: object-table brush lookup is kept
 * separate from direct-color tokens, and each rectangle is transformed before
 * clipping. Failure policy: malformed counts are protocol errors; missing
 * brushes are reported through the unsupported counter without partial output.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_fill_rects(rdp_gdi_backend_kind backend,
                                                               librdp_surface* surface,
                                                               const rdp_gdi_backend_gdiplus_context* context,
                                                               uint16_t flags,
                                                               const uint8_t* payload,
                                                               uint32_t data_size,
                                                               uint32_t* rasterized,
                                                               uint32_t* unsupported)
{
    uint32_t brush = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    int compressed = (flags & 0x4000u) != 0;
    const uint8_t* rects = NULL;
    const rdp_gdi_backend_gdiplus_object* brush_object = NULL;
    int direct_color = (flags & RDP_GDIPLUS_RECORD_FLAG_DIRECT_COLOR) != 0;
    size_t rect_size = compressed ? 8u : 16u;

    if (data_size < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush = rdp_gdi_backend_read_u32_le(payload);
    if (!direct_color)
        brush_object = rdp_gdi_backend_gdiplus_get_object(context,
                                                          brush & 0xffu,
                                                          RDP_GDIPLUS_OBJECT_TYPE_BRUSH);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush,
                                                    RDP_GDIPLUS_OBJECT_KIND_BRUSH,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    count = rdp_gdi_backend_read_u32_le(payload + 4u);
    if (count == 0 || count > 4096u || rect_size > (size_t)-1 / count ||
        data_size != (uint32_t)(8u + (count * rect_size)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pen_width;
    rects = payload + 8u;
    for (i = 0; i < count; i++)
    {
        int32_t x = 0;
        int32_t y = 0;
        uint32_t width = 0;
        uint32_t height = 0;
        size_t used = 0;
        librdp_status status = rdp_gdi_backend_gdiplus_read_rect(rects + ((size_t)i * rect_size),
                                                                 rect_size,
                                                                 compressed,
                                                                 &x,
                                                                 &y,
                                                                 &width,
                                                                 &height,
                                                                 &used);

        if (status != LIBRDP_STATUS_OK)
            return status;
        (void)used;
        status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (brush_object && brush_object->brush_type != RDP_GDIPLUS_BRUSH_SOLID_COLOR)
            status = rdp_gdi_backend_fill_rect_brush_clipped(surface,
                                                             x,
                                                             y,
                                                             width,
                                                             height,
                                                             context,
                                                             brush_object);
        else
            status = rdp_gdi_backend_fill_rect_clipped(backend,
                                                       surface,
                                                       x,
                                                       y,
                                                       width,
                                                       height,
                                                       color,
                                                       context ? &context->clip : NULL);
        if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
            continue;
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (rasterized)
            (*rasterized)++;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Rasterizes EMF+ point arrays for polygon fills and line strips. The first
 * payload DWORD can be either a direct ARGB value or an object-table brush/pen
 * ID; malformed counts and compressed point bounds are rejected before drawing.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_points(rdp_gdi_backend_kind backend,
                                                           librdp_surface* surface,
                                                           const rdp_gdi_backend_gdiplus_context* context,
                                                           uint16_t flags,
                                                           const uint8_t* payload,
                                                           uint32_t data_size,
                                                           uint32_t* rasterized,
                                                           uint32_t* unsupported,
                                                           int fill_polygon)
{
    uint32_t brush_or_pen = 0;
    uint32_t count = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    size_t point_size = rdp_gdi_backend_gdiplus_point_record_size(flags);
    rdp_gdi_backend_point* points = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (data_size < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush_or_pen = rdp_gdi_backend_read_u32_le(payload);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush_or_pen,
                                                    fill_polygon ? RDP_GDIPLUS_OBJECT_KIND_BRUSH :
                                                                   RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    count = rdp_gdi_backend_read_u32_le(payload + 4u);
    if (count == 0 || count > 4096u || point_size > (size_t)-1 / count ||
        data_size != (uint32_t)(8u + (count * point_size)))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((fill_polygon && count < 3u) || (!fill_polygon && count < 2u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_gdi_backend_gdiplus_read_point_array(payload + 8u,
                                                      data_size - 8u,
                                                      flags,
                                                      count,
                                                      &points);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_gdi_backend_gdiplus_transform_points(context, points, count);
    if (fill_polygon)
    {
        status = rdp_gdi_backend_fill_polygon(backend,
                                              surface,
                                              points,
                                              count,
                                              (flags & 0x2000u) != 0 ? 2u : 1u,
                                              color,
                                              context ? &context->clip : NULL,
                                              NULL,
                                              NULL,
                                              NULL,
                                              NULL);
        if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
            status = LIBRDP_STATUS_OK;
        if (status == LIBRDP_STATUS_OK && rasterized)
            (*rasterized)++;
    }
    else
    {
        status = rdp_gdi_backend_gdiplus_draw_polyline(backend,
                                                       surface,
                                                       context,
                                                       points,
                                                       count,
                                                       pen_width,
                                                       color,
                                                       0,
                                                       rasterized);
    }
    free(points);
    return status;
}

static librdp_status rdp_gdi_backend_render_gdiplus_draw_lines(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported)
{
    uint32_t count = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    rdp_gdi_backend_point* points = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t point_size = rdp_gdi_backend_gdiplus_point_record_size(flags);
    uint32_t token = flags & 0xffu;
    size_t point_offset = 4u;

    if (!payload || data_size < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = rdp_gdi_backend_read_u32_le(payload);
    if (count == 0u || count > RDP_GDIPLUS_MAX_PATH_POINTS ||
        point_size > (size_t)-1 / count ||
        data_size != 4u + ((uint32_t)point_size * count))
    {
        if (data_size < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        token = rdp_gdi_backend_read_u32_le(payload);
        count = rdp_gdi_backend_read_u32_le(payload + 4u);
        point_offset = 8u;
        if (count == 0u || count > RDP_GDIPLUS_MAX_PATH_POINTS ||
            point_size > (size_t)-1 / count ||
            data_size != 8u + ((uint32_t)point_size * count))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    token,
                                                    RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_point_array(payload + point_offset,
                                                      data_size - point_offset,
                                                      flags,
                                                      count,
                                                      &points);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_gdi_backend_gdiplus_transform_points(context, points, count);
    status = rdp_gdi_backend_gdiplus_draw_polyline(backend,
                                                   surface,
                                                   context,
                                                   points,
                                                   count,
                                                   pen_width,
                                                   color,
                                                   (flags & RDP_GDIPLUS_RECORD_FLAG_CLOSE_OR_WINDING) != 0u,
                                                   rasterized);
    free(points);
    return status;
}

/*
 * Purpose: render EMF+ FillClosedCurve and DrawClosedCurve records from their
 * typed cardinal-spline layout. Invariants: brush/pen resolution is performed
 * before curve allocation, and flattened points are transformed once. Failure
 * policy: invalid counts, ranges or object references do not produce partial
 * output.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_closed_curve(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported,
    int fill)
{
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    uint32_t token = flags & 0xffu;
    uint32_t count = 0u;
    float tension = 0.5f;
    size_t point_size = rdp_gdi_backend_gdiplus_point_record_size(flags);
    size_t point_offset = fill ? 12u : 8u;
    rdp_gdi_backend_point* points = NULL;
    rdp_gdi_backend_point* flattened = NULL;
    uint32_t flattened_count = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || data_size < point_offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (fill)
    {
        token = rdp_gdi_backend_read_u32_le(payload);
        tension = rdp_gdi_backend_read_float_le(payload + 4u);
        count = rdp_gdi_backend_read_u32_le(payload + 8u);
    }
    else
    {
        tension = rdp_gdi_backend_read_float_le(payload);
        count = rdp_gdi_backend_read_u32_le(payload + 4u);
    }
    if (count < 2u || count > RDP_GDIPLUS_MAX_PATH_POINTS ||
        point_size > (size_t)-1 / count ||
        data_size != point_offset + ((uint32_t)point_size * count))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    token,
                                                    fill ? RDP_GDIPLUS_OBJECT_KIND_BRUSH :
                                                           RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_point_array(payload + point_offset,
                                                      data_size - point_offset,
                                                      flags,
                                                      count,
                                                      &points);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_gdi_backend_gdiplus_flatten_cardinal_curve(points,
                                                        count,
                                                        tension,
                                                        1,
                                                        0,
                                                        count,
                                                        &flattened,
                                                        &flattened_count))
    {
        free(points);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_gdi_backend_gdiplus_transform_points(context, flattened, flattened_count);
    if (fill)
        status = rdp_gdi_backend_fill_polygon(backend,
                                              surface,
                                              flattened,
                                              flattened_count,
                                              (flags & RDP_GDIPLUS_RECORD_FLAG_CLOSE_OR_WINDING) != 0u ? 2u : 1u,
                                              color,
                                              context ? &context->clip : NULL,
                                              NULL,
                                              NULL,
                                              NULL,
                                              NULL);
    else
        status = rdp_gdi_backend_gdiplus_draw_polyline(backend,
                                                       surface,
                                                       context,
                                                       flattened,
                                                       flattened_count,
                                                       pen_width,
                                                       color,
                                                       1,
                                                       NULL);
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        status = LIBRDP_STATUS_OK;
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    free(flattened);
    free(points);
    return status;
}

/*
 * Purpose: render EMF+ DrawCurve with explicit offset and segment count.
 * Invariants: selected segments remain within the source point array and the
 * flattened polyline is bounded. Failure policy: malformed spline ranges are
 * protocol errors rather than silently drawing a different curve.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_draw_curve(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported)
{
    uint32_t count = 0u;
    uint32_t offset = 0u;
    uint32_t segment_count = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    float tension = 0.0f;
    size_t point_size = rdp_gdi_backend_gdiplus_point_record_size(flags);
    rdp_gdi_backend_point* points = NULL;
    rdp_gdi_backend_point* flattened = NULL;
    uint32_t flattened_count = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || data_size < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    tension = rdp_gdi_backend_read_float_le(payload);
    offset = rdp_gdi_backend_read_u32_le(payload + 4u);
    segment_count = rdp_gdi_backend_read_u32_le(payload + 8u);
    count = rdp_gdi_backend_read_u32_le(payload + 12u);
    if (count < 2u || count > RDP_GDIPLUS_MAX_PATH_POINTS ||
        point_size > (size_t)-1 / count ||
        data_size != 16u + ((uint32_t)point_size * count))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    flags & 0xffu,
                                                    RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_point_array(payload + 16u,
                                                      data_size - 16u,
                                                      flags,
                                                      count,
                                                      &points);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_gdi_backend_gdiplus_flatten_cardinal_curve(points,
                                                        count,
                                                        tension,
                                                        0,
                                                        offset,
                                                        segment_count,
                                                        &flattened,
                                                        &flattened_count))
    {
        free(points);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_gdi_backend_gdiplus_transform_points(context, flattened, flattened_count);
    status = rdp_gdi_backend_gdiplus_draw_polyline(backend,
                                                   surface,
                                                   context,
                                                   flattened,
                                                   flattened_count,
                                                   pen_width,
                                                   color,
                                                   0,
                                                   rasterized);
    free(flattened);
    free(points);
    return status;
}

/*
 * Purpose: render EMF+ DrawBeziers as connected cubic Bezier segments.
 * Invariants: the point count must be 1+3n and each segment is flattened into
 * a bounded deterministic polyline. Failure policy: malformed segment counts
 * fail before drawing.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_draw_beziers(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported)
{
    uint32_t count = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    size_t point_size = rdp_gdi_backend_gdiplus_point_record_size(flags);
    rdp_gdi_backend_point* points = NULL;
    rdp_gdi_backend_point* flattened = NULL;
    uint32_t flattened_count = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || data_size < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = rdp_gdi_backend_read_u32_le(payload);
    if (count < 4u || count > RDP_GDIPLUS_MAX_PATH_POINTS ||
        ((count - 1u) % 3u) != 0u || point_size > (size_t)-1 / count ||
        data_size != 4u + ((uint32_t)point_size * count))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    flags & 0xffu,
                                                    RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_point_array(payload + 4u,
                                                      data_size - 4u,
                                                      flags,
                                                      count,
                                                      &points);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_gdi_backend_gdiplus_flatten_beziers(points, count, &flattened, &flattened_count))
    {
        free(points);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_gdi_backend_gdiplus_transform_points(context, flattened, flattened_count);
    status = rdp_gdi_backend_gdiplus_draw_polyline(backend,
                                                   surface,
                                                   context,
                                                   flattened,
                                                   flattened_count,
                                                   pen_width,
                                                   color,
                                                   0,
                                                   rasterized);
    free(flattened);
    free(points);
    return status;
}

static librdp_status rdp_gdi_backend_render_gdiplus_fill_ellipse(rdp_gdi_backend_kind backend,
                                                                 librdp_surface* surface,
                                                                 const rdp_gdi_backend_gdiplus_context* context,
                                                                 uint16_t flags,
                                                                 const uint8_t* payload,
                                                                 uint32_t data_size,
                                                                 uint32_t* rasterized,
                                                                 uint32_t* unsupported)
{
    uint32_t brush = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    int32_t x = 0;
    int32_t y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t used = 0;
    int compressed = (flags & 0x4000u) != 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (data_size != (compressed ? 12u : 20u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush = rdp_gdi_backend_read_u32_le(payload);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush,
                                                    RDP_GDIPLUS_OBJECT_KIND_BRUSH,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    (void)pen_width;
    status = rdp_gdi_backend_gdiplus_read_rect(payload + 4u,
                                               data_size - 4u,
                                               compressed,
                                               &x,
                                               &y,
                                               &width,
                                               &height,
                                               &used);
    if (status != LIBRDP_STATUS_OK)
        return status;
    (void)used;
    status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_gdi_backend_fill_ellipse(backend,
                                          surface,
                                          x,
                                          y,
                                          width,
                                          height,
                                          color,
                                          context ? &context->clip : NULL);
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        return LIBRDP_STATUS_OK;
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

static librdp_status rdp_gdi_backend_render_gdiplus_draw_ellipse(rdp_gdi_backend_kind backend,
                                                                 librdp_surface* surface,
                                                                 const rdp_gdi_backend_gdiplus_context* context,
                                                                 uint16_t flags,
                                                                 const uint8_t* payload,
                                                                 uint32_t data_size,
                                                                 uint32_t* rasterized,
                                                                 uint32_t* unsupported)
{
    uint32_t pen = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    int32_t x = 0;
    int32_t y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t used = 0;
    int compressed = (flags & 0x4000u) != 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (data_size != (compressed ? 12u : 20u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pen = rdp_gdi_backend_read_u32_le(payload);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    pen,
                                                    RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_rect(payload + 4u,
                                               data_size - 4u,
                                               compressed,
                                               &x,
                                               &y,
                                               &width,
                                               &height,
                                               &used);
    if (status != LIBRDP_STATUS_OK)
        return status;
    (void)used;
    status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_gdi_backend_draw_ellipse(backend,
                                          surface,
                                          x,
                                          y,
                                          width,
                                          height,
                                          pen_width,
                                          color,
                                          context ? &context->clip : NULL);
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        return LIBRDP_STATUS_OK;
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

static librdp_status rdp_gdi_backend_render_gdiplus_arc_points(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    int32_t x,
    int32_t y,
    uint32_t width,
    uint32_t height,
    float start_angle,
    float sweep_angle,
    uint32_t color,
    uint32_t pen_width,
    int fill_pie,
    int close_pie,
    uint32_t* rasterized);

static librdp_status rdp_gdi_backend_render_gdiplus_pie_or_arc(rdp_gdi_backend_kind backend,
                                                               librdp_surface* surface,
                                                               const rdp_gdi_backend_gdiplus_context* context,
                                                               uint16_t flags,
                                                               const uint8_t* payload,
                                                               uint32_t data_size,
                                                               uint32_t* rasterized,
                                                               uint32_t* unsupported,
                                                               uint16_t record_type)
{
    uint32_t brush_or_pen = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    int32_t x = 0;
    int32_t y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t used = 0;
    float start_angle = 0.0f;
    float sweep_angle = 0.0f;
    int compressed = (flags & 0x4000u) != 0;
    uint8_t expected_kind = record_type == RDP_GDIPLUS_RECORD_FILL_PIE ?
                                RDP_GDIPLUS_OBJECT_KIND_BRUSH :
                                RDP_GDIPLUS_OBJECT_KIND_PEN;
    librdp_status status = LIBRDP_STATUS_OK;

    if (data_size != (compressed ? 20u : 28u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush_or_pen = rdp_gdi_backend_read_u32_le(payload);
    start_angle = rdp_gdi_backend_read_float_le(payload + 4u);
    sweep_angle = rdp_gdi_backend_read_float_le(payload + 8u);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush_or_pen,
                                                    expected_kind,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_rect(payload + 12u,
                                               data_size - 12u,
                                               compressed,
                                               &x,
                                               &y,
                                               &width,
                                               &height,
                                               &used);
    if (status != LIBRDP_STATUS_OK)
        return status;
    (void)used;
    return rdp_gdi_backend_render_gdiplus_arc_points(backend,
                                                     surface,
                                                     context,
                                                     x,
                                                     y,
                                                     width,
                                                     height,
                                                     start_angle,
                                                     sweep_angle,
                                                     color,
                                                     pen_width,
                                                     record_type == RDP_GDIPLUS_RECORD_FILL_PIE,
                                                     record_type == RDP_GDIPLUS_RECORD_DRAW_PIE,
                                                     rasterized);
}

static librdp_status rdp_gdi_backend_render_gdiplus_path_object(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    const rdp_gdi_backend_gdiplus_object* object,
    uint32_t color,
    uint32_t pen_width,
    int fill,
    uint32_t* rasterized)
{
    rdp_gdi_backend_gdiplus_path path;
    rdp_gdi_backend_point* flattened = NULL;
    uint32_t flattened_count = 0u;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0u;

    memset(&path, 0, sizeof(path));
    status = rdp_gdi_backend_gdiplus_parse_path_object(object, &path);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_gdi_backend_gdiplus_flatten_path(&path, context, &flattened, &flattened_count))
    {
        rdp_gdi_backend_gdiplus_path_free(&path);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (fill)
    {
        status = rdp_gdi_backend_fill_polygon(backend,
                                              surface,
                                              flattened,
                                              flattened_count,
                                              1u,
                                              color,
                                              context ? &context->clip : NULL,
                                              NULL,
                                              NULL,
                                              NULL,
                                              NULL);
    }
    else
    {
        for (i = 1u; i < flattened_count && status == LIBRDP_STATUS_OK; i++)
        {
            uint32_t dirty_left = UINT32_MAX;
            uint32_t dirty_top = UINT32_MAX;
            uint32_t dirty_right = 0u;
            uint32_t dirty_bottom = 0u;

            status = rdp_gdi_backend_draw_line(backend,
                                               surface,
                                               flattened[i - 1u].x,
                                               flattened[i - 1u].y,
                                               flattened[i].x,
                                               flattened[i].y,
                                               pen_width,
                                               color,
                                               context ? &context->clip : NULL,
                                               &dirty_left,
                                               &dirty_top,
                                               &dirty_right,
                                               &dirty_bottom);
        }
    }
    free(flattened);
    rdp_gdi_backend_gdiplus_path_free(&path);
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        status = LIBRDP_STATUS_OK;
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

/*
 * Purpose: render FillPath, DrawPath and StrokeFillPath through the same path
 * object resolver. Invariants: the path id comes from the record flags while
 * brush/pen tokens stay in the payload. Failure policy: missing objects are
 * counted as unsupported input references; malformed records fail the stream.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_fill_or_draw_path(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported,
    uint16_t record_type)
{
    const rdp_gdi_backend_gdiplus_object* path_object = NULL;
    uint32_t brush_or_pen = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    uint8_t expected_kind = record_type == RDP_GDIPLUS_RECORD_DRAW_PATH ?
                                RDP_GDIPLUS_OBJECT_KIND_PEN :
                                RDP_GDIPLUS_OBJECT_KIND_BRUSH;
    uint8_t object_id = (uint8_t)(flags & 0xffu);
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || data_size != (record_type == RDP_GDIPLUS_RECORD_STROKE_FILL_PATH ? 8u : 4u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    path_object = rdp_gdi_backend_gdiplus_get_object(context,
                                                     object_id,
                                                     RDP_GDIPLUS_OBJECT_TYPE_PATH);
    if (!path_object)
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    brush_or_pen = rdp_gdi_backend_read_u32_le(payload);
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags & 0xff00u,
                                                    brush_or_pen,
                                                    expected_kind,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    if (record_type == RDP_GDIPLUS_RECORD_STROKE_FILL_PATH)
    {
        status = rdp_gdi_backend_render_gdiplus_path_object(backend,
                                                            surface,
                                                            context,
                                                            path_object,
                                                            color,
                                                            1u,
                                                            1,
                                                            rasterized);
        if (status != LIBRDP_STATUS_OK)
            return status;
        brush_or_pen = rdp_gdi_backend_read_u32_le(payload + 4u);
        if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                        flags & 0xff00u,
                                                        brush_or_pen,
                                                        RDP_GDIPLUS_OBJECT_KIND_PEN,
                                                        &color,
                                                        &pen_width))
            return LIBRDP_STATUS_OK;
        return rdp_gdi_backend_render_gdiplus_path_object(backend,
                                                          surface,
                                                          context,
                                                          path_object,
                                                          color,
                                                          pen_width,
                                                          0,
                                                          rasterized);
    }
    return rdp_gdi_backend_render_gdiplus_path_object(backend,
                                                      surface,
                                                      context,
                                                      path_object,
                                                      color,
                                                      pen_width,
                                                      record_type == RDP_GDIPLUS_RECORD_FILL_PATH,
                                                      rasterized);
}

/*
 * Purpose: replay the bounded subset of EMF+ region nodes needed by FillRegion.
 * Invariants: node count and geometry are checked before rasterization; path
 * nodes borrow the remaining region payload without taking ownership. Failure
 * policy: unknown node types fail the stream instead of being ignored.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_region_nodes(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    const uint8_t* data,
    size_t length,
    uint32_t color,
    uint32_t* rasterized)
{
    uint32_t count = 0u;
    size_t offset = 8u;
    uint32_t i = 0u;

    if (!data || length < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    count = rdp_gdi_backend_read_u32_le(data + 4u);
    if (count == 0u || count > 256u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0u; i < count; i++)
    {
        uint32_t node_type = 0u;
        librdp_status status = LIBRDP_STATUS_OK;

        if (length - offset < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        node_type = rdp_gdi_backend_read_u32_le(data + offset);
        offset += 4u;
        if (node_type == RDP_GDIPLUS_REGION_NODE_EMPTY)
            continue;
        if (node_type == RDP_GDIPLUS_REGION_NODE_INFINITE)
        {
            status = rdp_gdi_backend_fill_rect_clipped(backend,
                                                       surface,
                                                       0,
                                                       0,
                                                       librdp_surface_width(surface),
                                                       librdp_surface_height(surface),
                                                       color,
                                                       context ? &context->clip : NULL);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (rasterized)
                (*rasterized)++;
            continue;
        }
        if (node_type == RDP_GDIPLUS_REGION_NODE_RECT)
        {
            int32_t x = 0;
            int32_t y = 0;
            uint32_t width = 0u;
            uint32_t height = 0u;
            size_t used = 0u;

            status = rdp_gdi_backend_gdiplus_read_rect(data + offset,
                                                       length - offset,
                                                       0,
                                                       &x,
                                                       &y,
                                                       &width,
                                                       &height,
                                                       &used);
            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += used;
            status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_gdi_backend_fill_rect_clipped(backend,
                                                       surface,
                                                       x,
                                                       y,
                                                       width,
                                                       height,
                                                       color,
                                                       context ? &context->clip : NULL);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (rasterized)
                (*rasterized)++;
            continue;
        }
        if (node_type == RDP_GDIPLUS_REGION_NODE_PATH)
        {
            rdp_gdi_backend_gdiplus_object path_object;

            memset(&path_object, 0, sizeof(path_object));
            path_object.active = 1u;
            path_object.object_type = RDP_GDIPLUS_OBJECT_TYPE_PATH;
            path_object.data = (uint8_t*)(data + offset);
            path_object.data_len = length - offset;
            return rdp_gdi_backend_render_gdiplus_path_object(backend,
                                                              surface,
                                                              context,
                                                              &path_object,
                                                              color,
                                                              1u,
                                                              1,
                                                              rasterized);
        }
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_render_gdiplus_fill_region(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported)
{
    uint32_t brush = 0u;
    uint32_t region_id = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    const rdp_gdi_backend_gdiplus_object* region = NULL;

    if (!payload || data_size != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush = rdp_gdi_backend_read_u32_le(payload);
    region_id = flags & 0xffu;
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush,
                                                    RDP_GDIPLUS_OBJECT_KIND_BRUSH,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    (void)pen_width;
    region = rdp_gdi_backend_gdiplus_get_object(context,
                                                region_id,
                                                RDP_GDIPLUS_OBJECT_TYPE_REGION);
    if (!region)
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    return rdp_gdi_backend_render_gdiplus_region_nodes(backend,
                                                       surface,
                                                       context,
                                                       region->data,
                                                       region->data_len,
                                                       color,
                                                       rasterized);
}

/*
 * Purpose: draw an uncompressed EMF+ bitmap into an arbitrary destination
 * rectangle with mode-aware scaling. Invariants: source crop and target
 * bounds are clipped before mapping the surface. Failure policy: inconsistent
 * strides, dimensions or crop rectangles are rejected as malformed input.
 */
static librdp_status rdp_gdi_backend_gdiplus_scale_bgra32(librdp_surface* surface,
                                                          int32_t dst_x,
                                                          int32_t dst_y,
                                                          uint32_t dst_width,
                                                          uint32_t dst_height,
                                                          const uint8_t* source,
                                                          uint32_t src_x,
                                                          uint32_t src_y,
                                                          uint32_t src_width,
                                                          uint32_t src_height,
                                                          uint32_t image_width,
                                                          uint32_t image_height,
                                                          size_t source_stride,
                                                          int source_bottom_up,
                                                          uint32_t interpolation_mode,
                                                          const rdp_gdi_backend_clip* clip)
{
    librdp_surface_mapping mapping;
    uint32_t surface_width = 0u;
    uint32_t surface_height = 0u;
    int32_t left = dst_x;
    int32_t top = dst_y;
    int32_t right = 0;
    int32_t bottom = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_status unmap_status = LIBRDP_STATUS_OK;
    int32_t y = 0;

    if (!surface || !source || dst_width == 0u || dst_height == 0u ||
        src_width == 0u || src_height == 0u || src_x > image_width ||
        src_y > image_height || src_width > image_width - src_x ||
        src_height > image_height - src_y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface_width = librdp_surface_width(surface);
    surface_height = librdp_surface_height(surface);
    if (dst_width > (uint32_t)INT32_MAX || dst_height > (uint32_t)INT32_MAX ||
        dst_x > INT32_MAX - (int32_t)dst_width || dst_y > INT32_MAX - (int32_t)dst_height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    right = dst_x + (int32_t)dst_width;
    bottom = dst_y + (int32_t)dst_height;
    if (left < 0)
        left = 0;
    if (top < 0)
        top = 0;
    if (right > (int32_t)surface_width)
        right = (int32_t)surface_width;
    if (bottom > (int32_t)surface_height)
        bottom = (int32_t)surface_height;
    if (clip && clip->present)
    {
        if (left < clip->left)
            left = clip->left;
        if (top < clip->top)
            top = clip->top;
        if (right > clip->right + 1)
            right = clip->right + 1;
        if (bottom > clip->bottom + 1)
            bottom = clip->bottom + 1;
    }
    if (left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (y = top; y < bottom; y++)
    {
        int32_t x = 0;

        for (x = left; x < right; x++)
        {
            uint32_t rel_x = (uint32_t)(x - dst_x);
            uint32_t rel_y = (uint32_t)(y - dst_y);
            uint32_t sx = src_x + (uint32_t)(((uint64_t)rel_x * src_width) / dst_width);
            uint32_t sy = src_y + (uint32_t)(((uint64_t)rel_y * src_height) / dst_height);
            uint32_t color = 0u;

            if (interpolation_mode >= 3u && interpolation_mode != 5u &&
                dst_width > 1u && dst_height > 1u && src_width > 1u && src_height > 1u)
            {
                uint64_t fx = ((uint64_t)rel_x * (uint64_t)(src_width - 1u) * 256u) /
                              (uint64_t)(dst_width - 1u);
                uint64_t fy = ((uint64_t)rel_y * (uint64_t)(src_height - 1u) * 256u) /
                              (uint64_t)(dst_height - 1u);
                uint32_t sx0 = src_x + (uint32_t)(fx / 256u);
                uint32_t sy0 = src_y + (uint32_t)(fy / 256u);
                uint32_t sx1 = sx0 + 1u < src_x + src_width ? sx0 + 1u : sx0;
                uint32_t sy1 = sy0 + 1u < src_y + src_height ? sy0 + 1u : sy0;
                uint32_t wx = (uint32_t)(fx & 0xffu);
                uint32_t wy = (uint32_t)(fy & 0xffu);
                uint32_t row0 = source_bottom_up ? (image_height - 1u - sy0) : sy0;
                uint32_t row1 = source_bottom_up ? (image_height - 1u - sy1) : sy1;
                const uint8_t* p00 = source + ((size_t)row0 * source_stride) + ((size_t)sx0 * 4u);
                const uint8_t* p10 = source + ((size_t)row0 * source_stride) + ((size_t)sx1 * 4u);
                const uint8_t* p01 = source + ((size_t)row1 * source_stride) + ((size_t)sx0 * 4u);
                const uint8_t* p11 = source + ((size_t)row1 * source_stride) + ((size_t)sx1 * 4u);
                uint32_t c00 = ((uint32_t)p00[3] << 24u) | ((uint32_t)p00[2] << 16u) |
                               ((uint32_t)p00[1] << 8u) | (uint32_t)p00[0];
                uint32_t c10 = ((uint32_t)p10[3] << 24u) | ((uint32_t)p10[2] << 16u) |
                               ((uint32_t)p10[1] << 8u) | (uint32_t)p10[0];
                uint32_t c01 = ((uint32_t)p01[3] << 24u) | ((uint32_t)p01[2] << 16u) |
                               ((uint32_t)p01[1] << 8u) | (uint32_t)p01[0];
                uint32_t c11 = ((uint32_t)p11[3] << 24u) | ((uint32_t)p11[2] << 16u) |
                               ((uint32_t)p11[1] << 8u) | (uint32_t)p11[0];
                uint32_t top_color = rdp_gdi_backend_gdiplus_mix_color(c00, c10, wx);
                uint32_t bottom_color = rdp_gdi_backend_gdiplus_mix_color(c01, c11, wx);

                color = rdp_gdi_backend_gdiplus_mix_color(top_color, bottom_color, wy);
            }
            else
            {
                uint32_t row = source_bottom_up ? (image_height - 1u - sy) : sy;
                const uint8_t* src = source + ((size_t)row * source_stride) + ((size_t)sx * 4u);

                color = ((uint32_t)src[3] << 24u) |
                        ((uint32_t)src[2] << 16u) |
                        ((uint32_t)src[1] << 8u) |
                        (uint32_t)src[0];
            }
            rdp_gdi_backend_put_pixel(mapping.writable_pixels,
                                      mapping.stride,
                                      (uint32_t)x,
                                      (uint32_t)y,
                                      color);
        }
    }
    unmap_status = librdp_surface_unmap(surface, &mapping);
    return status == LIBRDP_STATUS_OK ? unmap_status : status;
}

/*
 * Purpose: resolve an EMF+ Image object and route bitmap data to the scaler.
 * Invariants: only bounded bitmap metadata reaches the pixel loop; compressed
 * or metafile image payloads produce a deterministic placeholder rather than
 * disappearing silently. Failure policy: invalid dimensions and strides fail
 * the stream before touching destination pixels.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_image(
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    const rdp_gdi_backend_gdiplus_object* image,
    int32_t dst_x,
    int32_t dst_y,
    uint32_t dst_width,
    uint32_t dst_height,
    int32_t src_x,
    int32_t src_y,
    uint32_t src_width,
    uint32_t src_height,
    uint32_t* rasterized)
{
    const uint8_t* data = NULL;
    uint32_t image_type = 0u;
    uint32_t width = 0u;
    uint32_t height = 0u;
    int32_t stride = 0;
    uint32_t pixel_format = 0u;
    uint32_t bitmap_type = 0u;
    size_t abs_stride = 0u;
    const uint8_t* pixels = NULL;
    int source_bottom_up = 0;
    uint32_t interpolation_mode = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!surface || !image || image->object_type != RDP_GDIPLUS_OBJECT_TYPE_IMAGE ||
        !image->data || image->data_len < 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    data = image->data;
    image_type = rdp_gdi_backend_read_u32_le(data + 4u);
    if (image_type != RDP_GDIPLUS_IMAGE_TYPE_BITMAP)
        return rdp_gdi_backend_fill_rect_clipped(RDP_GDI_BACKEND_SOFTWARE,
                                                surface,
                                                dst_x,
                                                dst_y,
                                                dst_width,
                                                dst_height,
                                                0,
                                                context ? &context->clip : NULL);
    width = rdp_gdi_backend_read_u32_le(data + 8u);
    height = rdp_gdi_backend_read_u32_le(data + 12u);
    stride = (int32_t)rdp_gdi_backend_read_u32_le(data + 16u);
    pixel_format = rdp_gdi_backend_read_u32_le(data + 20u);
    bitmap_type = rdp_gdi_backend_read_u32_le(data + 24u);
    if (width == 0u || height == 0u || width > 16384u || height > 16384u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bitmap_type != RDP_GDIPLUS_BITMAP_DATA_PIXEL ||
        (pixel_format != RDP_GDIPLUS_PIXEL_FORMAT_32BPP_ARGB &&
         pixel_format != RDP_GDIPLUS_PIXEL_FORMAT_32BPP_PARGB &&
         pixel_format != RDP_GDIPLUS_PIXEL_FORMAT_32BPP_RGB))
    {
        status = rdp_gdi_backend_fill_rect_clipped(RDP_GDI_BACKEND_SOFTWARE,
                                                   surface,
                                                   dst_x,
                                                   dst_y,
                                                   dst_width,
                                                   dst_height,
                                                   0x404040u,
                                                   context ? &context->clip : NULL);
        if (status == LIBRDP_STATUS_OK && rasterized)
            (*rasterized)++;
        return status;
    }
    abs_stride = stride < 0 ? (size_t)(-stride) : (size_t)stride;
    source_bottom_up = stride > 0;
    if (abs_stride < (size_t)width * 4u ||
        (size_t)height > ((size_t)-1) / abs_stride ||
        image->data_len - 28u < (size_t)height * abs_stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pixels = data + 28u;
    if (src_x < 0)
        src_x = 0;
    if (src_y < 0)
        src_y = 0;
    if (src_width == 0u || src_x >= (int32_t)width)
        src_width = width - (uint32_t)src_x;
    if (src_height == 0u || src_y >= (int32_t)height)
        src_height = height - (uint32_t)src_y;
    if (src_width > width - (uint32_t)src_x)
        src_width = width - (uint32_t)src_x;
    if (src_height > height - (uint32_t)src_y)
        src_height = height - (uint32_t)src_y;
    if (context)
    {
        interpolation_mode = context->interpolation_mode;
        if (context->compositing_quality >= 4u && interpolation_mode < 3u)
            interpolation_mode = 3u;
    }
    status = rdp_gdi_backend_gdiplus_scale_bgra32(surface,
                                                  dst_x,
                                                  dst_y,
                                                  dst_width,
                                                  dst_height,
                                                  pixels,
                                                  (uint32_t)src_x,
                                                  (uint32_t)src_y,
                                                  src_width,
                                                  src_height,
                                                  width,
                                                  height,
                                                  abs_stride,
                                                  source_bottom_up,
                                                  interpolation_mode,
                                                  context ? &context->clip : NULL);
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

/*
 * Purpose: parse DrawImage and DrawImagePoints records and normalize them to a
 * destination rectangle for the shared image renderer. Invariants: the image
 * object id is taken from flags and source rectangles are validated once.
 * Failure policy: malformed point counts or rectangles fail the stream.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_draw_image(
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported,
    int points_record)
{
    const rdp_gdi_backend_gdiplus_object* image = NULL;
    int32_t dst_x = 0;
    int32_t dst_y = 0;
    uint32_t dst_width = 0u;
    uint32_t dst_height = 0u;
    int32_t src_x = 0;
    int32_t src_y = 0;
    uint32_t src_width = 0u;
    uint32_t src_height = 0u;
    size_t used = 0u;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t object_id = (uint8_t)(flags & 0xffu);

    if (!payload || data_size < (points_record ? 52u : 32u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    image = rdp_gdi_backend_gdiplus_get_object(context,
                                               object_id,
                                               RDP_GDIPLUS_OBJECT_TYPE_IMAGE);
    if (!image)
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    status = rdp_gdi_backend_gdiplus_read_rect(payload + 8u,
                                               data_size - 8u,
                                               0,
                                               &src_x,
                                               &src_y,
                                               &src_width,
                                               &src_height,
                                               &used);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (points_record)
    {
        uint32_t count = 0u;
        rdp_gdi_backend_point p0;
        rdp_gdi_backend_point p1;
        rdp_gdi_backend_point p2;
        int32_t right = 0;
        int32_t bottom = 0;
        size_t point_offset = 24u;
        size_t point_size = (flags & RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE) != 0u ?
                                2u :
                                ((flags & RDP_GDIPLUS_PATH_POINT_FLAGS_COMPRESSED) != 0u ? 4u : 8u);
        int compressed = (flags & RDP_GDIPLUS_PATH_POINT_FLAGS_COMPRESSED) != 0u;

        if (data_size < point_offset + 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        count = rdp_gdi_backend_read_u32_le(payload + point_offset);
        point_offset += 4u;
        if (count != 3u || data_size < point_offset + (3u * point_size))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((flags & RDP_GDIPLUS_PATH_POINT_FLAGS_RELATIVE) != 0u)
        {
            p0.x = (int8_t)payload[point_offset];
            p0.y = (int8_t)payload[point_offset + 1u];
            p1.x = p0.x + (int8_t)payload[point_offset + 2u];
            p1.y = p0.y + (int8_t)payload[point_offset + 3u];
            p2.x = p1.x + (int8_t)payload[point_offset + 4u];
            p2.y = p1.y + (int8_t)payload[point_offset + 5u];
        }
        else
        {
            status = rdp_gdi_backend_gdiplus_read_point(payload + point_offset,
                                                        data_size - point_offset,
                                                        compressed,
                                                        &p0,
                                                        &used);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_gdi_backend_gdiplus_read_point(payload + point_offset + point_size,
                                                        data_size - point_offset - point_size,
                                                        compressed,
                                                        &p1,
                                                        &used);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_gdi_backend_gdiplus_read_point(payload + point_offset + (2u * point_size),
                                                        data_size - point_offset - (2u * point_size),
                                                        compressed,
                                                        &p2,
                                                        &used);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &p0);
        rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &p1);
        rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &p2);
        dst_x = p0.x;
        dst_y = p0.y;
        right = p1.x > p2.x ? p1.x : p2.x;
        bottom = p1.y > p2.y ? p1.y : p2.y;
        if (right <= dst_x || bottom <= dst_y)
            return LIBRDP_STATUS_OK;
        dst_width = (uint32_t)(right - dst_x);
        dst_height = (uint32_t)(bottom - dst_y);
    }
    else
    {
        int compressed = (flags & 0x4000u) != 0;

        status = rdp_gdi_backend_gdiplus_read_rect(payload + 24u,
                                                   data_size - 24u,
                                                   compressed,
                                                   &dst_x,
                                                   &dst_y,
                                                   &dst_width,
                                                   &dst_height,
                                                   &used);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_gdi_backend_gdiplus_transform_rect(context,
                                                        &dst_x,
                                                        &dst_y,
                                                        &dst_width,
                                                        &dst_height);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return rdp_gdi_backend_render_gdiplus_image(surface,
                                                context,
                                                image,
                                                dst_x,
                                                dst_y,
                                                dst_width,
                                                dst_height,
                                                src_x,
                                                src_y,
                                                src_width,
                                                src_height,
                                                rasterized);
}

static librdp_status rdp_gdi_backend_gdiplus_draw_text_cell(rdp_gdi_backend_kind backend,
                                                            librdp_surface* surface,
                                                            const rdp_gdi_backend_gdiplus_context* context,
                                                            int32_t x,
                                                            int32_t y,
                                                            uint32_t color,
                                                            uint16_t glyph)
{
    uint32_t stripe = (uint32_t)(glyph % RDP_GDIPLUS_TEXT_CELL_WIDTH);
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_gdi_backend_fill_rect_clipped(backend,
                                               surface,
                                               x,
                                               y,
                                               RDP_GDIPLUS_TEXT_CELL_WIDTH,
                                               RDP_GDIPLUS_TEXT_CELL_HEIGHT,
                                               color,
                                               context ? &context->clip : NULL);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_gdi_backend_fill_rect_clipped(backend,
                                             surface,
                                             x + (int32_t)stripe,
                                             y + 1,
                                             1u,
                                             RDP_GDIPLUS_TEXT_CELL_HEIGHT - 2u,
                                             0xffffffu ^ color,
                                             context ? &context->clip : NULL);
}

static librdp_status rdp_gdi_backend_render_gdiplus_draw_string(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported)
{
    uint32_t brush = 0u;
    uint32_t length = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    int32_t x = 0;
    int32_t y = 0;
    uint32_t width = 0u;
    uint32_t height = 0u;
    size_t used = 0u;
    uint32_t i = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!payload || data_size < 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush = rdp_gdi_backend_read_u32_le(payload);
    length = rdp_gdi_backend_read_u32_le(payload + 8u);
    if (length > 4096u || data_size < 28u + ((size_t)length * 2u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush,
                                                    RDP_GDIPLUS_OBJECT_KIND_BRUSH,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    (void)pen_width;
    status = rdp_gdi_backend_gdiplus_read_rect(payload + 12u,
                                               data_size - 12u,
                                               0,
                                               &x,
                                               &y,
                                               &width,
                                               &height,
                                               &used);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
    if (status != LIBRDP_STATUS_OK)
        return status;
    for (i = 0u; i < length; i++)
    {
        uint16_t glyph = rdp_gdi_backend_read_u16_le(payload + 28u + ((size_t)i * 2u));
        int32_t glyph_x = x + (int32_t)(i * RDP_GDIPLUS_TEXT_CELL_WIDTH);

        if (glyph == 0u || glyph == 0x20u || glyph_x >= x + (int32_t)width)
            continue;
        status = rdp_gdi_backend_gdiplus_draw_text_cell(backend,
                                                        surface,
                                                        context,
                                                        glyph_x,
                                                        y,
                                                        color,
                                                        glyph);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (rasterized)
        (*rasterized)++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_render_gdiplus_draw_driver_string(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    uint16_t flags,
    const uint8_t* payload,
    uint32_t data_size,
    uint32_t* rasterized,
    uint32_t* unsupported)
{
    uint32_t brush = 0u;
    uint32_t glyph_count = 0u;
    uint32_t color = 0u;
    uint32_t pen_width = 1u;
    size_t glyph_offset = 16u;
    size_t point_offset = 0u;
    uint32_t i = 0u;

    if (!payload || data_size < 16u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    brush = rdp_gdi_backend_read_u32_le(payload);
    glyph_count = rdp_gdi_backend_read_u32_le(payload + 12u);
    if (glyph_count == 0u || glyph_count > 4096u ||
        (size_t)glyph_count > ((size_t)-1 - glyph_offset) / 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    point_offset = glyph_offset + ((size_t)glyph_count * 2u);
    if (data_size < point_offset + ((size_t)glyph_count * 8u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (!rdp_gdi_backend_gdiplus_resolve_draw_color(context,
                                                    flags,
                                                    brush,
                                                    RDP_GDIPLUS_OBJECT_KIND_BRUSH,
                                                    &color,
                                                    &pen_width))
    {
        if (unsupported)
            (*unsupported)++;
        return LIBRDP_STATUS_OK;
    }
    (void)pen_width;
    for (i = 0u; i < glyph_count; i++)
    {
        uint16_t glyph = rdp_gdi_backend_read_u16_le(payload + glyph_offset + ((size_t)i * 2u));
        rdp_gdi_backend_point point;
        size_t used = 0u;
        librdp_status status = rdp_gdi_backend_gdiplus_read_point(payload + point_offset + ((size_t)i * 8u),
                                                                  data_size - point_offset - ((size_t)i * 8u),
                                                                  0,
                                                                  &point,
                                                                  &used);

        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &point);
        status = rdp_gdi_backend_gdiplus_draw_text_cell(backend,
                                                        surface,
                                                        context,
                                                        point.x,
                                                        point.y,
                                                        color,
                                                        glyph);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (rasterized)
        (*rasterized)++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_render_gdiplus_serializable_object(const uint8_t* payload,
                                                                        uint32_t data_size)
{
    uint32_t buffer_size = 0u;

    if (!payload || data_size < 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    buffer_size = rdp_gdi_backend_read_u32_le(payload + 16u);
    if (buffer_size > data_size - 20u || data_size != 20u + buffer_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_gdi_backend_gdiplus_set_clip_from_path(
    rdp_gdi_backend_gdiplus_context* context,
    const rdp_gdi_backend_gdiplus_object* object)
{
    rdp_gdi_backend_gdiplus_path path;
    rdp_gdi_backend_point* flattened = NULL;
    uint32_t count = 0u;
    uint32_t i = 0u;
    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 0;
    int32_t bottom = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !object)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&path, 0, sizeof(path));
    status = rdp_gdi_backend_gdiplus_parse_path_object(object, &path);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_gdi_backend_gdiplus_flatten_path(&path, context, &flattened, &count))
    {
        rdp_gdi_backend_gdiplus_path_free(&path);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    left = flattened[0].x;
    right = flattened[0].x;
    top = flattened[0].y;
    bottom = flattened[0].y;
    for (i = 1u; i < count; i++)
    {
        if (flattened[i].x < left)
            left = flattened[i].x;
        if (flattened[i].x > right)
            right = flattened[i].x;
        if (flattened[i].y < top)
            top = flattened[i].y;
        if (flattened[i].y > bottom)
            bottom = flattened[i].y;
    }
    context->clip.present = 1u;
    context->clip.left = left;
    context->clip.top = top;
    context->clip.right = right;
    context->clip.bottom = bottom;
    free(flattened);
    rdp_gdi_backend_gdiplus_path_free(&path);
    return LIBRDP_STATUS_OK;
}

/*
 * Purpose: derive the active clip bounds from an EMF+ region object. Invariants:
 * only rect/path/infinite/empty nodes update the clip, and path node memory is
 * borrowed from the region object. Failure policy: unsupported node encodings
 * fail the stream so later drawing is not clipped with stale state.
 */
static librdp_status rdp_gdi_backend_gdiplus_set_clip_from_region(
    rdp_gdi_backend_gdiplus_context* context,
    const rdp_gdi_backend_gdiplus_object* region)
{
    const uint8_t* data = NULL;
    size_t length = 0u;
    uint32_t count = 0u;
    size_t offset = 8u;
    uint32_t i = 0u;
    int have_bounds = 0;
    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 0;
    int32_t bottom = 0;

    if (!context || !region || !region->data || region->data_len < 8u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    data = region->data;
    length = region->data_len;
    count = rdp_gdi_backend_read_u32_le(data + 4u);
    if (count == 0u || count > 256u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0u; i < count; i++)
    {
        uint32_t node_type = 0u;

        if (length - offset < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        node_type = rdp_gdi_backend_read_u32_le(data + offset);
        offset += 4u;
        if (node_type == RDP_GDIPLUS_REGION_NODE_EMPTY)
            continue;
        if (node_type == RDP_GDIPLUS_REGION_NODE_INFINITE)
        {
            context->clip.present = 0u;
            return LIBRDP_STATUS_OK;
        }
        if (node_type == RDP_GDIPLUS_REGION_NODE_RECT)
        {
            int32_t x = 0;
            int32_t y = 0;
            uint32_t width = 0u;
            uint32_t height = 0u;
            size_t used = 0u;
            librdp_status status = rdp_gdi_backend_gdiplus_read_rect(data + offset,
                                                                     length - offset,
                                                                     0,
                                                                     &x,
                                                                     &y,
                                                                     &width,
                                                                     &height,
                                                                     &used);

            if (status != LIBRDP_STATUS_OK)
                return status;
            offset += used;
            status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (!have_bounds)
            {
                left = x;
                top = y;
                right = x + (int32_t)width - 1;
                bottom = y + (int32_t)height - 1;
                have_bounds = 1;
            }
            else
            {
                if (x < left)
                    left = x;
                if (y < top)
                    top = y;
                if (x + (int32_t)width - 1 > right)
                    right = x + (int32_t)width - 1;
                if (y + (int32_t)height - 1 > bottom)
                    bottom = y + (int32_t)height - 1;
            }
            continue;
        }
        if (node_type == RDP_GDIPLUS_REGION_NODE_PATH)
        {
            rdp_gdi_backend_gdiplus_object path_object;

            memset(&path_object, 0, sizeof(path_object));
            path_object.active = 1u;
            path_object.object_type = RDP_GDIPLUS_OBJECT_TYPE_PATH;
            path_object.data = (uint8_t*)(data + offset);
            path_object.data_len = length - offset;
            return rdp_gdi_backend_gdiplus_set_clip_from_path(context, &path_object);
        }
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (have_bounds)
    {
        context->clip.present = 1u;
        context->clip.left = left;
        context->clip.top = top;
        context->clip.right = right;
        context->clip.bottom = bottom;
    }
    else
    {
        context->clip.present = 1u;
        context->clip.left = 1;
        context->clip.top = 1;
        context->clip.right = 0;
        context->clip.bottom = 0;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_gdi_backend_gdiplus_matrix_multiply(float dst[6], const float rhs[6])
{
    float lhs[6];

    memcpy(lhs, dst, sizeof(lhs));
    dst[0] = (lhs[0] * rhs[0]) + (lhs[2] * rhs[1]);
    dst[1] = (lhs[1] * rhs[0]) + (lhs[3] * rhs[1]);
    dst[2] = (lhs[0] * rhs[2]) + (lhs[2] * rhs[3]);
    dst[3] = (lhs[1] * rhs[2]) + (lhs[3] * rhs[3]);
    dst[4] = (lhs[0] * rhs[4]) + (lhs[2] * rhs[5]) + lhs[4];
    dst[5] = (lhs[1] * rhs[4]) + (lhs[3] * rhs[5]) + lhs[5];
}

static float rdp_gdi_backend_gdiplus_sin_approx(float radians)
{
    const float pi = 3.14159265358979323846f;

    while (radians > pi)
        radians -= 2.0f * pi;
    while (radians < -pi)
        radians += 2.0f * pi;
    return radians - ((radians * radians * radians) / 6.0f) +
           ((radians * radians * radians * radians * radians) / 120.0f);
}

static float rdp_gdi_backend_gdiplus_cos_approx(float radians)
{
    const float half_pi = 1.57079632679489661923f;

    return rdp_gdi_backend_gdiplus_sin_approx(radians + half_pi);
}

/*
 * Purpose: rasterize EMF+ arc and pie records using the record start/sweep
 * angles instead of falling back to a full ellipse. Invariants: generated
 * points are stack-bounded and transformed before dispatch. Failure policy:
 * invalid geometry is rejected before drawing and clipped output is treated as
 * a successful no-op.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_arc_points(
    rdp_gdi_backend_kind backend,
    librdp_surface* surface,
    const rdp_gdi_backend_gdiplus_context* context,
    int32_t x,
    int32_t y,
    uint32_t width,
    uint32_t height,
    float start_angle,
    float sweep_angle,
    uint32_t color,
    uint32_t pen_width,
    int fill_pie,
    int close_pie,
    uint32_t* rasterized)
{
    const uint32_t segments = 32u;
    rdp_gdi_backend_point points[34];
    uint32_t count = 0u;
    uint32_t i = 0u;
    float center_x = (float)x + ((float)width / 2.0f);
    float center_y = (float)y + ((float)height / 2.0f);
    float radius_x = (float)width / 2.0f;
    float radius_y = (float)height / 2.0f;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!surface || width == 0u || height == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (fill_pie)
    {
        points[count].x = rdp_gdi_backend_gdiplus_round_i32(center_x);
        points[count].y = rdp_gdi_backend_gdiplus_round_i32(center_y);
        rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &points[count]);
        count++;
    }
    for (i = 0u; i <= segments; i++)
    {
        float angle = (start_angle + (sweep_angle * ((float)i / (float)segments))) *
                      0.01745329251994329577f;
        float px = center_x + (rdp_gdi_backend_gdiplus_cos_approx(angle) * radius_x);
        float py = center_y + (rdp_gdi_backend_gdiplus_sin_approx(angle) * radius_y);

        if (count >= sizeof(points) / sizeof(points[0]))
            break;
        points[count].x = rdp_gdi_backend_gdiplus_round_i32(px);
        points[count].y = rdp_gdi_backend_gdiplus_round_i32(py);
        rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &points[count]);
        count++;
    }
    if (fill_pie)
    {
        status = rdp_gdi_backend_fill_polygon(backend,
                                              surface,
                                              points,
                                              count,
                                              1u,
                                              color,
                                              context ? &context->clip : NULL,
                                              NULL,
                                              NULL,
                                              NULL,
                                              NULL);
    }
    else
    {
        uint32_t start_index = 0u;

        for (i = 1u; i < count && status == LIBRDP_STATUS_OK; i++)
        {
            uint32_t dirty_left = UINT32_MAX;
            uint32_t dirty_top = UINT32_MAX;
            uint32_t dirty_right = 0u;
            uint32_t dirty_bottom = 0u;

            status = rdp_gdi_backend_draw_line(backend,
                                               surface,
                                               points[i - 1u].x,
                                               points[i - 1u].y,
                                               points[i].x,
                                               points[i].y,
                                               pen_width,
                                               color,
                                               context ? &context->clip : NULL,
                                               &dirty_left,
                                               &dirty_top,
                                               &dirty_right,
                                               &dirty_bottom);
        }
        if (close_pie && status == LIBRDP_STATUS_OK)
        {
            rdp_gdi_backend_point center;
            uint32_t dirty_left = UINT32_MAX;
            uint32_t dirty_top = UINT32_MAX;
            uint32_t dirty_right = 0u;
            uint32_t dirty_bottom = 0u;

            center.x = rdp_gdi_backend_gdiplus_round_i32(center_x);
            center.y = rdp_gdi_backend_gdiplus_round_i32(center_y);
            rdp_gdi_backend_gdiplus_transform_point(context ? context->transform : NULL, &center);
            status = rdp_gdi_backend_draw_line(backend,
                                               surface,
                                               center.x,
                                               center.y,
                                               points[start_index].x,
                                               points[start_index].y,
                                               pen_width,
                                               color,
                                               context ? &context->clip : NULL,
                                               &dirty_left,
                                               &dirty_top,
                                               &dirty_right,
                                               &dirty_bottom);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_gdi_backend_draw_line(backend,
                                                   surface,
                                                   center.x,
                                                   center.y,
                                                   points[count - 1u].x,
                                                   points[count - 1u].y,
                                                   pen_width,
                                                   color,
                                                   context ? &context->clip : NULL,
                                                   &dirty_left,
                                                   &dirty_top,
                                                   &dirty_right,
                                                   &dirty_bottom);
        }
    }
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        status = LIBRDP_STATUS_OK;
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

/*
 * Purpose: apply EMF+ state records that affect subsequent rendering. Invariants:
 * transform, clip and save-stack state remain local to one stream replay.
 * Failure policy: stack underflow/overflow and malformed state payloads fail
 * the stream instead of leaving partially updated drawing state.
 */
static librdp_status rdp_gdi_backend_render_gdiplus_state_only(rdp_gdi_backend_gdiplus_context* context,
                                                               uint16_t flags,
                                                               uint16_t type,
                                                               const uint8_t* payload,
                                                               uint32_t data_size)
{
    float matrix[6];

    if (!context || (!payload && data_size > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (type == RDP_GDIPLUS_RECORD_RESET_WORLD_TRANSFORM)
    {
        rdp_gdi_backend_gdiplus_transform_identity(context->transform);
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_WORLD_TRANSFORM ||
        type == RDP_GDIPLUS_RECORD_MULTIPLY_WORLD_TRANSFORM)
    {
        if (data_size < 24u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        matrix[0] = rdp_gdi_backend_read_float_le(payload);
        matrix[1] = rdp_gdi_backend_read_float_le(payload + 4u);
        matrix[2] = rdp_gdi_backend_read_float_le(payload + 8u);
        matrix[3] = rdp_gdi_backend_read_float_le(payload + 12u);
        matrix[4] = rdp_gdi_backend_read_float_le(payload + 16u);
        matrix[5] = rdp_gdi_backend_read_float_le(payload + 20u);
        if (type == RDP_GDIPLUS_RECORD_SET_WORLD_TRANSFORM)
            memcpy(context->transform, matrix, sizeof(matrix));
        else
            rdp_gdi_backend_gdiplus_matrix_multiply(context->transform, matrix);
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_TRANSLATE_WORLD_TRANSFORM ||
        type == RDP_GDIPLUS_RECORD_SCALE_WORLD_TRANSFORM)
    {
        float a = 0.0f;
        float b = 0.0f;

        if (data_size < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        a = rdp_gdi_backend_read_float_le(payload);
        b = rdp_gdi_backend_read_float_le(payload + 4u);
        if (type == RDP_GDIPLUS_RECORD_TRANSLATE_WORLD_TRANSFORM)
        {
            matrix[0] = 1.0f;
            matrix[1] = 0.0f;
            matrix[2] = 0.0f;
            matrix[3] = 1.0f;
            matrix[4] = a;
            matrix[5] = b;
        }
        else
        {
            matrix[0] = a;
            matrix[1] = 0.0f;
            matrix[2] = 0.0f;
            matrix[3] = b;
            matrix[4] = 0.0f;
            matrix[5] = 0.0f;
        }
        rdp_gdi_backend_gdiplus_matrix_multiply(context->transform, matrix);
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_ROTATE_WORLD_TRANSFORM)
    {
        float angle = 0.0f;
        float radians = 0.0f;
        float sin_v = 0.0f;
        float cos_v = 0.0f;

        if (data_size < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        angle = rdp_gdi_backend_read_float_le(payload);
        radians = angle * 0.01745329251994329577f;
        sin_v = rdp_gdi_backend_gdiplus_sin_approx(radians);
        cos_v = rdp_gdi_backend_gdiplus_cos_approx(radians);
        matrix[0] = cos_v;
        matrix[1] = sin_v;
        matrix[2] = -sin_v;
        matrix[3] = cos_v;
        matrix[4] = 0.0f;
        matrix[5] = 0.0f;
        rdp_gdi_backend_gdiplus_matrix_multiply(context->transform, matrix);
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SAVE || type == RDP_GDIPLUS_RECORD_BEGIN_CONTAINER ||
        type == RDP_GDIPLUS_RECORD_BEGIN_CONTAINER_NO_PARAMS)
    {
        if (context->stack_depth >= RDP_GDIPLUS_STATE_STACK_SIZE)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_gdi_backend_gdiplus_state_capture(context, &context->stack[context->stack_depth]);
        context->stack_depth++;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_RESTORE || type == RDP_GDIPLUS_RECORD_END_CONTAINER)
    {
        if (context->stack_depth == 0u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        context->stack_depth--;
        rdp_gdi_backend_gdiplus_state_restore(context, &context->stack[context->stack_depth]);
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_RENDERING_ORIGIN)
    {
        if (data_size < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        context->rendering_origin_x = (int32_t)rdp_gdi_backend_read_u32_le(payload);
        context->rendering_origin_y = (int32_t)rdp_gdi_backend_read_u32_le(payload + 4u);
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_ANTI_ALIAS_MODE)
    {
        context->anti_alias_mode = flags & 0xffu;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_TEXT_RENDERING_HINT)
    {
        context->text_rendering_hint = flags & 0xffu;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_TEXT_CONTRAST)
    {
        context->text_contrast = flags & 0x0fffu;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_INTERPOLATION_MODE)
    {
        context->interpolation_mode = flags & 0xffu;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_PIXEL_OFFSET_MODE)
    {
        context->pixel_offset_mode = flags & 0xffu;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_COMPOSITING_MODE)
    {
        context->compositing_mode = flags & 0xffu;
        if (context->compositing_mode > 1u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_COMPOSITING_QUALITY)
    {
        context->compositing_quality = flags & 0xffu;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_PAGE_TRANSFORM)
    {
        float page_scale = 0.0f;

        if (data_size < 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        page_scale = rdp_gdi_backend_read_float_le(payload);
        if (!(page_scale > 0.0f && page_scale <= 1024.0f))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        context->page_unit = flags & 0xffu;
        context->page_scale = page_scale;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_RESET_CLIP)
    {
        memset(&context->clip, 0, sizeof(context->clip));
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_CLIP_RECT)
    {
        int32_t x = 0;
        int32_t y = 0;
        uint32_t width = 0u;
        uint32_t height = 0u;
        size_t used = 0u;
        librdp_status status = rdp_gdi_backend_gdiplus_read_rect(payload,
                                                                 data_size,
                                                                 (data_size >= 8u && data_size < 16u),
                                                                 &x,
                                                                 &y,
                                                                 &width,
                                                                 &height,
                                                                 &used);

        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_gdi_backend_gdiplus_transform_rect(context, &x, &y, &width, &height);
        if (status != LIBRDP_STATUS_OK)
            return status;
        context->clip.present = 1u;
        context->clip.left = x;
        context->clip.top = y;
        context->clip.right = x + (int32_t)width - 1;
        context->clip.bottom = y + (int32_t)height - 1;
        (void)used;
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_OFFSET_CLIP)
    {
        int32_t dx = 0;
        int32_t dy = 0;

        if (data_size < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        dx = rdp_gdi_backend_gdiplus_round_i32(rdp_gdi_backend_read_float_le(payload));
        dy = rdp_gdi_backend_gdiplus_round_i32(rdp_gdi_backend_read_float_le(payload + 4u));
        if (context->clip.present)
        {
            context->clip.left += dx;
            context->clip.right += dx;
            context->clip.top += dy;
            context->clip.bottom += dy;
        }
        return LIBRDP_STATUS_OK;
    }
    if (type == RDP_GDIPLUS_RECORD_SET_CLIP_PATH)
    {
        uint32_t object_id = flags & 0xffu;
        const rdp_gdi_backend_gdiplus_object* path_object = NULL;

        if (payload && data_size >= 4u)
            object_id = rdp_gdi_backend_read_u32_le(payload) & 0xffu;
        path_object = rdp_gdi_backend_gdiplus_get_object(context,
                                                         object_id,
                                                         RDP_GDIPLUS_OBJECT_TYPE_PATH);
        if (!path_object)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return rdp_gdi_backend_gdiplus_set_clip_from_path(context, path_object);
    }
    if (type == RDP_GDIPLUS_RECORD_SET_CLIP_REGION)
    {
        uint32_t object_id = flags & 0xffu;
        const rdp_gdi_backend_gdiplus_object* region = NULL;

        if (payload && data_size >= 4u)
            object_id = rdp_gdi_backend_read_u32_le(payload) & 0xffu;
        region = rdp_gdi_backend_gdiplus_get_object(context,
                                                    object_id,
                                                    RDP_GDIPLUS_OBJECT_TYPE_REGION);
        if (!region)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        return rdp_gdi_backend_gdiplus_set_clip_from_region(context, region);
    }
    if (type == RDP_GDIPLUS_RECORD_SET_TS_CLIP && data_size >= 16u)
    {
        int32_t x = 0;
        int32_t y = 0;
        uint32_t width = 0u;
        uint32_t height = 0u;
        size_t used = 0u;
        librdp_status status = rdp_gdi_backend_gdiplus_read_rect(payload,
                                                                 data_size,
                                                                 0,
                                                                 &x,
                                                                 &y,
                                                                 &width,
                                                                 &height,
                                                                 &used);

        if (status != LIBRDP_STATUS_OK)
            return status;
        context->clip.present = 1u;
        context->clip.left = x;
        context->clip.top = y;
        context->clip.right = x + (int32_t)width - 1;
        context->clip.bottom = y + (int32_t)height - 1;
    }
    return LIBRDP_STATUS_OK;
}

static int rdp_gdi_backend_gdiplus_is_state_only(uint16_t type)
{
    return type == RDP_GDIPLUS_RECORD_HEADER ||
           type == RDP_GDIPLUS_RECORD_END_OF_FILE ||
           type == RDP_GDIPLUS_RECORD_COMMENT ||
           type == RDP_GDIPLUS_RECORD_GET_DC ||
           type == RDP_GDIPLUS_RECORD_MULTIFORMAT_START ||
           type == RDP_GDIPLUS_RECORD_MULTIFORMAT_SECTION ||
           type == RDP_GDIPLUS_RECORD_MULTIFORMAT_END ||
           (type >= RDP_GDIPLUS_RECORD_SET_RENDERING_ORIGIN &&
            type <= RDP_GDIPLUS_RECORD_SET_TS_CLIP);
}

/*
 * Parses a bounded EMF+ stream and routes visual records to either native
 * backend primitives or deterministic software helpers before returning.
 * State records update the transform and clip context used by later records.
 */
librdp_status rdp_gdi_backend_render_gdiplus_stream(rdp_gdi_backend_kind backend,
                                                    librdp_surface* surface,
                                                    const uint8_t* data,
                                                    size_t length,
                                                    uint32_t* records,
                                                    uint32_t* rasterized,
                                                    uint32_t* unsupported)
{
    size_t offset = 0;
    rdp_gdi_backend_gdiplus_context context;
    librdp_status final_status = LIBRDP_STATUS_OK;

    if (!surface || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_gdi_backend_gdiplus_context_init(&context);
    if (records)
        *records = 0;
    if (rasterized)
        *rasterized = 0;
    if (unsupported)
        *unsupported = 0;
    if (length == 0)
        return LIBRDP_STATUS_OK;
    while (offset < length)
    {
        uint16_t type = 0;
        uint16_t flags = 0;
        uint32_t size = 0;
        uint32_t data_size = 0;
        uint32_t total_object_size = 0;
        int continued_object = 0;
        const uint8_t* payload = NULL;
        librdp_status status = LIBRDP_STATUS_OK;

        if (length - offset < 12u)
        {
            rdp_gdi_backend_gdiplus_context_free(&context);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        type = rdp_gdi_backend_read_u16_le(data + offset);
        flags = rdp_gdi_backend_read_u16_le(data + offset + 2u);
        size = rdp_gdi_backend_read_u32_le(data + offset + 4u);
        if (type == RDP_GDIPLUS_RECORD_OBJECT && (flags & 0x8000u) != 0)
        {
            if (length - offset < 16u)
            {
                rdp_gdi_backend_gdiplus_context_free(&context);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            total_object_size = rdp_gdi_backend_read_u32_le(data + offset + 8u);
            data_size = rdp_gdi_backend_read_u32_le(data + offset + 12u);
            if (size < 16u || data_size > size - 16u || size > length - offset)
            {
                rdp_gdi_backend_gdiplus_context_free(&context);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            payload = data + offset + 16u;
            continued_object = 1;
        }
        else
        {
            data_size = rdp_gdi_backend_read_u32_le(data + offset + 8u);
            if (size < 12u || data_size > size - 12u || size > length - offset)
            {
                rdp_gdi_backend_gdiplus_context_free(&context);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            total_object_size = data_size;
            payload = data + offset + 12u;
        }
        if (records)
            (*records)++;
        switch (type)
        {
            case RDP_GDIPLUS_RECORD_OBJECT:
                status = rdp_gdi_backend_render_gdiplus_object(&context,
                                                               flags,
                                                               payload,
                                                               data_size,
                                                               total_object_size,
                                                               continued_object,
                                                               unsupported);
                break;
            case RDP_GDIPLUS_RECORD_CLEAR:
                status = rdp_gdi_backend_render_gdiplus_clear(backend,
                                                              surface,
                                                              payload,
                                                              data_size,
                                                              rasterized);
                break;
            case RDP_GDIPLUS_RECORD_FILL_RECTS:
                status = rdp_gdi_backend_render_gdiplus_fill_rects(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_RECTS:
                status = rdp_gdi_backend_render_gdiplus_draw_rects(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported);
                break;
            case RDP_GDIPLUS_RECORD_FILL_POLYGON:
                status = rdp_gdi_backend_render_gdiplus_points(backend,
                                                               surface,
                                                               &context,
                                                               flags,
                                                               payload,
                                                               data_size,
                                                               rasterized,
                                                               unsupported,
                                                               1);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_LINES:
                status = rdp_gdi_backend_render_gdiplus_draw_lines(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_CLOSED_CURVE:
                status = rdp_gdi_backend_render_gdiplus_closed_curve(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported,
                                                                     0);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_CURVE:
                status = rdp_gdi_backend_render_gdiplus_draw_curve(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_BEZIERS:
                status = rdp_gdi_backend_render_gdiplus_draw_beziers(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported);
                break;
            case RDP_GDIPLUS_RECORD_FILL_CLOSED_CURVE:
                status = rdp_gdi_backend_render_gdiplus_closed_curve(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported,
                                                                     1);
                break;
            case RDP_GDIPLUS_RECORD_FILL_ELLIPSE:
                status = rdp_gdi_backend_render_gdiplus_fill_ellipse(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_ELLIPSE:
                status = rdp_gdi_backend_render_gdiplus_draw_ellipse(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported);
                break;
            case RDP_GDIPLUS_RECORD_FILL_PIE:
            case RDP_GDIPLUS_RECORD_DRAW_PIE:
            case RDP_GDIPLUS_RECORD_DRAW_ARC:
                status = rdp_gdi_backend_render_gdiplus_pie_or_arc(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported,
                                                                   type);
                break;
            case RDP_GDIPLUS_RECORD_FILL_REGION:
                status = rdp_gdi_backend_render_gdiplus_fill_region(backend,
                                                                    surface,
                                                                    &context,
                                                                    flags,
                                                                    payload,
                                                                    data_size,
                                                                    rasterized,
                                                                    unsupported);
                break;
            case RDP_GDIPLUS_RECORD_FILL_PATH:
            case RDP_GDIPLUS_RECORD_DRAW_PATH:
            case RDP_GDIPLUS_RECORD_STROKE_FILL_PATH:
                status = rdp_gdi_backend_render_gdiplus_fill_or_draw_path(backend,
                                                                          surface,
                                                                          &context,
                                                                          flags,
                                                                          payload,
                                                                          data_size,
                                                                          rasterized,
                                                                          unsupported,
                                                                          type);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_IMAGE:
                status = rdp_gdi_backend_render_gdiplus_draw_image(surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported,
                                                                   0);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_IMAGE_POINTS:
                status = rdp_gdi_backend_render_gdiplus_draw_image(surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported,
                                                                   1);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_STRING:
                status = rdp_gdi_backend_render_gdiplus_draw_string(backend,
                                                                    surface,
                                                                    &context,
                                                                    flags,
                                                                    payload,
                                                                    data_size,
                                                                    rasterized,
                                                                    unsupported);
                break;
            case RDP_GDIPLUS_RECORD_DRAW_DRIVER_STRING:
                status = rdp_gdi_backend_render_gdiplus_draw_driver_string(backend,
                                                                           surface,
                                                                           &context,
                                                                           flags,
                                                                           payload,
                                                                           data_size,
                                                                           rasterized,
                                                                           unsupported);
                break;
            case RDP_GDIPLUS_RECORD_SERIALIZABLE_OBJECT:
                status = rdp_gdi_backend_render_gdiplus_serializable_object(payload, data_size);
                break;
            default:
                if (rdp_gdi_backend_gdiplus_is_state_only(type))
                    status = rdp_gdi_backend_render_gdiplus_state_only(&context,
                                                                       flags,
                                                                       type,
                                                                       payload,
                                                                       data_size);
                else
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
        }
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_gdi_backend_gdiplus_context_free(&context);
            return status;
        }
        offset += size;
    }
    if (context.partial.active)
        final_status = LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_gdi_backend_gdiplus_context_free(&context);
    return final_status;
}

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
           RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM;
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
    return argb & 0x00ffffffu;
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
            pixel[0] = b;
            pixel[1] = g;
            pixel[2] = r;
            pixel[3] = 0xffu;
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
#define RDP_GDIPLUS_OBJECT_TYPE_BRUSH 1u
#define RDP_GDIPLUS_OBJECT_TYPE_PEN 2u

typedef struct rdp_gdi_backend_gdiplus_object
{
    uint8_t active;
    uint8_t kind;
    uint32_t color;
    uint32_t pen_width;
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

typedef struct rdp_gdi_backend_gdiplus_context
{
    rdp_gdi_backend_gdiplus_object objects[RDP_GDIPLUS_OBJECT_TABLE_SIZE];
    rdp_gdi_backend_gdiplus_partial_object partial;
} rdp_gdi_backend_gdiplus_context;

static void rdp_gdi_backend_gdiplus_context_free(rdp_gdi_backend_gdiplus_context* context)
{
    if (!context)
        return;
    free(context->partial.data);
    memset(context, 0, sizeof(*context));
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

static int rdp_gdi_backend_gdiplus_parse_solid_pen(const uint8_t* data,
                                                   size_t length,
                                                   uint32_t* color,
                                                   uint32_t* pen_width)
{
    uint32_t object_type = 0;
    uint32_t pen_flags = 0;
    float width = 0.0f;
    size_t brush_offset = 20u;

    if (!data || !color || !pen_width || length < brush_offset + 12u)
        return 0;
    object_type = rdp_gdi_backend_read_u32_le(data + 4u);
    pen_flags = rdp_gdi_backend_read_u32_le(data + 8u);
    if (object_type != 0)
        return 0;
    if ((pen_flags & (0x00000100u | 0x00000400u | 0x00000800u | 0x00001000u)) != 0)
        return 0;
    if ((pen_flags & 0x00000001u) != 0)
        brush_offset += 24u;
    if ((pen_flags & 0x00000002u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000004u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000008u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000010u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000020u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000040u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000080u) != 0)
        brush_offset += 4u;
    if ((pen_flags & 0x00000200u) != 0)
        brush_offset += 4u;
    if (brush_offset > length || length - brush_offset < 12u)
        return 0;
    width = rdp_gdi_backend_read_float_le(data + 16u);
    if (!rdp_gdi_backend_gdiplus_parse_solid_brush(data + brush_offset, length - brush_offset, color))
        return 0;
    *pen_width = rdp_gdi_backend_float_to_pen_width(width);
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
    uint32_t pen_width = 1u;

    if (!context || object_id >= RDP_GDIPLUS_OBJECT_TABLE_SIZE || !data)
        return 0;
    object = &context->objects[object_id];
    memset(object, 0, sizeof(*object));
    if (object_type == RDP_GDIPLUS_OBJECT_TYPE_BRUSH)
    {
        if (!rdp_gdi_backend_gdiplus_parse_solid_brush(data, length, &color))
            return 0;
        object->kind = RDP_GDIPLUS_OBJECT_KIND_BRUSH;
        object->color = color;
        object->pen_width = 1u;
        object->active = 1u;
        return 1;
    }
    if (object_type == RDP_GDIPLUS_OBJECT_TYPE_PEN)
    {
        if (!rdp_gdi_backend_gdiplus_parse_solid_pen(data, length, &color, &pen_width))
            return 0;
        object->kind = RDP_GDIPLUS_OBJECT_KIND_PEN;
        object->color = color;
        object->pen_width = pen_width;
        object->active = 1u;
        return 1;
    }
    return 0;
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
        return 1;
    }
    if (!context || object_id >= RDP_GDIPLUS_OBJECT_TABLE_SIZE)
        return 0;
    object = &context->objects[object_id];
    if (!object->active || object->kind != expected_kind)
        return 0;
    *color = object->color;
    *pen_width = object->pen_width == 0u ? 1u : object->pen_width;
    return 1;
}

static librdp_status rdp_gdi_backend_draw_rect_outline(rdp_gdi_backend_kind backend,
                                                       librdp_surface* surface,
                                                       int32_t x,
                                                       int32_t y,
                                                       uint32_t width,
                                                       uint32_t height,
                                                       uint32_t pen_width,
                                                       uint32_t color)
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
                                       NULL,
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
                                       NULL,
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
                                       NULL,
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
                                     NULL,
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
        status = rdp_gdi_backend_draw_rect_outline(backend, surface, x, y, width, height, pen_width, color);
        if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
            continue;
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (rasterized)
            (*rasterized)++;
    }
    return LIBRDP_STATUS_OK;
}

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
    size_t rect_size = compressed ? 8u : 16u;

    if (data_size < 8u)
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
        status = rdp_gdi_backend_fill_rect(backend, surface, (uint32_t)x, (uint32_t)y, width, height, color);
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
    uint32_t i = 0;
    uint32_t color = 0;
    uint32_t pen_width = 1u;
    int compressed = (flags & 0x4000u) != 0;
    size_t point_size = compressed ? 4u : 8u;
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
    points = (rdp_gdi_backend_point*)calloc(count, sizeof(*points));
    if (!points)
        return LIBRDP_STATUS_NO_MEMORY;
    for (i = 0; i < count; i++)
    {
        size_t used = 0;

        status = rdp_gdi_backend_gdiplus_read_point(payload + 8u + ((size_t)i * point_size),
                                                    point_size,
                                                    compressed,
                                                    &points[i],
                                                    &used);
        if (status != LIBRDP_STATUS_OK)
        {
            free(points);
            return status;
        }
        (void)used;
    }
    if (fill_polygon)
    {
        status = rdp_gdi_backend_fill_polygon(backend,
                                              surface,
                                              points,
                                              count,
                                              (flags & 0x2000u) != 0 ? 2u : 1u,
                                              color,
                                              NULL,
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
        for (i = 1; i < count && status == LIBRDP_STATUS_OK; i++)
        {
            uint32_t dirty_left = UINT32_MAX;
            uint32_t dirty_top = UINT32_MAX;
            uint32_t dirty_right = 0;
            uint32_t dirty_bottom = 0;

            status = rdp_gdi_backend_draw_line(backend,
                                               surface,
                                               points[i - 1u].x,
                                               points[i - 1u].y,
                                               points[i].x,
                                               points[i].y,
                                               pen_width,
                                               color,
                                               NULL,
                                               &dirty_left,
                                               &dirty_top,
                                               &dirty_right,
                                               &dirty_bottom);
        }
        if (status == LIBRDP_STATUS_OK && rasterized)
            (*rasterized)++;
    }
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
    status = rdp_gdi_backend_fill_ellipse(backend, surface, x, y, width, height, color, NULL);
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
    status = rdp_gdi_backend_draw_ellipse(backend, surface, x, y, width, height, pen_width, color, NULL);
    if (status == LIBRDP_STATUS_INVALID_ARGUMENT)
        return LIBRDP_STATUS_OK;
    if (status == LIBRDP_STATUS_OK && rasterized)
        (*rasterized)++;
    return status;
}

/*
 * Parses a bounded EMF+ stream and rasterizes records whose semantics map to
 * the backend primitives. Brush and pen objects are kept in a local object
 * table, while text, image and path-only records are counted as unsupported
 * rather than guessed from incomplete state.
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
    memset(&context, 0, sizeof(context));
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
            if (unsupported)
                (*unsupported)++;
            rdp_gdi_backend_gdiplus_context_free(&context);
            return LIBRDP_STATUS_OK;
        }
        type = rdp_gdi_backend_read_u16_le(data + offset);
        flags = rdp_gdi_backend_read_u16_le(data + offset + 2u);
        size = rdp_gdi_backend_read_u32_le(data + offset + 4u);
        if (type == 0x4008u && (flags & 0x8000u) != 0)
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
            case 0x4001u:
            case 0x4002u:
                break;
            case 0x4008u:
                status = rdp_gdi_backend_render_gdiplus_object(&context,
                                                               flags,
                                                               payload,
                                                               data_size,
                                                               total_object_size,
                                                               continued_object,
                                                               unsupported);
                break;
            case 0x4009u:
                status = rdp_gdi_backend_render_gdiplus_clear(backend,
                                                              surface,
                                                              payload,
                                                              data_size,
                                                              rasterized);
                break;
            case 0x400au:
                status = rdp_gdi_backend_render_gdiplus_fill_rects(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported);
                break;
            case 0x400bu:
                status = rdp_gdi_backend_render_gdiplus_draw_rects(backend,
                                                                   surface,
                                                                   &context,
                                                                   flags,
                                                                   payload,
                                                                   data_size,
                                                                   rasterized,
                                                                   unsupported);
                break;
            case 0x400cu:
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
            case 0x400du:
                status = rdp_gdi_backend_render_gdiplus_points(backend,
                                                               surface,
                                                               &context,
                                                               flags,
                                                               payload,
                                                               data_size,
                                                               rasterized,
                                                               unsupported,
                                                               0);
                break;
            case 0x400eu:
                status = rdp_gdi_backend_render_gdiplus_fill_ellipse(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported);
                break;
            case 0x400fu:
                status = rdp_gdi_backend_render_gdiplus_draw_ellipse(backend,
                                                                     surface,
                                                                     &context,
                                                                     flags,
                                                                     payload,
                                                                     data_size,
                                                                     rasterized,
                                                                     unsupported);
                break;
            default:
                if (unsupported)
                    (*unsupported)++;
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

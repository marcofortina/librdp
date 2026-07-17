/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cairo-backed GDI raster primitives.
 * Invariants: Cairo is given only mapped BGRA32 image surfaces with checked
 * dimensions and stride.
 * Ownership: Cairo objects are local to each operation and never own the
 * librdp surface buffer.
 * Threading: callers serialize surface access; Cairo contexts are not shared.
 * Trust boundary: geometry comes from decoded RDP orders and is already
 * clipped by the dispatcher.
 */

#include "graphics/gdi_backend.h"

#include <limits.h>

#if defined(RDP_HAVE_CAIRO)
#include <cairo.h>
#endif

#if defined(RDP_HAVE_CAIRO)
static librdp_status rdp_gdi_backend_cairo_status(cairo_status_t status)
{
    if (status == CAIRO_STATUS_SUCCESS)
        return LIBRDP_STATUS_OK;
    if (status == CAIRO_STATUS_NO_MEMORY)
        return LIBRDP_STATUS_NO_MEMORY;
    return LIBRDP_STATUS_IO_ERROR;
}
#endif

#if defined(RDP_HAVE_CAIRO)
static uint32_t rdp_gdi_backend_cairo_caps(void)
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

static void rdp_gdi_backend_cairo_set_color(cairo_t* cr, uint32_t color)
{
    double b = (double)(color & 0xffu) / 255.0;
    double g = (double)((color >> 8u) & 0xffu) / 255.0;
    double r = (double)((color >> 16u) & 0xffu) / 255.0;
    uint8_t alpha_byte = (uint8_t)((color >> 24u) & 0xffu);
    double alpha = (double)(alpha_byte == 0u ? 0xffu : alpha_byte) / 255.0;

    cairo_set_source_rgba(cr, r, g, b, alpha);
}

static void rdp_gdi_backend_cairo_set_operator_for_color(cairo_t* cr, uint32_t color)
{
    uint8_t alpha_byte = (uint8_t)((color >> 24u) & 0xffu);

    cairo_set_operator(cr, alpha_byte == 0u || alpha_byte == 0xffu ? CAIRO_OPERATOR_SOURCE :
                                                               CAIRO_OPERATOR_OVER);
}

static librdp_status rdp_gdi_backend_cairo_create_context(librdp_surface* surface,
                                                          librdp_surface_mapping* mapping,
                                                          cairo_surface_t** cairo_surface,
                                                          cairo_t** cr)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!surface || !mapping || !cairo_surface || !cr)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *cairo_surface = NULL;
    *cr = NULL;
    if (librdp_surface_mapping_init(mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (mapping->width > INT_MAX || mapping->height > INT_MAX || mapping->stride > INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *cairo_surface = cairo_image_surface_create_for_data(mapping->writable_pixels,
                                                         CAIRO_FORMAT_ARGB32,
                                                         (int)mapping->width,
                                                         (int)mapping->height,
                                                         (int)mapping->stride);
    if (!*cairo_surface)
        return LIBRDP_STATUS_NO_MEMORY;
    status = rdp_gdi_backend_cairo_status(cairo_surface_status(*cairo_surface));
    if (status != LIBRDP_STATUS_OK)
        return status;
    *cr = cairo_create(*cairo_surface);
    if (!*cr)
        return LIBRDP_STATUS_NO_MEMORY;
    return rdp_gdi_backend_cairo_status(cairo_status(*cr));
}

static void rdp_gdi_backend_cairo_clip(cairo_t* cr, const rdp_gdi_backend_clip* clip)
{
    if (!cr || !clip || !clip->present)
        return;
    cairo_rectangle(cr,
                    (double)clip->left,
                    (double)clip->top,
                    (double)(clip->right - clip->left + 1),
                    (double)(clip->bottom - clip->top + 1));
    cairo_clip(cr);
}

static void rdp_gdi_backend_cairo_destroy_context(librdp_surface* surface,
                                                  librdp_surface_mapping* mapping,
                                                  cairo_surface_t* cairo_surface,
                                                  cairo_t* cr,
                                                  librdp_status* status)
{
    librdp_status unmap_status = LIBRDP_STATUS_OK;

    if (cairo_surface)
        cairo_surface_flush(cairo_surface);
    if (cr)
        cairo_destroy(cr);
    if (cairo_surface)
        cairo_surface_destroy(cairo_surface);
    if (mapping && mapping->pixels)
        unmap_status = librdp_surface_unmap(surface, mapping);
    if (status && *status == LIBRDP_STATUS_OK)
        *status = unmap_status;
}
#endif

librdp_status rdp_gdi_backend_cairo_query(rdp_gdi_backend_caps* caps)
{
    if (!caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#if defined(RDP_HAVE_CAIRO)
    caps->name = "cairo";
    caps->caps = rdp_gdi_backend_cairo_caps();
    return LIBRDP_STATUS_OK;
#else
    caps->name = "cairo";
    caps->caps = 0;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

librdp_status rdp_gdi_backend_cairo_fill_rect(librdp_surface* surface,
                                              uint32_t x,
                                              uint32_t y,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t color)
{
#if defined(RDP_HAVE_CAIRO)
    librdp_surface_mapping mapping;
    cairo_surface_t* cairo_surface = NULL;
    cairo_t* cr = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!surface || x > INT_MAX || y > INT_MAX || width > INT_MAX || height > INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gdi_backend_cairo_create_context(surface, &mapping, &cairo_surface, &cr);
    if (status == LIBRDP_STATUS_OK)
    {
        cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
        rdp_gdi_backend_cairo_set_color(cr, color);
        cairo_rectangle(cr, (double)x, (double)y, (double)width, (double)height);
        cairo_fill(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    rdp_gdi_backend_cairo_destroy_context(surface, &mapping, cairo_surface, cr, &status);
    return status;
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

librdp_status rdp_gdi_backend_cairo_blit_bgra32(librdp_surface* surface,
                                                uint32_t x,
                                                uint32_t y,
                                                uint32_t width,
                                                uint32_t height,
                                                const uint8_t* pixels,
                                                size_t stride)
{
#if defined(RDP_HAVE_CAIRO)
    librdp_surface_mapping mapping;
    cairo_surface_t* cairo_surface = NULL;
    cairo_surface_t* source_surface = NULL;
    cairo_t* cr = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!surface || !pixels || width > INT_MAX || height > INT_MAX || stride > INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gdi_backend_cairo_create_context(surface, &mapping, &cairo_surface, &cr);
    if (status == LIBRDP_STATUS_OK)
    {
        source_surface = cairo_image_surface_create_for_data((unsigned char*)pixels,
                                                             CAIRO_FORMAT_ARGB32,
                                                             (int)width,
                                                             (int)height,
                                                             (int)stride);
        if (!source_surface)
            status = LIBRDP_STATUS_NO_MEMORY;
        else
            status = rdp_gdi_backend_cairo_status(cairo_surface_status(source_surface));
    }
    if (status == LIBRDP_STATUS_OK)
    {
        cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
        cairo_set_source_surface(cr, source_surface, (double)x, (double)y);
        cairo_rectangle(cr, (double)x, (double)y, (double)width, (double)height);
        cairo_fill(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    if (source_surface)
        cairo_surface_destroy(source_surface);
    rdp_gdi_backend_cairo_destroy_context(surface, &mapping, cairo_surface, cr, &status);
    return status;
#else
    (void)surface;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)pixels;
    (void)stride;
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
}

librdp_status rdp_gdi_backend_cairo_copy_rect(librdp_surface* surface,
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

librdp_status rdp_gdi_backend_cairo_draw_line(librdp_surface* surface,
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
#if defined(RDP_HAVE_CAIRO)
    librdp_surface_mapping mapping;
    cairo_surface_t* cairo_surface = NULL;
    cairo_t* cr = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    double half = pen_width == 0 ? 0.5 : (double)pen_width / 2.0;
    int32_t left = x0 < x1 ? x0 : x1;
    int32_t top = y0 < y1 ? y0 : y1;
    int32_t right = x0 > x1 ? x0 : x1;
    int32_t bottom = y0 > y1 ? y0 : y1;

    status = rdp_gdi_backend_cairo_create_context(surface, &mapping, &cairo_surface, &cr);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_gdi_backend_cairo_set_operator_for_color(cr, color);
        cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
        rdp_gdi_backend_cairo_clip(cr, clip);
        rdp_gdi_backend_cairo_set_color(cr, color);
        cairo_set_line_width(cr, pen_width == 0 ? 1.0 : (double)pen_width);
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_SQUARE);
        cairo_move_to(cr, (double)x0 + 0.5, (double)y0 + 0.5);
        cairo_line_to(cr, (double)x1 + 0.5, (double)y1 + 0.5);
        cairo_stroke(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    rdp_gdi_backend_cairo_destroy_context(surface, &mapping, cairo_surface, cr, &status);
    if (status == LIBRDP_STATUS_OK)
    {
        if (left - (int32_t)half < 0)
            left = 0;
        else
            left -= (int32_t)half;
        if (top - (int32_t)half < 0)
            top = 0;
        else
            top -= (int32_t)half;
        right += (int32_t)half + 1;
        bottom += (int32_t)half + 1;
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
 * Fills a simple source-copy polygon through Cairo with antialiasing disabled.
 * The caller already restricts this path to solid-color records; patterned and
 * ROP-dependent GDI operations remain in the software renderer.
 */
librdp_status rdp_gdi_backend_cairo_fill_polygon(librdp_surface* surface,
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
#if defined(RDP_HAVE_CAIRO)
    librdp_surface_mapping mapping;
    cairo_surface_t* cairo_surface = NULL;
    cairo_t* cr = NULL;
    uint32_t i = 0;
    int32_t left = INT32_MAX;
    int32_t top = INT32_MAX;
    int32_t right = INT32_MIN;
    int32_t bottom = INT32_MIN;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!points || count < 3)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gdi_backend_cairo_create_context(surface, &mapping, &cairo_surface, &cr);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_gdi_backend_cairo_set_operator_for_color(cr, color);
        cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
        cairo_set_fill_rule(cr, fill_mode == 2u ? CAIRO_FILL_RULE_WINDING : CAIRO_FILL_RULE_EVEN_ODD);
        rdp_gdi_backend_cairo_clip(cr, clip);
        rdp_gdi_backend_cairo_set_color(cr, color);
        cairo_move_to(cr, (double)points[0].x, (double)points[0].y);
        for (i = 1; i < count; i++)
            cairo_line_to(cr, (double)points[i].x, (double)points[i].y);
        cairo_close_path(cr);
        cairo_fill(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    rdp_gdi_backend_cairo_destroy_context(surface, &mapping, cairo_surface, cr, &status);
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

librdp_status rdp_gdi_backend_cairo_fill_ellipse(librdp_surface* surface,
                                                 int32_t x,
                                                 int32_t y,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 uint32_t color,
                                                 const rdp_gdi_backend_clip* clip)
{
#if defined(RDP_HAVE_CAIRO)
    librdp_surface_mapping mapping;
    cairo_surface_t* cairo_surface = NULL;
    cairo_t* cr = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_gdi_backend_cairo_create_context(surface, &mapping, &cairo_surface, &cr);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_gdi_backend_cairo_set_operator_for_color(cr, color);
        cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
        rdp_gdi_backend_cairo_clip(cr, clip);
        rdp_gdi_backend_cairo_set_color(cr, color);
        cairo_translate(cr, (double)x + ((double)width / 2.0), (double)y + ((double)height / 2.0));
        cairo_scale(cr, (double)width / 2.0, (double)height / 2.0);
        cairo_arc(cr, 0.0, 0.0, 1.0, 0.0, 6.28318530717958647692);
        cairo_fill(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    rdp_gdi_backend_cairo_destroy_context(surface, &mapping, cairo_surface, cr, &status);
    return status;
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

librdp_status rdp_gdi_backend_cairo_draw_ellipse(librdp_surface* surface,
                                                 int32_t x,
                                                 int32_t y,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 uint32_t pen_width,
                                                 uint32_t color,
                                                 const rdp_gdi_backend_clip* clip)
{
#if defined(RDP_HAVE_CAIRO)
    librdp_surface_mapping mapping;
    cairo_surface_t* cairo_surface = NULL;
    cairo_t* cr = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!surface || width == 0 || height == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_gdi_backend_cairo_create_context(surface, &mapping, &cairo_surface, &cr);
    if (status == LIBRDP_STATUS_OK)
    {
        cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
        cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
        rdp_gdi_backend_cairo_clip(cr, clip);
        rdp_gdi_backend_cairo_set_color(cr, color);
        cairo_save(cr);
        cairo_translate(cr, (double)x + ((double)width / 2.0), (double)y + ((double)height / 2.0));
        cairo_scale(cr, (double)width / 2.0, (double)height / 2.0);
        cairo_arc(cr, 0.0, 0.0, 1.0, 0.0, 6.28318530717958647692);
        cairo_restore(cr);
        cairo_set_line_width(cr, pen_width == 0 ? 1.0 : (double)pen_width);
        cairo_stroke(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    rdp_gdi_backend_cairo_destroy_context(surface, &mapping, cairo_surface, cr, &status);
    return status;
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

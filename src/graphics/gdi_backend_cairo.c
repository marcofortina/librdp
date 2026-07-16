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
#include <cairo/cairo.h>
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

librdp_status rdp_gdi_backend_cairo_query(rdp_gdi_backend_caps* caps)
{
    if (!caps)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
#if defined(RDP_HAVE_CAIRO)
    caps->name = "cairo";
    caps->caps = RDP_GDI_BACKEND_CAP_FILL_RECT;
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
    librdp_status unmap_status = LIBRDP_STATUS_OK;
    double b = (double)(color & 0xffu) / 255.0;
    double g = (double)((color >> 8u) & 0xffu) / 255.0;
    double r = (double)((color >> 16u) & 0xffu) / 255.0;

    if (!surface || x > INT_MAX || y > INT_MAX || width > INT_MAX || height > INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_surface_map(surface, LIBRDP_SURFACE_ACCESS_WRITE, &mapping);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (mapping.width > INT_MAX || mapping.height > INT_MAX || mapping.stride > INT_MAX)
    {
        unmap_status = librdp_surface_unmap(surface, &mapping);
        return unmap_status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_INVALID_ARGUMENT : unmap_status;
    }

    cairo_surface = cairo_image_surface_create_for_data(mapping.writable_pixels,
                                                        CAIRO_FORMAT_ARGB32,
                                                        (int)mapping.width,
                                                        (int)mapping.height,
                                                        (int)mapping.stride);
    if (!cairo_surface)
        status = LIBRDP_STATUS_NO_MEMORY;
    else
        status = rdp_gdi_backend_cairo_status(cairo_surface_status(cairo_surface));
    if (status == LIBRDP_STATUS_OK)
    {
        cr = cairo_create(cairo_surface);
        if (!cr)
            status = LIBRDP_STATUS_NO_MEMORY;
        else
            status = rdp_gdi_backend_cairo_status(cairo_status(cr));
    }
    if (status == LIBRDP_STATUS_OK)
    {
        cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
        cairo_set_source_rgba(cr, r, g, b, 1.0);
        cairo_rectangle(cr, (double)x, (double)y, (double)width, (double)height);
        cairo_fill(cr);
        status = rdp_gdi_backend_cairo_status(cairo_status(cr));
        cairo_surface_flush(cairo_surface);
    }
    if (cr)
        cairo_destroy(cr);
    if (cairo_surface)
        cairo_surface_destroy(cairo_surface);

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

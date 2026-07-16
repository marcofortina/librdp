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
    caps->caps = RDP_GDI_BACKEND_CAP_FILL_RECT;
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

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal GDI raster backend abstraction.
 * Invariants: backend operations receive validated BGRA surfaces and clipped
 * rectangles before touching pixels or native drawing contexts.
 * Ownership: surfaces are borrowed for the duration of each call; native
 * contexts are created and destroyed inside the backend operation.
 * Threading: not internally synchronized; callers serialize through the
 * owning session or surface.
 * Trust boundary: coordinates and colors originate from decoded RDP orders.
 */

#ifndef RDP_GRAPHICS_GDI_BACKEND_H
#define RDP_GRAPHICS_GDI_BACKEND_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/surface.h>

#define RDP_GDI_BACKEND_CAP_FILL_RECT 0x00000001u

typedef enum rdp_gdi_backend_kind
{
    RDP_GDI_BACKEND_SOFTWARE = 0,
    RDP_GDI_BACKEND_CAIRO = 1,
    RDP_GDI_BACKEND_QUARTZ = 2
} rdp_gdi_backend_kind;

typedef struct rdp_gdi_backend_caps
{
    const char* name;
    uint32_t caps;
} rdp_gdi_backend_caps;

rdp_gdi_backend_kind rdp_gdi_backend_default(void);
librdp_status rdp_gdi_backend_query(rdp_gdi_backend_kind backend, rdp_gdi_backend_caps* caps);
librdp_status rdp_gdi_backend_fill_rect(rdp_gdi_backend_kind backend,
                                        librdp_surface* surface,
                                        uint32_t x,
                                        uint32_t y,
                                        uint32_t width,
                                        uint32_t height,
                                        uint32_t color);

librdp_status rdp_gdi_backend_cairo_query(rdp_gdi_backend_caps* caps);
librdp_status rdp_gdi_backend_cairo_fill_rect(librdp_surface* surface,
                                              uint32_t x,
                                              uint32_t y,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t color);
librdp_status rdp_gdi_backend_quartz_query(rdp_gdi_backend_caps* caps);
librdp_status rdp_gdi_backend_quartz_fill_rect(librdp_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height,
                                               uint32_t color);

#endif

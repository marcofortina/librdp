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

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>
#include <librdp/surface.h>

#define RDP_GDI_BACKEND_CAP_FILL_RECT 0x00000001u
#define RDP_GDI_BACKEND_CAP_BLIT_BGRA32 0x00000002u
#define RDP_GDI_BACKEND_CAP_COPY_RECT 0x00000004u
#define RDP_GDI_BACKEND_CAP_DRAW_LINE 0x00000008u
#define RDP_GDI_BACKEND_CAP_FILL_POLYGON 0x00000010u
#define RDP_GDI_BACKEND_CAP_FILL_ELLIPSE 0x00000020u
#define RDP_GDI_BACKEND_CAP_DRAW_ELLIPSE 0x00000040u
/* GDI+ stream support is split between parsed/rasterized primitive records and complete visual record coverage. */
#define RDP_GDI_BACKEND_CAP_GDIPLUS_STREAM 0x00000080u
#define RDP_GDI_BACKEND_CAP_GDIPLUS_PARTIAL_VISUALS 0x00000100u
#define RDP_GDI_BACKEND_CAP_GDIPLUS_COMPLETE_VISUALS 0x00000200u

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

typedef struct rdp_gdi_backend_clip
{
    uint8_t present;
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} rdp_gdi_backend_clip;

typedef struct rdp_gdi_backend_point
{
    int32_t x;
    int32_t y;
} rdp_gdi_backend_point;

rdp_gdi_backend_kind rdp_gdi_backend_default(void);
librdp_status rdp_gdi_backend_query(rdp_gdi_backend_kind backend, rdp_gdi_backend_caps* caps);
librdp_status rdp_gdi_backend_fill_rect(rdp_gdi_backend_kind backend,
                                        librdp_surface* surface,
                                        uint32_t x,
                                        uint32_t y,
                                        uint32_t width,
                                        uint32_t height,
                                        uint32_t color);
librdp_status rdp_gdi_backend_blit_bgra32(rdp_gdi_backend_kind backend,
                                          librdp_surface* surface,
                                          uint32_t x,
                                          uint32_t y,
                                          uint32_t width,
                                          uint32_t height,
                                          const uint8_t* pixels,
                                          size_t stride);
librdp_status rdp_gdi_backend_copy_rect(rdp_gdi_backend_kind backend,
                                        librdp_surface* surface,
                                        uint32_t src_x,
                                        uint32_t src_y,
                                        uint32_t dst_x,
                                        uint32_t dst_y,
                                        uint32_t width,
                                        uint32_t height);
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
                                        uint32_t* dirty_bottom);
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
                                           uint32_t* dirty_bottom);
librdp_status rdp_gdi_backend_fill_ellipse(rdp_gdi_backend_kind backend,
                                           librdp_surface* surface,
                                           int32_t x,
                                           int32_t y,
                                           uint32_t width,
                                           uint32_t height,
                                           uint32_t color,
                                           const rdp_gdi_backend_clip* clip);
librdp_status rdp_gdi_backend_draw_ellipse(rdp_gdi_backend_kind backend,
                                           librdp_surface* surface,
                                           int32_t x,
                                           int32_t y,
                                           uint32_t width,
                                           uint32_t height,
                                           uint32_t pen_width,
                                           uint32_t color,
                                           const rdp_gdi_backend_clip* clip);
librdp_status rdp_gdi_backend_render_gdiplus_stream(rdp_gdi_backend_kind backend,
                                                    librdp_surface* surface,
                                                    const uint8_t* data,
                                                    size_t length,
                                                    uint32_t* records,
                                                    uint32_t* rasterized,
                                                    uint32_t* unsupported);

librdp_status rdp_gdi_backend_cairo_query(rdp_gdi_backend_caps* caps);
librdp_status rdp_gdi_backend_cairo_fill_rect(librdp_surface* surface,
                                              uint32_t x,
                                              uint32_t y,
                                              uint32_t width,
                                              uint32_t height,
                                              uint32_t color);
librdp_status rdp_gdi_backend_cairo_blit_bgra32(librdp_surface* surface,
                                                uint32_t x,
                                                uint32_t y,
                                                uint32_t width,
                                                uint32_t height,
                                                const uint8_t* pixels,
                                                size_t stride);
librdp_status rdp_gdi_backend_cairo_copy_rect(librdp_surface* surface,
                                              uint32_t src_x,
                                              uint32_t src_y,
                                              uint32_t dst_x,
                                              uint32_t dst_y,
                                              uint32_t width,
                                              uint32_t height);
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
                                              uint32_t* dirty_bottom);
librdp_status rdp_gdi_backend_cairo_fill_polygon(librdp_surface* surface,
                                                 const rdp_gdi_backend_point* points,
                                                 uint32_t count,
                                                 uint32_t fill_mode,
                                                 uint32_t color,
                                                 const rdp_gdi_backend_clip* clip,
                                                 uint32_t* dirty_left,
                                                 uint32_t* dirty_top,
                                                 uint32_t* dirty_right,
                                                 uint32_t* dirty_bottom);
librdp_status rdp_gdi_backend_cairo_fill_ellipse(librdp_surface* surface,
                                                 int32_t x,
                                                 int32_t y,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 uint32_t color,
                                                 const rdp_gdi_backend_clip* clip);
librdp_status rdp_gdi_backend_cairo_draw_ellipse(librdp_surface* surface,
                                                 int32_t x,
                                                 int32_t y,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 uint32_t pen_width,
                                                 uint32_t color,
                                                 const rdp_gdi_backend_clip* clip);
librdp_status rdp_gdi_backend_quartz_query(rdp_gdi_backend_caps* caps);
librdp_status rdp_gdi_backend_quartz_fill_rect(librdp_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height,
                                               uint32_t color);
librdp_status rdp_gdi_backend_quartz_blit_bgra32(librdp_surface* surface,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height,
                                                 const uint8_t* pixels,
                                                 size_t stride);
librdp_status rdp_gdi_backend_quartz_copy_rect(librdp_surface* surface,
                                               uint32_t src_x,
                                               uint32_t src_y,
                                               uint32_t dst_x,
                                               uint32_t dst_y,
                                               uint32_t width,
                                               uint32_t height);
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
                                               uint32_t* dirty_bottom);
librdp_status rdp_gdi_backend_quartz_fill_polygon(librdp_surface* surface,
                                                  const rdp_gdi_backend_point* points,
                                                  uint32_t count,
                                                  uint32_t fill_mode,
                                                  uint32_t color,
                                                  const rdp_gdi_backend_clip* clip,
                                                  uint32_t* dirty_left,
                                                  uint32_t* dirty_top,
                                                  uint32_t* dirty_right,
                                                  uint32_t* dirty_bottom);
librdp_status rdp_gdi_backend_quartz_fill_ellipse(librdp_surface* surface,
                                                  int32_t x,
                                                  int32_t y,
                                                  uint32_t width,
                                                  uint32_t height,
                                                  uint32_t color,
                                                  const rdp_gdi_backend_clip* clip);
librdp_status rdp_gdi_backend_quartz_draw_ellipse(librdp_surface* surface,
                                                  int32_t x,
                                                  int32_t y,
                                                  uint32_t width,
                                                  uint32_t height,
                                                  uint32_t pen_width,
                                                  uint32_t color,
                                                  const rdp_gdi_backend_clip* clip);

#endif

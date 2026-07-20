/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer rendering boundary declarations.
 * Invariants: surface pixels are treated as read-only snapshots owned by the
 * public session API.
 * Ownership: no framebuffer memory is retained after a draw call.
 * Threading: rendering runs on the viewer event thread.
 * Trust boundary: dimensions, stride, and window liveness are validated before
 * issuing X11 presentation calls.
 */

#ifndef LIBRDP_X11_VIEWER_RENDER_H
#define LIBRDP_X11_VIEWER_RENDER_H

#include "x11_app.h"

#include <stddef.h>
#include <stdint.h>

typedef enum x11_render_method
{
    X11_RENDER_METHOD_NONE = 0,
    X11_RENDER_METHOD_XPUTIMAGE = 1,
    X11_RENDER_METHOD_XSHM = 2
} x11_render_method;

int x11_render_init(x11_app* app);
void x11_render_shutdown(x11_app* app);
int x11_render_copy_bgra_rows(uint8_t* dst,
                              size_t dst_stride,
                              const uint8_t* src,
                              size_t src_stride,
                              uint32_t width,
                              uint32_t height);
int x11_render_copy_bgra_rect(uint8_t* dst,
                              size_t dst_stride,
                              const uint8_t* src,
                              size_t src_stride,
                              uint32_t x,
                              uint32_t y,
                              uint32_t width,
                              uint32_t height);
void x11_render_mark_dirty(x11_app* app,
                           uint32_t x,
                           uint32_t y,
                           uint32_t width,
                           uint32_t height);
void x11_render_mark_all_dirty(x11_app* app);
x11_render_method x11_render_last_method(const x11_app* app);
int x11_render_draw_bgra(x11_app* app,
                          const uint8_t* pixels,
                          uint32_t width,
                          uint32_t height,
                          size_t stride);
void x11_render_draw_surface(x11_app* app);

#endif

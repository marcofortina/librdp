/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 framebuffer presentation for the viewer.
 * Invariants: all reads are bounded by the public surface stride and size, and
 * XImage never owns the session framebuffer pointer.
 * Ownership: librdp owns surface pixels; the viewer owns only transient XImage
 * wrappers and releases them before returning.
 * Threading: called from the viewer event thread after session dispatch marks
 * the surface dirty.
 * Trust boundary: server-provided graphics updates are consumed only through
 * normalized public surface APIs and are not trusted to match window geometry.
 */

#include "viewer_render.h"

#include "viewer_trace.h"
#include "viewer_window.h"

#include <X11/Xutil.h>

static uint64_t x11_trace_hash_seed(uint64_t hash, uint64_t value)
{
    unsigned int i = 0;

    for (i = 0; i < 8; i++)
    {
        hash ^= (uint8_t)((value >> (i * 8u)) & 0xffu);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t x11_trace_hash_bytes(uint64_t hash, const uint8_t* bytes, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t x11_trace_hash_bgra(const uint8_t* pixels, uint32_t width, uint32_t height, size_t stride)
{
    const size_t row_bytes = (size_t)width * 4u;
    const uint64_t offset = 1469598103934665603ull;
    uint64_t hash = offset;
    uint64_t pixel_count = 0;
    uint64_t samples = 0;
    uint64_t i = 0;

    if (!x11_trace_enabled_level(X11_TRACE_CLIENT, X11_TRACE_LEVEL_TRACE) ||
        !pixels || width == 0 || height == 0 || stride < row_bytes)
        return 0;

    hash = x11_trace_hash_seed(hash, width);
    hash = x11_trace_hash_seed(hash, height);
    pixel_count = (uint64_t)width * (uint64_t)height;
    samples = pixel_count < 8192u ? pixel_count : 8192u;
    if (samples == 0)
        return hash;
    if (samples == 1)
        return x11_trace_hash_bytes(hash, pixels, 4u);

    for (i = 0; i < samples; i++)
    {
        const uint64_t pixel_index = (i * (pixel_count - 1u)) / (samples - 1u);
        const uint32_t row = (uint32_t)(pixel_index / width);
        const uint32_t column = (uint32_t)(pixel_index % width);
        const uint8_t* p = pixels + ((size_t)row * stride) + ((size_t)column * 4u);

        hash = x11_trace_hash_bytes(hash, p, 4u);
    }
    return hash;
}

/*
 * Present the current session surface into the X11 window. Clipping and stride
 * handling stay here so expose and resize repaint paths cannot read outside
 * the framebuffer snapshot delivered by the core.
 */
void x11_render_draw_surface(x11_app* app)
{
    const librdp_surface* surface = NULL;
    XImage* image = NULL;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    uint64_t surface_hash = 0;
    int put_result = 0;

    if (!app || !app->display || !app->session || x11_window_is_invalid())
        return;

    surface = librdp_session_get_surface(app->session);
    if (!surface || !librdp_surface_pixels(surface))
        return;

    width = librdp_surface_width(surface);
    height = librdp_surface_height(surface);
    stride = librdp_surface_stride(surface);
    surface_hash = x11_trace_hash_bgra(librdp_surface_pixels(surface), width, height, stride);
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_TRACE,
                          "x11.surface.draw.start",
                          "surface_width=%u surface_height=%u surface_stride=%u window_width=%u window_height=%u dirty=%u hash=%016llx",
                          width,
                          height,
                          (unsigned)stride,
                          app->window_width,
                          app->window_height,
                          app->dirty ? 1u : 0u,
                          (unsigned long long)surface_hash);
    if ((app->window_width != 0 && app->window_width != width) ||
        (app->window_height != 0 && app->window_height != height))
    {
        XClearWindow(app->display, app->window);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.window.clear",
                        "reason=surface_window_mismatch surface_width=%u surface_height=%u window_width=%u window_height=%u",
                        width,
                        height,
                        app->window_width,
                        app->window_height);
    }
    image = XCreateImage(app->display,
                         DefaultVisual(app->display, app->screen),
                         (unsigned)DefaultDepth(app->display, app->screen),
                         ZPixmap,
                         0,
                         (char*)librdp_surface_pixels(surface),
                         width,
                         height,
                         32,
                         (int)stride);
    if (!image)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.surface.draw.failed",
                        "stage=create_image surface_width=%u surface_height=%u surface_stride=%u",
                        width,
                        height,
                        (unsigned)stride);
        return;
    }

    put_result = XPutImage(app->display, app->window, app->gc, image, 0, 0, 0, 0, width, height);
    image->data = NULL;
    XDestroyImage(image);
    XFlush(app->display);
    x11_trace_event_level(X11_TRACE_CLIENT,
                          X11_TRACE_LEVEL_TRACE,
                          "x11.surface.draw.done",
                          "surface_width=%u surface_height=%u surface_stride=%u window_width=%u window_height=%u put_result=%d hash=%016llx",
                          width,
                          height,
                          (unsigned)stride,
                          app->window_width,
                          app->window_height,
                          put_result,
                          (unsigned long long)surface_hash);
    app->dirty = 0;
}

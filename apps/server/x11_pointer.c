/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: XFixes pointer observation for the X11 desktop server.
 * Invariants: cursor shapes are emitted as bounded straight-alpha BGRA32,
 * coordinates are relative to the capture source, and hidden state is explicit.
 * Ownership: converted shape storage is context-owned and borrowed by the host
 * only during the update callback.
 * Threading: cursor queries and callbacks run on the X11 host thread.
 * Trust boundary: XFixes dimensions, hotspots and ARGB pixels are checked
 * before allocation and conversion.
 */

#include "x11_server_internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define X11_SERVER_MAX_POINTER_DIMENSION 512u

static uint8_t x11_server_unpremultiply(uint8_t value, uint8_t alpha)
{
    unsigned int expanded = 0u;

    if (alpha == 0u)
        return 0u;
    expanded = ((unsigned int)value * 255u + (unsigned int)alpha / 2u) /
               (unsigned int)alpha;
    return expanded > 255u ? 255u : (uint8_t)expanded;
}

static int x11_server_pointer_position(x11_server_context* context,
                                       int32_t* x,
                                       int32_t* y,
                                       int* visible)
{
    Window root_return = None;
    Window child_return = None;
    int root_x = 0;
    int root_y = 0;
    int window_x = 0;
    int window_y = 0;
    unsigned int mask = 0u;

    if (!context || !x || !y || !visible ||
        !XQueryPointer(context->display,
                       context->target,
                       &root_return,
                       &child_return,
                       &root_x,
                       &root_y,
                       &window_x,
                       &window_y,
                       &mask))
        return 0;
    if (context->config.source_kind == X11_SERVER_SOURCE_WINDOW)
    {
        *x = window_x;
        *y = window_y;
    }
    else
    {
        *x = root_x - context->capture_x;
        *y = root_y - context->capture_y;
    }
    *visible = *x >= 0 && *y >= 0 &&
               (uint32_t)*x < context->width &&
               (uint32_t)*y < context->height;
    return 1;
}

static int x11_server_pointer_shape(x11_server_context* context,
                                    XFixesCursorImage* image)
{
    size_t stride = 0u;
    size_t bytes = 0u;
    uint32_t y = 0u;

    if (!context || !image || !image->pixels || image->width == 0u ||
        image->height == 0u ||
        image->width > X11_SERVER_MAX_POINTER_DIMENSION ||
        image->height > X11_SERVER_MAX_POINTER_DIMENSION ||
        image->xhot >= image->width || image->yhot >= image->height ||
        !x11_server_checked_multiply((size_t)image->width, 4u, &stride) ||
        !x11_server_checked_multiply(stride,
                                     (size_t)image->height,
                                     &bytes) ||
        bytes > context->config.max_frame_bytes)
        return 0;
    if (bytes > context->pointer_capacity)
    {
        uint8_t* resized = (uint8_t*)realloc(context->pointer_pixels, bytes);

        if (!resized)
            return 0;
        context->pointer_pixels = resized;
        context->pointer_capacity = bytes;
    }
    for (y = 0u; y < image->height; y++)
    {
        uint32_t x = 0u;
        uint8_t* row = context->pointer_pixels + (size_t)y * stride;

        for (x = 0u; x < image->width; x++)
        {
            unsigned long argb =
                image->pixels[(size_t)y * image->width + x];
            uint8_t alpha = (uint8_t)((argb >> 24u) & 0xfful);
            uint8_t red = (uint8_t)((argb >> 16u) & 0xfful);
            uint8_t green = (uint8_t)((argb >> 8u) & 0xfful);
            uint8_t blue = (uint8_t)(argb & 0xfful);
            uint8_t* output = row + (size_t)x * 4u;

            output[0] = x11_server_unpremultiply(blue, alpha);
            output[1] = x11_server_unpremultiply(green, alpha);
            output[2] = x11_server_unpremultiply(red, alpha);
            output[3] = alpha;
        }
    }
    context->pointer_width = image->width;
    context->pointer_height = image->height;
    context->pointer_hotspot_x = image->xhot;
    context->pointer_hotspot_y = image->yhot;
    context->pointer_stride = stride;
    context->cursor_serial = image->cursor_serial;
    return 1;
}

void x11_server_pointer_emit(x11_server_context* context, int include_shape)
{
    XFixesCursorImage* image = NULL;
    server_platform_pointer pointer;
    int32_t x = 0;
    int32_t y = 0;
    int visible = 0;

    if (!context || !context->pointer_started ||
        !context->pointer_sink.update ||
        !x11_server_pointer_position(context, &x, &y, &visible))
        return;
    if (include_shape)
    {
        image = XFixesGetCursorImage(context->display);
        if (image && !x11_server_pointer_shape(context, image))
        {
            XFree(image);
            image = NULL;
            include_shape = 0;
        }
    }
    memset(&pointer, 0, sizeof(pointer));
    pointer.x = x;
    pointer.y = y;
    pointer.visible = visible;
    pointer.sequence = ++context->pointer_sequence;
    if (include_shape && image)
    {
        pointer.width = context->pointer_width;
        pointer.height = context->pointer_height;
        pointer.hotspot_x = context->pointer_hotspot_x;
        pointer.hotspot_y = context->pointer_hotspot_y;
        pointer.stride = context->pointer_stride;
        pointer.pixels = context->pointer_pixels;
        pointer.pixels_len =
            context->pointer_stride * context->pointer_height;
        pointer.shape_valid = 1;
    }
    context->pointer_x = x;
    context->pointer_y = y;
    context->pointer_visible = visible;
    context->pointer_sink.update(&pointer,
                                 context->pointer_sink.user_data);
    if (image)
        XFree(image);
}

void x11_server_pointer_handle_event(x11_server_context* context,
                                     const XEvent* event)
{
    if (!context || !event || !context->pointer_started)
        return;
    if (event->type == context->fixes_event_base + XFixesCursorNotify)
        x11_server_pointer_emit(context, 1);
    else if (event->type == MotionNotify)
        x11_server_pointer_emit(context, 0);
}

static librdp_status x11_server_pointer_start(
    void* opaque,
    const server_platform_pointer_sink* sink)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !sink || !sink->update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->pointer_started)
        return LIBRDP_STATUS_STATE;
    context->pointer_sink = *sink;
    context->pointer_started = 1;
    x11_server_pointer_emit(context, 1);
    return LIBRDP_STATUS_OK;
}

static void x11_server_pointer_stop(void* opaque)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context)
        return;
    memset(&context->pointer_sink, 0, sizeof(context->pointer_sink));
    context->pointer_started = 0;
}

const server_platform_pointer_vtable x11_server_pointer_vtable = {
    SERVER_PLATFORM_POINTER_VERSION,
    sizeof(server_platform_pointer_vtable),
    x11_server_pointer_start,
    x11_server_pointer_stop,
    NULL,
};

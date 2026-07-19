/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 pointer, cursor, and mouse bridge.
 * Invariants: pointer-shape buffers are bounds-checked before Xcursor use, and
 * local pointer movement is clipped to the current remote surface.
 * Ownership: X cursor objects are owned by x11_app and freed before replacing
 * or destroying the viewer window.
 * Threading: all input operations run on the viewer event thread.
 * Trust boundary: local X11 events and remote pointer updates are independent
 * untrusted inputs normalized through public librdp APIs.
 */

#include "x11_input.h"

#include "x11_keyboard.h"
#include "x11_trace.h"
#include "x11_window.h"

#include <X11/Xcursor/Xcursor.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

void x11_input_clear_cursor(x11_app* app)
{
    if (!app || !app->display)
        return;
    if (app->cursor != None)
    {
        XFreeCursor(app->display, app->cursor);
        app->cursor = None;
    }
    app->cursor_mode = X11_CURSOR_DEFAULT;
    app->hidden_cursor_locally_visible = 0;
}

void x11_input_restore_cursor_after_local_mouse(x11_app* app)
{
    if (!app || !app->display || !app->window || x11_window_is_invalid())
        return;
    if (app->cursor_mode != X11_CURSOR_HIDDEN || app->hidden_cursor_locally_visible)
        return;
    if (!x11_window_is_live(app))
        return;

    XUndefineCursor(app->display, app->window);
    XFlush(app->display);
    app->hidden_cursor_locally_visible = 1;
    x11_trace_event(X11_TRACE_CLIENT, "x11.pointer.local_restore", "visible=1");
}

static Cursor create_hidden_cursor(x11_app* app)
{
    Pixmap pixmap = None;
    XColor color;
    Cursor cursor = None;
    static const char data[1] = {0};

    if (!app || !app->display || !app->window)
        return None;

    memset(&color, 0, sizeof(color));
    pixmap = XCreateBitmapFromData(app->display, app->window, data, 1, 1);
    if (pixmap == None)
        return None;
    cursor = XCreatePixmapCursor(app->display, pixmap, pixmap, &color, &color, 0, 0);
    XFreePixmap(app->display, pixmap);
    return cursor;
}

static Cursor create_shape_cursor(x11_app* app, const librdp_pointer_event* pointer)
{
    XcursorImage* image = NULL;
    Cursor cursor = None;
    uint16_t y = 0;
    uint16_t x = 0;

    if (!app || !app->display || !pointer || !pointer->pixels ||
        pointer->width == 0 || pointer->height == 0 || pointer->stride < (uint32_t)pointer->width * 4u)
        return None;
    if (pointer->pixels_len < (size_t)pointer->stride * pointer->height)
        return None;

    image = XcursorImageCreate(pointer->width, pointer->height);
    if (!image)
        return None;
    image->xhot = pointer->hot_x;
    image->yhot = pointer->hot_y;
    for (y = 0; y < pointer->height; y++)
    {
        const uint8_t* src = pointer->pixels + ((size_t)y * pointer->stride);
        for (x = 0; x < pointer->width; x++)
        {
            const uint8_t* pixel = src + ((size_t)x * 4u);
            image->pixels[(size_t)y * pointer->width + x] =
                ((XcursorPixel)pixel[3] << 24) |
                ((XcursorPixel)pixel[2] << 16) |
                ((XcursorPixel)pixel[1] << 8) |
                (XcursorPixel)pixel[0];
        }
    }
    cursor = XcursorImageLoadCursor(app->display, image);
    XcursorImageDestroy(image);
    return cursor;
}

void x11_input_apply_cursor(x11_app* app)
{
    if (!app || !app->display || !app->window || x11_window_is_invalid())
        return;
    if (!x11_window_is_live(app))
        return;
    if (app->cursor_mode == X11_CURSOR_DEFAULT)
        XUndefineCursor(app->display, app->window);
    else if (app->cursor != None)
        XDefineCursor(app->display, app->window, app->cursor);
    XFlush(app->display);
}

void x11_input_handle_pointer_event(x11_app* app, const librdp_pointer_event* pointer)
{
    Cursor cursor = None;

    if (!app || !pointer)
        return;

    if (pointer->update_type == LIBRDP_POINTER_UPDATE_DEFAULT)
    {
        x11_input_clear_cursor(app);
        app->cursor_mode = X11_CURSOR_DEFAULT;
        x11_input_apply_cursor(app);
        x11_trace_event(X11_TRACE_CLIENT, "x11.pointer.default", "visible=1");
    }
    else if (pointer->update_type == LIBRDP_POINTER_UPDATE_HIDDEN)
    {
        cursor = create_hidden_cursor(app);
        if (cursor == None)
            return;
        x11_input_clear_cursor(app);
        app->cursor = cursor;
        app->cursor_mode = X11_CURSOR_HIDDEN;
        app->hidden_cursor_locally_visible = 0;
        x11_input_apply_cursor(app);
        x11_trace_event(X11_TRACE_CLIENT, "x11.pointer.hidden", "visible=0");
    }
    else if (pointer->update_type == LIBRDP_POINTER_UPDATE_POSITION)
    {
        if (x11_window_is_live(app))
        {
            app->suppress_motion++;
            XWarpPointer(app->display, None, app->window, 0, 0, 0, 0, pointer->x, pointer->y);
            XFlush(app->display);
        }
        x11_trace_event(X11_TRACE_CLIENT, "x11.pointer.position", "x=%u y=%u", pointer->x, pointer->y);
    }
    else if (pointer->update_type == LIBRDP_POINTER_UPDATE_SHAPE)
    {
        cursor = create_shape_cursor(app, pointer);
        if (cursor == None)
            return;
        x11_input_clear_cursor(app);
        app->cursor = cursor;
        app->cursor_mode = X11_CURSOR_SHAPE;
        app->hidden_cursor_locally_visible = 0;
        x11_input_apply_cursor(app);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.pointer.shape",
                        "cache_index=%u width=%u height=%u hot_x=%u hot_y=%u",
                        pointer->cache_index,
                        pointer->width,
                        pointer->height,
                        pointer->hot_x,
                        pointer->hot_y);
    }
}

static uint16_t clamp_u16_coord(int value)
{
    if (value <= 0)
        return 0;
    if (value > UINT16_MAX)
        return UINT16_MAX;
    return (uint16_t)value;
}

static uint16_t clamp_surface_coord(x11_app* app, int value, int y_axis)
{
    const librdp_surface* surface = NULL;
    uint32_t limit = 0;

    if (value <= 0)
        return 0;
    if (!app || !app->session)
        return clamp_u16_coord(value);

    surface = librdp_session_get_surface(app->session);
    if (!surface)
        return clamp_u16_coord(value);

    limit = y_axis ? librdp_surface_height(surface) : librdp_surface_width(surface);
    if (limit == 0)
        return 0;
    if ((uint32_t)value >= limit)
    {
        uint32_t clipped = limit - 1u;
        return clipped > UINT16_MAX ? UINT16_MAX : (uint16_t)clipped;
    }
    return clamp_u16_coord(value);
}

void x11_input_handle_button(x11_app* app, XButtonEvent* button, librdp_mouse_state state)
{
    librdp_mouse_event event;

    if (!app || !button)
        return;

    app->pointer_inside = 1;
    x11_input_restore_cursor_after_local_mouse(app);
    x11_keyboard_maybe_grab(app, button->time);
    if (state == LIBRDP_MOUSE_RELEASED &&
        (button->button == Button4 || button->button == Button5 || button->button == 6 || button->button == 7))
        return;

    event.x = clamp_surface_coord(app, button->x, 0);
    event.y = clamp_surface_coord(app, button->y, 1);
    event.state = state;

    switch (button->button)
    {
        case Button1:
            event.button = LIBRDP_MOUSE_BUTTON_LEFT;
            break;
        case Button2:
            event.button = LIBRDP_MOUSE_BUTTON_MIDDLE;
            break;
        case Button3:
            event.button = LIBRDP_MOUSE_BUTTON_RIGHT;
            break;
        case Button4:
            event.button = LIBRDP_MOUSE_BUTTON_WHEEL_UP;
            break;
        case Button5:
            event.button = LIBRDP_MOUSE_BUTTON_WHEEL_DOWN;
            break;
        case 6:
            event.button = LIBRDP_MOUSE_BUTTON_WHEEL_LEFT;
            break;
        case 7:
            event.button = LIBRDP_MOUSE_BUTTON_WHEEL_RIGHT;
            break;
        case 8:
            event.button = LIBRDP_MOUSE_BUTTON_X1;
            break;
        case 9:
            event.button = LIBRDP_MOUSE_BUTTON_X2;
            break;
        default:
            x11_trace_event(X11_TRACE_CLIENT,
                            "x11.mouse.button_ignored",
                            "button=%u state=%u",
                            button->button,
                            (unsigned)state);
            return;
    }

    (void)librdp_session_send_mouse(app->session, &event);
}

void x11_input_handle_motion(x11_app* app, XMotionEvent* motion)
{
    librdp_mouse_event event;

    if (!app || !motion)
        return;

    if (app->suppress_motion > 0)
    {
        app->suppress_motion--;
        app->pointer_inside = 1;
        return;
    }
    app->pointer_inside = 1;
    x11_input_restore_cursor_after_local_mouse(app);
    x11_keyboard_maybe_grab(app, motion->time);
    event.x = clamp_surface_coord(app, motion->x, 0);
    event.y = clamp_surface_coord(app, motion->y, 1);
    event.button = LIBRDP_MOUSE_BUTTON_NONE;
    event.state = LIBRDP_MOUSE_MOVED;
    (void)librdp_session_send_mouse(app->session, &event);
}

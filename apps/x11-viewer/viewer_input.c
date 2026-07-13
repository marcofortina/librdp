/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 keyboard, pointer, cursor, and mouse bridge.
 * Invariants: keyboard grabs are released only after remote key releases have
 * been sent, and pointer-shape buffers are bounds-checked before Xcursor use.
 * Ownership: X cursor objects are owned by x11_app and freed before replacing
 * or destroying the viewer window.
 * Threading: all input operations run on the viewer event thread.
 * Trust boundary: local X11 events and remote pointer updates are independent
 * untrusted inputs normalized through public librdp APIs.
 */

#include "viewer_input.h"

#include "viewer_trace.h"
#include "viewer_window.h"

#include <X11/Xatom.h>
#include <X11/Xcursor/Xcursor.h>
#include <xkbcommon/xkbcommon.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef struct x11_scancode_map
{
    const char* name;
    uint32_t scancode;
    uint32_t flags;
} x11_scancode_map;

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

void x11_input_allow_xwayland_keyboard_grab(x11_app* app)
{
    unsigned long value = 1;
    XClientMessageEvent message;

    if (!app || !app->display || !app->window)
        return;

    if (app->xwayland_grab == None)
        app->xwayland_grab = XInternAtom(app->display, "_XWAYLAND_MAY_GRAB_KEYBOARD", False);
    if (app->xwayland_grab == None)
        return;

    XChangeProperty(app->display,
                    app->window,
                    app->xwayland_grab,
                    XA_CARDINAL,
                    32,
                    PropModeReplace,
                    (const unsigned char*)&value,
                    1);

    memset(&message, 0, sizeof(message));
    message.type = ClientMessage;
    message.display = app->display;
    message.window = app->window;
    message.message_type = app->xwayland_grab;
    message.format = 32;
    message.data.l[0] = 1;
    XSendEvent(app->display,
               DefaultRootWindow(app->display),
               False,
               SubstructureNotifyMask | SubstructureRedirectMask,
               (XEvent*)&message);
}

void x11_input_maybe_grab_keyboard(x11_app* app, Time time)
{
    int result = 0;

    if (!app || !app->display || !app->window || !app->focused || !app->pointer_inside)
        return;
    if (!app->running)
        return;
    if (app->keyboard_grabbed)
    {
        app->pending_ungrab = 0;
        return;
    }
    if (!x11_window_is_live(app))
        return;

    x11_input_allow_xwayland_keyboard_grab(app);
    result = XGrabKeyboard(app->display,
                           app->window,
                           False,
                           GrabModeAsync,
                           GrabModeAsync,
                           time == 0 ? CurrentTime : time);
    if (result == GrabInvalidTime)
        result = XGrabKeyboard(app->display, app->window, False, GrabModeAsync, GrabModeAsync, CurrentTime);
    if (result == GrabSuccess)
    {
        app->keyboard_grabbed = 1;
        app->pending_ungrab = 0;
    }
    x11_trace_event(X11_TRACE_CLIENT, "x11.keyboard.grab", "result=%d active=%u", result, app->keyboard_grabbed);
}

void x11_input_ungrab_keyboard(x11_app* app, Time time, int force)
{
    if (!app || !app->display || !app->keyboard_grabbed)
        return;
    if (!force && app->pressed_count > 0)
    {
        app->pending_ungrab = 1;
        return;
    }

    XUngrabKeyboard(app->display, time == 0 ? CurrentTime : time);
    app->keyboard_grabbed = 0;
    app->pending_ungrab = 0;
    x11_trace_event(X11_TRACE_CLIENT, "x11.keyboard.ungrab", "active=0");
}

static int xkb_name_equals(const char name[4], const char* text)
{
    size_t i = 0;
    size_t length = 0;

    if (!name || !text)
        return 0;

    length = strlen(text);
    if (length > 4)
        return 0;
    for (i = 0; i < length; i++)
    {
        if (name[i] != text[i])
            return 0;
    }
    for (; i < 4; i++)
    {
        if (name[i] != ' ' && name[i] != '\0')
            return 0;
    }
    return 1;
}

/*
 * Map canonical XKB key names to RDP set-1 scancodes. The table is the
 * viewer trust boundary between host layout metadata and remote input; unknown
 * names fail closed so callers can fall back to Unicode input when available.
 */
static int xkb_key_name_to_rdp_scancode(const char name[4], uint32_t* scancode, uint32_t* flags)
{
    static const x11_scancode_map map[] = {
        {"ESC", 0x01, 0},
        {"AE01", 0x02, 0},
        {"AE02", 0x03, 0},
        {"AE03", 0x04, 0},
        {"AE04", 0x05, 0},
        {"AE05", 0x06, 0},
        {"AE06", 0x07, 0},
        {"AE07", 0x08, 0},
        {"AE08", 0x09, 0},
        {"AE09", 0x0a, 0},
        {"AE10", 0x0b, 0},
        {"AE11", 0x0c, 0},
        {"AE12", 0x0d, 0},
        {"BKSP", 0x0e, 0},
        {"TAB", 0x0f, 0},
        {"AD01", 0x10, 0},
        {"AD02", 0x11, 0},
        {"AD03", 0x12, 0},
        {"AD04", 0x13, 0},
        {"AD05", 0x14, 0},
        {"AD06", 0x15, 0},
        {"AD07", 0x16, 0},
        {"AD08", 0x17, 0},
        {"AD09", 0x18, 0},
        {"AD10", 0x19, 0},
        {"AD11", 0x1a, 0},
        {"AD12", 0x1b, 0},
        {"RTRN", 0x1c, 0},
        {"LCTL", 0x1d, 0},
        {"AC01", 0x1e, 0},
        {"AC02", 0x1f, 0},
        {"AC03", 0x20, 0},
        {"AC04", 0x21, 0},
        {"AC05", 0x22, 0},
        {"AC06", 0x23, 0},
        {"AC07", 0x24, 0},
        {"AC08", 0x25, 0},
        {"AC09", 0x26, 0},
        {"AC10", 0x27, 0},
        {"AC11", 0x28, 0},
        {"TLDE", 0x29, 0},
        {"LFSH", 0x2a, 0},
        {"BKSL", 0x2b, 0},
        {"AB01", 0x2c, 0},
        {"AB02", 0x2d, 0},
        {"AB03", 0x2e, 0},
        {"AB04", 0x2f, 0},
        {"AB05", 0x30, 0},
        {"AB06", 0x31, 0},
        {"AB07", 0x32, 0},
        {"AB08", 0x33, 0},
        {"AB09", 0x34, 0},
        {"AB10", 0x35, 0},
        {"RTSH", 0x36, 0},
        {"KPMU", 0x37, 0},
        {"LALT", 0x38, 0},
        {"SPCE", 0x39, 0},
        {"CAPS", 0x3a, 0},
        {"FK01", 0x3b, 0},
        {"FK02", 0x3c, 0},
        {"FK03", 0x3d, 0},
        {"FK04", 0x3e, 0},
        {"FK05", 0x3f, 0},
        {"FK06", 0x40, 0},
        {"FK07", 0x41, 0},
        {"FK08", 0x42, 0},
        {"FK09", 0x43, 0},
        {"FK10", 0x44, 0},
        {"NMLK", 0x45, 0},
        {"SCLK", 0x46, 0},
        {"KP7", 0x47, 0},
        {"KP8", 0x48, 0},
        {"KP9", 0x49, 0},
        {"KPSU", 0x4a, 0},
        {"KP4", 0x4b, 0},
        {"KP5", 0x4c, 0},
        {"KP6", 0x4d, 0},
        {"KPAD", 0x4e, 0},
        {"KP1", 0x4f, 0},
        {"KP2", 0x50, 0},
        {"KP3", 0x51, 0},
        {"KP0", 0x52, 0},
        {"KPDL", 0x53, 0},
        {"LSGT", 0x56, 0},
        {"FK11", 0x57, 0},
        {"FK12", 0x58, 0},
        {"KPEN", 0x1c, LIBRDP_KEY_FLAG_EXTENDED},
        {"RCTL", 0x1d, LIBRDP_KEY_FLAG_EXTENDED},
        {"KPDV", 0x35, LIBRDP_KEY_FLAG_EXTENDED},
        {"PRSC", 0x37, LIBRDP_KEY_FLAG_EXTENDED},
        {"RALT", 0x38, LIBRDP_KEY_FLAG_EXTENDED},
        {"HOME", 0x47, LIBRDP_KEY_FLAG_EXTENDED},
        {"UP", 0x48, LIBRDP_KEY_FLAG_EXTENDED},
        {"PGUP", 0x49, LIBRDP_KEY_FLAG_EXTENDED},
        {"LEFT", 0x4b, LIBRDP_KEY_FLAG_EXTENDED},
        {"RGHT", 0x4d, LIBRDP_KEY_FLAG_EXTENDED},
        {"END", 0x4f, LIBRDP_KEY_FLAG_EXTENDED},
        {"DOWN", 0x50, LIBRDP_KEY_FLAG_EXTENDED},
        {"PGDN", 0x51, LIBRDP_KEY_FLAG_EXTENDED},
        {"INS", 0x52, LIBRDP_KEY_FLAG_EXTENDED},
        {"DELE", 0x53, LIBRDP_KEY_FLAG_EXTENDED},
        {"LWIN", 0x5b, LIBRDP_KEY_FLAG_EXTENDED},
        {"RWIN", 0x5c, LIBRDP_KEY_FLAG_EXTENDED},
        {"MENU", 0x5d, LIBRDP_KEY_FLAG_EXTENDED},
        {"PAUS", 0x45, LIBRDP_KEY_FLAG_EXTENDED1},
    };
    size_t i = 0;

    if (!name || !scancode || !flags)
        return 0;

    for (i = 0; i < sizeof(map) / sizeof(map[0]); i++)
    {
        if (xkb_name_equals(name, map[i].name))
        {
            *scancode = map[i].scancode;
            *flags = map[i].flags;
            return 1;
        }
    }
    return 0;
}

static int xkb_to_rdp_scancode(const x11_app* app, KeyCode keycode, uint32_t* scancode, uint32_t* flags)
{
    char name[4];

    if (!app || !app->xkb || !app->xkb->names || !scancode || !flags)
        return 0;
    if (keycode < app->xkb->min_key_code || keycode > app->xkb->max_key_code)
        return 0;

    memcpy(name, app->xkb->names->keys[keycode].name, sizeof(name));
    return xkb_key_name_to_rdp_scancode(name, scancode, flags);
}

/*
 * Map evdev key codes to RDP scancodes for XKB fallback paths. The function
 * preserves extended-key invariants explicitly and rejects unknown codes
 * instead of guessing a remote keyboard position.
 */
static int evdev_to_rdp_scancode(unsigned int evdev, uint32_t* scancode, uint32_t* flags)
{
    if (!scancode || !flags)
        return 0;

    *flags = 0;
    if (evdev >= 1 && evdev <= 83)
    {
        *scancode = evdev;
        return 1;
    }

    switch (evdev)
    {
        case 86:
            *scancode = 0x56;
            return 1;
        case 87:
            *scancode = 0x57;
            return 1;
        case 88:
            *scancode = 0x58;
            return 1;
        case 96:
            *scancode = 0x1c;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 97:
            *scancode = 0x1d;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 98:
            *scancode = 0x35;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 99:
            *scancode = 0x37;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 100:
            *scancode = 0x38;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 102:
            *scancode = 0x47;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 103:
            *scancode = 0x48;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 104:
            *scancode = 0x49;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 105:
            *scancode = 0x4b;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 106:
            *scancode = 0x4d;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 107:
            *scancode = 0x4f;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 108:
            *scancode = 0x50;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 109:
            *scancode = 0x51;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 110:
            *scancode = 0x52;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 111:
            *scancode = 0x53;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 119:
            *scancode = 0x45;
            *flags = LIBRDP_KEY_FLAG_EXTENDED1;
            return 1;
        case 125:
            *scancode = 0x5b;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 126:
            *scancode = 0x5c;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 127:
            *scancode = 0x5d;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        default:
            return 0;
    }
}

static int translate_key_event(const x11_app* app, const XKeyEvent* key, librdp_key_event* event, librdp_key_state state)
{
    unsigned int evdev = 0;

    if (!key || !event || key->keycode < 8)
        return 0;

    memset(event, 0, sizeof(*event));
    event->state = state;
    if (xkb_to_rdp_scancode(app, (KeyCode)key->keycode, &event->scancode, &event->flags))
        return 1;

    evdev = key->keycode - 8u;
    return evdev_to_rdp_scancode(evdev, &event->scancode, &event->flags);
}

static int utf8_next(const char** cursor, const char* end, uint32_t* codepoint)
{
    const unsigned char* s = NULL;
    uint32_t value = 0;
    size_t need = 0;
    size_t i = 0;

    if (!cursor || !*cursor || !end || !codepoint || *cursor >= end)
        return 0;

    s = (const unsigned char*)*cursor;
    if (s[0] < 0x80u)
    {
        *codepoint = s[0];
        *cursor += 1;
        return 1;
    }
    if ((s[0] & 0xe0u) == 0xc0u)
    {
        value = s[0] & 0x1fu;
        need = 2;
    }
    else if ((s[0] & 0xf0u) == 0xe0u)
    {
        value = s[0] & 0x0fu;
        need = 3;
    }
    else if ((s[0] & 0xf8u) == 0xf0u)
    {
        value = s[0] & 0x07u;
        need = 4;
    }
    else
        return 0;

    if ((size_t)(end - *cursor) < need)
        return 0;
    for (i = 1; i < need; i++)
    {
        if ((s[i] & 0xc0u) != 0x80u)
            return 0;
        value = (value << 6) | (uint32_t)(s[i] & 0x3fu);
    }
    *codepoint = value;
    *cursor += need;
    return 1;
}

static void send_unicode_unit(x11_app* app, uint16_t code)
{
    librdp_key_event event;

    if (!app || !app->session || code == 0)
        return;

    memset(&event, 0, sizeof(event));
    event.flags = LIBRDP_KEY_FLAG_UNICODE;
    event.unicode = code;
    event.state = LIBRDP_KEY_PRESSED;
    (void)librdp_session_send_key(app->session, &event);
    event.state = LIBRDP_KEY_RELEASED;
    (void)librdp_session_send_key(app->session, &event);
}

static void send_unicode_codepoint(x11_app* app, uint32_t codepoint)
{
    if (codepoint < 0x20u || codepoint == 0x7fu || codepoint > 0x10ffffu)
        return;
    if (codepoint <= 0xffffu)
        send_unicode_unit(app, (uint16_t)codepoint);
    else
    {
        uint32_t value = codepoint - 0x10000u;
        send_unicode_unit(app, (uint16_t)(0xd800u | ((value >> 10) & 0x3ffu)));
        send_unicode_unit(app, (uint16_t)(0xdc00u | (value & 0x3ffu)));
    }
}

static void send_unicode_text(x11_app* app, const char* text, size_t length)
{
    const char* cursor = text;
    const char* end = text ? text + length : NULL;
    uint32_t codepoint = 0;

    while (cursor && cursor < end && utf8_next(&cursor, end, &codepoint))
        send_unicode_codepoint(app, codepoint);
}

static size_t lookup_utf8_text(x11_app* app, XKeyEvent* key, char* buffer, size_t capacity)
{
    Status status = 0;
    KeySym sym = NoSymbol;
    int length = 0;
    uint32_t codepoint = 0;

    if (!app || !key || !buffer || capacity == 0)
        return 0;

    buffer[0] = '\0';
    if (app->ic)
    {
        length = Xutf8LookupString(app->ic, key, buffer, (int)capacity - 1, &sym, &status);
        if (length > 0 && (status == XLookupChars || status == XLookupBoth))
        {
            buffer[length] = '\0';
            return (size_t)length;
        }
    }

    sym = XLookupKeysym(key, 0);
    codepoint = xkb_keysym_to_utf32((xkb_keysym_t)sym);
    if (codepoint >= 0x20u && codepoint != 0x7fu && codepoint <= 0x7fu && capacity >= 2)
    {
        buffer[0] = (char)codepoint;
        buffer[1] = '\0';
        return 1;
    }
    return 0;
}

static int is_auto_repeat_release(x11_app* app, XKeyEvent* key)
{
    XEvent next;

    if (!app || !key || app->detectable_auto_repeat)
        return 0;
    if (XPending(app->display) <= 0)
        return 0;
    XPeekEvent(app->display, &next);
    return next.type == KeyPress && next.xkey.keycode == key->keycode && next.xkey.time == key->time;
}

static void send_remote_key(x11_app* app, const librdp_key_event* event)
{
    if (!app || !event)
        return;
    (void)librdp_session_send_key(app->session, event);
}

void x11_input_release_all_remote_keys(x11_app* app)
{
    size_t i = 0;

    if (!app)
        return;
    for (i = 0; i < sizeof(app->pressed) / sizeof(app->pressed[0]); i++)
    {
        if (app->pressed[i].down)
        {
            librdp_key_event event = app->pressed[i].event;
            event.state = LIBRDP_KEY_RELEASED;
            send_remote_key(app, &event);
            app->pressed[i].down = 0;
        }
    }
    app->pressed_count = 0;
}

void x11_input_handle_key_press(x11_app* app, XKeyEvent* key)
{
    librdp_key_event event;
    char text[128];
    size_t text_len = 0;

    if (!app || !key)
        return;

    x11_input_maybe_grab_keyboard(app, key->time);
    text_len = lookup_utf8_text(app, key, text, sizeof(text));
    if (translate_key_event(app, key, &event, LIBRDP_KEY_PRESSED))
    {
        if (key->keycode < sizeof(app->pressed) / sizeof(app->pressed[0]) && app->pressed[key->keycode].down)
            return;
        send_remote_key(app, &event);
        if (key->keycode < sizeof(app->pressed) / sizeof(app->pressed[0]))
        {
            app->pressed[key->keycode].down = 1;
            app->pressed[key->keycode].event = event;
            app->pressed_count++;
        }
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.keyboard.key",
                        "keycode=%u scancode=%u flags=%u state=pressed text=%u",
                        key->keycode,
                        event.scancode,
                        event.flags,
                        text_len > 0 ? 1u : 0u);
    }
    else if (text_len > 0 && (key->state & (ControlMask | Mod1Mask | Mod4Mask)) == 0)
    {
        send_unicode_text(app, text, text_len);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.keyboard.unicode",
                        "keycode=%u bytes=%u",
                        key->keycode,
                        (unsigned)text_len);
    }
}

void x11_input_handle_key_release(x11_app* app, XKeyEvent* key)
{
    librdp_key_event event;

    if (!app || !key)
        return;
    if (is_auto_repeat_release(app, key))
        return;

    if (key->keycode < sizeof(app->pressed) / sizeof(app->pressed[0]) && app->pressed[key->keycode].down)
    {
        event = app->pressed[key->keycode].event;
        event.state = LIBRDP_KEY_RELEASED;
        send_remote_key(app, &event);
        app->pressed[key->keycode].down = 0;
        if (app->pressed_count > 0)
            app->pressed_count--;
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.keyboard.key",
                        "keycode=%u scancode=%u flags=%u state=released",
                        key->keycode,
                        event.scancode,
                        event.flags);
    }
    else if (translate_key_event(app, key, &event, LIBRDP_KEY_RELEASED))
        send_remote_key(app, &event);

    if (app->pending_ungrab && app->pressed_count == 0)
        x11_input_ungrab_keyboard(app, key->time, 0);
}

void x11_input_handle_button(x11_app* app, XButtonEvent* button, librdp_mouse_state state)
{
    librdp_mouse_event event;

    if (!app || !button)
        return;

    app->pointer_inside = 1;
    x11_input_restore_cursor_after_local_mouse(app);
    x11_input_maybe_grab_keyboard(app, button->time);
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
    x11_input_maybe_grab_keyboard(app, motion->time);
    event.x = clamp_surface_coord(app, motion->x, 0);
    event.y = clamp_surface_coord(app, motion->y, 1);
    event.button = LIBRDP_MOUSE_BUTTON_NONE;
    event.state = LIBRDP_MOUSE_MOVED;
    (void)librdp_session_send_mouse(app->session, &event);
}

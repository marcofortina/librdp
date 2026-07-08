#include <librdp/librdp.h>

#include "common/trace.h"

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xcursor/Xcursor.h>
#include <X11/XKBlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <xkbcommon/xkbcommon.h>

#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct x11_pressed_key
{
    int down;
    librdp_key_event event;
} x11_pressed_key;

typedef struct x11_app
{
    Display* display;
    int screen;
    Window window;
    GC gc;
    Atom wm_delete;
    Atom xwayland_grab;
    XIM im;
    XIC ic;
    XkbDescPtr xkb;
    Cursor cursor;
    int cursor_mode;
    int hidden_cursor_locally_visible;
    int suppress_motion;
    librdp_session* session;
    int running;
    int dirty;
    uint64_t event_serial;
    uint32_t window_width;
    uint32_t window_height;
    int focused;
    int pointer_inside;
    int keyboard_grabbed;
    int pending_ungrab;
    int detectable_auto_repeat;
    unsigned int pressed_count;
    x11_pressed_key pressed[256];
} x11_app;

#define X11_CURSOR_DEFAULT 0
#define X11_CURSOR_HIDDEN 1
#define X11_CURSOR_SHAPE 2
#define X11_MAX_EVENTS_PER_TICK 128u
#define X11_MAX_NETWORK_PUMP 64u

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

    if (!rdp_trace_enabled(RDP_TRACE_CLIENT) || !pixels || width == 0 || height == 0 || stride < row_bytes)
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

typedef struct x11_scancode_map
{
    const char* name;
    uint32_t scancode;
    uint32_t flags;
} x11_scancode_map;

static volatile int x11_window_invalid = 0;
static volatile int x11_trap_error = 0;

static int handle_x_error(Display* display, XErrorEvent* error)
{
    if (display && error)
    {
        if (error->error_code == BadDrawable || error->error_code == BadWindow)
            x11_window_invalid = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.error",
                        "code=%u request=%u resource=%lu",
                        (unsigned)error->error_code,
                        (unsigned)error->request_code,
                        error->resourceid);
    }
    return 0;
}

static int trap_x_error(Display* display, XErrorEvent* error)
{
    (void)display;

    if (error)
    {
        x11_trap_error = 1;
        if (error->error_code == BadDrawable || error->error_code == BadWindow)
            x11_window_invalid = 1;
    }
    return 0;
}

static int window_is_live(x11_app* app)
{
    XWindowAttributes attributes;
    XErrorHandler previous = NULL;
    int result = 0;

    if (!app || !app->display || !app->window || x11_window_invalid)
        return 0;

    XSync(app->display, False);
    x11_trap_error = 0;
    previous = XSetErrorHandler(trap_x_error);
    result = XGetWindowAttributes(app->display, app->window, &attributes);
    XSync(app->display, False);
    XSetErrorHandler(previous);

    if (!result || x11_trap_error)
    {
        x11_window_invalid = 1;
        app->running = 0;
        return 0;
    }
    return 1;
}

static void clear_viewer_cursor(x11_app* app)
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

static void restore_cursor_after_local_mouse(x11_app* app)
{
    if (!app || !app->display || !app->window || x11_window_invalid)
        return;
    if (app->cursor_mode != X11_CURSOR_HIDDEN || app->hidden_cursor_locally_visible)
        return;
    if (!window_is_live(app))
        return;

    XUndefineCursor(app->display, app->window);
    XFlush(app->display);
    app->hidden_cursor_locally_visible = 1;
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.pointer.local_restore", "visible=1");
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

static void apply_viewer_cursor(x11_app* app)
{
    if (!app || !app->display || !app->window || x11_window_invalid)
        return;
    if (!window_is_live(app))
        return;
    if (app->cursor_mode == X11_CURSOR_DEFAULT)
        XUndefineCursor(app->display, app->window);
    else if (app->cursor != None)
        XDefineCursor(app->display, app->window, app->cursor);
    XFlush(app->display);
}

static void handle_pointer_event(x11_app* app, const librdp_pointer_event* pointer)
{
    Cursor cursor = None;

    if (!app || !pointer)
        return;

    if (pointer->update_type == LIBRDP_POINTER_UPDATE_DEFAULT)
    {
        clear_viewer_cursor(app);
        app->cursor_mode = X11_CURSOR_DEFAULT;
        apply_viewer_cursor(app);
        rdp_trace_event(RDP_TRACE_CLIENT, "x11.pointer.default", "visible=1");
    }
    else if (pointer->update_type == LIBRDP_POINTER_UPDATE_HIDDEN)
    {
        cursor = create_hidden_cursor(app);
        if (cursor == None)
            return;
        clear_viewer_cursor(app);
        app->cursor = cursor;
        app->cursor_mode = X11_CURSOR_HIDDEN;
        app->hidden_cursor_locally_visible = 0;
        apply_viewer_cursor(app);
        rdp_trace_event(RDP_TRACE_CLIENT, "x11.pointer.hidden", "visible=0");
    }
    else if (pointer->update_type == LIBRDP_POINTER_UPDATE_POSITION)
    {
        if (window_is_live(app))
        {
            app->suppress_motion++;
            XWarpPointer(app->display, None, app->window, 0, 0, 0, 0, pointer->x, pointer->y);
            XFlush(app->display);
        }
        rdp_trace_event(RDP_TRACE_CLIENT, "x11.pointer.position", "x=%u y=%u", pointer->x, pointer->y);
    }
    else if (pointer->update_type == LIBRDP_POINTER_UPDATE_SHAPE)
    {
        cursor = create_shape_cursor(app, pointer);
        if (cursor == None)
            return;
        clear_viewer_cursor(app);
        app->cursor = cursor;
        app->cursor_mode = X11_CURSOR_SHAPE;
        app->hidden_cursor_locally_visible = 0;
        apply_viewer_cursor(app);
        rdp_trace_event(RDP_TRACE_CLIENT,
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

static void set_window_identity(x11_app* app)
{
    XClassHint hint;

    if (!app || !app->display || !app->window)
        return;

    XStoreName(app->display, app->window, "librdp-x11-viewer");
    hint.res_name = (char*)"librdp-x11-viewer";
    hint.res_class = (char*)"LibrdpX11Viewer";
    XSetClassHint(app->display, app->window, &hint);
}

static void allow_xwayland_keyboard_grab(x11_app* app)
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

static void maybe_grab_keyboard(x11_app* app, Time time)
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
    if (!window_is_live(app))
        return;

    allow_xwayland_keyboard_grab(app);
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
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.keyboard.grab", "result=%d active=%u", result, app->keyboard_grabbed);
}

static void ungrab_keyboard(x11_app* app, Time time, int force)
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
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.keyboard.ungrab", "active=0");
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

static void release_all_remote_keys(x11_app* app)
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

static int parse_u16(const char* text, uint16_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;
    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 65535ul)
        return 0;
    *value = (uint16_t)parsed;
    return 1;
}

static int parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;
    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 8192ul)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int parse_security(const char* text, librdp_security_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "auto") == 0)
        *mode = LIBRDP_SECURITY_AUTO;
    else if (strcmp(text, "rdp") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(text, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(text, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

static int require_value(int argc, int* index)
{
    if (*index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static void app_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    x11_app* app = (x11_app*)user_data;
    (void)session;

    if (!app || !event)
        return;
    app->event_serial++;

    switch (event->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
        {
            const int dirty_before = app->dirty;

            app->dirty = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.active.framebuffer.blit",
                            "x=%u y=%u width=%u height=%u dirty_before=%u event_serial=%llu",
                            event->data.surface.x,
                            event->data.surface.y,
                            event->data.surface.width,
                            event->data.surface.height,
                            dirty_before ? 1u : 0u,
                            (unsigned long long)app->event_serial);
            break;
        }
        case LIBRDP_EVENT_DISCONNECTED:
            app->running = 0;
            break;
        case LIBRDP_EVENT_POINTER:
            handle_pointer_event(app, &event->data.pointer);
            break;
        case LIBRDP_EVENT_ERROR:
            fprintf(stderr, "error=%s\n", librdp_status_string(event->data.error.status));
            app->running = 0;
            break;
        default:
            break;
    }
}

static void run_session_pump(x11_app* app)
{
    librdp_status status = LIBRDP_STATUS_OK;
    unsigned int i = 0;

    if (!app || !app->session || !app->running)
        return;

    status = librdp_session_run_once(app->session, 16);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "error=%s\n", librdp_status_string(status));
        app->running = 0;
        return;
    }

    for (i = 0; app->running && i < X11_MAX_NETWORK_PUMP; i++)
    {
        uint64_t before = app->event_serial;

        status = librdp_session_run_once(app->session, 0);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "error=%s\n", librdp_status_string(status));
            app->running = 0;
            return;
        }
        if (!app->dirty && app->event_serial == before)
            break;
    }
}

static void draw_surface(x11_app* app)
{
    const librdp_surface* surface = NULL;
    XImage* image = NULL;
    uint32_t width = 0;
    uint32_t height = 0;
    size_t stride = 0;
    uint64_t surface_hash = 0;
    int put_result = 0;

    if (!app || !app->display || !app->session || x11_window_invalid)
        return;

    surface = librdp_session_get_surface(app->session);
    if (!surface || !librdp_surface_pixels(surface))
        return;

    width = librdp_surface_width(surface);
    height = librdp_surface_height(surface);
    stride = librdp_surface_stride(surface);
    surface_hash = x11_trace_hash_bgra(librdp_surface_pixels(surface), width, height, stride);
    rdp_trace_event(RDP_TRACE_CLIENT,
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
        rdp_trace_event(RDP_TRACE_CLIENT,
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
        rdp_trace_event(RDP_TRACE_CLIENT,
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
    rdp_trace_event(RDP_TRACE_CLIENT,
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

static void handle_key_press(x11_app* app, XKeyEvent* key)
{
    librdp_key_event event;
    char text[128];
    size_t text_len = 0;

    if (!app || !key)
        return;

    maybe_grab_keyboard(app, key->time);
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
        rdp_trace_event(RDP_TRACE_CLIENT,
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
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.keyboard.unicode",
                        "keycode=%u bytes=%u",
                        key->keycode,
                        (unsigned)text_len);
    }
}

static void handle_key_release(x11_app* app, XKeyEvent* key)
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
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.keyboard.key",
                        "keycode=%u scancode=%u flags=%u state=released",
                        key->keycode,
                        event.scancode,
                        event.flags);
    }
    else if (translate_key_event(app, key, &event, LIBRDP_KEY_RELEASED))
        send_remote_key(app, &event);

    if (app->pending_ungrab && app->pressed_count == 0)
        ungrab_keyboard(app, key->time, 0);
}

static void handle_button(x11_app* app, XButtonEvent* button, librdp_mouse_state state)
{
    librdp_mouse_event event;

    if (!app || !button)
        return;

    app->pointer_inside = 1;
    restore_cursor_after_local_mouse(app);
    maybe_grab_keyboard(app, button->time);
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
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.mouse.button_ignored",
                            "button=%u state=%u",
                            button->button,
                            (unsigned)state);
            return;
    }

    (void)librdp_session_send_mouse(app->session, &event);
}

static void handle_motion(x11_app* app, XMotionEvent* motion)
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
    restore_cursor_after_local_mouse(app);
    maybe_grab_keyboard(app, motion->time);
    event.x = clamp_surface_coord(app, motion->x, 0);
    event.y = clamp_surface_coord(app, motion->y, 1);
    event.button = LIBRDP_MOUSE_BUTTON_NONE;
    event.state = LIBRDP_MOUSE_MOVED;
    (void)librdp_session_send_mouse(app->session, &event);
}

static int configure_settings(librdp_settings* settings, int argc, char** argv)
{
    int i = 1;
    uint32_t width = librdp_settings_width(settings);
    uint32_t height = librdp_settings_height(settings);

    while (i < argc)
    {
        if (strcmp(argv[i], "--target") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_target(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_username(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_password(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_domain(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            uint16_t port = 0;
            if (!require_value(argc, &i) || !parse_u16(argv[i], &port) ||
                librdp_settings_set_port(settings, port) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!require_value(argc, &i) || !parse_u32(argv[i], &width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!require_value(argc, &i) || !parse_u32(argv[i], &height))
                return 0;
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            librdp_security_mode mode = LIBRDP_SECURITY_AUTO;
            if (!require_value(argc, &i) || !parse_security(argv[i], &mode) ||
                librdp_settings_set_security_mode(settings, mode) != LIBRDP_STATUS_OK)
                return 0;
        }
        else
        {
            return 0;
        }
        i++;
    }

    return librdp_settings_set_desktop_size(settings, width, height) == LIBRDP_STATUS_OK &&
           librdp_settings_target(settings) != NULL;
}

int main(int argc, char** argv)
{
    librdp_settings* settings = NULL;
    x11_app app;
    XEvent event;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;
    Bool detectable = False;

    (void)setlocale(LC_CTYPE, "");
    (void)XSetLocaleModifiers("");
    memset(&app, 0, sizeof(app));
    settings = librdp_settings_new();
    if (!settings)
        return 1;

    if (!configure_settings(settings, argc, argv))
    {
        fprintf(stderr,
                "usage: %s --target host [--port port] [--user name] [--password value] [--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla]\n",
                argv[0]);
        librdp_settings_free(settings);
        return 2;
    }

    width = librdp_settings_width(settings);
    height = librdp_settings_height(settings);
    app.display = XOpenDisplay(NULL);
    if (!app.display)
    {
        fprintf(stderr, "error=x11_open_display\n");
        librdp_settings_free(settings);
        return 1;
    }

    XSetErrorHandler(handle_x_error);
    app.screen = DefaultScreen(app.display);
    app.xkb = XkbGetKeyboard(app.display, XkbNamesMask, XkbUseCoreKbd);
    app.window = XCreateSimpleWindow(app.display,
                                     RootWindow(app.display, app.screen),
                                     0,
                                     0,
                                     width,
                                     height,
                                     0,
                                     BlackPixel(app.display, app.screen),
                                     BlackPixel(app.display, app.screen));
    app.gc = XCreateGC(app.display, app.window, 0, NULL);
    app.window_width = width;
    app.window_height = height;
    set_window_identity(&app);
    allow_xwayland_keyboard_grab(&app);
    app.wm_delete = XInternAtom(app.display, "WM_DELETE_WINDOW", False);
    (void)XSetWMProtocols(app.display, app.window, &app.wm_delete, 1);
    app.im = XOpenIM(app.display, NULL, NULL, NULL);
    if (app.im)
        app.ic = XCreateIC(app.im,
                           XNInputStyle,
                           XIMPreeditNothing | XIMStatusNothing,
                           XNClientWindow,
                           app.window,
                           XNFocusWindow,
                           app.window,
                           NULL);
    if (XkbSetDetectableAutoRepeat(app.display, True, &detectable))
        app.detectable_auto_repeat = detectable ? 1 : 0;
    XSelectInput(app.display,
                 app.window,
                 ExposureMask | KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask |
                     PointerMotionMask | StructureNotifyMask | FocusChangeMask | EnterWindowMask | LeaveWindowMask);
    XMapWindow(app.display, app.window);

    app.session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!app.session)
    {
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        clear_viewer_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }

    librdp_session_set_event_callback(app.session, app_event, &app);
    status = librdp_session_connect(app.session);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "error=%s\n", librdp_status_string(status));
        librdp_session_free(app.session);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        clear_viewer_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }

    app.running = 1;
    app.dirty = 1;
    while (app.running)
    {
        unsigned int events_processed = 0;

        if (x11_window_invalid)
        {
            app.running = 0;
            break;
        }
        while (XPending(app.display) > 0 && events_processed < X11_MAX_EVENTS_PER_TICK)
        {
            XNextEvent(app.display, &event);
            events_processed++;
            if ((event.type == KeyPress || event.type == KeyRelease) && XFilterEvent(&event, app.window))
                continue;
            if (event.type == Expose)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "x11.window.expose",
                                "x=%d y=%d width=%d height=%d count=%d dirty_before=%u",
                                event.xexpose.x,
                                event.xexpose.y,
                                event.xexpose.width,
                                event.xexpose.height,
                                event.xexpose.count,
                                app.dirty ? 1u : 0u);
                if (event.xexpose.width > 0 && event.xexpose.height > 0)
                    (void)librdp_session_refresh(app.session,
                                                 event.xexpose.x < 0 ? 0u : (uint32_t)event.xexpose.x,
                                                 event.xexpose.y < 0 ? 0u : (uint32_t)event.xexpose.y,
                                                 (uint32_t)event.xexpose.width,
                                                 (uint32_t)event.xexpose.height);
                app.dirty = 1;
            }
            else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == app.wm_delete)
                app.running = 0;
            else if (event.type == DestroyNotify)
            {
                x11_window_invalid = 1;
                app.running = 0;
            }
            else if (event.type == KeyPress)
                handle_key_press(&app, &event.xkey);
            else if (event.type == KeyRelease)
                handle_key_release(&app, &event.xkey);
            else if (event.type == ButtonPress)
                handle_button(&app, &event.xbutton, LIBRDP_MOUSE_PRESSED);
            else if (event.type == ButtonRelease)
                handle_button(&app, &event.xbutton, LIBRDP_MOUSE_RELEASED);
            else if (event.type == MotionNotify)
                handle_motion(&app, &event.xmotion);
            else if (event.type == MappingNotify)
            {
                XRefreshKeyboardMapping(&event.xmapping);
                if (app.xkb)
                    XkbFreeKeyboard(app.xkb, 0, True);
                app.xkb = XkbGetKeyboard(app.display, XkbNamesMask, XkbUseCoreKbd);
            }
            else if (event.type == EnterNotify)
            {
                app.pointer_inside = 1;
                restore_cursor_after_local_mouse(&app);
                maybe_grab_keyboard(&app, event.xcrossing.time);
            }
            else if (event.type == LeaveNotify)
            {
                app.pointer_inside = 0;
                ungrab_keyboard(&app, event.xcrossing.time, 0);
            }
            else if (event.type == FocusIn)
            {
                app.focused = 1;
                if (app.ic)
                    XSetICFocus(app.ic);
                apply_viewer_cursor(&app);
                restore_cursor_after_local_mouse(&app);
                maybe_grab_keyboard(&app, CurrentTime);
            }
            else if (event.type == FocusOut)
            {
                if (event.xfocus.mode != NotifyGrab && event.xfocus.mode != NotifyUngrab)
                {
                    app.focused = 0;
                    if (app.ic)
                        XUnsetICFocus(app.ic);
                    release_all_remote_keys(&app);
                    ungrab_keyboard(&app, CurrentTime, 1);
                }
            }
            else if (event.type == ConfigureNotify && event.xconfigure.width > 0 && event.xconfigure.height > 0)
            {
                uint32_t configured_width = (uint32_t)event.xconfigure.width;
                uint32_t configured_height = (uint32_t)event.xconfigure.height;

                if (configured_width == app.window_width && configured_height == app.window_height)
                    continue;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "x11.window.configure",
                                "old_width=%u old_height=%u new_width=%u new_height=%u",
                                app.window_width,
                                app.window_height,
                                configured_width,
                                configured_height);
                app.window_width = configured_width;
                app.window_height = configured_height;
                (void)librdp_session_resize(app.session, configured_width, configured_height);
                XClearWindow(app.display, app.window);
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "x11.window.clear",
                                "reason=configure width=%u height=%u",
                                configured_width,
                                configured_height);
                app.dirty = 1;
                apply_viewer_cursor(&app);
            }
            if (x11_window_invalid)
            {
                app.running = 0;
                break;
            }
        }

        if (!app.running)
            break;
        run_session_pump(&app);
        if (app.running && app.dirty)
            draw_surface(&app);
    }

    release_all_remote_keys(&app);
    ungrab_keyboard(&app, CurrentTime, 1);
    (void)librdp_session_disconnect(app.session);
    librdp_session_free(app.session);
    if (app.xkb)
        XkbFreeKeyboard(app.xkb, 0, True);
    if (app.ic)
        XDestroyIC(app.ic);
    if (app.im)
        XCloseIM(app.im);
    clear_viewer_cursor(&app);
    XFreeGC(app.display, app.gc);
    if (!x11_window_invalid)
        XDestroyWindow(app.display, app.window);
    XCloseDisplay(app.display);
    return 0;
}

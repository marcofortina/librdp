#include <librdp/librdp.h>

#include "audio_pipewire.h"
#include "camera_v4l2.h"
#include "common/charset.h"
#include "common/trace.h"
#include "device_backends.h"

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xcursor/Xcursor.h>
#include <X11/extensions/Xfixes.h>
#include <X11/XKBlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <xkbcommon/xkbcommon.h>

#include <ctype.h>
#include <errno.h>
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

#define X11_AUDIO_OUTPUT_FORMATS_MAX 32u

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
    int xfixes_event_base;
    int xfixes_error_base;
    int xfixes_available;
    Atom clipboard_selection;
    Atom clipboard_property;
    Atom atom_targets;
    Atom atom_utf8_string;
    Atom atom_text;
    Atom atom_incr;
    uint8_t* clipboard_remote_utf8;
    size_t clipboard_remote_utf8_len;
    int clipboard_owns_selection;
    int clipboard_request_pending;
    x11_pipewire_audio* audio;
    x11_camera_capture* camera;
    char* audio_output_device;
    char* audio_input_device;
    char* camera_source;
    char* echo_payload;
    FILE* video_output_file;
    int audio_output_requested;
    int audio_input_requested;
    int echo_requested;
    int telemetry_requested;
    int video_requested;
    int audio_input_active;
    uint32_t audio_output_format_count;
    uint32_t audio_output_current_format;
    librdp_audio_format audio_output_formats[X11_AUDIO_OUTPUT_FORMATS_MAX];
    int camera_requested;
    size_t audio_input_chunk;
    uint8_t audio_input_buffer[16384];
    unsigned int pressed_count;
    x11_pressed_key pressed[256];
} x11_app;

#define X11_CURSOR_DEFAULT 0
#define X11_CURSOR_HIDDEN 1
#define X11_CURSOR_SHAPE 2
#define X11_MAX_EVENTS_PER_TICK 128u
#define X11_MAX_NETWORK_PUMP 64u
#define X11_CLIPBOARD_MAX_BYTES (16u * 1024u * 1024u)
#define X11_AUDIO_INPUT_BUFFER_BYTES 16384u

static char* x11_strdup_text(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text) + 1u;
    copy = (char*)malloc(length);
    if (!copy)
        return NULL;
    memcpy(copy, text, length);
    return copy;
}

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

    if (!rdp_trace_enabled_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_TRACE) ||
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

static void x11_clipboard_free(x11_app* app)
{
    if (!app)
        return;
    free(app->clipboard_remote_utf8);
    app->clipboard_remote_utf8 = NULL;
    app->clipboard_remote_utf8_len = 0;
    app->clipboard_owns_selection = 0;
    app->clipboard_request_pending = 0;
}

static int x11_clipboard_store_utf8(x11_app* app, const uint8_t* data, size_t length)
{
    uint8_t* copy = NULL;

    if (!app || (!data && length > 0) || length > X11_CLIPBOARD_MAX_BYTES)
        return 0;
    copy = (uint8_t*)malloc(length + 1u);
    if (!copy)
        return 0;
    if (length > 0)
        memcpy(copy, data, length);
    copy[length] = 0;
    free(app->clipboard_remote_utf8);
    app->clipboard_remote_utf8 = copy;
    app->clipboard_remote_utf8_len = length;
    return 1;
}

static size_t utf8_to_utf16le_bytes(const uint8_t* data, size_t length, uint8_t** out)
{
    size_t out_len = 0;

    if (!out || (!data && length > 0) || length > X11_CLIPBOARD_MAX_BYTES)
        return 0;
    if (rdp_charset_utf8_bytes_to_utf16le_alloc(data, length, 1, out, &out_len) != LIBRDP_STATUS_OK)
        return 0;
    return out_len;
}

static size_t utf16le_to_utf8_bytes(const uint8_t* data, size_t length, uint8_t** out)
{
    char* text = NULL;
    size_t text_len = 0;

    if (!out || (!data && length > 0) || (length & 1u) != 0 || length > X11_CLIPBOARD_MAX_BYTES)
        return 0;
    if (rdp_charset_utf16le_to_utf8_alloc(data, length, 1, &text, &text_len) != LIBRDP_STATUS_OK)
        return 0;
    *out = (uint8_t*)text;
    return text_len;
}

static void x11_clipboard_init(x11_app* app)
{
    if (!app || !app->display || !app->window)
        return;
    app->clipboard_selection = XInternAtom(app->display, "CLIPBOARD", False);
    app->clipboard_property = XInternAtom(app->display, "LIBRDP_CLIPBOARD_DATA", False);
    app->atom_targets = XInternAtom(app->display, "TARGETS", False);
    app->atom_utf8_string = XInternAtom(app->display, "UTF8_STRING", False);
    app->atom_text = XInternAtom(app->display, "TEXT", False);
    app->atom_incr = XInternAtom(app->display, "INCR", False);
    app->xfixes_available = XFixesQueryExtension(app->display,
                                                 &app->xfixes_event_base,
                                                 &app->xfixes_error_base);
    if (app->xfixes_available)
        XFixesSelectSelectionInput(app->display,
                                   app->window,
                                   app->clipboard_selection,
                                   XFixesSetSelectionOwnerNotifyMask);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.clipboard.init",
                    "xfixes=%u",
                    app->xfixes_available ? 1u : 0u);
}

static void x11_clipboard_request_local(x11_app* app, Time time)
{
    Window owner = None;

    if (!app || !app->display || !app->window || app->clipboard_selection == None ||
        app->atom_utf8_string == None || app->clipboard_property == None)
        return;
    owner = XGetSelectionOwner(app->display, app->clipboard_selection);
    if (owner == None || owner == app->window)
        return;
    XConvertSelection(app->display,
                      app->clipboard_selection,
                      app->atom_utf8_string,
                      app->clipboard_property,
                      app->window,
                      time == 0 ? CurrentTime : time);
    app->clipboard_request_pending = 1;
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.clipboard.request_local", "owner=%lu", owner);
}

static void x11_clipboard_handle_owner_notify(x11_app* app, XEvent* event)
{
    XFixesSelectionNotifyEvent* notify = NULL;

    if (!app || !event || !app->xfixes_available || event->type != app->xfixes_event_base + XFixesSelectionNotify)
        return;
    notify = (XFixesSelectionNotifyEvent*)event;
    if (notify->selection != app->clipboard_selection)
        return;
    if (notify->owner == app->window)
        return;
    app->clipboard_owns_selection = 0;
    x11_clipboard_request_local(app, notify->timestamp);
}

static void x11_clipboard_handle_selection_notify(x11_app* app, XSelectionEvent* selection)
{
    Atom actual_type = None;
    int actual_format = 0;
    unsigned long nitems = 0;
    unsigned long bytes_after = 0;
    unsigned char* property = NULL;
    uint8_t* utf16 = NULL;
    size_t utf16_len = 0;

    if (!app || !selection || selection->selection != app->clipboard_selection)
        return;
    app->clipboard_request_pending = 0;
    if (selection->property == None)
        return;
    if (XGetWindowProperty(app->display,
                           app->window,
                           selection->property,
                           0,
                           (long)((X11_CLIPBOARD_MAX_BYTES / 4u) + 1u),
                           True,
                           AnyPropertyType,
                           &actual_type,
                           &actual_format,
                           &nitems,
                           &bytes_after,
                           &property) != Success)
        return;
    if (actual_type == app->atom_incr || actual_format != 8 || bytes_after != 0 ||
        nitems > X11_CLIPBOARD_MAX_BYTES)
    {
        if (property)
            XFree(property);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.clipboard.local_ignored",
                        "type=%lu format=%d nitems=%lu bytes_after=%lu",
                        actual_type,
                        actual_format,
                        nitems,
                        bytes_after);
        return;
    }
    if (actual_type == app->atom_utf8_string || actual_type == XA_STRING || actual_type == app->atom_text)
    {
        utf16_len = utf8_to_utf16le_bytes(property, (size_t)nitems, &utf16);
        if (utf16_len > 0)
        {
            (void)librdp_session_clipboard_set_data(app->session,
                                                    LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                                    utf16,
                                                    utf16_len);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.clipboard.local_data",
                            "utf8_len=%lu utf16_len=%u",
                            nitems,
                            (unsigned)utf16_len);
        }
        free(utf16);
    }
    if (property)
        XFree(property);
}

static void x11_clipboard_handle_selection_request(x11_app* app, XSelectionRequestEvent* request)
{
    XSelectionEvent response;
    Atom property = None;
    Atom type = None;

    if (!app || !request)
        return;

    memset(&response, 0, sizeof(response));
    response.type = SelectionNotify;
    response.display = request->display;
    response.requestor = request->requestor;
    response.selection = request->selection;
    response.target = request->target;
    response.time = request->time;
    response.property = None;

    if (request->selection == app->clipboard_selection)
    {
        property = request->property == None ? request->target : request->property;
        if (request->target == app->atom_targets)
        {
            Atom targets[4];

            targets[0] = app->atom_targets;
            targets[1] = app->atom_utf8_string;
            targets[2] = app->atom_text;
            targets[3] = XA_STRING;
            XChangeProperty(app->display,
                            request->requestor,
                            property,
                            XA_ATOM,
                            32,
                            PropModeReplace,
                            (const unsigned char*)targets,
                            4);
            response.property = property;
        }
        else if ((request->target == app->atom_utf8_string ||
                  request->target == XA_STRING ||
                  request->target == app->atom_text) &&
                 app->clipboard_remote_utf8)
        {
            type = request->target == app->atom_text ? app->atom_utf8_string : request->target;
            XChangeProperty(app->display,
                            request->requestor,
                            property,
                            type,
                            8,
                            PropModeReplace,
                            app->clipboard_remote_utf8,
                            (int)app->clipboard_remote_utf8_len);
            response.property = property;
        }
    }

    XSendEvent(app->display, request->requestor, False, 0, (XEvent*)&response);
    XFlush(app->display);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.clipboard.selection_request",
                    "target=%lu served=%u data_len=%u",
                    request->target,
                    response.property == None ? 0u : 1u,
                    response.property == None ? 0u : (unsigned)app->clipboard_remote_utf8_len);
}

static void x11_clipboard_set_remote_data(x11_app* app, const uint8_t* data, size_t length)
{
    if (!app || !app->display || !app->window)
        return;
    if (!x11_clipboard_store_utf8(app, data, length))
        return;
    XSetSelectionOwner(app->display, app->clipboard_selection, app->window, CurrentTime);
    app->clipboard_owns_selection =
        XGetSelectionOwner(app->display, app->clipboard_selection) == app->window ? 1 : 0;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.clipboard.remote_data",
                    "utf8_len=%u owner=%u",
                    (unsigned)length,
                    app->clipboard_owns_selection ? 1u : 0u);
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

static int add_drive_arg(librdp_settings* settings, const char* text)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    return librdp_settings_add_drive(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int add_port_arg(librdp_settings* settings, const char* text, int serial)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    if (serial)
        return librdp_settings_add_serial_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
    return librdp_settings_add_parallel_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int add_printer_arg(librdp_settings* settings, const char* text)
{
    const char* first = NULL;
    const char* second = NULL;
    char name[128];
    char driver[128];
    size_t name_len = 0;
    size_t driver_len = 0;

    if (!settings || !text)
        return 0;
    first = strchr(text, '=');
    if (!first || first == text || first[1] == '\0')
        return 0;
    second = strchr(first + 1, '=');
    if (!second || second == first + 1 || second[1] == '\0')
        return 0;
    name_len = (size_t)(first - text);
    driver_len = (size_t)(second - first - 1);
    if (name_len >= sizeof(name) || driver_len >= sizeof(driver))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    memcpy(driver, first + 1, driver_len);
    driver[driver_len] = '\0';
    return librdp_settings_add_printer(settings, name, driver, second + 1) == LIBRDP_STATUS_OK;
}

static const char* value_after_prefix(const char* text, const char* prefix)
{
    const size_t prefix_len = prefix ? strlen(prefix) : 0;

    if (!text || !prefix)
        return NULL;
    if (strncmp(text, prefix, prefix_len) != 0)
        return NULL;
    if (text[prefix_len] == '\0')
        return NULL;
    return text + prefix_len;
}

static int add_camera_arg(librdp_settings* settings, const char* text)
{
    const char* value = NULL;

    if (!settings || !text)
        return 0;
    value = value_after_prefix(text, "device=");
    if (!value)
        value = value_after_prefix(text, "file=");
    if (!value)
        value = text;
    return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_camera(settings, value) == LIBRDP_STATUS_OK;
}

static int add_smartcard_arg(librdp_settings* settings, const char* text)
{
    const char* value = text && text[0] != '\0' ? text : "pcsc";

    return settings &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_smartcard(settings, value) == LIBRDP_STATUS_OK;
}

static int add_usb_arg(librdp_settings* settings, const char* text)
{
    return settings && text && text[0] != '\0' &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_usb_device(settings, text) == LIBRDP_STATUS_OK;
}

static int add_webauthn_arg(librdp_settings* settings, const char* text)
{
    const char* value = text && text[0] != '\0' ? text : "fido2";

    return settings &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_set_webauthn_provider(settings, value) == LIBRDP_STATUS_OK;
}

static int add_rail_arg(librdp_settings* settings, const char* text)
{
    const char* value = NULL;

    if (!settings || !text)
        return 0;
    value = value_after_prefix(text, "app=");
    if (!value)
        value = text;
    return librdp_settings_enable_feature(settings, LIBRDP_FEATURE_RAIL, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_add_rail_app(settings, value) == LIBRDP_STATUS_OK;
}

static int set_echo_arg(librdp_settings* settings, const char* text)
{
    const char* value = text && text[0] != '\0' ? text : "probe";

    return settings &&
           librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) == LIBRDP_STATUS_OK &&
           librdp_settings_set_echo_payload(settings, value) == LIBRDP_STATUS_OK;
}

static int require_value(int argc, int* index)
{
    if (*index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static const char* optional_value(int argc, int* index, char** argv)
{
    if (!index || !argv || *index + 1 >= argc)
        return NULL;
    if (strncmp(argv[*index + 1], "--", 2) == 0)
        return NULL;
    (*index)++;
    return argv[*index];
}

static void trace_viewer_settings(const librdp_settings* settings)
{
    uint32_t i = 0;

    if (!settings)
        return;

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.viewer.features",
                    "audio_output=%u audio_input=%u video=%u camera=%u smartcard=%u usb=%u pnp=%u webauthn=%u rail=%u cr2=%u echo=%u telemetry=%u drives=%u printers=%u pnp_devices=%u",
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_INPUT) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_VIDEO) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_SMARTCARD) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_USB) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_PNP) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_WEBAUTHN) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_RAIL) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CR2) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_ECHO) ? 1u : 0u,
                    librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_TELEMETRY) ? 1u : 0u,
                    librdp_settings_drive_count(settings),
                    librdp_settings_printer_count(settings),
                    librdp_settings_pnp_device_count(settings));
    if (librdp_settings_audio_output_device(settings))
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.audio.output.config",
                        "backend=pipewire device=\"%s\"",
                        librdp_settings_audio_output_device(settings));
    if (librdp_settings_audio_input_device(settings))
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.audio.input.config",
                        "backend=pipewire device=\"%s\"",
                        librdp_settings_audio_input_device(settings));
    if (librdp_settings_video_output_path(settings))
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.video.config",
                        "path=\"%s\"",
                        librdp_settings_video_output_path(settings));
    for (i = 0; i < librdp_settings_camera_count(settings); i++)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.camera.config",
                        "index=%u source=\"%s\"",
                        i,
                        librdp_settings_camera_source(settings, i));
    for (i = 0; i < librdp_settings_smartcard_count(settings); i++)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.smartcard.config",
                        "index=%u source=\"%s\"",
                        i,
                        librdp_settings_smartcard_source(settings, i));
    for (i = 0; i < librdp_settings_usb_device_count(settings); i++)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.usb.config",
                        "index=%u selector=\"%s\"",
                        i,
                        librdp_settings_usb_device_selector(settings, i));
    if (librdp_settings_webauthn_provider(settings))
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.webauthn.config",
                        "provider=\"%s\"",
                        librdp_settings_webauthn_provider(settings));
    for (i = 0; i < librdp_settings_rail_app_count(settings); i++)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.rail.config",
                        "index=%u app=\"%s\"",
                        i,
                        librdp_settings_rail_app(settings, i));
}

static int x11_audio_configure(x11_app* app, const librdp_settings* settings)
{
    const char* output_device = NULL;
    const char* input_device = NULL;

    if (!app || !settings)
        return 0;
    app->audio_output_requested =
        librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_OUTPUT) ? 1 : 0;
    app->audio_input_requested =
        librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_AUDIO_INPUT) ? 1 : 0;
    if (!app->audio_output_requested && !app->audio_input_requested)
        return 1;

    output_device = librdp_settings_audio_output_device(settings);
    input_device = librdp_settings_audio_input_device(settings);
    if (app->audio_output_requested)
    {
        app->audio_output_device = x11_strdup_text(output_device ? output_device : "pipewire");
        if (!app->audio_output_device)
            return 0;
    }
    if (app->audio_input_requested)
    {
        app->audio_input_device = x11_strdup_text(input_device ? input_device : "pipewire");
        if (!app->audio_input_device)
            return 0;
    }
    app->audio = x11_pipewire_audio_new();
    if (!app->audio)
        return 0;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.audio.configured",
                    "output=%u input=%u backend=pipewire",
                    app->audio_output_requested ? 1u : 0u,
                    app->audio_input_requested ? 1u : 0u);
    return 1;
}

static void x11_audio_free(x11_app* app)
{
    if (!app)
        return;
    x11_pipewire_audio_free(app->audio);
    app->audio = NULL;
    free(app->audio_output_device);
    app->audio_output_device = NULL;
    free(app->audio_input_device);
    app->audio_input_device = NULL;
    app->audio_input_active = 0;
}

static int x11_runtime_features_configure(x11_app* app, const librdp_settings* settings)
{
    const char* echo_payload = NULL;
    const char* video_path = NULL;
    const char* camera_source = NULL;

    if (!app || !settings)
        return 0;
    app->echo_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_ECHO) ? 1 : 0;
    app->telemetry_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_TELEMETRY) ? 1 : 0;
    app->video_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_VIDEO) ? 1 : 0;
    app->camera_requested = librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA) &&
                                    librdp_settings_camera_count(settings) > 0 ?
                                1 :
                                0;
    if (app->echo_requested)
    {
        echo_payload = librdp_settings_echo_payload(settings);
        app->echo_payload = x11_strdup_text(echo_payload ? echo_payload : "probe");
        if (!app->echo_payload)
            return 0;
    }
    if (app->video_requested)
    {
        video_path = librdp_settings_video_output_path(settings);
        if (video_path)
        {
            app->video_output_file = fopen(video_path, "ab");
            if (!app->video_output_file)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "x11.video.file.failed",
                                "path=\"%s\" errno=%d",
                                video_path,
                                errno);
                return 0;
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.video.file.open",
                            "path=\"%s\"",
                            video_path);
        }
    }
    if (app->camera_requested)
    {
        camera_source = librdp_settings_camera_source(settings, 0);
        app->camera_source = x11_strdup_text(camera_source);
        if (!app->camera_source)
            return 0;
        app->camera = x11_camera_capture_new();
        if (!app->camera)
            return 0;
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.runtime.features",
                    "echo=%u telemetry=%u video=%u video_file=%u camera=%u",
                    app->echo_requested ? 1u : 0u,
                    app->telemetry_requested ? 1u : 0u,
                    app->video_requested ? 1u : 0u,
                    app->video_output_file ? 1u : 0u,
                    app->camera_requested ? 1u : 0u);
    return 1;
}

static void x11_runtime_features_free(x11_app* app)
{
    if (!app)
        return;
    free(app->echo_payload);
    app->echo_payload = NULL;
    if (app->video_output_file)
        fclose(app->video_output_file);
    app->video_output_file = NULL;
    x11_camera_capture_free(app->camera);
    app->camera = NULL;
    free(app->camera_source);
    app->camera_source = NULL;
    app->camera_requested = 0;
}

static size_t x11_audio_input_chunk_size(const librdp_audio_input_open_event* open)
{
    size_t chunk = 0;

    if (!open || open->format.block_align == 0)
        return 0;
    chunk = (size_t)open->frames_per_packet * open->format.block_align;
    if (chunk == 0)
        chunk = open->format.block_align;
    if (chunk > X11_AUDIO_INPUT_BUFFER_BYTES)
    {
        chunk = X11_AUDIO_INPUT_BUFFER_BYTES - (X11_AUDIO_INPUT_BUFFER_BYTES % open->format.block_align);
        if (chunk == 0)
            chunk = open->format.block_align;
    }
    return chunk;
}

static void x11_audio_output_store_formats(x11_app* app, const librdp_audio_output_formats_event* formats)
{
    uint32_t count = 0;

    if (!app || !formats)
        return;
    app->audio_output_format_count = 0;
    app->audio_output_current_format = UINT32_MAX;
    memset(app->audio_output_formats, 0, sizeof(app->audio_output_formats));
    if (!formats->formats || formats->count == 0)
        return;
    count = formats->count > X11_AUDIO_OUTPUT_FORMATS_MAX ? X11_AUDIO_OUTPUT_FORMATS_MAX : formats->count;
    memcpy(app->audio_output_formats, formats->formats, sizeof(app->audio_output_formats[0]) * count);
    app->audio_output_format_count = count;
}

static int x11_audio_output_select_format(x11_app* app, uint32_t format_no)
{
    int ok = 0;

    if (!app || !app->audio_output_requested || !app->audio)
        return 0;
    if (format_no >= app->audio_output_format_count)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.audio.output.format.failed",
                        "reason=index format=%u count=%u",
                        format_no,
                        app->audio_output_format_count);
        return 0;
    }
    if (app->audio_output_current_format == format_no)
        return 1;
    ok = x11_pipewire_audio_start_output(app->audio,
                                         &app->audio_output_formats[format_no],
                                         app->audio_output_device);
    if (ok)
    {
        app->audio_output_current_format = format_no;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.audio.output.format",
                        "format=%u tag=%u channels=%u rate=%u bits=%u",
                        format_no,
                        app->audio_output_formats[format_no].format_tag,
                        app->audio_output_formats[format_no].channels,
                        app->audio_output_formats[format_no].samples_per_sec,
                        app->audio_output_formats[format_no].bits_per_sample);
    }
    return ok;
}

static void x11_audio_input_pump(x11_app* app)
{
    size_t bytes = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!app || !app->audio_input_active || !app->audio || !app->session || app->audio_input_chunk == 0)
        return;
    bytes = x11_pipewire_audio_read_input(app->audio,
                                          app->audio_input_buffer,
                                          app->audio_input_chunk);
    if (bytes == 0)
        return;
    status = librdp_session_audio_input_send_data(app->session, app->audio_input_buffer, bytes);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.audio.input.send.failed",
                        "status=%s bytes=%u",
                        librdp_status_string(status),
                        (unsigned)bytes);
        app->audio_input_active = 0;
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_TRACE,
                              "x11.audio.input.send",
                              "bytes=%u",
                              (unsigned)bytes);
    }
}

static int x11_channel_name_contains(const char* name, size_t name_len, const char* needle)
{
    size_t needle_len = 0;
    size_t i = 0;
    size_t j = 0;

    if (!name || !needle)
        return 0;
    needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > name_len)
        return 0;
    for (i = 0; i + needle_len <= name_len; i++)
    {
        for (j = 0; j < needle_len; j++)
        {
            if (tolower((unsigned char)name[i + j]) != tolower((unsigned char)needle[j]))
                break;
        }
        if (j == needle_len)
            return 1;
    }
    return 0;
}

static int x11_channel_name_print_len(size_t name_len)
{
    return name_len > 255u ? 255 : (int)name_len;
}

static void x11_handle_channel_open(x11_app* app, librdp_session* session, const librdp_channel_open_event* event)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!app || !session || !event)
        return;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.channel.open",
                    "id=%u name=\"%.*s\" echo=%u telemetry=%u video=%u",
                    event->channel_id,
                    x11_channel_name_print_len(event->name_len),
                    event->name ? event->name : "",
                    app->echo_requested ? 1u : 0u,
                    app->telemetry_requested ? 1u : 0u,
                    app->video_requested ? 1u : 0u);
    if (app->echo_requested && app->echo_payload &&
        x11_channel_name_contains(event->name, event->name_len, "echo"))
    {
        status = librdp_session_channel_send(session,
                                             event->channel_id,
                                             app->echo_payload,
                                             strlen(app->echo_payload));
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.echo.send",
                        "id=%u bytes=%u status=%s",
                        event->channel_id,
                        (unsigned)strlen(app->echo_payload),
                        librdp_status_string(status));
    }
}

static void x11_handle_channel_data(x11_app* app, librdp_session* session, const librdp_channel_data_event* event)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t video_written = 0;

    if (!app || !session || !event)
        return;
    if (app->video_output_file && x11_channel_name_contains(event->name, event->name_len, "video") &&
        event->data_len > 0)
    {
        video_written = fwrite(event->data, 1, event->data_len, app->video_output_file);
        fflush(app->video_output_file);
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "x11.channel.data",
                          "id=%u name=\"%.*s\" bytes=%u video_written=%u",
                          event->channel_id,
                          x11_channel_name_print_len(event->name_len),
                          event->name ? event->name : "",
                          (unsigned)event->data_len,
                          (unsigned)video_written);
    if (app->echo_requested && x11_channel_name_contains(event->name, event->name_len, "echo"))
    {
        const void* payload = event->data;
        size_t payload_len = event->data_len;

        if (payload_len == 0 && app->echo_payload)
        {
            payload = app->echo_payload;
            payload_len = strlen(app->echo_payload);
        }
        if (payload_len > 65536u)
            payload_len = 65536u;
        status = librdp_session_channel_send(session, event->channel_id, payload, payload_len);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "x11.echo.reply",
                        "id=%u bytes=%u status=%s",
                        event->channel_id,
                        (unsigned)payload_len,
                        librdp_status_string(status));
    }
}

static void x11_handle_channel_close(x11_app* app, const librdp_channel_close_event* event)
{
    if (!app || !event)
        return;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "x11.channel.close",
                    "id=%u name=\"%.*s\"",
                    event->channel_id,
                    x11_channel_name_print_len(event->name_len),
                    event->name ? event->name : "");
}

static void app_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    x11_app* app = (x11_app*)user_data;

    if (!app || !event)
        return;
    app->event_serial++;

    switch (event->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
        {
            const int dirty_before = app->dirty;

            app->dirty = 1;
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_TRACE,
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
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
        {
            uint32_t i = 0;

            for (i = 0; i < event->data.clipboard_formats.count; i++)
            {
                if (event->data.clipboard_formats.formats[i].format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
                {
                    (void)librdp_session_clipboard_request_data(app->session,
                                                                LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT);
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "x11.clipboard.remote_formats",
                                    "unicode_text=1 count=%u total=%u",
                                    event->data.clipboard_formats.count,
                                    event->data.clipboard_formats.total_count);
                    break;
                }
            }
            break;
        }
        case LIBRDP_EVENT_CLIPBOARD_DATA:
        {
            uint8_t* utf8 = NULL;
            size_t utf8_len = 0;

            if (event->data.clipboard_data.ok &&
                event->data.clipboard_data.format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
            {
                utf8_len = utf16le_to_utf8_bytes(event->data.clipboard_data.data,
                                                 event->data.clipboard_data.data_len,
                                                 &utf8);
                if (utf8_len > 0 || utf8)
                    x11_clipboard_set_remote_data(app, utf8, utf8_len);
                free(utf8);
            }
            break;
        }
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
        {
            x11_audio_output_store_formats(app, &event->data.audio_output_formats);
            if (app->audio_output_format_count > 0)
                (void)x11_audio_output_select_format(app, 0);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.audio.output.formats",
                            "count=%u stored=%u version=%u requested=%u",
                            event->data.audio_output_formats.count,
                            app->audio_output_format_count,
                            event->data.audio_output_formats.version,
                            app->audio_output_requested ? 1u : 0u);
            break;
        }
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
        {
            if (x11_audio_output_select_format(app, event->data.audio_output_data.format_no))
                (void)x11_pipewire_audio_write_output(app->audio,
                                                      event->data.audio_output_data.data,
                                                      event->data.audio_output_data.data_len);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_TRACE,
                                  "x11.audio.output.data",
                                  "bytes=%u format=%u block=%u requested=%u",
                                  (unsigned)event->data.audio_output_data.data_len,
                                  event->data.audio_output_data.format_no,
                                  event->data.audio_output_data.block_no,
                                  app->audio_output_requested ? 1u : 0u);
            break;
        }
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
            if (app->audio)
                x11_pipewire_audio_stop_output(app->audio);
            app->audio_output_current_format = UINT32_MAX;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.audio.output.close",
                            "requested=%u",
                            app->audio_output_requested ? 1u : 0u);
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_FORMATS:
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.audio.input.formats",
                            "count=%u version=%u requested=%u",
                            event->data.audio_input_formats.count,
                            event->data.audio_input_formats.version,
                            app->audio_input_requested ? 1u : 0u);
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
        {
            int ok = 0;

            app->audio_input_active = 0;
            app->audio_input_chunk = x11_audio_input_chunk_size(&event->data.audio_input_open);
            if (app->audio_input_requested && app->audio && app->audio_input_chunk > 0)
                ok = x11_pipewire_audio_start_input(app->audio,
                                                    &event->data.audio_input_open.format,
                                                    app->audio_input_device);
            (void)librdp_session_audio_input_open_reply(session,
                                                        ok ? LIBRDP_AUDIO_INPUT_RESULT_OK :
                                                             LIBRDP_AUDIO_INPUT_RESULT_FAIL);
            app->audio_input_active = ok ? 1 : 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.audio.input.open",
                            "ok=%u requested=%u frames=%u chunk=%u initial_format=%u",
                            ok ? 1u : 0u,
                            app->audio_input_requested ? 1u : 0u,
                            event->data.audio_input_open.frames_per_packet,
                            (unsigned)app->audio_input_chunk,
                            event->data.audio_input_open.initial_format);
            break;
        }
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
        {
            int ok = 0;

            if (app->camera_requested && app->camera && app->camera_source)
                ok = x11_camera_capture_start(app->camera,
                                              app->camera_source,
                                              &event->data.video_capture_open.media);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.camera.open",
                            "ok=%u requested=%u stream=%u format=%u width=%u height=%u",
                            ok ? 1u : 0u,
                            app->camera_requested ? 1u : 0u,
                            event->data.video_capture_open.stream_index,
                            event->data.video_capture_open.media.format,
                            event->data.video_capture_open.media.width,
                            event->data.video_capture_open.media.height);
            break;
        }
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
        {
            uint8_t* sample = NULL;
            size_t sample_len = 0;
            int sample_result = 0;
            librdp_status status = LIBRDP_STATUS_OK;

            if (app->camera_requested && app->camera)
                sample_result = x11_camera_capture_read_sample(app->camera, &sample, &sample_len);
            if (sample_result == 1)
                status = librdp_session_video_capture_send_sample(
                    session,
                    event->data.video_capture_sample_request.stream_index,
                    sample,
                    sample_len);
            else
                status = librdp_session_video_capture_send_error(
                    session,
                    event->data.video_capture_sample_request.stream_index,
                    sample_result == 0 ? LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                         LIBRDP_VIDEO_CAPTURE_ERROR_UNEXPECTED);
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "x11.camera.sample.reply",
                                  "status=%s result=%d stream=%u bytes=%u",
                                  librdp_status_string(status),
                                  sample_result,
                                  event->data.video_capture_sample_request.stream_index,
                                  (unsigned)sample_len);
            free(sample);
            break;
        }
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            if (app->camera)
                x11_camera_capture_stop(app->camera);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "x11.camera.close",
                            "stream=%u",
                            event->data.video_capture_close.stream_index);
            break;
        case LIBRDP_EVENT_CHANNEL_OPEN:
            x11_handle_channel_open(app, session, &event->data.channel_open);
            break;
        case LIBRDP_EVENT_CHANNEL_DATA:
            x11_handle_channel_data(app, session, &event->data.channel_data);
            break;
        case LIBRDP_EVENT_CHANNEL_CLOSE:
            x11_handle_channel_close(app, &event->data.channel_close);
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
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
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
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_TRACE,
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
        else if (strcmp(argv[i], "--drive") == 0)
        {
            if (!require_value(argc, &i) || !add_drive_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--serial") == 0)
        {
            if (!require_value(argc, &i) || !add_port_arg(settings, argv[i], 1))
                return 0;
        }
        else if (strcmp(argv[i], "--parallel") == 0)
        {
            if (!require_value(argc, &i) || !add_port_arg(settings, argv[i], 0))
                return 0;
        }
        else if (strcmp(argv[i], "--printer") == 0)
        {
            if (!require_value(argc, &i) || !add_printer_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--audio-output") == 0)
        {
            const char* value = optional_value(argc, &i, argv);
            const char* device = value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : "pipewire";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_output_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--audio-input") == 0)
        {
            const char* value = optional_value(argc, &i, argv);
            const char* device = value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : "pipewire";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_input_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--video") == 0)
        {
            const char* value = optional_value(argc, &i, argv);
            const char* path = value_after_prefix(value, "file=");

            if (!path)
                path = value;
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) != LIBRDP_STATUS_OK)
                return 0;
            if (path && librdp_settings_set_video_output_path(settings, path) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--camera") == 0)
        {
            if (!require_value(argc, &i) || !add_camera_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--smartcard") == 0)
        {
            const char* value = optional_value(argc, &i, argv);

            if (!add_smartcard_arg(settings, value))
                return 0;
        }
        else if (strcmp(argv[i], "--usb") == 0)
        {
            if (!require_value(argc, &i) || !add_usb_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--pnp") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn") == 0)
        {
            const char* value = optional_value(argc, &i, argv);

            if (!add_webauthn_arg(settings, value))
                return 0;
        }
        else if (strcmp(argv[i], "--rail") == 0)
        {
            if (!require_value(argc, &i) || !add_rail_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--cr2") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--echo") == 0)
        {
            const char* value = optional_value(argc, &i, argv);

            if (!set_echo_arg(settings, value))
                return 0;
        }
        else if (strcmp(argv[i], "--telemetry") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1) != LIBRDP_STATUS_OK)
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
                "usage: %s --target host [--port port] [--user name] [--password value] [--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla] [--drive name=path] [--serial name=path] [--parallel name=path] [--printer name=driver=path] [--audio-output [device=name]] [--audio-input [device=name]] [--video [file=path]] [--camera device=/dev/videoN] [--smartcard [pcsc|vsmartcard=path]] [--usb vid:pid|bus:dev] [--pnp] [--webauthn [fido2|fido2=/dev/hidrawN|mock|mock=path]] [--rail app=path] [--cr2] [--echo [payload]] [--telemetry]\n",
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
    x11_clipboard_init(&app);
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

    trace_viewer_settings(settings);
    if (!x11_audio_configure(&app, settings))
    {
        fprintf(stderr, "error=pipewire_audio_config\n");
        librdp_settings_free(settings);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        clear_viewer_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }
    if (!x11_device_backends_probe(settings))
    {
        fprintf(stderr, "error=device_backend_probe\n");
        librdp_settings_free(settings);
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        clear_viewer_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }
    if (!x11_runtime_features_configure(&app, settings))
    {
        fprintf(stderr, "error=runtime_feature_config\n");
        librdp_settings_free(settings);
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
        clear_viewer_cursor(&app);
        XFreeGC(app.display, app.gc);
        XDestroyWindow(app.display, app.window);
        XCloseDisplay(app.display);
        return 1;
    }
    app.session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!app.session)
    {
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
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
        x11_runtime_features_free(&app);
        x11_audio_free(&app);
        if (app.xkb)
            XkbFreeKeyboard(app.xkb, 0, True);
        if (app.ic)
            XDestroyIC(app.ic);
        if (app.im)
            XCloseIM(app.im);
        x11_clipboard_free(&app);
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
            else if (app.xfixes_available && event.type == app.xfixes_event_base + XFixesSelectionNotify)
                x11_clipboard_handle_owner_notify(&app, &event);
            else if (event.type == SelectionNotify)
                x11_clipboard_handle_selection_notify(&app, &event.xselection);
            else if (event.type == SelectionRequest)
                x11_clipboard_handle_selection_request(&app, &event.xselectionrequest);
            else if (event.type == SelectionClear && event.xselectionclear.selection == app.clipboard_selection)
            {
                app.clipboard_owns_selection = 0;
                rdp_trace_event(RDP_TRACE_CLIENT, "x11.clipboard.selection_clear", "owner=0");
            }
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
        x11_audio_input_pump(&app);
        if (app.running && app.dirty)
            draw_surface(&app);
    }

    release_all_remote_keys(&app);
    ungrab_keyboard(&app, CurrentTime, 1);
    (void)librdp_session_disconnect(app.session);
    librdp_session_free(app.session);
    x11_runtime_features_free(&app);
    x11_audio_free(&app);
    if (app.xkb)
        XkbFreeKeyboard(app.xkb, 0, True);
    if (app.ic)
        XDestroyIC(app.ic);
    if (app.im)
        XCloseIM(app.im);
    x11_clipboard_free(&app);
    clear_viewer_cursor(&app);
    XFreeGC(app.display, app.gc);
    if (!x11_window_invalid)
        XDestroyWindow(app.display, app.window);
    XCloseDisplay(app.display);
    return 0;
}

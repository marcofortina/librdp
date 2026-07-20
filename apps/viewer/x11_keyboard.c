/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 keyboard bridge.
 * Invariants: XKB key positions provide scancodes, X input methods provide
 * composed Unicode fallback only when no physical scancode is available, and
 * grabbed keys are released remotely before the local grab is dropped.
 * Ownership: no XKB or input-method objects are owned here; pressed-key entries
 * are borrowed from x11_app and updated only by the viewer event thread.
 * Threading: synchronous viewer event-thread code; callbacks into librdp are not
 * re-entered from worker threads.
 * Trust boundary: local keycodes, key names, and composed text are bounded before
 * becoming remote input.
 */

#include "x11_keyboard.h"

#include "x11_trace.h"
#include "x11_window.h"
#include "x11_keymap.h"

#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <xkbcommon/xkbcommon.h>

#include <stdint.h>
#include <string.h>

/*
 * Validate canonical XKB key names at the local input boundary and translate
 * them into RDP set-1 scancodes. The table maps physical positions defined by
 * the active OS layout metadata, so AltGr, dead keys, and compose sequences
 * keep using the platform stack for text while the remote side still receives
 * correct key-up/key-down positions.
 */
int x11_keyboard_map_xkb_name(const char name[4], uint32_t* scancode, uint32_t* flags)
{
    return x11_keymap_xkb_name_to_rdp(name, scancode, flags);
}

static int xkb_to_rdp_scancode(const x11_app* app, KeyCode keycode, uint32_t* scancode, uint32_t* flags)
{
    char name[4];

    if (!app || !app->xkb || !app->xkb->names || !scancode || !flags)
        return 0;
    if (keycode < app->xkb->min_key_code || keycode > app->xkb->max_key_code)
        return 0;

    memcpy(name, app->xkb->names->keys[keycode].name, sizeof(name));
    return x11_keyboard_map_xkb_name(name, scancode, flags);
}

/*
 * Validate evdev keycodes exposed by XKB fallback paths rather than canonical
 * key names. Unknown codes fail closed so text-only compose fallback remains
 * the only path for unmapped printable input.
 */
int x11_keyboard_map_evdev(unsigned int evdev, uint32_t* scancode, uint32_t* flags)
{
    return x11_keymap_evdev_to_rdp(evdev, scancode, flags);
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
    return x11_keyboard_map_evdev(evdev, &event->scancode, &event->flags);
}

int x11_keyboard_next_utf8_codepoint(const char** cursor, const char* end, uint32_t* codepoint)
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
    if ((need == 2u && value < 0x80u) ||
        (need == 3u && value < 0x800u) ||
        (need == 4u && value < 0x10000u) ||
        (value >= 0xd800u && value <= 0xdfffu) ||
        value > 0x10ffffu)
        return 0;
    *codepoint = value;
    *cursor += need;
    return 1;
}

static void emit_unicode_unit(uint16_t code,
                              x11_keyboard_event_sink sink,
                              void* user_data)
{
    librdp_key_event event;

    if (!sink || code == 0u)
        return;

    memset(&event, 0, sizeof(event));
    event.flags = LIBRDP_KEY_FLAG_UNICODE;
    event.unicode = code;
    event.state = LIBRDP_KEY_PRESSED;
    sink(&event, user_data);
    event.state = LIBRDP_KEY_RELEASED;
    sink(&event, user_data);
}

static size_t emit_unicode_codepoint(uint32_t codepoint,
                                     x11_keyboard_event_sink sink,
                                     void* user_data)
{
    if (codepoint < 0x20u || codepoint == 0x7fu || codepoint > 0x10ffffu)
        return 0u;
    if (codepoint <= 0xffffu)
    {
        emit_unicode_unit((uint16_t)codepoint, sink, user_data);
        return 1u;
    }
    else
    {
        uint32_t value = codepoint - 0x10000u;
        emit_unicode_unit((uint16_t)(0xd800u | ((value >> 10) & 0x3ffu)),
                          sink,
                          user_data);
        emit_unicode_unit((uint16_t)(0xdc00u | (value & 0x3ffu)),
                          sink,
                          user_data);
        return 2u;
    }
}

/*
 * Convert text supplied by XIM into UTF-16 input units. Invalid UTF-8 stops the
 * sequence at the malformed byte so no replacement or guessed input reaches
 * the remote session; supplementary code points are emitted as surrogate
 * pairs with a press and release for each unit.
 */
size_t x11_keyboard_emit_utf8(const char* text,
                              size_t length,
                              x11_keyboard_event_sink sink,
                              void* user_data)
{
    const char* cursor = text;
    const char* end = text ? text + length : NULL;
    uint32_t codepoint = 0;
    size_t units = 0u;

    if (!text || !sink)
        return 0u;
    while (cursor && cursor < end && x11_keyboard_next_utf8_codepoint(&cursor, end, &codepoint))
        units += emit_unicode_codepoint(codepoint, sink, user_data);
    return units;
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

int x11_keyboard_should_send_unicode_fallback(unsigned int state, size_t text_len, int translated)
{
    if (translated || text_len == 0)
        return 0;
    return (state & (ControlMask | Mod1Mask | Mod4Mask)) == 0;
}

int x11_keyboard_auto_repeat_release_match(int detectable_auto_repeat,
                                           int has_next_event,
                                           int next_type,
                                           unsigned int next_keycode,
                                           Time next_time,
                                           unsigned int keycode,
                                           Time time)
{
    if (detectable_auto_repeat || !has_next_event)
        return 0;
    return next_type == KeyPress && next_keycode == keycode && next_time == time;
}

static int is_auto_repeat_release(x11_app* app, XKeyEvent* key)
{
    XEvent next;

    if (!app || !key || XPending(app->display) <= 0)
        return 0;
    XPeekEvent(app->display, &next);
    return x11_keyboard_auto_repeat_release_match(app->detectable_auto_repeat,
                                                  1,
                                                  next.type,
                                                  next.xkey.keycode,
                                                  next.xkey.time,
                                                  key->keycode,
                                                  key->time);
}

/*
 * Record a remote key-down after duplicate suppression. Out-of-range X11
 * keycodes are still sent but are intentionally not tracked for deferred grab
 * release because the fixed pressed-key table cannot represent them safely.
 */
int x11_keyboard_record_press(x11_pressed_key* pressed,
                              size_t capacity,
                              unsigned int* pressed_count,
                              unsigned int keycode,
                              const librdp_key_event* event)
{
    if (!pressed || !pressed_count || !event)
        return 0;
    if ((size_t)keycode >= capacity)
        return 1;
    if (pressed[keycode].down)
        return 0;
    pressed[keycode].down = 1;
    pressed[keycode].event = *event;
    if (*pressed_count < capacity)
        (*pressed_count)++;
    return 1;
}

int x11_keyboard_prepare_release(x11_pressed_key* pressed,
                                 size_t capacity,
                                 unsigned int* pressed_count,
                                 unsigned int keycode,
                                 librdp_key_event* event)
{
    if (!pressed || !pressed_count || !event || (size_t)keycode >= capacity || !pressed[keycode].down)
        return 0;
    *event = pressed[keycode].event;
    event->state = LIBRDP_KEY_RELEASED;
    pressed[keycode].down = 0;
    if (*pressed_count > 0)
        (*pressed_count)--;
    return 1;
}

static void send_remote_key(x11_app* app, const librdp_key_event* event)
{
    if (!app || !event)
        return;
    (void)librdp_session_send_key(app->session, event);
}

static void send_unicode_event(const librdp_key_event* event, void* user_data)
{
    send_remote_key((x11_app*)user_data, event);
}

void x11_keyboard_allow_xwayland_grab(x11_app* app)
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

void x11_keyboard_maybe_grab(x11_app* app, Time time)
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

    x11_keyboard_allow_xwayland_grab(app);
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

void x11_keyboard_ungrab(x11_app* app, Time time, int force)
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

void x11_keyboard_release_all_remote_keys(x11_app* app)
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

void x11_keyboard_handle_key_press(x11_app* app, XKeyEvent* key)
{
    librdp_key_event event;
    char text[128];
    size_t text_len = 0;
    int translated = 0;

    if (!app || !key)
        return;

    x11_keyboard_maybe_grab(app, key->time);
    text_len = lookup_utf8_text(app, key, text, sizeof(text));
    translated = translate_key_event(app, key, &event, LIBRDP_KEY_PRESSED);
    if (translated)
    {
        if (!x11_keyboard_record_press(app->pressed,
                                       sizeof(app->pressed) / sizeof(app->pressed[0]),
                                       &app->pressed_count,
                                       key->keycode,
                                       &event))
            return;
        send_remote_key(app, &event);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.keyboard.key",
                        "keycode=%u scancode=%u flags=%u state=pressed text=%u",
                        key->keycode,
                        event.scancode,
                        event.flags,
                        text_len > 0 ? 1u : 0u);
    }
    else if (x11_keyboard_should_send_unicode_fallback(key->state, text_len, translated))
    {
        (void)x11_keyboard_emit_utf8(text,
                                     text_len,
                                     send_unicode_event,
                                     app);
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.keyboard.unicode",
                        "keycode=%u bytes=%u",
                        key->keycode,
                        (unsigned)text_len);
    }
}

void x11_keyboard_handle_key_release(x11_app* app, XKeyEvent* key)
{
    librdp_key_event event;

    if (!app || !key)
        return;
    if (is_auto_repeat_release(app, key))
        return;

    if (x11_keyboard_prepare_release(app->pressed,
                                     sizeof(app->pressed) / sizeof(app->pressed[0]),
                                     &app->pressed_count,
                                     key->keycode,
                                     &event))
    {
        send_remote_key(app, &event);
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
        x11_keyboard_ungrab(app, key->time, 0);
}

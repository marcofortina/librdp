/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: XTest and XKB input injection for the X11 desktop server.
 * Invariants: physical keys are resolved through canonical XKB positions,
 * every tracked press has a matching release, and pointer coordinates remain
 * clipped to the captured desktop.
 * Ownership: XKB metadata and pressed-state arrays are context-owned.
 * Threading: injection runs synchronously on the X11 host thread.
 * Trust boundary: remote input flags, scancodes, Unicode units, coordinates
 * and wheel deltas are validated before XTest calls.
 */

#include "server_x11_internal.h"

#include "x11_keymap.h"

#include <X11/keysym.h>
#include <X11/extensions/XTest.h>

#include <limits.h>
#include <string.h>

#define X11_RDP_KBD_RELEASE 0x8000u
#define X11_RDP_KBD_EXTENDED 0x0100u
#define X11_RDP_KBD_EXTENDED1 0x0200u
#define X11_RDP_POINTER_DOWN 0x8000u
#define X11_RDP_POINTER_MOVE 0x0800u
#define X11_RDP_POINTER_BUTTON1 0x1000u
#define X11_RDP_POINTER_BUTTON2 0x2000u
#define X11_RDP_POINTER_BUTTON3 0x4000u
#define X11_RDP_POINTER_WHEEL 0x0200u
#define X11_RDP_POINTER_HWHEEL 0x0400u

static KeyCode x11_server_keycode_from_name(x11_server_context* context,
                                            const char name[4])
{
    int keycode = 0;

    if (!context->keyboard)
    {
        context->keyboard =
            XkbGetKeyboard(context->display,
                           XkbAllComponentsMask,
                           XkbUseCoreKbd);
    }
    if (!context->keyboard || !context->keyboard->names)
        return 0;
    for (keycode = context->keyboard->min_key_code;
         keycode <= context->keyboard->max_key_code;
         keycode++)
    {
        if (memcmp(context->keyboard->names->keys[keycode].name,
                   name,
                   4u) == 0)
            return (KeyCode)keycode;
    }
    return 0;
}

static librdp_status x11_server_inject_scancode(
    x11_server_context* context,
    const librdp_server_input_event* event)
{
    uint32_t key_flags = 0u;
    char name[4];
    KeyCode keycode = 0;
    int pressed = 0;

    if (event->param1 == 0u || event->param1 > 0xffu ||
        (event->flags &
         ~(X11_RDP_KBD_RELEASE | X11_RDP_KBD_EXTENDED |
           X11_RDP_KBD_EXTENDED1)) != 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((event->flags & X11_RDP_KBD_EXTENDED) != 0u)
        key_flags |= LIBRDP_KEY_FLAG_EXTENDED;
    if ((event->flags & X11_RDP_KBD_EXTENDED1) != 0u)
        key_flags |= LIBRDP_KEY_FLAG_EXTENDED1;
    if (!x11_keymap_rdp_to_xkb_name(event->param1, key_flags, name))
        return LIBRDP_STATUS_UNSUPPORTED;
    keycode = x11_server_keycode_from_name(context, name);
    if (keycode == 0u)
        return LIBRDP_STATUS_UNSUPPORTED;
    pressed = (event->flags & X11_RDP_KBD_RELEASE) == 0u;
    if (!XTestFakeKeyEvent(context->display,
                           keycode,
                           pressed ? True : False,
                           CurrentTime))
        return LIBRDP_STATUS_IO_ERROR;
    context->pressed_keys[keycode] = pressed ? 1u : 0u;
    XFlush(context->display);
    return LIBRDP_STATUS_OK;
}

static int x11_server_find_keysym(x11_server_context* context,
                                  KeySym keysym,
                                  KeyCode* keycode,
                                  int* shift,
                                  int* level3)
{
    int minimum = 0;
    int maximum = 0;
    int code = 0;

    if (!context || !keycode || !shift || !level3)
        return 0;
    XDisplayKeycodes(context->display, &minimum, &maximum);
    for (code = minimum; code <= maximum; code++)
    {
        int group = 0;

        for (group = 0; group < 4; group++)
        {
            int level = 0;

            for (level = 0; level < 4; level++)
            {
                if (XkbKeycodeToKeysym(context->display,
                                       (KeyCode)code,
                                       group,
                                       level) == keysym)
                {
                    *keycode = (KeyCode)code;
                    *shift = (level & 1) != 0;
                    *level3 = level >= 2 || group > 0;
                    return 1;
                }
            }
        }
    }
    return 0;
}

static librdp_status x11_server_inject_codepoint(
    x11_server_context* context,
    uint32_t codepoint)
{
    KeySym keysym = NoSymbol;
    KeyCode keycode = 0;
    KeyCode shift_code = 0;
    KeyCode level3_code = 0;
    int shift = 0;
    int level3 = 0;

    if (codepoint == 0u || codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    keysym = codepoint <= 0xffu ? (KeySym)codepoint
                               : (KeySym)(0x01000000u | codepoint);
    if (!x11_server_find_keysym(context,
                                keysym,
                                &keycode,
                                &shift,
                                &level3))
        return LIBRDP_STATUS_UNSUPPORTED;
    shift_code = XKeysymToKeycode(context->display, XK_Shift_L);
    level3_code =
        XKeysymToKeycode(context->display, XK_ISO_Level3_Shift);
    if ((shift && shift_code == 0u) || (level3 && level3_code == 0u))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (level3)
        XTestFakeKeyEvent(context->display, level3_code, True, CurrentTime);
    if (shift)
        XTestFakeKeyEvent(context->display, shift_code, True, CurrentTime);
    XTestFakeKeyEvent(context->display, keycode, True, CurrentTime);
    XTestFakeKeyEvent(context->display, keycode, False, CurrentTime);
    if (shift)
        XTestFakeKeyEvent(context->display, shift_code, False, CurrentTime);
    if (level3)
        XTestFakeKeyEvent(context->display, level3_code, False, CurrentTime);
    XFlush(context->display);
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_inject_unicode(
    x11_server_context* context,
    const librdp_server_input_event* event)
{
    uint16_t unit = event->param1;

    if ((event->flags & ~X11_RDP_KBD_RELEASE) != 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((event->flags & X11_RDP_KBD_RELEASE) != 0u)
        return LIBRDP_STATUS_OK;
    if (unit >= 0xd800u && unit <= 0xdbffu)
    {
        context->pending_high_surrogate = unit;
        return LIBRDP_STATUS_OK;
    }
    if (unit >= 0xdc00u && unit <= 0xdfffu)
    {
        uint32_t codepoint = 0u;

        if (context->pending_high_surrogate == 0u)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        codepoint =
            0x10000u +
            (((uint32_t)context->pending_high_surrogate - 0xd800u) << 10u) +
            ((uint32_t)unit - 0xdc00u);
        context->pending_high_surrogate = 0u;
        return x11_server_inject_codepoint(context, codepoint);
    }
    if (context->pending_high_surrogate != 0u)
    {
        context->pending_high_surrogate = 0u;
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    return x11_server_inject_codepoint(context, unit);
}

static void x11_server_inject_button(x11_server_context* context,
                                     unsigned int button,
                                     int pressed)
{
    if (button == 0u || button > 16u)
        return;
    XTestFakeButtonEvent(context->display,
                         button,
                         pressed ? True : False,
                         CurrentTime);
    if (pressed)
        context->pressed_buttons |= (uint16_t)(1u << (button - 1u));
    else
        context->pressed_buttons &= (uint16_t)~(1u << (button - 1u));
}

static librdp_status x11_server_inject_pointer(
    x11_server_context* context,
    const librdp_server_input_event* event)
{
    uint16_t flags = event->flags;
    int root_x = context->desktop_x + (int)event->x;
    int root_y = context->desktop_y + (int)event->y;
    int pressed = (flags & X11_RDP_POINTER_DOWN) != 0u;
    unsigned int button = 0u;

    if ((uint32_t)event->x >= context->width ||
        (uint32_t)event->y >= context->height)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((flags & X11_RDP_POINTER_MOVE) != 0u)
        XTestFakeMotionEvent(context->display,
                             context->screen,
                             root_x,
                             root_y,
                             CurrentTime);
    if ((flags & X11_RDP_POINTER_WHEEL) != 0u ||
        (flags & X11_RDP_POINTER_HWHEEL) != 0u)
    {
        int16_t delta = (int16_t)(flags & 0x01ffu);
        unsigned int steps = 0u;

        if ((delta & 0x0100) != 0)
            delta = (int16_t)(delta | (int16_t)~0x01ff);
        steps = (unsigned int)(delta < 0 ? -delta : delta);
        steps = steps == 0u ? 1u : (steps + 119u) / 120u;
        if ((flags & X11_RDP_POINTER_HWHEEL) != 0u)
            button = delta < 0 ? 6u : 7u;
        else
            button = delta < 0 ? 5u : 4u;
        while (steps-- > 0u)
        {
            XTestFakeButtonEvent(context->display,
                                 button,
                                 True,
                                 CurrentTime);
            XTestFakeButtonEvent(context->display,
                                 button,
                                 False,
                                 CurrentTime);
        }
    }
    else
    {
        if ((flags & X11_RDP_POINTER_BUTTON1) != 0u)
            button = 1u;
        else if ((flags & X11_RDP_POINTER_BUTTON2) != 0u)
            button = 3u;
        else if ((flags & X11_RDP_POINTER_BUTTON3) != 0u)
            button = 2u;
        else if (event->type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE)
        {
            if ((flags & 0x0001u) != 0u)
                button = 8u;
            else if ((flags & 0x0002u) != 0u)
                button = 9u;
        }
        if (button != 0u)
            x11_server_inject_button(context, button, pressed);
    }
    XFlush(context->display);
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_input_inject(
    void* opaque,
    const librdp_server_input_event* event)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !event ||
        event->version != LIBRDP_SERVER_INPUT_EVENT_VERSION ||
        event->size < sizeof(*event))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (event->type)
    {
        case LIBRDP_SERVER_INPUT_SYNCHRONIZE:
            return LIBRDP_STATUS_OK;
        case LIBRDP_SERVER_INPUT_SCANCODE_KEY:
            return x11_server_inject_scancode(context, event);
        case LIBRDP_SERVER_INPUT_UNICODE_KEY:
            return x11_server_inject_unicode(context, event);
        case LIBRDP_SERVER_INPUT_MOUSE:
        case LIBRDP_SERVER_INPUT_EXTENDED_MOUSE:
            return x11_server_inject_pointer(context, event);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

static void x11_server_input_release_all(void* opaque)
{
    x11_server_context* context = (x11_server_context*)opaque;
    unsigned int keycode = 0u;
    unsigned int button = 0u;

    if (!context)
        return;
    for (keycode = 0u; keycode < 256u; keycode++)
    {
        if (!context->pressed_keys[keycode])
            continue;
        XTestFakeKeyEvent(context->display,
                           (KeyCode)keycode,
                           False,
                           CurrentTime);
        context->pressed_keys[keycode] = 0u;
    }
    for (button = 1u; button <= 16u; button++)
    {
        if ((context->pressed_buttons & (uint16_t)(1u << (button - 1u))) ==
            0u)
            continue;
        XTestFakeButtonEvent(context->display,
                             button,
                             False,
                             CurrentTime);
    }
    context->pressed_buttons = 0u;
    context->pending_high_surrogate = 0u;
    XFlush(context->display);
}

const server_platform_input_vtable x11_server_input_vtable = {
    SERVER_PLATFORM_INPUT_VERSION,
    sizeof(server_platform_input_vtable),
    x11_server_input_inject,
    x11_server_input_release_all,
};

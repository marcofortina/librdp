/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: CoreGraphics input injection for the Cocoa desktop server.
 * Invariants: RDP physical keys map to Carbon virtual-key positions, text is
 * resolved through the active TIS layout before Unicode fallback, and every
 * tracked press is released when ownership or permission is lost.
 * Ownership: TIS and CGEvent objects are retained only within one injection;
 * pressed-state storage belongs to the Cocoa server context.
 * Threading: all injection methods run on the serialized server-host thread.
 * Trust boundary: remote flags, scancodes, UTF-16 units, pointer coordinates
 * and wheel deltas are validated before creating host input events.
 */

#include "cocoa_server_internal.h"

#include "cocoa_keymap.h"

#import <ApplicationServices/ApplicationServices.h>
#import <Carbon/Carbon.h>

#include <math.h>
#include <string.h>

#define COCOA_RDP_KBD_RELEASE 0x8000u
#define COCOA_RDP_KBD_EXTENDED 0x0100u
#define COCOA_RDP_KBD_EXTENDED1 0x0200u
#define COCOA_RDP_POINTER_DOWN 0x8000u
#define COCOA_RDP_POINTER_MOVE 0x0800u
#define COCOA_RDP_POINTER_BUTTON1 0x1000u
#define COCOA_RDP_POINTER_BUTTON2 0x2000u
#define COCOA_RDP_POINTER_BUTTON3 0x4000u
#define COCOA_RDP_POINTER_WHEEL 0x0200u
#define COCOA_RDP_POINTER_HWHEEL 0x0400u

static int cocoa_server_scancode_keycode(uint16_t scancode,
                                         uint16_t flags,
                                         CGKeyCode* keycode)
{
    uint16_t mapped = 0u;
    uint32_t key_flags = 0u;

    if (!keycode || scancode == 0u || scancode > 0xffu ||
        (flags & ~(COCOA_RDP_KBD_RELEASE |
                   COCOA_RDP_KBD_EXTENDED |
                   COCOA_RDP_KBD_EXTENDED1)) != 0u ||
        (flags & COCOA_RDP_KBD_EXTENDED1) != 0u)
        return 0;
    if ((flags & COCOA_RDP_KBD_EXTENDED) != 0u)
        key_flags |= LIBRDP_KEY_FLAG_EXTENDED;
    if (!cocoa_keymap_rdp_to_native(scancode,
                                    key_flags,
                                    &mapped))
        return 0;
    *keycode = (CGKeyCode)mapped;
    return 1;
}

static int cocoa_server_post_key(CGKeyCode keycode, int pressed)
{
    CGEventRef event =
        CGEventCreateKeyboardEvent(NULL,
                                   keycode,
                                   pressed ? true : false);

    if (!event)
        return 0;
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
    return 1;
}

static librdp_status cocoa_server_inject_scancode(
    cocoa_server_context* context,
    const librdp_server_input_event* event)
{
    CGKeyCode keycode = 0u;
    int pressed = 0;

    if (!cocoa_server_scancode_keycode(
            event->param1, event->flags, &keycode) ||
        keycode >= COCOA_SERVER_KEY_CAPACITY)
        return LIBRDP_STATUS_UNSUPPORTED;
    pressed =
        (event->flags & COCOA_RDP_KBD_RELEASE) == 0u;
    if (!cocoa_server_post_key(keycode, pressed))
        return LIBRDP_STATUS_IO_ERROR;
    context->pressed_keys[keycode] = pressed ? 1u : 0u;
    return LIBRDP_STATUS_OK;
}

static int cocoa_server_layout_key_for_units(
    const UniChar* units,
    UniCharCount unit_count,
    CGKeyCode* keycode,
    UInt32* modifiers)
{
    static const UInt32 modifier_candidates[] = {
        0u,
        shiftKey,
        optionKey,
        shiftKey | optionKey,
    };
    TISInputSourceRef source =
        TISCopyCurrentKeyboardLayoutInputSource();
    CFDataRef layout_data = NULL;
    const UCKeyboardLayout* layout = NULL;
    CGEventSourceRef event_source = NULL;
    UInt32 keyboard_type = 0u;
    int found = 0;

    if (!source || !units || unit_count == 0u ||
        !keycode || !modifiers)
    {
        if (source)
            CFRelease(source);
        return 0;
    }
    layout_data = (CFDataRef)TISGetInputSourceProperty(
        source, kTISPropertyUnicodeKeyLayoutData);
    if (!layout_data)
    {
        CFRelease(source);
        return 0;
    }
    layout =
        (const UCKeyboardLayout*)CFDataGetBytePtr(layout_data);
    event_source =
        CGEventSourceCreate(kCGEventSourceStateCombinedSessionState);
    if (event_source)
        keyboard_type = CGEventSourceGetKeyboardType(event_source);
    for (CGKeyCode candidate = 0u;
         candidate < COCOA_SERVER_KEY_CAPACITY && !found;
         candidate++)
    {
        size_t modifier_index = 0u;

        for (modifier_index = 0u;
             modifier_index <
                 sizeof(modifier_candidates) /
                     sizeof(modifier_candidates[0]);
             modifier_index++)
        {
            UInt32 dead_key_state = 0u;
            UniChar output[4];
            UniCharCount output_count = 0u;
            UInt32 candidate_modifiers =
                modifier_candidates[modifier_index];
            OSStatus status = UCKeyTranslate(
                layout,
                candidate,
                kUCKeyActionDown,
                (candidate_modifiers >> 8u) & 0xffu,
                keyboard_type,
                kUCKeyTranslateNoDeadKeysBit,
                &dead_key_state,
                (UniCharCount)(sizeof(output) / sizeof(output[0])),
                &output_count,
                output);

            if (status == noErr &&
                output_count == unit_count &&
                memcmp(output,
                       units,
                       (size_t)unit_count * sizeof(UniChar)) == 0)
            {
                *keycode = candidate;
                *modifiers = candidate_modifiers;
                found = 1;
                break;
            }
        }
    }
    if (event_source)
        CFRelease(event_source);
    CFRelease(source);
    return found;
}

static int cocoa_server_modifier_pressed(
    const cocoa_server_context* context)
{
    return context &&
           (context->pressed_keys[kVK_Shift] ||
            context->pressed_keys[kVK_RightShift] ||
            context->pressed_keys[kVK_Option] ||
            context->pressed_keys[kVK_RightOption] ||
            context->pressed_keys[kVK_Control] ||
            context->pressed_keys[kVK_RightControl] ||
            context->pressed_keys[kVK_Command] ||
            context->pressed_keys[kVK_RightCommand]);
}

static int cocoa_server_post_layout_key(
    const cocoa_server_context* context,
    CGKeyCode keycode,
    UInt32 modifiers)
{
    int temporary_shift =
        (modifiers & shiftKey) != 0u &&
        !context->pressed_keys[kVK_Shift] &&
        !context->pressed_keys[kVK_RightShift];
    int temporary_option =
        (modifiers & optionKey) != 0u &&
        !context->pressed_keys[kVK_Option] &&
        !context->pressed_keys[kVK_RightOption];
    int ok = 1;

    if (temporary_option)
        ok = cocoa_server_post_key(kVK_Option, 1);
    if (ok && temporary_shift)
        ok = cocoa_server_post_key(kVK_Shift, 1);
    if (ok)
        ok = cocoa_server_post_key(keycode, 1);
    if (ok)
        ok = cocoa_server_post_key(keycode, 0);
    if (temporary_shift)
        ok = cocoa_server_post_key(kVK_Shift, 0) && ok;
    if (temporary_option)
        ok = cocoa_server_post_key(kVK_Option, 0) && ok;
    return ok;
}

static int cocoa_server_post_unicode(const UniChar* units,
                                     UniCharCount count)
{
    CGEventRef down = NULL;
    CGEventRef up = NULL;
    int ok = 0;

    if (!units || count == 0u || count > 2u)
        return 0;
    down = CGEventCreateKeyboardEvent(NULL, 0u, true);
    up = CGEventCreateKeyboardEvent(NULL, 0u, false);
    if (down && up)
    {
        CGEventKeyboardSetUnicodeString(down, count, units);
        CGEventKeyboardSetUnicodeString(up, count, units);
        CGEventPost(kCGHIDEventTap, down);
        CGEventPost(kCGHIDEventTap, up);
        ok = 1;
    }
    if (down)
        CFRelease(down);
    if (up)
        CFRelease(up);
    return ok;
}

static librdp_status cocoa_server_inject_unicode_units(
    const cocoa_server_context* context,
    const UniChar* units,
    UniCharCount count)
{
    CGKeyCode keycode = 0u;
    UInt32 modifiers = 0u;

    if (!cocoa_server_modifier_pressed(context) &&
        cocoa_server_layout_key_for_units(
            units, count, &keycode, &modifiers))
    {
        return cocoa_server_post_layout_key(
                   context, keycode, modifiers)
                   ? LIBRDP_STATUS_OK
                   : LIBRDP_STATUS_IO_ERROR;
    }
    return cocoa_server_post_unicode(units, count)
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_IO_ERROR;
}

static librdp_status cocoa_server_inject_unicode(
    cocoa_server_context* context,
    const librdp_server_input_event* event)
{
    UniChar units[2];
    UniCharCount count = 1u;
    uint16_t unit = event->param1;

    if ((event->flags & ~COCOA_RDP_KBD_RELEASE) != 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((event->flags & COCOA_RDP_KBD_RELEASE) != 0u)
        return LIBRDP_STATUS_OK;
    if (unit >= 0xd800u && unit <= 0xdbffu)
    {
        context->pending_high_surrogate = unit;
        return LIBRDP_STATUS_OK;
    }
    if (unit >= 0xdc00u && unit <= 0xdfffu)
    {
        if (context->pending_high_surrogate == 0u)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        units[0] = context->pending_high_surrogate;
        units[1] = unit;
        count = 2u;
        context->pending_high_surrogate = 0u;
        return cocoa_server_inject_unicode_units(
            context, units, count);
    }
    if (context->pending_high_surrogate != 0u)
    {
        context->pending_high_surrogate = 0u;
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (unit == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    units[0] = unit;
    return cocoa_server_inject_unicode_units(
        context, units, count);
}

static int cocoa_server_pointer_point(
    const cocoa_server_context* context,
    const librdp_server_input_event* event,
    CGPoint* point)
{
    double scale = context ? context->source_scale : 0.0;

    if (!context || !event || !point ||
        event->x >= context->width ||
        event->y >= context->height ||
        !isfinite(scale) || scale <= 0.0)
        return 0;
    point->x =
        context->source_rect.origin.x +
        (double)event->x / scale;
    point->y =
        context->source_rect.origin.y +
        (double)event->y / scale;
    return isfinite(point->x) && isfinite(point->y);
}

static int cocoa_server_post_mouse(CGEventType type,
                                   CGPoint point,
                                   CGMouseButton button)
{
    CGEventRef event =
        CGEventCreateMouseEvent(NULL, type, point, button);

    if (!event)
        return 0;
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
    return 1;
}

static int32_t cocoa_server_wheel_steps(uint16_t flags)
{
    int16_t delta = (int16_t)(flags & 0x01ffu);
    int32_t magnitude = 0;

    if ((delta & 0x0100) != 0)
        delta = (int16_t)(delta | (int16_t)~0x01ff);
    magnitude = delta < 0 ? -(int32_t)delta : (int32_t)delta;
    magnitude = magnitude == 0 ? 1 : (magnitude + 119) / 120;
    return delta < 0 ? -magnitude : magnitude;
}

static int cocoa_server_pointer_flags_valid(
    librdp_server_input_type type,
    uint16_t flags)
{
    const uint16_t wheel_flags =
        COCOA_RDP_POINTER_WHEEL | COCOA_RDP_POINTER_HWHEEL;
    const uint16_t button_flags =
        COCOA_RDP_POINTER_BUTTON1 |
        COCOA_RDP_POINTER_BUTTON2 |
        COCOA_RDP_POINTER_BUTTON3;

    if (type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE)
    {
        uint16_t buttons = flags & 0x0003u;

        return (flags & ~(COCOA_RDP_POINTER_DOWN | 0x0003u)) == 0u &&
               (buttons == 0x0001u || buttons == 0x0002u);
    }
    if (type != LIBRDP_SERVER_INPUT_MOUSE)
        return 0;
    if ((flags & wheel_flags) != 0u)
    {
        return (flags & wheel_flags) != wheel_flags &&
               (flags & (COCOA_RDP_POINTER_DOWN |
                         COCOA_RDP_POINTER_MOVE |
                         button_flags)) == 0u &&
               (flags & ~(wheel_flags | 0x01ffu)) == 0u;
    }
    if ((flags & 0x01ffu) != 0u ||
        (flags & ~(COCOA_RDP_POINTER_DOWN |
                   COCOA_RDP_POINTER_MOVE |
                   button_flags)) != 0u)
        return 0;
    if ((flags & button_flags) != 0u &&
        (flags & button_flags) != COCOA_RDP_POINTER_BUTTON1 &&
        (flags & button_flags) != COCOA_RDP_POINTER_BUTTON2 &&
        (flags & button_flags) != COCOA_RDP_POINTER_BUTTON3)
        return 0;
    return (flags & (COCOA_RDP_POINTER_MOVE | button_flags)) != 0u;
}

static librdp_status cocoa_server_inject_wheel(
    const librdp_server_input_event* event)
{
    CGEventRef scroll = NULL;
    int32_t steps = cocoa_server_wheel_steps(event->flags);

    if ((event->flags & COCOA_RDP_POINTER_HWHEEL) != 0u)
        scroll = CGEventCreateScrollWheelEvent(
            NULL, kCGScrollEventUnitLine, 2u, 0, steps);
    else
        scroll = CGEventCreateScrollWheelEvent(
            NULL, kCGScrollEventUnitLine, 1u, steps);
    if (!scroll)
        return LIBRDP_STATUS_IO_ERROR;
    CGEventPost(kCGHIDEventTap, scroll);
    CFRelease(scroll);
    return LIBRDP_STATUS_OK;
}

static CGEventType cocoa_server_drag_type(uint16_t buttons)
{
    if ((buttons & 0x0001u) != 0u)
        return kCGEventLeftMouseDragged;
    if ((buttons & 0x0002u) != 0u)
        return kCGEventRightMouseDragged;
    if (buttons != 0u)
        return kCGEventOtherMouseDragged;
    return kCGEventMouseMoved;
}

static librdp_status cocoa_server_inject_pointer(
    cocoa_server_context* context,
    const librdp_server_input_event* event)
{
    CGPoint point = CGPointZero;
    uint16_t flags = event->flags;
    uint16_t button_mask = 0u;
    CGMouseButton button = kCGMouseButtonLeft;
    CGEventType type = kCGEventNull;
    int pressed = (flags & COCOA_RDP_POINTER_DOWN) != 0u;

    if (!cocoa_server_pointer_flags_valid(event->type, flags) ||
        !cocoa_server_pointer_point(context, event, &point))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((flags & (COCOA_RDP_POINTER_WHEEL |
                  COCOA_RDP_POINTER_HWHEEL)) != 0u)
        return cocoa_server_inject_wheel(event);
    if ((flags & COCOA_RDP_POINTER_MOVE) != 0u &&
        !cocoa_server_post_mouse(
            cocoa_server_drag_type(context->pressed_buttons),
            point,
            kCGMouseButtonLeft))
        return LIBRDP_STATUS_IO_ERROR;
    if ((flags & COCOA_RDP_POINTER_BUTTON1) != 0u)
    {
        button = kCGMouseButtonLeft;
        button_mask = 0x0001u;
        type = pressed ? kCGEventLeftMouseDown
                       : kCGEventLeftMouseUp;
    }
    else if ((flags & COCOA_RDP_POINTER_BUTTON2) != 0u)
    {
        button = kCGMouseButtonRight;
        button_mask = 0x0002u;
        type = pressed ? kCGEventRightMouseDown
                       : kCGEventRightMouseUp;
    }
    else if ((flags & COCOA_RDP_POINTER_BUTTON3) != 0u)
    {
        button = kCGMouseButtonCenter;
        button_mask = 0x0004u;
        type = pressed ? kCGEventOtherMouseDown
                       : kCGEventOtherMouseUp;
    }
    else if (event->type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE &&
             (flags & 0x0003u) != 0u)
    {
        if ((flags & 0x0001u) != 0u)
        {
            button = (CGMouseButton)3u;
            button_mask = 0x0008u;
        }
        else
        {
            button = (CGMouseButton)4u;
            button_mask = 0x0010u;
        }
        type = pressed ? kCGEventOtherMouseDown
                       : kCGEventOtherMouseUp;
    }
    if (type == kCGEventNull)
        return LIBRDP_STATUS_OK;
    if (!cocoa_server_post_mouse(type, point, button))
        return LIBRDP_STATUS_IO_ERROR;
    if (pressed)
        context->pressed_buttons |= button_mask;
    else
        context->pressed_buttons &= (uint16_t)~button_mask;
    return LIBRDP_STATUS_OK;
}

static void cocoa_server_input_release_all(void* opaque)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;
    CGEventRef current = NULL;
    CGPoint point = CGPointZero;

    if (!context)
        return;
    if (context->pressed_buttons != 0u)
    {
        current = CGEventCreate(NULL);
        if (current)
        {
            point = CGEventGetLocation(current);
            CFRelease(current);
        }
    }
    for (CGKeyCode keycode = 0u;
         keycode < COCOA_SERVER_KEY_CAPACITY;
         keycode++)
    {
        if (context->pressed_keys[keycode])
        {
            (void)cocoa_server_post_key(keycode, 0);
            context->pressed_keys[keycode] = 0u;
        }
    }
    if ((context->pressed_buttons & 0x0001u) != 0u)
        (void)cocoa_server_post_mouse(
            kCGEventLeftMouseUp, point, kCGMouseButtonLeft);
    if ((context->pressed_buttons & 0x0002u) != 0u)
        (void)cocoa_server_post_mouse(
            kCGEventRightMouseUp, point, kCGMouseButtonRight);
    if ((context->pressed_buttons & 0x0004u) != 0u)
        (void)cocoa_server_post_mouse(
            kCGEventOtherMouseUp, point, kCGMouseButtonCenter);
    if ((context->pressed_buttons & 0x0008u) != 0u)
        (void)cocoa_server_post_mouse(
            kCGEventOtherMouseUp, point, (CGMouseButton)3u);
    if ((context->pressed_buttons & 0x0010u) != 0u)
        (void)cocoa_server_post_mouse(
            kCGEventOtherMouseUp, point, (CGMouseButton)4u);
    context->pressed_buttons = 0u;
    context->pending_high_surrogate = 0u;
}

static librdp_status cocoa_server_input_inject(
    void* opaque,
    const librdp_server_input_event* event)
{
    cocoa_server_context* context =
        (cocoa_server_context*)opaque;

    if (!context || !event ||
        event->version != LIBRDP_SERVER_INPUT_EVENT_VERSION ||
        event->size < sizeof(*event))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!cocoa_server_accessibility_permission(0))
    {
        cocoa_server_input_release_all(context);
        if (context->permission_sink.changed)
        {
            context->permission_sink.changed(
                SERVER_PLATFORM_PERMISSION_INPUT,
                SERVER_PLATFORM_PERMISSION_DENIED,
                context->permission_sink.user_data);
        }
        return LIBRDP_STATUS_STATE;
    }
    switch (event->type)
    {
        case LIBRDP_SERVER_INPUT_SYNCHRONIZE:
            return LIBRDP_STATUS_OK;
        case LIBRDP_SERVER_INPUT_SCANCODE_KEY:
            return cocoa_server_inject_scancode(context, event);
        case LIBRDP_SERVER_INPUT_UNICODE_KEY:
            return cocoa_server_inject_unicode(context, event);
        case LIBRDP_SERVER_INPUT_MOUSE:
        case LIBRDP_SERVER_INPUT_EXTENDED_MOUSE:
            return cocoa_server_inject_pointer(context, event);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

const server_platform_input_vtable cocoa_server_input_vtable = {
    SERVER_PLATFORM_INPUT_VERSION,
    sizeof(server_platform_input_vtable),
    cocoa_server_input_inject,
    cocoa_server_input_release_all,
};

#ifdef LIBRDP_COCOA_SERVER_TESTING
int cocoa_server_input_test_scancode(uint16_t scancode,
                                     uint16_t flags,
                                     uint16_t* keycode)
{
    CGKeyCode native = 0u;

    if (!keycode ||
        !cocoa_server_scancode_keycode(scancode, flags, &native))
        return 0;
    *keycode = native;
    return 1;
}

int32_t cocoa_server_input_test_wheel_steps(uint16_t flags)
{
    return cocoa_server_wheel_steps(flags);
}

int cocoa_server_input_test_pointer_flags(uint32_t type,
                                          uint16_t flags)
{
    return cocoa_server_pointer_flags_valid(
        (librdp_server_input_type)type, flags);
}
#endif

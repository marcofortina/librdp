/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared Cocoa physical-key translation.
 * Invariants: the table is one-to-one for each Carbon key position and maps
 * only RDP set-1 keys accepted by the public input API.
 * Ownership: the immutable table and all returned scalar values require no
 * allocation or retained platform object.
 * Threading: all state is immutable.
 * Trust boundary: unknown keys and unsupported prefix combinations fail
 * closed instead of producing guessed remote input.
 */

#include "cocoa_keymap.h"

#include <librdp/input.h>

#include <Carbon/Carbon.h>

#include <stddef.h>

typedef struct cocoa_key_mapping
{
    uint8_t scancode;
    uint8_t extended;
    uint16_t keycode;
} cocoa_key_mapping;

static const cocoa_key_mapping cocoa_key_mappings[] = {
    { 0x01u, 0u, kVK_Escape },
    { 0x02u, 0u, kVK_ANSI_1 },
    { 0x03u, 0u, kVK_ANSI_2 },
    { 0x04u, 0u, kVK_ANSI_3 },
    { 0x05u, 0u, kVK_ANSI_4 },
    { 0x06u, 0u, kVK_ANSI_5 },
    { 0x07u, 0u, kVK_ANSI_6 },
    { 0x08u, 0u, kVK_ANSI_7 },
    { 0x09u, 0u, kVK_ANSI_8 },
    { 0x0au, 0u, kVK_ANSI_9 },
    { 0x0bu, 0u, kVK_ANSI_0 },
    { 0x0cu, 0u, kVK_ANSI_Minus },
    { 0x0du, 0u, kVK_ANSI_Equal },
    { 0x0eu, 0u, kVK_Delete },
    { 0x0fu, 0u, kVK_Tab },
    { 0x10u, 0u, kVK_ANSI_Q },
    { 0x11u, 0u, kVK_ANSI_W },
    { 0x12u, 0u, kVK_ANSI_E },
    { 0x13u, 0u, kVK_ANSI_R },
    { 0x14u, 0u, kVK_ANSI_T },
    { 0x15u, 0u, kVK_ANSI_Y },
    { 0x16u, 0u, kVK_ANSI_U },
    { 0x17u, 0u, kVK_ANSI_I },
    { 0x18u, 0u, kVK_ANSI_O },
    { 0x19u, 0u, kVK_ANSI_P },
    { 0x1au, 0u, kVK_ANSI_LeftBracket },
    { 0x1bu, 0u, kVK_ANSI_RightBracket },
    { 0x1cu, 0u, kVK_Return },
    { 0x1du, 0u, kVK_Control },
    { 0x1eu, 0u, kVK_ANSI_A },
    { 0x1fu, 0u, kVK_ANSI_S },
    { 0x20u, 0u, kVK_ANSI_D },
    { 0x21u, 0u, kVK_ANSI_F },
    { 0x22u, 0u, kVK_ANSI_G },
    { 0x23u, 0u, kVK_ANSI_H },
    { 0x24u, 0u, kVK_ANSI_J },
    { 0x25u, 0u, kVK_ANSI_K },
    { 0x26u, 0u, kVK_ANSI_L },
    { 0x27u, 0u, kVK_ANSI_Semicolon },
    { 0x28u, 0u, kVK_ANSI_Quote },
    { 0x29u, 0u, kVK_ANSI_Grave },
    { 0x2au, 0u, kVK_Shift },
    { 0x2bu, 0u, kVK_ANSI_Backslash },
    { 0x2cu, 0u, kVK_ANSI_Z },
    { 0x2du, 0u, kVK_ANSI_X },
    { 0x2eu, 0u, kVK_ANSI_C },
    { 0x2fu, 0u, kVK_ANSI_V },
    { 0x30u, 0u, kVK_ANSI_B },
    { 0x31u, 0u, kVK_ANSI_N },
    { 0x32u, 0u, kVK_ANSI_M },
    { 0x33u, 0u, kVK_ANSI_Comma },
    { 0x34u, 0u, kVK_ANSI_Period },
    { 0x35u, 0u, kVK_ANSI_Slash },
    { 0x36u, 0u, kVK_RightShift },
    { 0x37u, 0u, kVK_ANSI_KeypadMultiply },
    { 0x38u, 0u, kVK_Option },
    { 0x39u, 0u, kVK_Space },
    { 0x3au, 0u, kVK_CapsLock },
    { 0x3bu, 0u, kVK_F1 },
    { 0x3cu, 0u, kVK_F2 },
    { 0x3du, 0u, kVK_F3 },
    { 0x3eu, 0u, kVK_F4 },
    { 0x3fu, 0u, kVK_F5 },
    { 0x40u, 0u, kVK_F6 },
    { 0x41u, 0u, kVK_F7 },
    { 0x42u, 0u, kVK_F8 },
    { 0x43u, 0u, kVK_F9 },
    { 0x44u, 0u, kVK_F10 },
    { 0x45u, 0u, kVK_ANSI_KeypadClear },
    { 0x47u, 0u, kVK_ANSI_Keypad7 },
    { 0x48u, 0u, kVK_ANSI_Keypad8 },
    { 0x49u, 0u, kVK_ANSI_Keypad9 },
    { 0x4au, 0u, kVK_ANSI_KeypadMinus },
    { 0x4bu, 0u, kVK_ANSI_Keypad4 },
    { 0x4cu, 0u, kVK_ANSI_Keypad5 },
    { 0x4du, 0u, kVK_ANSI_Keypad6 },
    { 0x4eu, 0u, kVK_ANSI_KeypadPlus },
    { 0x4fu, 0u, kVK_ANSI_Keypad1 },
    { 0x50u, 0u, kVK_ANSI_Keypad2 },
    { 0x51u, 0u, kVK_ANSI_Keypad3 },
    { 0x52u, 0u, kVK_ANSI_Keypad0 },
    { 0x53u, 0u, kVK_ANSI_KeypadDecimal },
    { 0x56u, 0u, kVK_ISO_Section },
    { 0x57u, 0u, kVK_F11 },
    { 0x58u, 0u, kVK_F12 },
    { 0x1cu, 1u, kVK_ANSI_KeypadEnter },
    { 0x1du, 1u, kVK_RightControl },
    { 0x35u, 1u, kVK_ANSI_KeypadDivide },
    { 0x37u, 1u, kVK_F13 },
    { 0x38u, 1u, kVK_RightOption },
    { 0x47u, 1u, kVK_Home },
    { 0x48u, 1u, kVK_UpArrow },
    { 0x49u, 1u, kVK_PageUp },
    { 0x4bu, 1u, kVK_LeftArrow },
    { 0x4du, 1u, kVK_RightArrow },
    { 0x4fu, 1u, kVK_End },
    { 0x50u, 1u, kVK_DownArrow },
    { 0x51u, 1u, kVK_PageDown },
    { 0x52u, 1u, kVK_Help },
    { 0x53u, 1u, kVK_ForwardDelete },
    { 0x5bu, 1u, kVK_Command },
    { 0x5cu, 1u, kVK_RightCommand },
};

/* Map a validated RDP physical key to its Carbon virtual-key position. */
int cocoa_keymap_rdp_to_native(uint32_t scancode,
                               uint32_t flags,
                               uint16_t* keycode)
{
    uint8_t extended = 0u;
    size_t index = 0u;

    if (!keycode || scancode == 0u || scancode > 0xffu ||
        (flags & ~(LIBRDP_KEY_FLAG_EXTENDED |
                   LIBRDP_KEY_FLAG_EXTENDED1)) != 0u ||
        (flags & LIBRDP_KEY_FLAG_EXTENDED1) != 0u)
        return 0;
    extended =
        (flags & LIBRDP_KEY_FLAG_EXTENDED) != 0u ? 1u : 0u;
    for (index = 0u;
         index < sizeof(cocoa_key_mappings) /
                     sizeof(cocoa_key_mappings[0]);
         index++)
    {
        if (cocoa_key_mappings[index].scancode ==
                (uint8_t)scancode &&
            cocoa_key_mappings[index].extended == extended)
        {
            *keycode = cocoa_key_mappings[index].keycode;
            return 1;
        }
    }
    return 0;
}

/* Map a Carbon virtual-key position to an RDP set-1 key and prefix. */
int cocoa_keymap_native_to_rdp(uint16_t keycode,
                               uint32_t* scancode,
                               uint32_t* flags)
{
    size_t index = 0u;

    if (!scancode || !flags)
        return 0;
    for (index = 0u;
         index < sizeof(cocoa_key_mappings) /
                     sizeof(cocoa_key_mappings[0]);
         index++)
    {
        if (cocoa_key_mappings[index].keycode == keycode)
        {
            *scancode = cocoa_key_mappings[index].scancode;
            *flags = cocoa_key_mappings[index].extended != 0u
                         ? LIBRDP_KEY_FLAG_EXTENDED
                         : 0u;
            return 1;
        }
    }
    return 0;
}

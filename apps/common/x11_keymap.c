/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bidirectional physical-key mapping between XKB names and RDP set-1.
 * Invariants: mappings describe hardware positions rather than characters, and
 * extended prefixes are part of key identity.
 * Ownership: the static table owns no runtime resources.
 * Threading: all functions are immutable lookups.
 * Trust boundary: unrecognized names, prefixes and codes are rejected.
 */

#include "x11_keymap.h"

#include <librdp/input.h>

#include <stddef.h>
#include <string.h>

typedef struct x11_keymap_entry
{
    const char* name;
    uint32_t scancode;
    uint32_t flags;
} x11_keymap_entry;

static const x11_keymap_entry x11_keymap_entries[] = {
    {"ESC", 0x01u, 0u},
    {"AE01", 0x02u, 0u},
    {"AE02", 0x03u, 0u},
    {"AE03", 0x04u, 0u},
    {"AE04", 0x05u, 0u},
    {"AE05", 0x06u, 0u},
    {"AE06", 0x07u, 0u},
    {"AE07", 0x08u, 0u},
    {"AE08", 0x09u, 0u},
    {"AE09", 0x0au, 0u},
    {"AE10", 0x0bu, 0u},
    {"AE11", 0x0cu, 0u},
    {"AE12", 0x0du, 0u},
    {"BKSP", 0x0eu, 0u},
    {"TAB", 0x0fu, 0u},
    {"AD01", 0x10u, 0u},
    {"AD02", 0x11u, 0u},
    {"AD03", 0x12u, 0u},
    {"AD04", 0x13u, 0u},
    {"AD05", 0x14u, 0u},
    {"AD06", 0x15u, 0u},
    {"AD07", 0x16u, 0u},
    {"AD08", 0x17u, 0u},
    {"AD09", 0x18u, 0u},
    {"AD10", 0x19u, 0u},
    {"AD11", 0x1au, 0u},
    {"AD12", 0x1bu, 0u},
    {"RTRN", 0x1cu, 0u},
    {"LCTL", 0x1du, 0u},
    {"AC01", 0x1eu, 0u},
    {"AC02", 0x1fu, 0u},
    {"AC03", 0x20u, 0u},
    {"AC04", 0x21u, 0u},
    {"AC05", 0x22u, 0u},
    {"AC06", 0x23u, 0u},
    {"AC07", 0x24u, 0u},
    {"AC08", 0x25u, 0u},
    {"AC09", 0x26u, 0u},
    {"AC10", 0x27u, 0u},
    {"AC11", 0x28u, 0u},
    {"TLDE", 0x29u, 0u},
    {"LFSH", 0x2au, 0u},
    {"BKSL", 0x2bu, 0u},
    {"AB01", 0x2cu, 0u},
    {"AB02", 0x2du, 0u},
    {"AB03", 0x2eu, 0u},
    {"AB04", 0x2fu, 0u},
    {"AB05", 0x30u, 0u},
    {"AB06", 0x31u, 0u},
    {"AB07", 0x32u, 0u},
    {"AB08", 0x33u, 0u},
    {"AB09", 0x34u, 0u},
    {"AB10", 0x35u, 0u},
    {"RTSH", 0x36u, 0u},
    {"KPMU", 0x37u, 0u},
    {"LALT", 0x38u, 0u},
    {"SPCE", 0x39u, 0u},
    {"CAPS", 0x3au, 0u},
    {"FK01", 0x3bu, 0u},
    {"FK02", 0x3cu, 0u},
    {"FK03", 0x3du, 0u},
    {"FK04", 0x3eu, 0u},
    {"FK05", 0x3fu, 0u},
    {"FK06", 0x40u, 0u},
    {"FK07", 0x41u, 0u},
    {"FK08", 0x42u, 0u},
    {"FK09", 0x43u, 0u},
    {"FK10", 0x44u, 0u},
    {"NMLK", 0x45u, 0u},
    {"SCLK", 0x46u, 0u},
    {"KP7", 0x47u, 0u},
    {"KP8", 0x48u, 0u},
    {"KP9", 0x49u, 0u},
    {"KPSU", 0x4au, 0u},
    {"KP4", 0x4bu, 0u},
    {"KP5", 0x4cu, 0u},
    {"KP6", 0x4du, 0u},
    {"KPAD", 0x4eu, 0u},
    {"KP1", 0x4fu, 0u},
    {"KP2", 0x50u, 0u},
    {"KP3", 0x51u, 0u},
    {"KP0", 0x52u, 0u},
    {"KPDL", 0x53u, 0u},
    {"LSGT", 0x56u, 0u},
    {"FK11", 0x57u, 0u},
    {"FK12", 0x58u, 0u},
    {"KPEN", 0x1cu, LIBRDP_KEY_FLAG_EXTENDED},
    {"RCTL", 0x1du, LIBRDP_KEY_FLAG_EXTENDED},
    {"KPDV", 0x35u, LIBRDP_KEY_FLAG_EXTENDED},
    {"PRSC", 0x37u, LIBRDP_KEY_FLAG_EXTENDED},
    {"RALT", 0x38u, LIBRDP_KEY_FLAG_EXTENDED},
    {"HOME", 0x47u, LIBRDP_KEY_FLAG_EXTENDED},
    {"UP", 0x48u, LIBRDP_KEY_FLAG_EXTENDED},
    {"PGUP", 0x49u, LIBRDP_KEY_FLAG_EXTENDED},
    {"LEFT", 0x4bu, LIBRDP_KEY_FLAG_EXTENDED},
    {"RGHT", 0x4du, LIBRDP_KEY_FLAG_EXTENDED},
    {"END", 0x4fu, LIBRDP_KEY_FLAG_EXTENDED},
    {"DOWN", 0x50u, LIBRDP_KEY_FLAG_EXTENDED},
    {"PGDN", 0x51u, LIBRDP_KEY_FLAG_EXTENDED},
    {"INS", 0x52u, LIBRDP_KEY_FLAG_EXTENDED},
    {"DELE", 0x53u, LIBRDP_KEY_FLAG_EXTENDED},
    {"LWIN", 0x5bu, LIBRDP_KEY_FLAG_EXTENDED},
    {"RWIN", 0x5cu, LIBRDP_KEY_FLAG_EXTENDED},
    {"MENU", 0x5du, LIBRDP_KEY_FLAG_EXTENDED},
    {"PAUS", 0x45u, LIBRDP_KEY_FLAG_EXTENDED1},
};

static int x11_keymap_name_equals(const char name[4], const char* text)
{
    size_t index = 0u;
    size_t length = text ? strlen(text) : 0u;

    if (!name || !text || length > 4u)
        return 0;
    for (index = 0u; index < length; index++)
    {
        if (name[index] != text[index])
            return 0;
    }
    for (; index < 4u; index++)
    {
        if (name[index] != ' ' && name[index] != '\0')
            return 0;
    }
    return 1;
}

int x11_keymap_xkb_name_to_rdp(const char name[4],
                               uint32_t* scancode,
                               uint32_t* flags)
{
    size_t index = 0u;

    if (!name || !scancode || !flags)
        return 0;
    for (index = 0u;
         index < sizeof(x11_keymap_entries) / sizeof(x11_keymap_entries[0]);
         index++)
    {
        if (x11_keymap_name_equals(name, x11_keymap_entries[index].name))
        {
            *scancode = x11_keymap_entries[index].scancode;
            *flags = x11_keymap_entries[index].flags;
            return 1;
        }
    }
    return 0;
}

int x11_keymap_rdp_to_xkb_name(uint32_t scancode,
                               uint32_t flags,
                               char name[4])
{
    const uint32_t identity_flags =
        flags & (LIBRDP_KEY_FLAG_EXTENDED | LIBRDP_KEY_FLAG_EXTENDED1);
    size_t index = 0u;

    if (!name)
        return 0;
    for (index = 0u;
         index < sizeof(x11_keymap_entries) / sizeof(x11_keymap_entries[0]);
         index++)
    {
        size_t length = 0u;

        if (x11_keymap_entries[index].scancode != scancode ||
            x11_keymap_entries[index].flags != identity_flags)
            continue;
        memset(name, 0, 4u);
        length = strlen(x11_keymap_entries[index].name);
        memcpy(name, x11_keymap_entries[index].name, length);
        return 1;
    }
    return 0;
}

/*
 * Translate an evdev key number reported by libxkbcommon into the RDP Set 1
 * scancode and extension flags. The output pair is committed only for entries
 * covered by the fixed protocol mapping; unknown host keys return false so the
 * caller can use its Unicode fallback without emitting a partial key event.
 */
int x11_keymap_evdev_to_rdp(unsigned int evdev,
                            uint32_t* scancode,
                            uint32_t* flags)
{
    if (!scancode || !flags)
        return 0;
    *flags = 0u;
    if (evdev >= 1u && evdev <= 83u)
    {
        *scancode = evdev;
        return 1;
    }
    switch (evdev)
    {
        case 86u:
            *scancode = 0x56u;
            return 1;
        case 87u:
            *scancode = 0x57u;
            return 1;
        case 88u:
            *scancode = 0x58u;
            return 1;
        case 96u:
            *scancode = 0x1cu;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 97u:
            *scancode = 0x1du;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 98u:
            *scancode = 0x35u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 99u:
            *scancode = 0x37u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 100u:
            *scancode = 0x38u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 102u:
            *scancode = 0x47u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 103u:
            *scancode = 0x48u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 104u:
            *scancode = 0x49u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 105u:
            *scancode = 0x4bu;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 106u:
            *scancode = 0x4du;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 107u:
            *scancode = 0x4fu;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 108u:
            *scancode = 0x50u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 109u:
            *scancode = 0x51u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 110u:
            *scancode = 0x52u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 111u:
            *scancode = 0x53u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 119u:
            *scancode = 0x45u;
            *flags = LIBRDP_KEY_FLAG_EXTENDED1;
            return 1;
        case 125u:
            *scancode = 0x5bu;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 126u:
            *scancode = 0x5cu;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        case 127u:
            *scancode = 0x5du;
            *flags = LIBRDP_KEY_FLAG_EXTENDED;
            return 1;
        default:
            return 0;
    }
}

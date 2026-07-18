/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared X11 physical-key mapping helpers.
 * Invariants: canonical XKB key names are the source of physical positions;
 * active keyboard layout and compose behavior remain owned by XKB.
 * Ownership: callers own all input and output storage.
 * Threading: pure lookup helpers are thread-safe.
 * Trust boundary: unknown or ambiguous key positions fail closed.
 */

#ifndef LIBRDP_X11_KEYMAP_H
#define LIBRDP_X11_KEYMAP_H

#include <stdint.h>

int x11_keymap_xkb_name_to_rdp(const char name[4],
                               uint32_t* scancode,
                               uint32_t* flags);
int x11_keymap_evdev_to_rdp(unsigned int evdev,
                            uint32_t* scancode,
                            uint32_t* flags);
int x11_keymap_rdp_to_xkb_name(uint32_t scancode,
                               uint32_t flags,
                               char name[4]);

#endif

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared Cocoa physical-key translation.
 * Invariants: mappings describe physical Carbon key positions and preserve the
 * RDP extended-key prefix independently of the active text input source.
 * Ownership: functions read and write caller-owned scalar storage only.
 * Threading: immutable tables make every function safe for concurrent calls.
 * Trust boundary: native key codes, scancodes, and flags are validated before
 * a mapping is returned.
 */

#ifndef LIBRDP_COCOA_KEYMAP_H
#define LIBRDP_COCOA_KEYMAP_H

#include <librdp/input.h>

#include <stdint.h>

int cocoa_keymap_rdp_to_native(uint32_t scancode,
                               uint32_t flags,
                               uint16_t* keycode);
int cocoa_keymap_native_to_rdp(uint16_t keycode,
                               uint32_t* scancode,
                               uint32_t* flags);

#endif

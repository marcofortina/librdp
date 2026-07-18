/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: private Cocoa server input contract.
 * Invariants: permission queries never prompt unless explicitly requested and
 * test helpers perform translation only without posting host input.
 * Ownership: no function retains caller storage.
 * Threading: production methods are confined to the server host thread.
 * Trust boundary: protocol flags and scancodes are validated before native
 * key codes or wheel steps are returned.
 */

#ifndef LIBRDP_COCOA_INPUT_H
#define LIBRDP_COCOA_INPUT_H

#include <stdint.h>

int cocoa_server_input_permission(int prompt);

#ifdef LIBRDP_COCOA_SERVER_TESTING
int cocoa_server_input_test_scancode(uint16_t scancode,
                                     uint16_t flags,
                                     uint16_t* keycode);
int32_t cocoa_server_input_test_wheel_steps(uint16_t flags);
int cocoa_server_input_test_pointer_flags(uint32_t type,
                                          uint16_t flags);
#endif

#endif

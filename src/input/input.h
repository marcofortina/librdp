/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: core input serialization declaration contract.
 * Invariants: declarations preserve explicit bounds, ownership, and error
 * propagation across module boundaries.
 * Ownership: input event pointers are borrowed for the duration of each send
 * helper.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: external inputs are untrusted until validated by the
 * declaring module or caller.
 */


#ifndef RDP_INPUT_INPUT_H
#define RDP_INPUT_INPUT_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/input.h>

librdp_status rdp_input_make_keyboard_flags(const librdp_key_event* event, uint16_t* flags);
librdp_status rdp_input_make_pointer_flags(const librdp_mouse_event* event, uint16_t* flags);
int rdp_input_mouse_uses_extended(const librdp_mouse_event* event);

#endif

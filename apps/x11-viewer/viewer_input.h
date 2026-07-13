/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer input bridge declarations.
 * Invariants: host input is translated into public librdp input APIs without
 * exposing private protocol internals.
 * Ownership: cursor resources stored in x11_app are owned by the viewer and
 * released through x11_input_clear_cursor().
 * Threading: all entry points run on the viewer event thread.
 * Trust boundary: X11 keyboard, pointer, and server pointer-shape events are
 * untrusted and validated before remote submission or cursor installation.
 */

#ifndef LIBRDP_X11_VIEWER_INPUT_H
#define LIBRDP_X11_VIEWER_INPUT_H

#include "viewer_app.h"

void x11_input_clear_cursor(x11_app* app);
void x11_input_apply_cursor(x11_app* app);
void x11_input_restore_cursor_after_local_mouse(x11_app* app);
void x11_input_handle_pointer_event(x11_app* app, const librdp_pointer_event* pointer);
void x11_input_allow_xwayland_keyboard_grab(x11_app* app);
void x11_input_maybe_grab_keyboard(x11_app* app, Time time);
void x11_input_ungrab_keyboard(x11_app* app, Time time, int force);
void x11_input_release_all_remote_keys(x11_app* app);
void x11_input_handle_key_press(x11_app* app, XKeyEvent* key);
void x11_input_handle_key_release(x11_app* app, XKeyEvent* key);
void x11_input_handle_button(x11_app* app, XButtonEvent* button, librdp_mouse_state state);
void x11_input_handle_motion(x11_app* app, XMotionEvent* motion);

#endif

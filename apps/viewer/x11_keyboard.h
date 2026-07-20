/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 keyboard bridge declarations.
 * Invariants: host keyboard events are translated through XKB key names,
 * X input-method text, and public librdp input calls without private protocol
 * access or viewer-local layout tables.
 * Ownership: pressed-key state belongs to x11_app and is cleared before focus
 * loss or shutdown releases the keyboard grab.
 * Threading: all entry points run on the viewer event thread.
 * Trust boundary: X11 key events and composed text are untrusted local input and
 * are bounded before being sent to the remote session.
 */

#ifndef LIBRDP_X11_VIEWER_KEYBOARD_H
#define LIBRDP_X11_VIEWER_KEYBOARD_H

#include "x11_app.h"

#include <stddef.h>
#include <stdint.h>

typedef void (*x11_keyboard_event_sink)(const librdp_key_event* event, void* user_data);

int x11_keyboard_map_xkb_name(const char name[4], uint32_t* scancode, uint32_t* flags);
int x11_keyboard_map_evdev(unsigned int evdev, uint32_t* scancode, uint32_t* flags);
int x11_keyboard_next_utf8_codepoint(const char** cursor, const char* end, uint32_t* codepoint);
size_t x11_keyboard_emit_utf8(const char* text,
                              size_t length,
                              x11_keyboard_event_sink sink,
                              void* user_data);
int x11_keyboard_should_send_unicode_fallback(unsigned int state, size_t text_len, int translated);
int x11_keyboard_auto_repeat_release_match(int detectable_auto_repeat,
                                           int has_next_event,
                                           int next_type,
                                           unsigned int next_keycode,
                                           Time next_time,
                                           unsigned int keycode,
                                           Time time);
int x11_keyboard_record_press(x11_pressed_key* pressed,
                              size_t capacity,
                              unsigned int* pressed_count,
                              unsigned int keycode,
                              const librdp_key_event* event);
int x11_keyboard_prepare_release(x11_pressed_key* pressed,
                                 size_t capacity,
                                 unsigned int* pressed_count,
                                 unsigned int keycode,
                                 librdp_key_event* event);
void x11_keyboard_allow_xwayland_grab(x11_app* app);
void x11_keyboard_maybe_grab(x11_app* app, Time time);
void x11_keyboard_ungrab(x11_app* app, Time time, int force);
void x11_keyboard_release_all_remote_keys(x11_app* app);
void x11_keyboard_handle_key_press(x11_app* app, XKeyEvent* key);
void x11_keyboard_handle_key_release(x11_app* app, XKeyEvent* key);

#endif

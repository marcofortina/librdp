/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal X11 viewer application context shared by viewer modules.
 * Invariants: fields are owned by the viewer event thread and are updated only
 * by modules that document the related X11 or host-backend lifecycle.
 * Ownership: pointers stored here are released during viewer shutdown by the
 * module that created or adopted them.
 * Threading: the context is not thread-safe; backend worker completions must
 * cross into the viewer event thread before mutating it.
 * Trust boundary: command-line options, local OS handles, X11 events, and RDP
 * server events remain distinct inputs even when stored in one context.
 */

#ifndef LIBRDP_X11_VIEWER_APP_H
#define LIBRDP_X11_VIEWER_APP_H

#include <librdp/librdp.h>

#include <X11/XKBlib.h>
#include <X11/Xlib.h>

#include <stdint.h>
#include <stdio.h>

typedef struct x11_camera_capture x11_camera_capture;
typedef struct x11_pipewire_audio x11_pipewire_audio;
typedef struct x11_render_state x11_render_state;

typedef struct x11_pressed_key
{
    int down;
    librdp_key_event event;
} x11_pressed_key;

#define X11_AUDIO_OUTPUT_FORMATS_MAX 32u
#define X11_CURSOR_DEFAULT 0
#define X11_CURSOR_HIDDEN 1
#define X11_CURSOR_SHAPE 2
#define X11_MAX_EVENTS_PER_TICK 128u
#define X11_MAX_NETWORK_PUMP 64u
#define X11_AUDIO_INPUT_BUFFER_BYTES 16384u

typedef struct x11_app
{
    Display* display;
    int screen;
    Window window;
    GC gc;
    Atom wm_delete;
    Atom xwayland_grab;
    XIM im;
    XIC ic;
    XkbDescPtr xkb;
    Cursor cursor;
    int cursor_mode;
    int hidden_cursor_locally_visible;
    int suppress_motion;
    librdp_session* session;
    int running;
    int dirty;
    uint64_t event_serial;
    uint32_t window_width;
    uint32_t window_height;
    int focused;
    int pointer_inside;
    int keyboard_grabbed;
    int pending_ungrab;
    int detectable_auto_repeat;
    int xfixes_event_base;
    int xfixes_error_base;
    int xfixes_available;
    int xrandr_event_base;
    int xrandr_error_base;
    int xrandr_available;
    Atom clipboard_selection;
    Atom clipboard_property;
    Atom atom_targets;
    Atom atom_utf8_string;
    Atom atom_text;
    Atom atom_incr;
    Atom atom_text_html;
    Atom atom_image_png;
    Atom atom_text_uri_list;
    uint8_t* clipboard_remote_utf8;
    size_t clipboard_remote_utf8_len;
    uint8_t* clipboard_remote_html;
    size_t clipboard_remote_html_len;
    uint8_t* clipboard_remote_png;
    size_t clipboard_remote_png_len;
    uint32_t clipboard_remote_html_format_id;
    uint32_t clipboard_remote_png_format_id;
    Atom clipboard_pending_target;
    int clipboard_owns_selection;
    int clipboard_request_pending;
    int clipboard_incr_active;
    Atom clipboard_incr_property;
    Atom clipboard_incr_target;
    uint8_t* clipboard_incr_data;
    size_t clipboard_incr_len;
    size_t clipboard_incr_capacity;
    uint64_t clipboard_incr_deadline_ms;
    int clipboard_out_incr_active;
    Window clipboard_out_requestor;
    Atom clipboard_out_property;
    Atom clipboard_out_target;
    const uint8_t* clipboard_out_data;
    size_t clipboard_out_data_len;
    size_t clipboard_out_offset;
    uint64_t clipboard_out_deadline_ms;
    char* clipboard_file_path;
    x11_pipewire_audio* audio;
    x11_camera_capture* camera;
    x11_render_state* render;
    char* audio_output_device;
    char* audio_input_device;
    char* camera_source;
    FILE* video_output_file;
    int audio_output_requested;
    int audio_input_requested;
    int telemetry_requested;
    int video_requested;
    int audio_input_active;
    uint32_t audio_output_format_count;
    uint32_t audio_output_current_format;
    librdp_audio_format audio_output_formats[X11_AUDIO_OUTPUT_FORMATS_MAX];
    int camera_requested;
    size_t audio_input_chunk;
    uint8_t audio_input_buffer[16384];
    unsigned int pressed_count;
    x11_pressed_key pressed[256];
} x11_app;

#endif

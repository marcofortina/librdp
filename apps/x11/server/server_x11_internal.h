/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: private X11 desktop-server state shared by provider modules.
 * Invariants: X resources belong to one display connection, dirty rectangles
 * remain clipped to capture geometry, and sinks are cleared before teardown.
 * Ownership: buffers, atoms, windows, pixmaps, damage objects and XKB metadata
 * are context-owned; callback sinks are copied values.
 * Threading: the complete structure is confined to the X11 host thread.
 * Trust boundary: every field derived from X replies is bounded before use in
 * allocation, pointer arithmetic or public callback payloads.
 */

#ifndef LIBRDP_X11_SERVER_X11_INTERNAL_H
#define LIBRDP_X11_SERVER_X11_INTERNAL_H

#include "server_clipboard_files.h"
#include "server_fuse.h"
#include "server_x11.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/Xdamage.h>
#include <X11/extensions/Xfixes.h>
#include <X11/extensions/Xrandr.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#define X11_SERVER_CLIPBOARD_MAX_FORMATS 8u
#define X11_SERVER_CLIPBOARD_TIMEOUT_NS 10000000000ull
typedef struct x11_server_shm_image
{
    XImage* image;
    XShmSegmentInfo segment;
    int attached;
} x11_server_shm_image;

typedef struct x11_server_clipboard_read
{
    uint64_t request_id;
    uint32_t format_id;
    Atom target;
    uint8_t* data;
    size_t length;
    size_t capacity;
    int active;
    int incremental;
    int discovering_formats;
    uint64_t deadline_ns;
} x11_server_clipboard_read;

typedef struct x11_server_clipboard_write
{
    XSelectionRequestEvent request;
    uint64_t request_id;
    uint32_t format_id;
    Atom target;
    uint8_t* data;
    size_t length;
    size_t offset;
    int active;
    int incremental;
    uint64_t deadline_ns;
} x11_server_clipboard_write;

struct x11_server_context
{
    Display* display;
    int screen;
    Window root;
    Window target;
    Window owner_window;
    Drawable capture_drawable;
    Pixmap composite_pixmap;
    Damage damage;
    XVisualInfo visual_info;
    x11_server_config config;
    char* display_name;
    char* drive_mount;
    x11_server_fuse* fuse;
    int capture_x;
    int capture_y;
    int desktop_x;
    int desktop_y;
    uint32_t width;
    uint32_t height;
    int depth;
    int damage_event_base;
    int damage_error_base;
    int fixes_event_base;
    int fixes_error_base;
    int randr_event_base;
    int randr_error_base;
    int composite_event_base;
    int composite_error_base;
    int connection_failed;
    int capture_started;
    int pointer_started;
    int input_started;
    int clipboard_started;
    int permission_started;
    int capture_due;
    int full_capture_due;
    int target_destroyed;
    int shm_available;
    uint64_t frame_sequence;
    uint64_t pointer_sequence;
    unsigned long cursor_serial;
    int32_t pointer_x;
    int32_t pointer_y;
    int pointer_visible;
    uint8_t* pointer_pixels;
    size_t pointer_capacity;
    size_t pointer_stride;
    uint32_t pointer_width;
    uint32_t pointer_height;
    uint32_t pointer_hotspot_x;
    uint32_t pointer_hotspot_y;
    XkbDescPtr keyboard;
    uint8_t pressed_keys[256];
    uint16_t pressed_buttons;
    uint16_t pending_high_surrogate;
    server_platform_rect dirty[X11_SERVER_MAX_DIRTY_RECTS];
    size_t dirty_count;
    uint8_t* frame_pixels;
    size_t frame_capacity;
    size_t frame_stride;
    x11_server_shm_image shm;
    server_platform_capture_sink capture_sink;
    server_platform_pointer_sink pointer_sink;
    server_platform_clipboard_sink clipboard_sink;
    server_platform_permission_sink permission_sink;
    server_platform_permission_state
        permissions[SERVER_PLATFORM_PERMISSION_DRIVE + 1u];
    Atom atom_clipboard;
    Atom atom_targets;
    Atom atom_incr;
    Atom atom_utf8;
    Atom atom_text;
    Atom atom_html;
    Atom atom_png;
    Atom atom_uri_list;
    Atom atom_property;
    Atom remote_targets[X11_SERVER_CLIPBOARD_MAX_FORMATS];
    uint32_t remote_format_ids[X11_SERVER_CLIPBOARD_MAX_FORMATS];
    size_t remote_format_count;
    uint64_t clipboard_local_generation;
    uint64_t clipboard_remote_generation;
    uint32_t clipboard_remote_peer_id;
    uint32_t clipboard_remote_peer_generation;
    uint64_t clipboard_next_request_id;
    x11_server_clipboard_read clipboard_read;
    x11_server_clipboard_write clipboard_write;
    server_clipboard_files* clipboard_files;
};

uint64_t x11_server_now_ns(void);
int x11_server_checked_multiply(size_t left, size_t right, size_t* result);
librdp_status x11_server_refresh_geometry(x11_server_context* context,
                                          int force);
void x11_server_invalidate(x11_server_context* context,
                           int x,
                           int y,
                           unsigned int width,
                           unsigned int height);
librdp_status x11_server_capture_frame(x11_server_context* context);
void x11_server_capture_handle_event(x11_server_context* context,
                                     const XEvent* event);
void x11_server_pointer_handle_event(x11_server_context* context,
                                     const XEvent* event);
void x11_server_clipboard_handle_event(x11_server_context* context,
                                       const XEvent* event);
void x11_server_clipboard_dispatch_timeout(x11_server_context* context,
                                           uint64_t now_ns);
int x11_server_clipboard_next_timeout_ms(const x11_server_context* context,
                                         uint64_t now_ns);
void x11_server_pointer_emit(x11_server_context* context, int include_shape);

extern const server_platform_capture_vtable x11_server_capture_vtable;
extern const server_platform_pointer_vtable x11_server_pointer_vtable;
extern const server_platform_input_vtable x11_server_input_vtable;
extern const server_platform_clipboard_vtable x11_server_clipboard_vtable;
extern const server_platform_permission_vtable x11_server_permission_vtable;

#endif

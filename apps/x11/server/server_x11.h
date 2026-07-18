/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 desktop-server platform facade.
 * Invariants: one context owns one X connection and capture source, all native
 * events are serialized through the shared host loop, and provider callbacks
 * receive only normalized data.
 * Ownership: the context owns X11 resources and borrowed configuration strings
 * are copied during construction; the returned platform vtables remain valid
 * until the context is freed.
 * Threading: all methods except host wakeup and cancellation run on the
 * creating thread.
 * Trust boundary: X server events, image metadata and selection payloads are
 * validated before crossing the common server-provider boundary.
 */

#ifndef LIBRDP_X11_SERVER_X11_H
#define LIBRDP_X11_SERVER_X11_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

#define X11_SERVER_CONFIG_VERSION 1u
#define X11_SERVER_MAX_DIRTY_RECTS 256u

typedef enum x11_server_source_kind
{
    X11_SERVER_SOURCE_ROOT = 1,
    X11_SERVER_SOURCE_MONITOR = 2,
    X11_SERVER_SOURCE_WINDOW = 3
} x11_server_source_kind;

typedef struct x11_server_config
{
    uint32_t version;
    size_t size;
    const char* display_name;
    x11_server_source_kind source_kind;
    uint32_t monitor_index;
    unsigned long window_id;
    size_t max_frame_bytes;
    const char* drive_mount;
    int allow_capture;
    int allow_input;
    int allow_clipboard;
    int allow_drive;
} x11_server_config;

typedef struct x11_server_context x11_server_context;

void x11_server_config_init(x11_server_config* config);
x11_server_context* x11_server_context_new(const x11_server_config* config);
void x11_server_context_free(x11_server_context* context);
librdp_status x11_server_context_platform(x11_server_context* context,
                                          server_platform* platform);
uint32_t x11_server_context_width(const x11_server_context* context);
uint32_t x11_server_context_height(const x11_server_context* context);
librdp_status x11_server_context_set_permission(
    x11_server_context* context,
    server_platform_permission_kind kind,
    server_platform_permission_state state);

#endif

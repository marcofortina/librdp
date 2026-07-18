/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native macOS desktop-server platform facade.
 * Invariants: one context captures one source from the active graphical
 * session and exposes only providers backed by public macOS facilities.
 * Ownership: the context owns all native resources and copied frame storage;
 * platform vtables remain borrowed until context destruction.
 * Threading: provider callbacks are delivered on the common host thread.
 * Trust boundary: ScreenCaptureKit metadata is validated and clipped before
 * crossing the shared server-provider boundary.
 */

#ifndef LIBRDP_COCOA_SERVER_H
#define LIBRDP_COCOA_SERVER_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

#define COCOA_SERVER_CONFIG_VERSION 1u
#define COCOA_SERVER_MAX_DIRTY_RECTS 256u

typedef enum cocoa_server_source_kind
{
    COCOA_SERVER_SOURCE_DISPLAY = 1,
    COCOA_SERVER_SOURCE_WINDOW = 2
} cocoa_server_source_kind;

typedef struct cocoa_server_config
{
    uint32_t version;
    size_t size;
    cocoa_server_source_kind source_kind;
    uint32_t source_id;
    uint32_t max_fps;
    size_t max_frame_bytes;
    int allow_capture;
} cocoa_server_config;

typedef struct cocoa_server_context cocoa_server_context;

void cocoa_server_config_init(cocoa_server_config* config);
cocoa_server_context* cocoa_server_context_new(
    const cocoa_server_config* config,
    librdp_status* output_status);
void cocoa_server_context_free(cocoa_server_context* context);
librdp_status cocoa_server_context_platform(cocoa_server_context* context,
                                             server_platform* platform);
uint32_t cocoa_server_context_width(const cocoa_server_context* context);
uint32_t cocoa_server_context_height(const cocoa_server_context* context);

#endif

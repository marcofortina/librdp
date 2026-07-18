/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded Cocoa desktop-server command-line policy.
 * Invariants: the native server exposes shadow mode only, secure transport is
 * the default, and each native capability requires an explicit consent flag.
 * Ownership: parsed strings borrow argv storage for process lifetime.
 * Threading: parsing is confined to process startup.
 * Trust boundary: all numeric and selector values are bounded before reaching
 * ScreenCaptureKit or the public server API.
 */

#ifndef LIBRDP_COCOA_SERVER_CLI_H
#define LIBRDP_COCOA_SERVER_CLI_H

#include "cocoa_server.h"

#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>

typedef struct cocoa_server_options
{
    const char* bind_address;
    const char* tls_certificate;
    const char* tls_private_key;
    const char* nla_username;
    const char* nla_domain;
    const char* password_environment;
    const char* drive_mount;
    cocoa_server_source_kind source_kind;
    uint32_t source_id;
    librdp_security_mode security_mode;
    uint16_t port;
    uint32_t max_peers;
    uint32_t max_fps;
    size_t max_frame_bytes;
    int allow_standard_security;
    int allow_capture;
    int allow_input;
    int allow_clipboard;
    int allow_drive;
    int show_help;
} cocoa_server_options;

void cocoa_server_options_init(cocoa_server_options* options);
void cocoa_server_usage(FILE* stream, const char* program);
int cocoa_server_parse_options(int argc,
                               char** argv,
                               cocoa_server_options* options);

#endif

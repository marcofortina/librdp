/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 desktop-server command-line policy.
 * Invariants: security-sensitive options are validated as a complete set,
 * Standard security and native providers require explicit opt-in, and managed
 * mode remains distinct from shadow capture.
 * Ownership: parsed strings remain borrowed from argv.
 * Threading: parsing is startup-only.
 * Trust boundary: untrusted numeric values and identifiers are bounded before
 * becoming listener or X11 configuration.
 */

#ifndef LIBRDP_X11_SERVER_CLI_H
#define LIBRDP_X11_SERVER_CLI_H

#include "x11_server.h"

#include <librdp/librdp.h>

#include <stdint.h>
#include <stdio.h>

typedef enum x11_server_session_mode
{
    X11_SERVER_SESSION_SHADOW = 1,
    X11_SERVER_SESSION_MANAGED = 2
} x11_server_session_mode;

typedef enum x11_server_managed_action
{
    X11_SERVER_MANAGED_START = 1,
    X11_SERVER_MANAGED_ATTACH = 2,
    X11_SERVER_MANAGED_QUERY = 3,
    X11_SERVER_MANAGED_RESIZE = 4,
    X11_SERVER_MANAGED_DETACH = 5,
    X11_SERVER_MANAGED_TERMINATE = 6
} x11_server_managed_action;

typedef struct x11_server_options
{
    const char* bind_address;
    const char* display_name;
    const char* broker_socket;
    const char* tls_certificate;
    const char* tls_private_key;
    const char* nla_username;
    const char* nla_domain;
    const char* nla_password;
    const char* password_environment;
    const char* reconnect_token_environment;
    const char* drive_mount;
    x11_server_session_mode session_mode;
    x11_server_managed_action managed_action;
    x11_server_source_kind source_kind;
    librdp_security_mode security_mode;
    uint64_t managed_session_id;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    uint32_t monitor_index;
    uint32_t max_fps;
    size_t max_frame_bytes;
    unsigned long window_id;
    uint32_t max_peers;
    int allow_standard_security;
    int allow_capture;
    int allow_input;
    int allow_clipboard;
    int allow_drive;
    int drive_read_only;
    int persistent_session;
    int reconnect_session;
} x11_server_options;

void x11_server_options_init(x11_server_options* options);
void x11_server_usage(FILE* stream, const char* program);
int x11_server_parse_options(int argc,
                             char** argv,
                             x11_server_options* options);

#endif

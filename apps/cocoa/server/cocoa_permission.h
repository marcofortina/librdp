/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa desktop-server consent and privacy policy.
 * Invariants: command-line requests do not imply macOS privacy authorization,
 * each provider is resolved independently, and non-interactive operation never
 * bypasses Screen Recording or Accessibility checks.
 * Ownership: policy strings and backend contexts are borrowed for one call.
 * Threading: resolution runs on the AppKit main thread before listener startup.
 * Trust boundary: native decisions are reduced to provider enablement flags;
 * no credential or clipboard content crosses this interface.
 */

#ifndef LIBRDP_COCOA_SERVER_PERMISSION_H
#define LIBRDP_COCOA_SERVER_PERMISSION_H

#include "server_platform.h"

typedef struct cocoa_server_permission_policy
{
    const char* drive_mount;
    int interactive;
    int request_capture;
    int request_input;
    int request_clipboard;
    int request_drive;
} cocoa_server_permission_policy;

typedef struct cocoa_server_permission_result
{
    int capture;
    int input;
    int clipboard;
    int drive;
} cocoa_server_permission_result;

typedef struct cocoa_server_permission_backend
{
    int (*screen_preflight)(void* context);
    int (*screen_request)(void* context);
    int (*accessibility_preflight)(void* context);
    int (*accessibility_request)(void* context);
    int (*confirm)(server_platform_permission_kind kind, const char* detail,
                   void* context);
    void (*show_denied)(server_platform_permission_kind kind, void* context);
    void* context;
} cocoa_server_permission_backend;

void cocoa_server_permission_policy_init(
    cocoa_server_permission_policy* policy);
int cocoa_server_accessibility_permission(int prompt);
librdp_status cocoa_server_permission_resolve(
    const cocoa_server_permission_policy* policy,
    cocoa_server_permission_result* result);

#ifdef LIBRDP_COCOA_SERVER_TESTING
librdp_status cocoa_server_permission_resolve_with_backend(
    const cocoa_server_permission_policy* policy,
    const cocoa_server_permission_backend* backend,
    cocoa_server_permission_result* result);
#endif

#endif

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: explicit X11 server permission provider.
 * Invariants: no provider starts unless its corresponding local consent flag
 * is granted, and runtime revocation is immediately reported to the host.
 * Ownership: permission state and the copied callback sink belong to the X11
 * context.
 * Threading: permission changes are serialized on the host thread.
 * Trust boundary: remote peers cannot grant local capture, input, clipboard or
 * drive permissions.
 */

#include "x11_server_internal.h"

#include <string.h>

static librdp_status x11_server_permission_start(
    void* opaque,
    const server_platform_permission_sink* sink)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !sink || !sink->changed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->permission_started)
        return LIBRDP_STATUS_STATE;
    context->permission_sink = *sink;
    context->permission_started = 1;
    return LIBRDP_STATUS_OK;
}

static void x11_server_permission_stop(void* opaque)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context)
        return;
    memset(&context->permission_sink, 0, sizeof(context->permission_sink));
    context->permission_started = 0;
}

static librdp_status x11_server_permission_query(
    void* opaque,
    server_platform_permission_kind kind,
    server_platform_permission_state* state)
{
    x11_server_context* context = (x11_server_context*)opaque;

    if (!context || !state ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *state = context->permissions[kind];
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_server_permission_request(
    void* opaque,
    server_platform_permission_kind kind)
{
    x11_server_context* context = (x11_server_context*)opaque;
    int configured = 0;

    if (!context ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (kind == SERVER_PLATFORM_PERMISSION_CAPTURE)
        configured = context->config.allow_capture;
    else if (kind == SERVER_PLATFORM_PERMISSION_INPUT)
        configured = context->config.allow_input;
    else if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD)
        configured = context->config.allow_clipboard;
    else if (kind == SERVER_PLATFORM_PERMISSION_DRIVE)
        configured = context->config.allow_drive;
    if (!configured)
        return LIBRDP_STATUS_UNSUPPORTED;
    return x11_server_context_set_permission(
        context,
        kind,
        SERVER_PLATFORM_PERMISSION_GRANTED);
}

static librdp_status x11_server_permission_revoke(
    void* opaque,
    server_platform_permission_kind kind)
{
    return x11_server_context_set_permission(
        (x11_server_context*)opaque,
        kind,
        SERVER_PLATFORM_PERMISSION_DENIED);
}

const server_platform_permission_vtable x11_server_permission_vtable = {
    SERVER_PLATFORM_PERMISSION_VERSION,
    sizeof(server_platform_permission_vtable),
    x11_server_permission_start,
    x11_server_permission_stop,
    x11_server_permission_query,
    x11_server_permission_request,
    x11_server_permission_revoke,
    NULL,
};

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa desktop-server lifecycle and shared-host dispatch.
 * Invariants: only shadow capture is started, transport security is explicit,
 * and shutdown releases protocol peers before native capture resources.
 * Ownership: this function owns the native context and host until exit.
 * Threading: one poll-driven owner thread; signals request host cancellation.
 * Trust boundary: password bytes remain in process environment storage and
 * are passed only to the public server configuration.
 */

#include "cocoa_server_runtime.h"

#include "cocoa_server.h"
#include "cocoa_permission.h"
#include "server_fuse.h"
#include "server_host.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static server_host* cocoa_server_signal_host = NULL;
static volatile sig_atomic_t cocoa_server_revoke_requested = 0;

static void cocoa_server_signal_handler(int signal_number)
{
    if (!cocoa_server_signal_host)
        return;
    if (signal_number == SIGUSR1)
    {
        cocoa_server_revoke_requested = 1;
        (void)server_host_wakeup(cocoa_server_signal_host);
    }
    else
        (void)server_host_cancel(cocoa_server_signal_host);
}

static int cocoa_server_install_signals(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = cocoa_server_signal_handler;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGUSR1, &action, NULL) == 0;
}

static librdp_status cocoa_server_apply_revocation(server_host* host)
{
    server_platform_permission_kind kind =
        SERVER_PLATFORM_PERMISSION_CAPTURE;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (kind = SERVER_PLATFORM_PERMISSION_CAPTURE;
         kind <= SERVER_PLATFORM_PERMISSION_DRIVE;
         kind = (server_platform_permission_kind)((int)kind + 1))
    {
        librdp_status status =
            server_host_revoke_permission(host, kind);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static void cocoa_server_trace(
    const server_host_trace_event* event,
    void* user_data)
{
    FILE* stream = (FILE*)user_data;

    if (!event || !stream)
        return;
    fprintf(stream,
            "librdp cocoa-server seq=%llu ts_ns=%llu event=%s "
            "peer=%u generation=%u status=%s value=%llu count=%llu\n",
            (unsigned long long)event->sequence,
            (unsigned long long)event->timestamp_ns,
            event->name ? event->name : "unknown",
            event->peer_id,
            event->generation,
            librdp_status_name(event->status),
            (unsigned long long)event->value,
            (unsigned long long)event->count);
}

static const char* cocoa_server_security_name(
    librdp_security_mode mode)
{
    if (mode == LIBRDP_SECURITY_NLA)
        return "nla";
    if (mode == LIBRDP_SECURITY_TLS)
        return "tls";
    return "standard";
}

/*
 * Construct optional providers before exposing the listener, then transfer
 * their borrowed vtables to one shared host. Every startup failure unwinds the
 * host, native capture and FUSE mount in reverse order; credentials remain
 * borrowed from their named environment entry and are never traced.
 */
int cocoa_server_run(const cocoa_server_options* options)
{
    cocoa_server_config native_config;
    cocoa_server_permission_policy permission_policy;
    cocoa_server_permission_result permissions;
    server_host_config host_config;
    cocoa_server_context* native = NULL;
    server_fuse* drive = NULL;
    server_host* host = NULL;
    const char* password = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 1;

    if (!options)
        return 2;
    cocoa_server_config_init(&native_config);
    cocoa_server_permission_policy_init(&permission_policy);
    permission_policy.drive_mount = options->drive_mount;
    permission_policy.interactive =
        options->non_interactive ? 0 : 1;
    permission_policy.request_input = options->allow_input;
    permission_policy.request_clipboard =
        options->allow_clipboard;
    permission_policy.request_drive = options->allow_drive;
    status = cocoa_server_permission_resolve(
        &permission_policy,
        &permissions);
    if (status != LIBRDP_STATUS_OK || !permissions.capture)
    {
        fprintf(stderr,
                "error=screen_recording_permission status=%s\n",
                librdp_status_name(
                    status == LIBRDP_STATUS_OK
                        ? LIBRDP_STATUS_STATE
                        : status));
        return 1;
    }
    if (options->allow_input && !permissions.input)
    {
        fprintf(stderr,
                "librdp cocoa-server provider=input state=disabled "
                "reason=permission-denied\n");
    }
    if (options->allow_clipboard && !permissions.clipboard)
    {
        fprintf(stderr,
                "librdp cocoa-server provider=clipboard state=disabled "
                "reason=consent-denied\n");
    }
    if (options->allow_drive && !permissions.drive)
    {
        fprintf(stderr,
                "librdp cocoa-server provider=drive state=disabled "
                "reason=consent-denied\n");
    }
    native_config.source_kind = options->source_kind;
    native_config.source_id = options->source_id;
    native_config.max_fps = options->max_fps;
    native_config.max_frame_bytes = options->max_frame_bytes;
    native_config.allow_capture = options->allow_capture;
    native_config.allow_input = permissions.input;
    native_config.allow_clipboard = permissions.clipboard;
    native_config.allow_drive = permissions.drive;
    if (permissions.drive)
    {
        server_fuse_config drive_config;

        if (!server_fuse_available())
        {
            fprintf(stderr,
                    "error=drive_provider status=unsupported\n");
            return 1;
        }
        server_fuse_config_init(&drive_config);
        drive_config.mount_path = options->drive_mount;
        drive = server_fuse_new(&drive_config);
        if (!drive)
        {
            fprintf(stderr,
                    "error=drive_provider status=invalid_argument\n");
            return 1;
        }
    }
    native = cocoa_server_context_new(&native_config, &status);
    if (!native)
    {
        fprintf(stderr,
                "error=native_context status=%s\n",
                librdp_status_name(status));
        server_fuse_free(drive);
        return 1;
    }
    server_host_config_init(&host_config);
    host_config.server.bind_address = options->bind_address;
    host_config.server.port = options->port;
    host_config.server.width =
        cocoa_server_context_width(native);
    host_config.server.height =
        cocoa_server_context_height(native);
    host_config.server.server_name = "librdp-server";
    host_config.server.security_mode = options->security_mode;
    host_config.server.tls_certificate_path =
        options->tls_certificate;
    host_config.server.tls_private_key_path =
        options->tls_private_key;
    host_config.server.nla_username = options->nla_username;
    host_config.server.nla_domain = options->nla_domain;
    if (options->security_mode == LIBRDP_SECURITY_NLA)
    {
        password = getenv(options->password_environment);
        if (!password || password[0] == '\0')
        {
            fprintf(stderr,
                    "error=credentials status=invalid_argument\n");
            cocoa_server_context_free(native);
            server_fuse_free(drive);
            return 1;
        }
        host_config.server.nla_password = password;
    }
    host_config.max_peers = options->max_peers;
    host_config.dirty.frame_interval_ns =
        1000000000ull / options->max_fps;
    host_config.input_policy =
        permissions.input
            ? SERVER_HOST_INPUT_FIRST_ACTIVE
            : SERVER_HOST_INPUT_DISABLED;
    host_config.trace_callback = cocoa_server_trace;
    host_config.trace_user_data = stderr;
    status = cocoa_server_context_platform(
        native,
        &host_config.platform);
    if (status == LIBRDP_STATUS_OK && drive)
    {
        host_config.platform.drive.vtable = server_fuse_vtable();
        host_config.platform.drive.context = drive;
        status = server_platform_validate(&host_config.platform);
    }
    host_config.drive.enabled = permissions.drive;
    host_config.drive.read_only = 1;
    if (status == LIBRDP_STATUS_OK)
        host = server_host_new(&host_config);
    if (status != LIBRDP_STATUS_OK || !host)
    {
        fprintf(stderr,
                "error=host_create status=%s\n",
                librdp_status_name(
                    status == LIBRDP_STATUS_OK
                        ? LIBRDP_STATUS_NO_MEMORY
                        : status));
        cocoa_server_context_free(native);
        server_fuse_free(drive);
        return 1;
    }
    cocoa_server_signal_host = host;
    cocoa_server_revoke_requested = 0;
    if (!cocoa_server_install_signals())
        status = LIBRDP_STATUS_IO_ERROR;
    else
        status = server_host_start(host);
    if (status == LIBRDP_STATUS_OK)
    {
        fprintf(stderr,
                "librdp cocoa-server state=listening port=%u "
                "mode=shadow security=%s width=%u height=%u\n",
                server_host_local_port(host),
                cocoa_server_security_name(options->security_mode),
                cocoa_server_context_width(native),
                cocoa_server_context_height(native));
        while (status == LIBRDP_STATUS_OK ||
               status == LIBRDP_STATUS_TIMEOUT ||
               status == LIBRDP_STATUS_AGAIN)
        {
            status = server_host_run_once(host, -1);
            if (cocoa_server_revoke_requested &&
                (status == LIBRDP_STATUS_OK ||
                 status == LIBRDP_STATUS_TIMEOUT ||
                 status == LIBRDP_STATUS_AGAIN))
            {
                cocoa_server_revoke_requested = 0;
                status = cocoa_server_apply_revocation(host);
            }
        }
        if (status == LIBRDP_STATUS_CANCELLED ||
            status == LIBRDP_STATUS_CLOSED)
            result = 0;
    }
    if (status != LIBRDP_STATUS_CANCELLED &&
        status != LIBRDP_STATUS_CLOSED &&
        status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr,
                "error=server_runtime status=%s\n",
                librdp_status_name(status));
    }
    (void)server_host_stop(host);
    cocoa_server_signal_host = NULL;
    cocoa_server_revoke_requested = 0;
    server_host_free(host);
    cocoa_server_context_free(native);
    server_fuse_free(drive);
    return result;
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 desktop-server process lifecycle.
 * Invariants: native providers start before the listener, secure transport is
 * the default, and shutdown releases peers before X11 resources.
 * Ownership: the runtime owns the X11 context and common host; option and
 * environment strings are borrowed only while configuration is copied.
 * Threading: one poll-driven owner thread; signal handlers request bounded
 * cancellation through the host wakeup descriptor.
 * Trust boundary: credentials are read from a named environment variable and
 * never printed; protocol bytes are handled exclusively by public APIs.
 */

#include "server_runtime.h"

#include "server_x11.h"

#include "server_host.h"
#include "server_options.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct x11_server_runtime
{
    x11_server_context* native;
    server_host* host;
    librdp_security_mode security_mode;
    volatile sig_atomic_t revoke_requested;
    int started;
};

static x11_server_runtime* x11_server_signal_runtime = NULL;

static void x11_server_signal_handler(int signal_number)
{
    x11_server_runtime* runtime = x11_server_signal_runtime;

    if (!runtime)
        return;
    if (signal_number == SIGUSR1)
    {
        runtime->revoke_requested = 1;
        (void)x11_server_runtime_wakeup(runtime);
    }
    else
        (void)x11_server_runtime_cancel(runtime);
}

static void x11_server_trace(const server_host_trace_event* event,
                             void* user_data)
{
    FILE* stream = (FILE*)user_data;

    if (!event || !stream)
        return;
    fprintf(stream,
            "librdp x11-server seq=%llu ts_ns=%llu event=%s "
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

static int x11_server_install_signals(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = x11_server_signal_handler;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGUSR1, &action, NULL) == 0;
}

static librdp_status x11_server_runtime_apply_revocation(
    x11_server_runtime* runtime)
{
    server_platform_permission_kind kind =
        SERVER_PLATFORM_PERMISSION_CAPTURE;

    if (!runtime || !runtime->host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (kind = SERVER_PLATFORM_PERMISSION_CAPTURE;
         kind <= SERVER_PLATFORM_PERMISSION_DRIVE;
         kind = (server_platform_permission_kind)((int)kind + 1))
    {
        librdp_status status =
            server_host_revoke_permission(runtime->host, kind);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

x11_server_runtime* x11_server_runtime_new(
    const x11_server_options* options,
    librdp_status* output_status)
{
    x11_server_config native_config;
    server_host_config host_config;
    x11_server_runtime* runtime = NULL;
    const char* password = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (output_status)
        *output_status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!options || !output_status ||
        options->max_fps == 0u ||
        options->max_fps > SERVER_OPTIONS_MAX_FPS)
        return NULL;
    runtime = (x11_server_runtime*)calloc(1u, sizeof(*runtime));
    if (!runtime)
    {
        *output_status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    x11_server_config_init(&native_config);
    native_config.display_name = options->display_name;
    native_config.source_kind = options->source_kind;
    native_config.monitor_index = options->monitor_index;
    native_config.window_id = options->window_id;
    native_config.allow_capture = options->allow_capture;
    native_config.allow_input = options->allow_input;
    native_config.allow_clipboard = options->allow_clipboard;
    native_config.allow_drive = options->allow_drive;
    native_config.drive_mount = options->drive_mount;
    native_config.max_frame_bytes = options->max_frame_bytes;
    runtime->native = x11_server_context_new(&native_config);
    if (!runtime->native)
    {
        *output_status = LIBRDP_STATUS_UNSUPPORTED;
        free(runtime);
        return NULL;
    }
    server_host_config_init(&host_config);
    host_config.server.bind_address = options->bind_address;
    host_config.server.port = options->port;
    host_config.server.width =
        x11_server_context_width(runtime->native);
    host_config.server.height =
        x11_server_context_height(runtime->native);
    host_config.server.server_name = "librdp-server";
    host_config.server.security_mode = options->security_mode;
    host_config.server.tls_certificate_path = options->tls_certificate;
    host_config.server.tls_private_key_path = options->tls_private_key;
    host_config.server.nla_username = options->nla_username;
    host_config.server.nla_domain = options->nla_domain;
    if (options->security_mode == LIBRDP_SECURITY_NLA)
    {
        password = options->nla_password
                       ? options->nla_password
                       : getenv(options->password_environment);
        if (!password || password[0] == '\0')
        {
            *output_status = LIBRDP_STATUS_INVALID_ARGUMENT;
            x11_server_context_free(runtime->native);
            free(runtime);
            return NULL;
        }
        host_config.server.nla_password = password;
    }
    host_config.max_peers = options->max_peers;
    host_config.dirty.frame_interval_ns =
        1000000000ull / options->max_fps;
    host_config.input_policy = options->allow_input
                                   ? SERVER_HOST_INPUT_FIRST_ACTIVE
                                   : SERVER_HOST_INPUT_DISABLED;
    host_config.drive.enabled = options->allow_drive;
    host_config.drive.read_only = options->drive_read_only;
    host_config.trace_callback = x11_server_trace;
    host_config.trace_user_data = stderr;
    status = x11_server_context_platform(runtime->native,
                                         &host_config.platform);
    if (status != LIBRDP_STATUS_OK)
    {
        *output_status = status;
        x11_server_context_free(runtime->native);
        free(runtime);
        return NULL;
    }
    runtime->host = server_host_new(&host_config);
    if (!runtime->host)
    {
        *output_status = LIBRDP_STATUS_NO_MEMORY;
        x11_server_context_free(runtime->native);
        free(runtime);
        return NULL;
    }
    runtime->security_mode = options->security_mode;
    *output_status = LIBRDP_STATUS_OK;
    return runtime;
}

void x11_server_runtime_free(x11_server_runtime* runtime)
{
    if (!runtime)
        return;
    (void)server_host_stop(runtime->host);
    server_host_free(runtime->host);
    x11_server_context_free(runtime->native);
    memset(runtime, 0, sizeof(*runtime));
    free(runtime);
}

librdp_status x11_server_runtime_start(x11_server_runtime* runtime)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !runtime->host || runtime->started)
        return LIBRDP_STATUS_STATE;
    status = server_host_start(runtime->host);
    if (status == LIBRDP_STATUS_OK)
        runtime->started = 1;
    return status;
}

librdp_status x11_server_runtime_run_once(x11_server_runtime* runtime,
                                          int timeout_ms)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !runtime->host || !runtime->started)
        return LIBRDP_STATUS_STATE;
    status = server_host_run_once(runtime->host, timeout_ms);
    if (runtime->revoke_requested &&
        (status == LIBRDP_STATUS_OK ||
         status == LIBRDP_STATUS_TIMEOUT ||
         status == LIBRDP_STATUS_AGAIN))
    {
        runtime->revoke_requested = 0;
        status = x11_server_runtime_apply_revocation(runtime);
    }
    return status;
}

librdp_status x11_server_runtime_wakeup(x11_server_runtime* runtime)
{
    if (!runtime || !runtime->host || !runtime->started)
        return LIBRDP_STATUS_STATE;
    return server_host_wakeup(runtime->host);
}

librdp_status x11_server_runtime_cancel(x11_server_runtime* runtime)
{
    if (!runtime || !runtime->host || !runtime->started)
        return LIBRDP_STATUS_STATE;
    return server_host_cancel(runtime->host);
}

uint16_t x11_server_runtime_local_port(
    const x11_server_runtime* runtime)
{
    return runtime && runtime->host
               ? server_host_local_port(runtime->host)
               : 0u;
}

uint32_t x11_server_runtime_width(
    const x11_server_runtime* runtime)
{
    return runtime && runtime->native
               ? x11_server_context_width(runtime->native)
               : 0u;
}

uint32_t x11_server_runtime_height(
    const x11_server_runtime* runtime)
{
    return runtime && runtime->native
               ? x11_server_context_height(runtime->native)
               : 0u;
}

int x11_server_run_shadow(const x11_server_options* options)
{
    x11_server_runtime* runtime = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 1;

    runtime = x11_server_runtime_new(options, &status);
    if (!runtime)
    {
        fprintf(stderr,
                "error=runtime_create status=%s\n",
                librdp_status_name(status));
        return 1;
    }
    x11_server_signal_runtime = runtime;
    if (!x11_server_install_signals())
    {
        fprintf(stderr, "error=signals status=io_error\n");
        goto cleanup;
    }
    status = x11_server_runtime_start(runtime);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr,
                "error=listen status=%s\n",
                librdp_status_name(status));
        goto cleanup;
    }
    fprintf(stderr,
            "librdp x11-server state=listening port=%u mode=shadow "
            "security=%s width=%u height=%u\n",
            x11_server_runtime_local_port(runtime),
            runtime->security_mode == LIBRDP_SECURITY_NLA
                ? "nla"
                : runtime->security_mode == LIBRDP_SECURITY_TLS
                      ? "tls"
                      : "standard",
            x11_server_runtime_width(runtime),
            x11_server_runtime_height(runtime));
    do
    {
        status = x11_server_runtime_run_once(runtime, -1);
    } while (status == LIBRDP_STATUS_OK ||
             status == LIBRDP_STATUS_TIMEOUT ||
             status == LIBRDP_STATUS_AGAIN);
    if (status == LIBRDP_STATUS_CANCELLED)
        result = 0;
    else
    {
        fprintf(stderr,
                "error=dispatch status=%s\n",
                librdp_status_name(status));
    }

cleanup:
    x11_server_signal_runtime = NULL;
    x11_server_runtime_free(runtime);
    return result;
}

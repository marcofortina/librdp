/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 desktop-server process lifecycle.
 * Invariants: native providers start before the listener, secure transport is
 * the default, and shutdown releases peers before X11 resources.
 * Ownership: main owns the X11 context and common host for process lifetime;
 * argv and environment strings are borrowed only while configuration is copied.
 * Threading: one poll-driven owner thread; signal handlers request bounded
 * cancellation through the host wakeup descriptor.
 * Trust boundary: credentials are read from a named environment variable and
 * never printed; protocol bytes are handled exclusively by public librdp APIs.
 */

#include "server_cli.h"
#include "server_x11.h"

#include "server_host.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static server_host* x11_server_signal_host = NULL;

static void x11_server_signal_handler(int signal_number)
{
    (void)signal_number;
    if (x11_server_signal_host)
        (void)server_host_cancel(x11_server_signal_host);
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
           sigaction(SIGTERM, &action, NULL) == 0;
}

static int x11_server_run_shadow(const x11_server_options* options)
{
    x11_server_config native_config;
    x11_server_context* native = NULL;
    server_host_config host_config;
    server_host* host = NULL;
    const char* password = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 1;

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
    native = x11_server_context_new(&native_config);
    if (!native)
    {
        fprintf(stderr, "error=x11_context status=unsupported\n");
        return 1;
    }
    server_host_config_init(&host_config);
    host_config.server.bind_address = options->bind_address;
    host_config.server.port = options->port;
    host_config.server.width = x11_server_context_width(native);
    host_config.server.height = x11_server_context_height(native);
    host_config.server.server_name = "librdp-x11-server";
    host_config.server.security_mode = options->security_mode;
    host_config.server.tls_certificate_path = options->tls_certificate;
    host_config.server.tls_private_key_path = options->tls_private_key;
    host_config.server.nla_username = options->nla_username;
    host_config.server.nla_domain = options->nla_domain;
    if (options->security_mode == LIBRDP_SECURITY_NLA)
    {
        password = getenv(options->password_environment);
        if (!password || password[0] == '\0')
        {
            fprintf(stderr,
                    "error=credentials status=missing_environment\n");
            x11_server_context_free(native);
            return 1;
        }
        host_config.server.nla_password = password;
    }
    host_config.max_peers = options->max_peers;
    host_config.input_policy = options->allow_input
                                   ? SERVER_HOST_INPUT_FIRST_ACTIVE
                                   : SERVER_HOST_INPUT_DISABLED;
    host_config.drive.enabled = options->allow_drive;
    host_config.drive.read_only = options->drive_read_only;
    host_config.trace_callback = x11_server_trace;
    host_config.trace_user_data = stderr;
    status = x11_server_context_platform(native, &host_config.platform);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr,
                "error=platform status=%s\n",
                librdp_status_name(status));
        x11_server_context_free(native);
        return 1;
    }
    host = server_host_new(&host_config);
    if (!host)
    {
        fprintf(stderr, "error=host_create status=no_memory\n");
        x11_server_context_free(native);
        return 1;
    }
    x11_server_signal_host = host;
    if (!x11_server_install_signals())
    {
        fprintf(stderr, "error=signals status=io_error\n");
        goto cleanup;
    }
    status = server_host_start(host);
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
            server_host_local_port(host),
            options->security_mode == LIBRDP_SECURITY_NLA
                ? "nla"
                : options->security_mode == LIBRDP_SECURITY_TLS
                      ? "tls"
                      : "standard",
            x11_server_context_width(native),
            x11_server_context_height(native));
    do
    {
        status = server_host_run_once(host, -1);
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
    x11_server_signal_host = NULL;
    (void)server_host_stop(host);
    server_host_free(host);
    x11_server_context_free(native);
    return result;
}

int main(int argc, char** argv)
{
    x11_server_options options;
    int parsed = x11_server_parse_options(argc, argv, &options);

    if (parsed == 2)
        return 0;
    if (parsed != 1)
    {
        x11_server_usage(stderr, argv[0]);
        return 2;
    }
    if (options.session_mode == X11_SERVER_SESSION_MANAGED)
    {
        fprintf(stderr,
                "error=managed_session status=unsupported\n");
        return 1;
    }
    return x11_server_run_shadow(&options);
}

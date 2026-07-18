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
#include "server_host.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static server_host* cocoa_server_signal_host = NULL;

static void cocoa_server_signal_handler(int signal_number)
{
    (void)signal_number;
    if (cocoa_server_signal_host)
        (void)server_host_cancel(cocoa_server_signal_host);
}

static int cocoa_server_install_signals(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = cocoa_server_signal_handler;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0;
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

int cocoa_server_run(const cocoa_server_options* options)
{
    cocoa_server_config native_config;
    server_host_config host_config;
    cocoa_server_context* native = NULL;
    server_host* host = NULL;
    const char* password = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    int result = 1;

    if (!options)
        return 2;
    cocoa_server_config_init(&native_config);
    native_config.source_kind = options->source_kind;
    native_config.source_id = options->source_id;
    native_config.max_fps = options->max_fps;
    native_config.max_frame_bytes = options->max_frame_bytes;
    native_config.allow_capture = options->allow_capture;
    native = cocoa_server_context_new(&native_config, &status);
    if (!native)
    {
        fprintf(stderr,
                "error=native_context status=%s\n",
                librdp_status_name(status));
        return 1;
    }
    server_host_config_init(&host_config);
    host_config.server.bind_address = options->bind_address;
    host_config.server.port = options->port;
    host_config.server.width =
        cocoa_server_context_width(native);
    host_config.server.height =
        cocoa_server_context_height(native);
    host_config.server.server_name = "librdp-cocoa-server";
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
            return 1;
        }
        host_config.server.nla_password = password;
    }
    host_config.max_peers = options->max_peers;
    host_config.input_policy = SERVER_HOST_INPUT_DISABLED;
    host_config.trace_callback = cocoa_server_trace;
    host_config.trace_user_data = stderr;
    status = cocoa_server_context_platform(
        native,
        &host_config.platform);
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
        return 1;
    }
    cocoa_server_signal_host = host;
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
               status == LIBRDP_STATUS_AGAIN)
            status = server_host_run_once(host, -1);
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
    server_host_free(host);
    cocoa_server_context_free(native);
    return result;
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded X11 desktop-server CLI parser.
 * Invariants: no listener starts from partial TLS/NLA configuration and every
 * local capability is denied unless its consent flag is present.
 * Ownership: options borrow argv storage for process lifetime.
 * Threading: single-threaded startup code.
 * Trust boundary: command-line input is rejected on unknown flags, overflow,
 * contradictory source selection or unsafe implicit downgrade.
 */

#include "server_cli.h"

#include "server_host.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

void x11_server_options_init(x11_server_options* options)
{
    if (!options)
        return;
    memset(options, 0, sizeof(*options));
    options->bind_address = "127.0.0.1";
    options->password_environment = "LIBRDP_SERVER_PASSWORD";
    options->session_mode = X11_SERVER_SESSION_SHADOW;
    options->source_kind = X11_SERVER_SOURCE_ROOT;
    options->security_mode = LIBRDP_SECURITY_TLS;
    options->max_peers = 4u;
    options->drive_read_only = 1;
}

void x11_server_usage(FILE* stream, const char* program)
{
    if (!stream || !program)
        return;
    fprintf(
        stream,
        "usage: %s --tls-cert path --tls-key path --allow-capture "
        "[--mode shadow|managed] [--display name] "
        "[--source root|monitor:index|window:id] [--bind address] "
        "[--port port] [--max-peers count] [--security tls|nla|standard] "
        "[--allow-standard-security] [--user name] [--domain name] "
        "[--password-env name] [--allow-input] [--allow-clipboard] "
        "[--allow-drive --drive-mount path [--drive-read-only]]\n",
        program);
}

static int x11_server_take_value(int argc, char** argv, int* index)
{
    if (!argv || !index || *index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static int x11_server_parse_ulong(const char* value,
                                  unsigned long maximum,
                                  unsigned long* output)
{
    char* end = NULL;
    unsigned long parsed = 0ul;

    if (!value || !output || value[0] == '\0' || value[0] == '-')
        return 0;
    errno = 0;
    parsed = strtoul(value, &end, 0);
    if (errno != 0 || !end || *end != '\0' || parsed > maximum)
        return 0;
    *output = parsed;
    return 1;
}

static int x11_server_parse_source(const char* value,
                                   x11_server_options* options)
{
    unsigned long parsed = 0ul;

    if (!value || !options)
        return 0;
    if (strcmp(value, "root") == 0)
    {
        options->source_kind = X11_SERVER_SOURCE_ROOT;
        return 1;
    }
    if (strncmp(value, "monitor:", 8u) == 0 &&
        x11_server_parse_ulong(value + 8u, UINT32_MAX, &parsed))
    {
        options->source_kind = X11_SERVER_SOURCE_MONITOR;
        options->monitor_index = (uint32_t)parsed;
        return 1;
    }
    if (strncmp(value, "window:", 7u) == 0 &&
        x11_server_parse_ulong(value + 7u, ULONG_MAX, &parsed) &&
        parsed != 0ul)
    {
        options->source_kind = X11_SERVER_SOURCE_WINDOW;
        options->window_id = parsed;
        return 1;
    }
    return 0;
}

static int x11_server_parse_security(const char* value,
                                     x11_server_options* options)
{
    if (!value || !options)
        return 0;
    if (strcmp(value, "tls") == 0)
        options->security_mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(value, "nla") == 0)
        options->security_mode = LIBRDP_SECURITY_NLA;
    else if (strcmp(value, "standard") == 0)
        options->security_mode = LIBRDP_SECURITY_STANDARD;
    else
        return 0;
    return 1;
}

static int x11_server_parse_mode(const char* value,
                                 x11_server_options* options)
{
    if (!value || !options)
        return 0;
    if (strcmp(value, "shadow") == 0)
        options->session_mode = X11_SERVER_SESSION_SHADOW;
    else if (strcmp(value, "managed") == 0)
        options->session_mode = X11_SERVER_SESSION_MANAGED;
    else
        return 0;
    return 1;
}

static int x11_server_validate_options(const x11_server_options* options)
{
    if (!options || !options->allow_capture)
    {
        fprintf(stderr, "--allow-capture is required\n");
        return 0;
    }
    if (options->security_mode == LIBRDP_SECURITY_STANDARD &&
        !options->allow_standard_security)
    {
        fprintf(stderr,
                "Standard RDP security requires --allow-standard-security\n");
        return 0;
    }
    if ((options->security_mode == LIBRDP_SECURITY_TLS ||
         options->security_mode == LIBRDP_SECURITY_NLA) &&
        (!options->tls_certificate || !options->tls_private_key))
    {
        fprintf(stderr, "--tls-cert and --tls-key are required\n");
        return 0;
    }
    if (options->security_mode == LIBRDP_SECURITY_NLA &&
        (!options->nla_username || !options->password_environment))
    {
        fprintf(stderr,
                "NLA requires --user and a password environment name\n");
        return 0;
    }
    if (options->allow_drive && !options->drive_mount)
    {
        fprintf(stderr, "--allow-drive requires --drive-mount\n");
        return 0;
    }
    return 1;
}

int x11_server_parse_options(int argc,
                             char** argv,
                             x11_server_options* options)
{
    int index = 0;

    if (!argv || !options)
        return 0;
    x11_server_options_init(options);
    for (index = 1; index < argc; index++)
    {
        const char* option = argv[index];

        if (strcmp(option, "--help") == 0 ||
            strcmp(option, "-h") == 0)
        {
            x11_server_usage(stdout, argv[0]);
            return 2;
        }
        if (strcmp(option, "--mode") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index) ||
                !x11_server_parse_mode(argv[index], options))
                return 0;
        }
        else if (strcmp(option, "--display") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->display_name = argv[index];
        }
        else if (strcmp(option, "--source") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index) ||
                !x11_server_parse_source(argv[index], options))
                return 0;
        }
        else if (strcmp(option, "--bind") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->bind_address = argv[index];
        }
        else if (strcmp(option, "--port") == 0)
        {
            unsigned long value = 0ul;

            if (!x11_server_take_value(argc, argv, &index) ||
                !x11_server_parse_ulong(argv[index], UINT16_MAX, &value))
                return 0;
            options->port = (uint16_t)value;
        }
        else if (strcmp(option, "--max-peers") == 0)
        {
            unsigned long value = 0ul;

            if (!x11_server_take_value(argc, argv, &index) ||
                !x11_server_parse_ulong(argv[index],
                                        SERVER_HOST_MAX_PEERS,
                                        &value) ||
                value == 0ul)
                return 0;
            options->max_peers = (uint32_t)value;
        }
        else if (strcmp(option, "--security") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index) ||
                !x11_server_parse_security(argv[index], options))
                return 0;
        }
        else if (strcmp(option, "--tls-cert") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->tls_certificate = argv[index];
        }
        else if (strcmp(option, "--tls-key") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->tls_private_key = argv[index];
        }
        else if (strcmp(option, "--user") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->nla_username = argv[index];
        }
        else if (strcmp(option, "--domain") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->nla_domain = argv[index];
        }
        else if (strcmp(option, "--password-env") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index) ||
                argv[index][0] == '\0')
                return 0;
            options->password_environment = argv[index];
        }
        else if (strcmp(option, "--drive-mount") == 0)
        {
            if (!x11_server_take_value(argc, argv, &index))
                return 0;
            options->drive_mount = argv[index];
        }
        else if (strcmp(option, "--allow-standard-security") == 0)
            options->allow_standard_security = 1;
        else if (strcmp(option, "--allow-capture") == 0)
            options->allow_capture = 1;
        else if (strcmp(option, "--allow-input") == 0)
            options->allow_input = 1;
        else if (strcmp(option, "--allow-clipboard") == 0)
            options->allow_clipboard = 1;
        else if (strcmp(option, "--allow-drive") == 0)
            options->allow_drive = 1;
        else if (strcmp(option, "--drive-read-only") == 0)
            options->drive_read_only = 1;
        else
        {
            fprintf(stderr, "unknown option: %s\n", option);
            return 0;
        }
    }
    return x11_server_validate_options(options) ? 1 : 0;
}

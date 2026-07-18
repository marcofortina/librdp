/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa desktop-server CLI parser.
 * Invariants: unsupported managed sessions and unimplemented providers fail
 * before native initialization, while TLS and NLA options are validated as
 * complete sets.
 * Ownership: successful parsing retains no storage and borrows argv strings.
 * Threading: parsing is single-threaded.
 * Trust boundary: unknown flags, overflow, unsafe security downgrade and
 * malformed capture identifiers are rejected.
 */

#include "cocoa_server_cli.h"

#include "server_host.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define COCOA_SERVER_MAX_FRAME_BYTES (512u * 1024u * 1024u)

void cocoa_server_options_init(cocoa_server_options* options)
{
    if (!options)
        return;
    memset(options, 0, sizeof(*options));
    options->bind_address = "127.0.0.1";
    options->password_environment = "LIBRDP_SERVER_PASSWORD";
    options->source_kind = COCOA_SERVER_SOURCE_DISPLAY;
    options->security_mode = LIBRDP_SECURITY_TLS;
    options->max_peers = 4u;
    options->max_fps = 30u;
    options->max_frame_bytes = 256u * 1024u * 1024u;
}

void cocoa_server_usage(FILE* stream, const char* program)
{
    if (!stream || !program)
        return;
    fprintf(
        stream,
        "usage: %s --tls-cert path --tls-key path --allow-capture "
        "[--mode shadow] [--source display:index|window:id] "
        "[--bind address] [--port port] [--max-peers count] "
        "[--max-fps count] [--max-frame-bytes bytes] "
        "[--security tls|nla|standard] [--allow-standard-security] "
        "[--user name] [--domain name] [--password-env name] "
        "[--allow-input]\n",
        program);
}

static int cocoa_server_take_value(int argc, char** argv, int* index)
{
    if (!argv || !index || *index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static int cocoa_server_parse_ulong(const char* text,
                                    unsigned long maximum,
                                    unsigned long* value)
{
    char* end = NULL;
    unsigned long parsed = 0ul;

    if (!text || !value || text[0] == '\0' || text[0] == '-')
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > maximum)
        return 0;
    *value = parsed;
    return 1;
}

static int cocoa_server_parse_source(const char* value,
                                     cocoa_server_options* options)
{
    unsigned long identifier = 0ul;

    if (!value || !options)
        return 0;
    if (strncmp(value, "display:", 8u) == 0 &&
        cocoa_server_parse_ulong(value + 8u, UINT32_MAX, &identifier))
    {
        options->source_kind = COCOA_SERVER_SOURCE_DISPLAY;
        options->source_id = (uint32_t)identifier;
        return 1;
    }
    if (strncmp(value, "window:", 7u) == 0 &&
        cocoa_server_parse_ulong(value + 7u, UINT32_MAX, &identifier) &&
        identifier != 0ul)
    {
        options->source_kind = COCOA_SERVER_SOURCE_WINDOW;
        options->source_id = (uint32_t)identifier;
        return 1;
    }
    return 0;
}

static int cocoa_server_parse_security(const char* value,
                                       cocoa_server_options* options)
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

static int cocoa_server_validate_options(const cocoa_server_options* options)
{
    if (!options || !options->allow_capture)
    {
        fprintf(stderr, "--allow-capture is required\n");
        return 0;
    }
    if (options->allow_clipboard || options->allow_drive)
    {
        fprintf(stderr,
                "clipboard and drive providers are not enabled "
                "in this build\n");
        return 0;
    }
    if (options->security_mode == LIBRDP_SECURITY_STANDARD &&
        !options->allow_standard_security)
    {
        fprintf(stderr,
                "Standard RDP security requires "
                "--allow-standard-security\n");
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
    return 1;
}

/*
 * Parse each option exactly once and validate the resulting policy as one
 * transaction. Value-taking flags never consume a missing operand, numeric
 * conversions reject sign and overflow, and no partially valid configuration
 * escapes when a later argument fails.
 */
int cocoa_server_parse_options(int argc,
                               char** argv,
                               cocoa_server_options* options)
{
    int index = 0;

    if (!argv || !options)
        return 0;
    cocoa_server_options_init(options);
    for (index = 1; index < argc; index++)
    {
        const char* option = argv[index];
        unsigned long numeric = 0ul;

        if (strcmp(option, "--help") == 0 ||
            strcmp(option, "-h") == 0)
        {
            options->show_help = 1;
            return 2;
        }
        if (strcmp(option, "--mode") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index))
                return 0;
            if (strcmp(argv[index], "managed") == 0)
            {
                fprintf(stderr,
                        "managed sessions are unavailable on macOS; "
                        "use --mode shadow\n");
                return 0;
            }
            if (strcmp(argv[index], "shadow") != 0)
                return 0;
        }
        else if (strcmp(option, "--source") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                !cocoa_server_parse_source(argv[index], options))
                return 0;
        }
        else if (strcmp(option, "--bind") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                argv[index][0] == '\0')
                return 0;
            options->bind_address = argv[index];
        }
        else if (strcmp(option, "--port") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                !cocoa_server_parse_ulong(argv[index],
                                          UINT16_MAX,
                                          &numeric))
                return 0;
            options->port = (uint16_t)numeric;
        }
        else if (strcmp(option, "--max-peers") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                !cocoa_server_parse_ulong(argv[index],
                                          SERVER_HOST_MAX_PEERS,
                                          &numeric) ||
                numeric == 0ul)
                return 0;
            options->max_peers = (uint32_t)numeric;
        }
        else if (strcmp(option, "--max-fps") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                !cocoa_server_parse_ulong(argv[index], 60ul, &numeric) ||
                numeric == 0ul)
                return 0;
            options->max_fps = (uint32_t)numeric;
        }
        else if (strcmp(option, "--max-frame-bytes") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                !cocoa_server_parse_ulong(
                    argv[index],
                    (unsigned long)COCOA_SERVER_MAX_FRAME_BYTES,
                    &numeric) ||
                numeric < 4ul)
                return 0;
            options->max_frame_bytes = (size_t)numeric;
        }
        else if (strcmp(option, "--security") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                !cocoa_server_parse_security(argv[index], options))
                return 0;
        }
        else if (strcmp(option, "--tls-cert") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index))
                return 0;
            options->tls_certificate = argv[index];
        }
        else if (strcmp(option, "--tls-key") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index))
                return 0;
            options->tls_private_key = argv[index];
        }
        else if (strcmp(option, "--user") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index))
                return 0;
            options->nla_username = argv[index];
        }
        else if (strcmp(option, "--domain") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index))
                return 0;
            options->nla_domain = argv[index];
        }
        else if (strcmp(option, "--password-env") == 0)
        {
            if (!cocoa_server_take_value(argc, argv, &index) ||
                argv[index][0] == '\0')
                return 0;
            options->password_environment = argv[index];
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
        else
            return 0;
    }
    return cocoa_server_validate_options(options);
}

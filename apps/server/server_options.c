/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded process-option validation shared by desktop servers.
 * Invariants: accepted strings terminate within their declared class limit
 * and contain no control bytes; environment names use the portable identifier
 * grammar and native paths start at the filesystem root.
 * Ownership: no storage is retained or allocated.
 * Threading: all helpers are pure and reentrant.
 * Trust boundary: command-line and environment selectors are rejected before
 * they can reach getaddrinfo, getenv, TLS, capture, or mount providers.
 */

#include "server_options.h"

#include <ctype.h>

static int server_options_text_valid(const char* value,
                                     size_t maximum,
                                     int allow_space)
{
    size_t index = 0u;

    if (!value || value[0] == '\0')
        return 0;
    for (index = 0u; index <= maximum; index++)
    {
        unsigned char byte = (unsigned char)value[index];

        if (byte == '\0')
            return 1;
        if (iscntrl(byte) || (!allow_space && isspace(byte)))
            return 0;
    }
    return 0;
}

int server_options_address_valid(const char* value)
{
    return server_options_text_valid(value,
                                     SERVER_OPTIONS_MAX_ADDRESS_BYTES,
                                     0);
}

int server_options_identity_valid(const char* value, int optional)
{
    if (optional && (!value || value[0] == '\0'))
        return 1;
    return server_options_text_valid(value,
                                     SERVER_OPTIONS_MAX_IDENTITY_BYTES,
                                     1);
}

int server_options_environment_valid(const char* value)
{
    size_t index = 0u;

    if (!server_options_text_valid(value,
                                   SERVER_OPTIONS_MAX_ENVIRONMENT_BYTES,
                                   0))
        return 0;
    if (value[0] != '_' && !isalpha((unsigned char)value[0]))
        return 0;
    for (index = 1u; value[index] != '\0'; index++)
    {
        unsigned char byte = (unsigned char)value[index];

        if (byte != '_' && !isalnum(byte))
            return 0;
    }
    return 1;
}

int server_options_absolute_path_valid(const char* value)
{
    return value && value[0] == '/' &&
           server_options_text_valid(value,
                                     SERVER_OPTIONS_MAX_PATH_BYTES,
                                     1);
}

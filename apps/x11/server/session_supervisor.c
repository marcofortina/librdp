/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: managed X11 session supervisor process entry point.
 * Invariants: the broker descriptor is inherited, authentication uses the
 * configured host adapter and no credential appears in process arguments.
 * Ownership: the supervisor runtime closes the inherited descriptor.
 * Threading: one event loop owns authentication and all child processes.
 * Trust boundary: only bounded absolute paths and a host-authentication service
 * name are accepted before entering the supervisor runtime.
 */

#include "server_managed_supervisor.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int x11_session_supervisor_parse_fd(const char* value,
                                           int* descriptor)
{
    char* end = NULL;
    long parsed = 0;

    if (!value || !descriptor || value[0] == '\0')
        return 0;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' ||
        parsed < 3 || parsed > INT32_MAX)
        return 0;
    *descriptor = (int)parsed;
    return 1;
}

static int x11_session_supervisor_path(const char* value)
{
    return value && value[0] == '/' &&
           strnlen(value, 4096u) < 4096u;
}

static int x11_session_supervisor_service(const char* value)
{
    size_t index = 0u;
    size_t length = value ? strnlen(value, 256u) : 0u;

    if (length == 0u || length >= 256u)
        return 0;
    for (index = 0u; index < length; index++)
    {
        unsigned char character = (unsigned char)value[index];

        if (!((character >= (unsigned char)'a' &&
               character <= (unsigned char)'z') ||
              (character >= (unsigned char)'A' &&
               character <= (unsigned char)'Z') ||
              (character >= (unsigned char)'0' &&
               character <= (unsigned char)'9') ||
              character == (unsigned char)'_' ||
              character == (unsigned char)'-' ||
              character == (unsigned char)'.'))
            return 0;
    }
    return 1;
}

static void x11_session_supervisor_usage(const char* program)
{
    fprintf(stderr,
            "usage: %s --control-fd fd --agent-path path "
            "[--auth-service name]\n",
            program);
}

int main(int argc, char** argv)
{
    x11_managed_supervisor_config config;
    int descriptor = -1;
    int index = 0;

    x11_managed_supervisor_config_init(&config);
    for (index = 1; index < argc; index++)
    {
        if (strcmp(argv[index], "--control-fd") == 0 &&
            index + 1 < argc)
        {
            index++;
            if (!x11_session_supervisor_parse_fd(
                    argv[index], &descriptor))
                descriptor = -1;
        }
        else if (strcmp(argv[index], "--agent-path") == 0 &&
                 index + 1 < argc)
        {
            index++;
            if (!x11_session_supervisor_path(argv[index]))
            {
                x11_session_supervisor_usage(argv[0]);
                return 2;
            }
            config.agent_path = argv[index];
        }
        else if (strcmp(argv[index], "--auth-service") == 0 &&
                 index + 1 < argc)
        {
            index++;
            if (!x11_session_supervisor_service(argv[index]))
            {
                x11_session_supervisor_usage(argv[0]);
                return 2;
            }
            config.authentication.service_name = argv[index];
        }
        else
        {
            x11_session_supervisor_usage(argv[0]);
            return 2;
        }
    }
    if (descriptor < 0)
    {
        x11_session_supervisor_usage(argv[0]);
        return 2;
    }
    return x11_managed_supervisor_run(descriptor, &config) ==
                   LIBRDP_STATUS_OK
               ? 0
               : 1;
}

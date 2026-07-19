/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral administration command policy.
 * Invariants: destructive actions require explicit confirmation and all
 * action-specific fields are validated before a network handle is created.
 * Ownership: parsed strings remain borrowed from argv or the process
 * environment until librdp_admin_new() copies the public configuration.
 * Threading: parsing is serialized startup work.
 * Trust boundary: command-line endpoint, credential and action fields remain
 * untrusted until admin_options_parse() succeeds.
 */

#ifndef LIBRDP_APP_ADMIN_OPTIONS_H
#define LIBRDP_APP_ADMIN_OPTIONS_H

#include <librdp/librdp.h>

#include <stdio.h>

typedef struct admin_options
{
    librdp_admin_config config;
    librdp_admin_action action;
    int no_window;
    int show_help;
    int execute_action;
    int confirm_action;
} admin_options;

void admin_options_usage(FILE* stream, const char* program);
int admin_options_parse(int argc, char** argv, admin_options* options, FILE* error_stream);

#endif

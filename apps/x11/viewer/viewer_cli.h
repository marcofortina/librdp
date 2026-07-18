/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer command-line boundary.
 * Invariants: parsed options update only public librdp settings and viewer
 * option storage owned by the caller.
 * Ownership: strings stored in x11_cli_options are heap-owned by the options
 * object and must be released with x11_cli_options_free().
 * Threading: the parser is single-threaded startup code.
 * Trust boundary: argv values are untrusted process input until validated.
 */

#ifndef LIBRDP_X11_VIEWER_CLI_H
#define LIBRDP_X11_VIEWER_CLI_H

#include "client_options.h"

#include <librdp/librdp.h>

typedef client_options x11_cli_options;

const char* x11_cli_usage(void);
void x11_cli_options_free(x11_cli_options* options);
int x11_cli_configure(librdp_settings* settings, x11_cli_options* options, int argc, char** argv);
void x11_cli_trace_settings(const librdp_settings* settings);

#endif

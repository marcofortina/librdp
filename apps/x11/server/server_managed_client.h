/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: managed X11 broker client used by the server command line.
 * Invariants: credentials and reconnect tokens are read from named environment
 * variables, copied only into one bounded IPC request and cleansed after use.
 * Ownership: the function borrows options and streams for the call duration.
 * Threading: one synchronous local IPC exchange runs on the caller thread.
 * Trust boundary: broker replies are decoded and correlated before any value
 * is printed for a caller.
 */

#ifndef LIBRDP_X11_SERVER_MANAGED_CLIENT_H
#define LIBRDP_X11_SERVER_MANAGED_CLIENT_H

#include "x11_cli.h"

#include <stdio.h>

int x11_server_run_managed(const x11_server_options* options,
                           FILE* output,
                           FILE* error);

#endif

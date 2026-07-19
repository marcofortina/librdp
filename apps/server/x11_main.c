/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 desktop-server command dispatch.
 * Invariants: validated command-line policy selects exactly one session mode.
 * Ownership: parsed options borrow argv storage until the selected runtime
 * returns.
 * Threading: startup and mode dispatch are single-threaded.
 * Trust boundary: this module does not read credentials or protocol payloads.
 */

#include "x11_cli.h"
#include "x11_managed_client.h"
#include "x11_runtime.h"

#include <stdio.h>

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
        return x11_server_run_managed(
            &options, stdout, stderr);
    return x11_server_run_shadow(&options);
}

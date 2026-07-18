/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: reusable X11 desktop-server runtime.
 * Invariants: native providers are configured before the listener starts and
 * one owner thread drives the host until cancellation or failure.
 * Ownership: the runtime borrows immutable options for the duration of the
 * call and owns all native and host objects it creates.
 * Threading: the caller owns the runtime thread; signal-driven cancellation is
 * process-global and only one runtime may install it at a time.
 * Trust boundary: passwords are read from the configured environment variable
 * and never written to diagnostics.
 */

#ifndef LIBRDP_X11_SERVER_RUNTIME_H
#define LIBRDP_X11_SERVER_RUNTIME_H

#include "server_cli.h"

int x11_server_run_shadow(const x11_server_options* options);

#endif

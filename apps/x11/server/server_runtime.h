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

typedef struct x11_server_runtime x11_server_runtime;

x11_server_runtime* x11_server_runtime_new(
    const x11_server_options* options,
    librdp_status* status);
void x11_server_runtime_free(x11_server_runtime* runtime);
librdp_status x11_server_runtime_start(x11_server_runtime* runtime);
librdp_status x11_server_runtime_run_once(x11_server_runtime* runtime,
                                          int timeout_ms);
librdp_status x11_server_runtime_wakeup(x11_server_runtime* runtime);
librdp_status x11_server_runtime_cancel(x11_server_runtime* runtime);
uint16_t x11_server_runtime_local_port(
    const x11_server_runtime* runtime);
uint32_t x11_server_runtime_width(
    const x11_server_runtime* runtime);
uint32_t x11_server_runtime_height(
    const x11_server_runtime* runtime);
int x11_server_run_shadow(const x11_server_options* options);

#endif

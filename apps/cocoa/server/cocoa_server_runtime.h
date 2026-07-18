/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa desktop-server process runtime.
 * Invariants: native providers are configured before listener startup and the
 * common host owns all protocol peers.
 * Ownership: a runtime owns one native context and one shared host.
 * Threading: dispatch is serialized on the process main thread; cancellation
 * may be requested by a signal handler through the host wakeup descriptor.
 * Trust boundary: credentials are obtained from a named environment variable
 * and are never printed or persisted.
 */

#ifndef LIBRDP_COCOA_SERVER_RUNTIME_H
#define LIBRDP_COCOA_SERVER_RUNTIME_H

#include "cocoa_server_cli.h"

int cocoa_server_run(const cocoa_server_options* options);

#endif

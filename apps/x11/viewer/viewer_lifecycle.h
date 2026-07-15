/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer lifecycle entry declarations.
 * Invariants: process startup and shutdown are represented by a single
 * top-level run function.
 * Ownership: the lifecycle owns viewer context setup and releases resources in
 * reverse construction order.
 * Threading: x11_viewer_run() runs on the process main thread.
 * Trust boundary: command-line arguments are parsed before any session is
 * created or connected.
 */

#ifndef LIBRDP_X11_VIEWER_LIFECYCLE_H
#define LIBRDP_X11_VIEWER_LIFECYCLE_H

int x11_viewer_run(int argc, char** argv);

#endif

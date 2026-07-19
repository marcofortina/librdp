/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer process entry point.
 * Invariants: main only delegates to the lifecycle module so platform setup,
 * session state, and shutdown ordering remain testable outside the C runtime
 * entry point.
 * Ownership: no resources are owned by this file.
 * Threading: called by the C runtime on the process main thread.
 * Trust boundary: command-line arguments are passed unchanged to the lifecycle
 * parser.
 */

#include "x11_lifecycle.h"

int main(int argc, char** argv)
{
    return x11_viewer_run(argc, argv);
}

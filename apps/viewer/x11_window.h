/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer window state boundary declarations.
 * Invariants: BadWindow/BadDrawable transitions are recorded once and checked
 * before drawing, pointer warps, cursor changes, or keyboard grabs.
 * Ownership: X11 handles remain owned by x11_app; this module stores only
 * process-local validity flags.
 * Threading: called from the viewer event thread and the Xlib error callback.
 * Trust boundary: asynchronous X server errors are treated as untrusted state
 * changes that force deterministic viewer shutdown.
 */

#ifndef LIBRDP_X11_VIEWER_WINDOW_H
#define LIBRDP_X11_VIEWER_WINDOW_H

#include "x11_app.h"

int x11_window_handle_error(Display* display, XErrorEvent* error);
int x11_window_is_invalid(void);
void x11_window_mark_invalid(x11_app* app);
int x11_window_is_live(x11_app* app);

#endif

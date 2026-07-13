/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer rendering boundary declarations.
 * Invariants: surface pixels are treated as read-only snapshots owned by the
 * public session API.
 * Ownership: no framebuffer memory is retained after a draw call.
 * Threading: rendering runs on the viewer event thread.
 * Trust boundary: dimensions, stride, and window liveness are validated before
 * issuing X11 presentation calls.
 */

#ifndef LIBRDP_X11_VIEWER_RENDER_H
#define LIBRDP_X11_VIEWER_RENDER_H

#include "viewer_app.h"

void x11_render_draw_surface(x11_app* app);

#endif

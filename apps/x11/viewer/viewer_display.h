/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 viewer display-control bridge declarations.
 * Invariants: monitor layouts sent to the session are derived from host
 * monitor geometry but contain only public librdp_display_monitor fields.
 * Ownership: no XRandR resources are retained after a query.
 * Threading: display updates run on the viewer event thread.
 * Trust boundary: host display-server metadata is validated before it reaches
 * the RDP display-control API.
 */

#ifndef LIBRDP_X11_VIEWER_DISPLAY_H
#define LIBRDP_X11_VIEWER_DISPLAY_H

#include "viewer_app.h"

#ifdef LIBRDP_HAVE_XRANDR
#include <X11/extensions/Xrandr.h>
#endif

int x11_display_init(x11_app* app);
int x11_display_handle_event(x11_app* app, const XEvent* event);
librdp_status x11_display_update_layout(x11_app* app, const char* reason);
librdp_status x11_display_update_or_resize(x11_app* app, const char* reason);

#ifdef LIBRDP_HAVE_XRANDR
uint32_t x11_display_translate_xrandr_monitors(librdp_display_monitor* out,
                                               uint32_t capacity,
                                               const XRRMonitorInfo* monitors,
                                               int monitor_count,
                                               int window_x,
                                               int window_y,
                                               uint32_t window_width,
                                               uint32_t window_height);
#endif

#endif

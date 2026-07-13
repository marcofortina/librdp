/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 clipboard bridge declarations for the viewer.
 * Invariants: local X11 ownership and remote clipboard data are serialized
 * through the viewer event loop.
 * Ownership: copied remote UTF-8 data and optional local file paths are owned
 * by the viewer context.
 * Threading: all entry points are called from the viewer event thread.
 * Trust boundary: X11 selection data and remote clipboard PDUs are untrusted
 * and must be length-checked before conversion or publication.
 */

#ifndef LIBRDP_X11_VIEWER_CLIPBOARD_H
#define LIBRDP_X11_VIEWER_CLIPBOARD_H

#include "viewer_app.h"

#include <stddef.h>
#include <stdint.h>

void x11_clipboard_init(x11_app* app);
void x11_clipboard_free(x11_app* app);
void x11_clipboard_handle_owner_notify(x11_app* app, XEvent* event);
void x11_clipboard_handle_selection_notify(x11_app* app, XSelectionEvent* selection);
void x11_clipboard_handle_selection_request(x11_app* app, XSelectionRequestEvent* request);
void x11_clipboard_handle_selection_clear(x11_app* app, const XSelectionClearEvent* event);
void x11_clipboard_set_remote_utf16le(x11_app* app, const uint8_t* data, size_t length);

#endif

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: private Cocoa clipboard provider contract.
 * Invariants: clipboard ownership and remote requests are generation-scoped,
 * and native payloads remain bounded before crossing the common host boundary.
 * Ownership: the provider object owns all pasteboard state and file promises.
 * Threading: vtable methods run on the host thread; promised-file writes use
 * one cancellable worker queue and marshal requests through the event source.
 * Trust boundary: pasteboard types, payloads, URLs and remote file metadata
 * are validated before publication or filesystem access.
 */

#ifndef LIBRDP_COCOA_CLIPBOARD_H
#define LIBRDP_COCOA_CLIPBOARD_H

#include "server_platform.h"

typedef struct cocoa_server_clipboard cocoa_server_clipboard;

cocoa_server_clipboard* cocoa_server_clipboard_new(void);
#ifdef LIBRDP_COCOA_SERVER_TESTING
cocoa_server_clipboard*
cocoa_server_clipboard_new_named(const char* pasteboard_name);
#endif
void cocoa_server_clipboard_free(cocoa_server_clipboard* clipboard);
void cocoa_server_clipboard_revoke(cocoa_server_clipboard* clipboard);

extern const server_platform_clipboard_vtable cocoa_server_clipboard_vtable;

#endif

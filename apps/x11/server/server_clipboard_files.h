/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: local file source for X11 clipboard file transfers.
 * Invariants: retained descriptors refer only to regular files opened without
 * following the final symlink, and one ownership generation replaces the
 * previous file set atomically.
 * Ownership: the source owns retained descriptors and names; encoded metadata
 * and range buffers returned to callers are caller-owned.
 * Threading: all operations run on the X11 server owner thread.
 * Trust boundary: URI-list input is untrusted and is decoded, bounded and
 * opened before any path or metadata is advertised to a remote peer.
 */

#ifndef LIBRDP_X11_SERVER_CLIPBOARD_FILES_H
#define LIBRDP_X11_SERVER_CLIPBOARD_FILES_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

#define X11_SERVER_CLIPBOARD_FILE_LIMIT 32u
#define X11_SERVER_CLIPBOARD_FILE_RANGE_LIMIT (1024u * 1024u)

typedef struct x11_server_clipboard_files x11_server_clipboard_files;

x11_server_clipboard_files* x11_server_clipboard_files_new(void);
void x11_server_clipboard_files_free(x11_server_clipboard_files* files);
void x11_server_clipboard_files_reset(x11_server_clipboard_files* files);
librdp_status x11_server_clipboard_files_import_uri_list(
    x11_server_clipboard_files* files,
    const uint8_t* data,
    size_t data_len,
    uint64_t ownership_generation,
    uint8_t** encoded,
    size_t* encoded_len);
librdp_status x11_server_clipboard_files_read(
    x11_server_clipboard_files* files,
    const server_platform_clipboard_file_request* request,
    uint8_t** data,
    size_t* data_len);
size_t x11_server_clipboard_files_count(
    const x11_server_clipboard_files* files);

#endif

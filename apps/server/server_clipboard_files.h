/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: local file source for desktop-server clipboard transfers.
 * Invariants: retained descriptors refer only to regular files opened without
 * following the final symlink, and one ownership generation replaces the
 * previous file set atomically.
 * Ownership: the source owns retained descriptors and names; encoded metadata
 * and range buffers returned to callers are caller-owned.
 * Threading: all operations run on the desktop-server owner thread.
 * Trust boundary: URI-list input is untrusted and is decoded, bounded and
 * opened before any path or metadata is advertised to a remote peer.
 */

#ifndef LIBRDP_APP_SERVER_CLIPBOARD_FILES_H
#define LIBRDP_APP_SERVER_CLIPBOARD_FILES_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

#define SERVER_CLIPBOARD_FILE_LIMIT 32u
#define SERVER_CLIPBOARD_FILE_RANGE_LIMIT (1024u * 1024u)

typedef struct server_clipboard_files server_clipboard_files;

server_clipboard_files* server_clipboard_files_new(void);
void server_clipboard_files_free(server_clipboard_files* files);
void server_clipboard_files_reset(server_clipboard_files* files);
librdp_status server_clipboard_files_import_uri_list(
    server_clipboard_files* files,
    const uint8_t* data,
    size_t data_len,
    uint64_t ownership_generation,
    uint8_t** encoded,
    size_t* encoded_len);
librdp_status server_clipboard_files_read(
    server_clipboard_files* files,
    const server_platform_clipboard_file_request* request,
    uint8_t** data,
    size_t* data_len);
size_t server_clipboard_files_count(
    const server_clipboard_files* files);

#endif

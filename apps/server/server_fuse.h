/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: optional FUSE presentation for client-announced drives.
 * Invariants: one mount belongs to one server process, every inode and open
 * handle is scoped to a peer generation, and all remote I/O is asynchronous.
 * Ownership: the provider copies its mount path and owns the FUSE session,
 * inode cache, remote handles and pending kernel requests.
 * Threading: callbacks and completions run on the shared server-host thread.
 * Trust boundary: mount paths, names, metadata and completion buffers are
 * validated and bounded before reaching the kernel filesystem interface.
 */

#ifndef LIBRDP_APP_SERVER_FUSE_H
#define LIBRDP_APP_SERVER_FUSE_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

#define SERVER_FUSE_CONFIG_VERSION 1u
#define SERVER_FUSE_DEFAULT_MAX_NODES 4096u
#define SERVER_FUSE_DEFAULT_MAX_HANDLES 256u
#define SERVER_FUSE_DEFAULT_MAX_PENDING 256u
#define SERVER_FUSE_DEFAULT_MAX_DIRECTORY_ENTRIES 2048u
#define SERVER_FUSE_DEFAULT_MAX_READ_BYTES (4u * 1024u * 1024u)

typedef struct server_fuse_config
{
    uint32_t version;
    size_t size;
    const char* mount_path;
    uint32_t max_nodes;
    uint32_t max_handles;
    uint32_t max_pending;
    uint32_t max_directory_entries;
    uint32_t max_read_bytes;
    int read_only;
} server_fuse_config;

typedef struct server_fuse server_fuse;

void server_fuse_config_init(server_fuse_config* config);
int server_fuse_available(void);
server_fuse* server_fuse_new(const server_fuse_config* config);
void server_fuse_free(server_fuse* provider);
const server_platform_drive_vtable* server_fuse_vtable(void);
librdp_status server_fuse_set_clipboard_sink(
    server_fuse* provider,
    server_platform_clipboard_file_request_callback request,
    server_platform_clipboard_cancel_callback cancel, void* user_data);
int server_fuse_clipboard_ready(const server_fuse* provider);
librdp_status server_fuse_clipboard_publish(
    server_fuse* provider, uint32_t peer_id, uint32_t generation,
    uint64_t ownership_generation, const void* descriptors,
    size_t descriptors_len, uint8_t** uri_list, size_t* uri_list_len);
librdp_status server_fuse_clipboard_complete(
    server_fuse* provider, const server_platform_clipboard_data* data);
void server_fuse_clipboard_clear(server_fuse* provider, uint32_t peer_id,
                                 uint32_t generation,
                                 uint64_t ownership_generation);

#ifdef LIBRDP_SERVER_FUSE_TESTING
librdp_status server_fuse_test_present(
    server_fuse* provider, const server_platform_drive_volume* volume);
size_t server_fuse_test_volume_count(const server_fuse* provider);
int server_fuse_test_mount_path_secure(const char* path);
librdp_status server_fuse_test_clipboard_publish(
    server_fuse* provider, uint32_t peer_id, uint32_t generation,
    uint64_t ownership_generation, const void* descriptors,
    size_t descriptors_len, uint8_t** uri_list, size_t* uri_list_len);
size_t server_fuse_test_clipboard_file_count(const server_fuse* provider);
#endif

#endif

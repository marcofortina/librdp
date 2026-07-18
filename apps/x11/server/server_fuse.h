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

#ifndef LIBRDP_X11_SERVER_FUSE_H
#define LIBRDP_X11_SERVER_FUSE_H

#include "server_platform.h"

#include <stddef.h>
#include <stdint.h>

#define X11_SERVER_FUSE_CONFIG_VERSION 1u
#define X11_SERVER_FUSE_DEFAULT_MAX_NODES 4096u
#define X11_SERVER_FUSE_DEFAULT_MAX_HANDLES 256u
#define X11_SERVER_FUSE_DEFAULT_MAX_PENDING 256u
#define X11_SERVER_FUSE_DEFAULT_MAX_DIRECTORY_ENTRIES 2048u
#define X11_SERVER_FUSE_DEFAULT_MAX_READ_BYTES (4u * 1024u * 1024u)

typedef struct x11_server_fuse_config
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
} x11_server_fuse_config;

typedef struct x11_server_fuse x11_server_fuse;

void x11_server_fuse_config_init(x11_server_fuse_config* config);
int x11_server_fuse_available(void);
x11_server_fuse* x11_server_fuse_new(const x11_server_fuse_config* config);
void x11_server_fuse_free(x11_server_fuse* provider);
const server_platform_drive_vtable* x11_server_fuse_vtable(void);

#ifdef LIBRDP_X11_SERVER_TESTING
librdp_status x11_server_fuse_test_present(
    x11_server_fuse* provider, const server_platform_drive_volume* volume);
size_t x11_server_fuse_test_volume_count(const x11_server_fuse* provider);
int x11_server_fuse_test_mount_path_secure(const char* path);
#endif

#endif

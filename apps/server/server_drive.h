/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: platform-neutral client-drive runtime for desktop servers.
 * Invariants: volumes, files and requests are scoped to one peer generation;
 * every accepted application request reaches one terminal completion; policy
 * and quotas are checked before protocol submission.
 * Ownership: the runtime copies retained policy names and volume names. Peer
 * and platform contexts remain borrowed until removal or runtime destruction.
 * Threading: all operations run on the serialized server-host owner thread.
 * Trust boundary: native paths and payloads are normalized and bounded before
 * reaching the public server API; remote metadata remains content-redacted.
 */

#ifndef LIBRDP_APP_SERVER_DRIVE_H
#define LIBRDP_APP_SERVER_DRIVE_H

#include "server_platform.h"

#include <librdp/librdp.h>

#include <stddef.h>
#include <stdint.h>

#define SERVER_DRIVE_CONFIG_VERSION 1u
#define SERVER_DRIVE_VOLUME_INFO_VERSION 1u
#define SERVER_DRIVE_DEFAULT_MAX_VOLUMES 16u
#define SERVER_DRIVE_DEFAULT_MAX_PENDING 32u
#define SERVER_DRIVE_DEFAULT_MAX_OPEN_FILES 128u
#define SERVER_DRIVE_DEFAULT_MAX_PATH_BYTES 4096u
#define SERVER_DRIVE_DEFAULT_MAX_REQUEST_BYTES (16u * 1024u * 1024u)
#define SERVER_DRIVE_DEFAULT_MAX_TRANSFER_BYTES (1024ull * 1024ull * 1024ull)
#define SERVER_DRIVE_DEFAULT_TIMEOUT_MS 30000u

typedef struct server_drive_config
{
    uint32_t version;
    size_t size;
    uint32_t max_peers;
    uint32_t max_volumes_per_peer;
    uint32_t max_pending_per_peer;
    uint32_t max_open_files_per_peer;
    size_t max_path_bytes;
    size_t max_request_bytes;
    uint64_t max_transfer_bytes_per_peer;
    uint32_t request_timeout_ms;
    const char* const* allowed_drive_names;
    size_t allowed_drive_name_count;
    int enabled;
    int read_only;
} server_drive_config;

typedef struct server_drive_volume_info
{
    uint32_t version;
    size_t size;
    uint64_t volume_id;
    uint32_t peer_id;
    uint32_t generation;
    librdp_server_drive_device_handle device;
    const char* name;
    int read_only;
} server_drive_volume_info;

typedef struct server_drive_protocol_vtable
{
    /*
     * submit borrows request fields for the call. cancel may emit the terminal
     * protocol callback synchronously; the runtime also handles providers that
     * return without doing so and rejects any later duplicate completion.
     */
    librdp_status (*submit)(void* context,
                            const librdp_server_drive_request* request,
                            librdp_server_drive_request_id* request_id);
    librdp_status (*cancel)(void* context,
                            librdp_server_drive_request_id request_id);
    librdp_status (*send_device_reply)(void* context,
                                       uint32_t device_id,
                                       uint32_t io_status);
} server_drive_protocol_vtable;

typedef struct server_drive_runtime server_drive_runtime;

void server_drive_config_init(server_drive_config* config);
librdp_status server_drive_config_validate(const server_drive_config* config);
void server_drive_volume_info_init(server_drive_volume_info* info);
server_drive_runtime* server_drive_runtime_new(
    const server_drive_config* config,
    const server_platform_drive_vtable* platform,
    void* platform_context);
void server_drive_runtime_free(server_drive_runtime* runtime);
librdp_status server_drive_runtime_add_peer(server_drive_runtime* runtime,
                                            uint32_t peer_id,
                                            uint32_t generation,
                                            const server_drive_protocol_vtable* protocol,
                                            void* protocol_context);
void server_drive_runtime_remove_peer(server_drive_runtime* runtime,
                                      uint32_t peer_id,
                                      uint32_t generation);
librdp_status server_drive_runtime_protocol_event(
    server_drive_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    const librdp_server_drive_event* event);
librdp_status server_drive_runtime_platform_request(
    server_drive_runtime* runtime,
    const server_platform_drive_request* request,
    uint64_t now_ns);
librdp_status server_drive_runtime_platform_cancel(
    server_drive_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t request_id);
librdp_status server_drive_runtime_set_enabled(server_drive_runtime* runtime,
                                               int enabled);
int server_drive_runtime_is_enabled(const server_drive_runtime* runtime);
void server_drive_runtime_revoke(server_drive_runtime* runtime);
librdp_status server_drive_runtime_dispatch_timeouts(
    server_drive_runtime* runtime,
    uint64_t now_ns);
int server_drive_runtime_next_timeout(const server_drive_runtime* runtime,
                                      uint64_t now_ns);
size_t server_drive_runtime_volume_count(const server_drive_runtime* runtime);
librdp_status server_drive_runtime_volume_at(
    const server_drive_runtime* runtime,
    size_t index,
    server_drive_volume_info* info);

#endif

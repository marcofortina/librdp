/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: bounded client-drive policy, volume and request orchestration.
 * Invariants: a platform request is associated with one accepted volume and
 * one peer generation, request identifiers are unique while pending, and all
 * reservations are released exactly once on completion, cancellation or
 * teardown.
 * Ownership: normalized paths are temporary; volume names and allowlist names
 * are runtime-owned; completion payloads remain borrowed during callbacks.
 * Threading: every entry point is confined to the shared server-host thread.
 * Trust boundary: client device metadata and native requests are validated
 * against policy, quotas and checked path rules before crossing the boundary.
 */

#include "server_drive.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define SERVER_DRIVE_IO_STATUS_SUCCESS 0x00000000u
#define SERVER_DRIVE_IO_STATUS_INVALID_PARAMETER 0xc000000du
#define SERVER_DRIVE_IO_STATUS_ACCESS_DENIED 0xc0000022u
#define SERVER_DRIVE_IO_STATUS_INSUFFICIENT_RESOURCES 0xc000009au
#define SERVER_DRIVE_WRITE_ACCESS_MASK 0x500d0116u
#define SERVER_DRIVE_CREATE_DISPOSITION_OPEN 1u
#define SERVER_DRIVE_NS_PER_MS 1000000ull

typedef struct server_drive_volume
{
    uint64_t volume_id;
    librdp_server_drive_device_handle device;
    char* name;
    uint32_t open_files;
    int occupied;
} server_drive_volume;

typedef struct server_drive_pending
{
    uint64_t application_request_id;
    uint64_t protocol_request_id;
    uint64_t volume_id;
    uint64_t deadline_ns;
    uint64_t reserved_bytes;
    librdp_server_drive_operation operation;
    uint32_t information_class;
    librdp_status terminal_status;
    int reserves_file;
    int occupied;
} server_drive_pending;

typedef struct server_drive_file
{
    uint64_t volume_id;
    librdp_server_drive_file_handle handle;
    int occupied;
} server_drive_file;

typedef struct server_drive_peer
{
    uint32_t peer_id;
    uint32_t generation;
    const server_drive_protocol_vtable* protocol;
    void* protocol_context;
    server_drive_volume* volumes;
    server_drive_pending* pending;
    server_drive_file* files;
    uint32_t volume_count;
    uint32_t pending_count;
    uint32_t open_files;
    uint32_t reserved_files;
    uint64_t transferred_bytes;
    uint64_t reserved_bytes;
    int platform_released;
    int occupied;
} server_drive_peer;

struct server_drive_runtime
{
    server_drive_config config;
    const server_platform_drive_vtable* platform;
    void* platform_context;
    server_drive_peer* peers;
    char** allowed_names;
    uint64_t next_volume_id;
    int enabled;
};

void server_drive_config_init(server_drive_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = SERVER_DRIVE_CONFIG_VERSION;
    config->size = sizeof(*config);
    config->max_peers = 4u;
    config->max_volumes_per_peer = SERVER_DRIVE_DEFAULT_MAX_VOLUMES;
    config->max_pending_per_peer = SERVER_DRIVE_DEFAULT_MAX_PENDING;
    config->max_open_files_per_peer = SERVER_DRIVE_DEFAULT_MAX_OPEN_FILES;
    config->max_path_bytes = SERVER_DRIVE_DEFAULT_MAX_PATH_BYTES;
    config->max_request_bytes = SERVER_DRIVE_DEFAULT_MAX_REQUEST_BYTES;
    config->max_transfer_bytes_per_peer =
        SERVER_DRIVE_DEFAULT_MAX_TRANSFER_BYTES;
    config->request_timeout_ms = SERVER_DRIVE_DEFAULT_TIMEOUT_MS;
    config->enabled = 0;
    config->read_only = 1;
}

static int server_drive_allocation_fits(uint32_t count, size_t item_size)
{
    return count == 0u || item_size <= SIZE_MAX / (size_t)count;
}

librdp_status server_drive_config_validate(const server_drive_config* config)
{
    if (!config || config->version != SERVER_DRIVE_CONFIG_VERSION ||
        config->size < sizeof(*config) || config->max_peers == 0u ||
        config->max_volumes_per_peer == 0u ||
        config->max_pending_per_peer == 0u ||
        config->max_open_files_per_peer == 0u ||
        config->max_path_bytes == 0u ||
        config->max_path_bytes > UINT32_MAX / 2u ||
        config->max_request_bytes == 0u ||
        config->max_request_bytes > UINT32_MAX ||
        config->max_transfer_bytes_per_peer == 0u ||
        config->request_timeout_ms == 0u ||
        (config->allowed_drive_name_count > 0u &&
         !config->allowed_drive_names) ||
        (config->enabled != 0 && config->enabled != 1) ||
        (config->read_only != 0 && config->read_only != 1))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!server_drive_allocation_fits(config->max_peers,
                                      sizeof(server_drive_peer)) ||
        !server_drive_allocation_fits(config->max_volumes_per_peer,
                                      sizeof(server_drive_volume)) ||
        !server_drive_allocation_fits(config->max_pending_per_peer,
                                      sizeof(server_drive_pending)) ||
        !server_drive_allocation_fits(config->max_open_files_per_peer,
                                      sizeof(server_drive_file)))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    return LIBRDP_STATUS_OK;
}

void server_drive_volume_info_init(server_drive_volume_info* info)
{
    if (!info)
        return;
    memset(info, 0, sizeof(*info));
    info->version = SERVER_DRIVE_VOLUME_INFO_VERSION;
    info->size = sizeof(*info);
}

static int server_drive_platform_valid(
    const server_platform_drive_vtable* platform)
{
    return platform && platform->version == SERVER_PLATFORM_DRIVE_VERSION &&
           platform->size >= sizeof(*platform) && platform->present &&
           platform->remove && platform->remove_peer && platform->complete;
}

static void server_drive_allowed_names_free(server_drive_runtime* runtime)
{
    size_t index = 0;

    if (!runtime || !runtime->allowed_names)
        return;
    for (index = 0; index < runtime->config.allowed_drive_name_count; index++)
        free(runtime->allowed_names[index]);
    free(runtime->allowed_names);
    runtime->allowed_names = NULL;
}

static librdp_status server_drive_allowed_names_copy(
    server_drive_runtime* runtime,
    const server_drive_config* config)
{
    size_t index = 0;

    if (config->allowed_drive_name_count == 0u)
        return LIBRDP_STATUS_OK;
    if (config->allowed_drive_name_count > SIZE_MAX / sizeof(char*))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    runtime->allowed_names =
        (char**)calloc(config->allowed_drive_name_count, sizeof(char*));
    if (!runtime->allowed_names)
        return LIBRDP_STATUS_NO_MEMORY;
    for (index = 0; index < config->allowed_drive_name_count; index++)
    {
        const char* name = config->allowed_drive_names[index];
        size_t length = 0u;

        if (name)
        {
            while (length <= 255u && name[length] != '\0')
                length++;
        }
        if (length == 0u || length > 255u)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        runtime->allowed_names[index] = (char*)malloc(length + 1u);
        if (!runtime->allowed_names[index])
            return LIBRDP_STATUS_NO_MEMORY;
        memcpy(runtime->allowed_names[index], name, length + 1u);
    }
    return LIBRDP_STATUS_OK;
}

static void server_drive_peer_storage_free(server_drive_runtime* runtime,
                                           server_drive_peer* peer)
{
    uint32_t index = 0;

    if (!runtime || !peer)
        return;
    if (peer->volumes)
    {
        for (index = 0;
             index < runtime->config.max_volumes_per_peer;
             index++)
            free(peer->volumes[index].name);
    }
    free(peer->volumes);
    free(peer->pending);
    free(peer->files);
    memset(peer, 0, sizeof(*peer));
}

server_drive_runtime* server_drive_runtime_new(
    const server_drive_config* config,
    const server_platform_drive_vtable* platform,
    void* platform_context)
{
    server_drive_runtime* runtime = NULL;
    librdp_status status = server_drive_config_validate(config);

    if (status != LIBRDP_STATUS_OK || !server_drive_platform_valid(platform))
        return NULL;
    runtime = (server_drive_runtime*)calloc(1u, sizeof(*runtime));
    if (!runtime)
        return NULL;
    runtime->peers =
        (server_drive_peer*)calloc(config->max_peers, sizeof(*runtime->peers));
    if (!runtime->peers)
    {
        free(runtime);
        return NULL;
    }
    runtime->config = *config;
    runtime->platform = platform;
    runtime->platform_context = platform_context;
    runtime->next_volume_id = 1u;
    runtime->enabled = config->enabled;
    status = server_drive_allowed_names_copy(runtime, config);
    if (status != LIBRDP_STATUS_OK)
    {
        server_drive_allowed_names_free(runtime);
        free(runtime->peers);
        free(runtime);
        return NULL;
    }
    runtime->config.allowed_drive_names =
        (const char* const*)runtime->allowed_names;
    return runtime;
}

static server_drive_peer* server_drive_find_peer(
    server_drive_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation)
{
    uint32_t index = 0;

    if (!runtime || peer_id == 0u || generation == 0u)
        return NULL;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_drive_peer* peer = &runtime->peers[index];

        if (peer->occupied && peer->peer_id == peer_id &&
            peer->generation == generation)
            return peer;
    }
    return NULL;
}

static server_drive_volume* server_drive_find_volume(
    const server_drive_runtime* runtime,
    server_drive_peer* peer,
    uint64_t volume_id)
{
    uint32_t index = 0;

    if (!runtime || !peer || volume_id == 0u)
        return NULL;
    for (index = 0; index < runtime->config.max_volumes_per_peer; index++)
    {
        server_drive_volume* volume = &peer->volumes[index];

        if (volume->occupied && volume->volume_id == volume_id)
            return volume;
    }
    return NULL;
}

static server_drive_volume* server_drive_find_device(
    const server_drive_runtime* runtime,
    server_drive_peer* peer,
    librdp_server_drive_device_handle device)
{
    uint32_t index = 0;

    if (!runtime || !peer || device.reconnect_generation == 0u ||
        device.device_id == 0u)
        return NULL;
    for (index = 0; index < runtime->config.max_volumes_per_peer; index++)
    {
        server_drive_volume* volume = &peer->volumes[index];

        if (volume->occupied &&
            volume->device.reconnect_generation ==
                device.reconnect_generation &&
            volume->device.device_id == device.device_id)
            return volume;
    }
    return NULL;
}

static server_drive_pending* server_drive_find_pending_application(
    const server_drive_runtime* runtime,
    server_drive_peer* peer,
    uint64_t request_id)
{
    uint32_t index = 0;

    if (!runtime || !peer || request_id == 0u)
        return NULL;
    for (index = 0; index < runtime->config.max_pending_per_peer; index++)
    {
        server_drive_pending* pending = &peer->pending[index];

        if (pending->occupied &&
            pending->application_request_id == request_id)
            return pending;
    }
    return NULL;
}

static server_drive_pending* server_drive_find_pending_protocol(
    const server_drive_runtime* runtime,
    server_drive_peer* peer,
    uint64_t request_id)
{
    uint32_t index = 0;

    if (!runtime || !peer || request_id == 0u)
        return NULL;
    for (index = 0; index < runtime->config.max_pending_per_peer; index++)
    {
        server_drive_pending* pending = &peer->pending[index];

        if (pending->occupied && pending->protocol_request_id == request_id)
            return pending;
    }
    return NULL;
}

static server_drive_file* server_drive_find_file(
    const server_drive_runtime* runtime,
    server_drive_peer* peer,
    librdp_server_drive_file_handle handle)
{
    uint32_t index = 0u;

    if (!runtime || !peer || handle.reconnect_generation == 0u ||
        handle.device_id == 0u || handle.file_id == 0u ||
        handle.reserved != 0u)
        return NULL;
    for (index = 0u;
         index < runtime->config.max_open_files_per_peer;
         index++)
    {
        server_drive_file* file = &peer->files[index];

        if (file->occupied &&
            file->handle.reconnect_generation ==
                handle.reconnect_generation &&
            file->handle.device_id == handle.device_id &&
            file->handle.file_id == handle.file_id)
            return file;
    }
    return NULL;
}

static int server_drive_protocol_valid(
    const server_drive_protocol_vtable* protocol)
{
    return protocol && protocol->submit && protocol->cancel &&
           protocol->send_device_reply;
}

static void server_drive_pending_clear(server_drive_peer* peer,
                                       server_drive_pending* pending)
{
    if (!peer || !pending || !pending->occupied)
        return;
    if (peer->reserved_bytes >= pending->reserved_bytes)
        peer->reserved_bytes -= pending->reserved_bytes;
    else
        peer->reserved_bytes = 0u;
    if (pending->reserves_file && peer->reserved_files > 0u)
        peer->reserved_files--;
    if (peer->pending_count > 0u)
        peer->pending_count--;
    memset(pending, 0, sizeof(*pending));
}

static librdp_status server_drive_complete(
    server_drive_runtime* runtime,
    const server_drive_peer* peer,
    const server_drive_pending* pending,
    const librdp_server_drive_event* event,
    librdp_status status)
{
    server_platform_drive_completion completion;

    if (!runtime || !peer || !pending)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&completion, 0, sizeof(completion));
    completion.request_id = pending->application_request_id;
    completion.volume_id = pending->volume_id;
    completion.peer_id = peer->peer_id;
    completion.generation = peer->generation;
    completion.type = event ? event->type
                            : LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED;
    completion.status = status;
    completion.operation = pending->operation;
    completion.information_class = pending->information_class;
    if (event)
    {
        completion.io_status = event->io_status;
        completion.device = event->device;
        completion.file = event->file;
        completion.information = event->information;
        completion.transferred = event->transferred;
        completion.data = event->data;
        completion.data_len = event->data_len;
    }
    return runtime->platform->complete(runtime->platform_context,
                                       &completion);
}

/*
 * Terminate one pending operation through the protocol cancel hook. The core
 * normally emits cancellation synchronously; if a provider does not, this
 * boundary supplies the terminal platform completion before releasing quota.
 */
static librdp_status server_drive_cancel_pending(
    server_drive_runtime* runtime,
    server_drive_peer* peer,
    server_drive_pending* pending,
    librdp_status terminal_status)
{
    librdp_status cancel_status = LIBRDP_STATUS_OK;
    librdp_status completion_status = LIBRDP_STATUS_OK;

    if (!runtime || !peer || !pending || !pending->occupied)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pending->terminal_status = terminal_status;
    cancel_status = peer->protocol->cancel(peer->protocol_context,
                                           pending->protocol_request_id);
    if (pending->occupied)
    {
        completion_status = server_drive_complete(runtime,
                                                  peer,
                                                  pending,
                                                  NULL,
                                                  terminal_status);
        server_drive_pending_clear(peer, pending);
    }
    return cancel_status != LIBRDP_STATUS_OK ? cancel_status
                                             : completion_status;
}

static void server_drive_cancel_all_pending(server_drive_runtime* runtime,
                                            server_drive_peer* peer,
                                            librdp_status terminal_status)
{
    uint32_t index = 0;

    if (!runtime || !peer)
        return;
    for (index = 0; index < runtime->config.max_pending_per_peer; index++)
    {
        server_drive_pending* pending = &peer->pending[index];
        if (!pending->occupied)
            continue;
        (void)server_drive_cancel_pending(runtime,
                                          peer,
                                          pending,
                                          terminal_status);
    }
}

static void server_drive_cancel_volume_pending(
    server_drive_runtime* runtime,
    server_drive_peer* peer,
    uint64_t volume_id,
    librdp_status terminal_status)
{
    uint32_t index = 0;

    if (!runtime || !peer || volume_id == 0u)
        return;
    for (index = 0; index < runtime->config.max_pending_per_peer; index++)
    {
        server_drive_pending* pending = &peer->pending[index];
        if (!pending->occupied || pending->volume_id != volume_id)
            continue;
        (void)server_drive_cancel_pending(runtime,
                                          peer,
                                          pending,
                                          terminal_status);
    }
}

static void server_drive_remove_all_volumes(server_drive_runtime* runtime,
                                            server_drive_peer* peer)
{
    uint32_t index = 0;

    if (!runtime || !peer)
        return;
    for (index = 0; index < runtime->config.max_volumes_per_peer; index++)
    {
        server_drive_volume* volume = &peer->volumes[index];

        if (!volume->occupied)
            continue;
        runtime->platform->remove(runtime->platform_context,
                                  peer->peer_id,
                                  peer->generation,
                                  volume->device.device_id);
        free(volume->name);
        memset(volume, 0, sizeof(*volume));
    }
    if (peer->files)
    {
        memset(peer->files,
               0,
               (size_t)runtime->config.max_open_files_per_peer *
                   sizeof(*peer->files));
    }
    peer->volume_count = 0u;
    peer->open_files = 0u;
    peer->reserved_files = 0u;
}

void server_drive_runtime_free(server_drive_runtime* runtime)
{
    uint32_t index = 0;

    if (!runtime)
        return;
    server_drive_runtime_revoke(runtime);
    for (index = 0; index < runtime->config.max_peers; index++)
        server_drive_peer_storage_free(runtime, &runtime->peers[index]);
    server_drive_allowed_names_free(runtime);
    free(runtime->peers);
    memset(runtime, 0, sizeof(*runtime));
    free(runtime);
}

librdp_status server_drive_runtime_add_peer(server_drive_runtime* runtime,
                                            uint32_t peer_id,
                                            uint32_t generation,
                                            const server_drive_protocol_vtable* protocol,
                                            void* protocol_context)
{
    uint32_t index = 0;

    if (!runtime || !server_drive_protocol_valid(protocol) ||
        peer_id == 0u || generation == 0u ||
        server_drive_find_peer(runtime, peer_id, generation))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_drive_peer* peer = &runtime->peers[index];

        if (peer->occupied)
            continue;
        peer->volumes = (server_drive_volume*)calloc(
            runtime->config.max_volumes_per_peer,
            sizeof(*peer->volumes));
        peer->pending = (server_drive_pending*)calloc(
            runtime->config.max_pending_per_peer,
            sizeof(*peer->pending));
        peer->files = (server_drive_file*)calloc(
            runtime->config.max_open_files_per_peer,
            sizeof(*peer->files));
        if (!peer->volumes || !peer->pending || !peer->files)
        {
            free(peer->volumes);
            free(peer->pending);
            free(peer->files);
            memset(peer, 0, sizeof(*peer));
            return LIBRDP_STATUS_NO_MEMORY;
        }
        peer->peer_id = peer_id;
        peer->generation = generation;
        peer->protocol = protocol;
        peer->protocol_context = protocol_context;
        peer->occupied = 1;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_LIMIT_EXCEEDED;
}

void server_drive_runtime_remove_peer(server_drive_runtime* runtime,
                                      uint32_t peer_id,
                                      uint32_t generation)
{
    server_drive_peer* peer =
        server_drive_find_peer(runtime, peer_id, generation);

    if (!peer)
        return;
    server_drive_cancel_all_pending(runtime, peer, LIBRDP_STATUS_CANCELLED);
    server_drive_remove_all_volumes(runtime, peer);
    if (!peer->platform_released)
    {
        runtime->platform->remove_peer(runtime->platform_context,
                                       peer_id,
                                       generation);
        peer->platform_released = 1;
    }
    server_drive_peer_storage_free(runtime, peer);
}

static int server_drive_ascii_equal(const char* left, const char* right)
{
    size_t index = 0;

    if (!left || !right)
        return 0;
    while (left[index] != '\0' && right[index] != '\0')
    {
        unsigned char l = (unsigned char)left[index];
        unsigned char r = (unsigned char)right[index];

        if (tolower(l) != tolower(r))
            return 0;
        index++;
    }
    return left[index] == '\0' && right[index] == '\0';
}

static int server_drive_name_allowed(const server_drive_runtime* runtime,
                                     const char* name)
{
    size_t index = 0;

    if (!runtime || !name || name[0] == '\0')
        return 0;
    if (strchr(name, '/') || strchr(name, '\\') || strchr(name, ':'))
        return 0;
    if (runtime->config.allowed_drive_name_count == 0u)
        return 1;
    for (index = 0; index < runtime->config.allowed_drive_name_count; index++)
    {
        if (server_drive_ascii_equal(runtime->allowed_names[index], name))
            return 1;
    }
    return 0;
}

static size_t server_drive_name_length(const char* name)
{
    size_t length = 0u;

    if (!name)
        return 0u;
    while (length <= 255u && name[length] != '\0')
        length++;
    return length <= 255u ? length : 0u;
}

static void server_drive_send_device_result(server_drive_peer* peer,
                                            uint32_t device_id,
                                            uint32_t io_status)
{
    if (!peer)
        return;
    (void)peer->protocol->send_device_reply(peer->protocol_context,
                                            device_id,
                                            io_status);
}

static librdp_status server_drive_add_volume(
    server_drive_runtime* runtime,
    server_drive_peer* peer,
    const librdp_server_drive_event* event)
{
    server_drive_volume* volume = NULL;
    server_platform_drive_volume platform_volume;
    size_t name_len = server_drive_name_length(event->name);
    uint32_t index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime->enabled || name_len == 0u ||
        event->device.reconnect_generation == 0u ||
        event->device.device_id == 0u ||
        !server_drive_name_allowed(runtime, event->name))
    {
        server_drive_send_device_result(peer,
                                        event->device.device_id,
                                        SERVER_DRIVE_IO_STATUS_ACCESS_DENIED);
        return LIBRDP_STATUS_STATE;
    }
    if (server_drive_find_device(runtime, peer, event->device))
    {
        server_drive_send_device_result(
            peer,
            event->device.device_id,
            SERVER_DRIVE_IO_STATUS_INVALID_PARAMETER);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (peer->volume_count >= runtime->config.max_volumes_per_peer)
    {
        server_drive_send_device_result(
            peer,
            event->device.device_id,
            SERVER_DRIVE_IO_STATUS_INSUFFICIENT_RESOURCES);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    for (index = 0; index < runtime->config.max_volumes_per_peer; index++)
    {
        if (!peer->volumes[index].occupied)
        {
            volume = &peer->volumes[index];
            break;
        }
    }
    if (!volume)
    {
        server_drive_send_device_result(
            peer,
            event->device.device_id,
            SERVER_DRIVE_IO_STATUS_INSUFFICIENT_RESOURCES);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    volume->name = (char*)malloc(name_len + 1u);
    if (!volume->name)
    {
        server_drive_send_device_result(
            peer,
            event->device.device_id,
            SERVER_DRIVE_IO_STATUS_INSUFFICIENT_RESOURCES);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    memcpy(volume->name, event->name, name_len + 1u);
    volume->volume_id = runtime->next_volume_id++;
    if (volume->volume_id == 0u)
        volume->volume_id = runtime->next_volume_id++;
    volume->device = event->device;
    volume->occupied = 1;
    memset(&platform_volume, 0, sizeof(platform_volume));
    platform_volume.volume_id = volume->volume_id;
    platform_volume.peer_id = peer->peer_id;
    platform_volume.generation = peer->generation;
    platform_volume.device = volume->device;
    platform_volume.name = volume->name;
    platform_volume.read_only = runtime->config.read_only;
    status = runtime->platform->present(runtime->platform_context,
                                        &platform_volume);
    if (status != LIBRDP_STATUS_OK)
    {
        free(volume->name);
        memset(volume, 0, sizeof(*volume));
        server_drive_send_device_result(
            peer,
            event->device.device_id,
            SERVER_DRIVE_IO_STATUS_INSUFFICIENT_RESOURCES);
        return status;
    }
    peer->volume_count++;
    server_drive_send_device_result(peer,
                                    event->device.device_id,
                                    SERVER_DRIVE_IO_STATUS_SUCCESS);
    return LIBRDP_STATUS_OK;
}

static librdp_status server_drive_remove_volume(
    server_drive_runtime* runtime,
    server_drive_peer* peer,
    librdp_server_drive_device_handle device)
{
    server_drive_volume* volume =
        server_drive_find_device(runtime, peer, device);
    uint32_t file_index = 0u;

    if (!volume)
        return LIBRDP_STATUS_STATE;
    server_drive_cancel_volume_pending(runtime,
                                       peer,
                                       volume->volume_id,
                                       LIBRDP_STATUS_CANCELLED);
    runtime->platform->remove(runtime->platform_context,
                              peer->peer_id,
                              peer->generation,
                              volume->device.device_id);
    if (peer->open_files >= volume->open_files)
        peer->open_files -= volume->open_files;
    else
        peer->open_files = 0u;
    for (file_index = 0u;
         file_index < runtime->config.max_open_files_per_peer;
         file_index++)
    {
        if (peer->files[file_index].occupied &&
            peer->files[file_index].volume_id == volume->volume_id)
            memset(&peer->files[file_index],
                   0,
                   sizeof(peer->files[file_index]));
    }
    free(volume->name);
    memset(volume, 0, sizeof(*volume));
    if (peer->volume_count > 0u)
        peer->volume_count--;
    return LIBRDP_STATUS_OK;
}

/*
 * Consume one validated core drive event. Device events update the browser
 * model transactionally; terminal request events are matched to both protocol
 * and application identifiers before quotas are committed and the native
 * provider receives one completion.
 */
librdp_status server_drive_runtime_protocol_event(
    server_drive_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    const librdp_server_drive_event* event)
{
    server_drive_peer* peer =
        server_drive_find_peer(runtime, peer_id, generation);
    server_drive_pending* pending = NULL;
    server_drive_volume* volume = NULL;
    librdp_status terminal_status = LIBRDP_STATUS_OK;
    librdp_status completion_status = LIBRDP_STATUS_OK;

    if (!peer || !event ||
        event->version != LIBRDP_SERVER_DRIVE_EVENT_VERSION ||
        event->size < sizeof(*event))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->type == LIBRDP_SERVER_DRIVE_DEVICE_ADDED)
        return server_drive_add_volume(runtime, peer, event);
    if (event->type == LIBRDP_SERVER_DRIVE_DEVICE_REMOVED)
        return server_drive_remove_volume(runtime, peer, event->device);
    if (event->type != LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED &&
        event->type != LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED)
        return LIBRDP_STATUS_UNSUPPORTED;
    pending = server_drive_find_pending_protocol(runtime,
                                                 peer,
                                                 event->request_id);
    if (!pending || pending->operation != event->operation)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    volume = server_drive_find_volume(runtime, peer, pending->volume_id);
    if (!volume)
        return LIBRDP_STATUS_STATE;
    if (event->device.reconnect_generation !=
            volume->device.reconnect_generation ||
        event->device.device_id != volume->device.device_id ||
        (event->data_len > 0u && !event->data))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    terminal_status = pending->terminal_status != LIBRDP_STATUS_OK
                          ? pending->terminal_status
                          : event->status;
    if (event->type == LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED &&
        terminal_status == LIBRDP_STATUS_OK &&
        event->data_len > runtime->config.max_request_bytes)
        terminal_status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (event->type == LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED &&
        terminal_status == LIBRDP_STATUS_OK &&
        event->io_status == SERVER_DRIVE_IO_STATUS_SUCCESS)
    {
        if (event->transferred >
            runtime->config.max_transfer_bytes_per_peer -
                peer->transferred_bytes)
            terminal_status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        else if (event->operation == LIBRDP_SERVER_DRIVE_CREATE)
        {
            server_drive_file* file = NULL;
            uint32_t index = 0u;

            if (peer->open_files >=
                    runtime->config.max_open_files_per_peer ||
                event->file.reconnect_generation !=
                    volume->device.reconnect_generation ||
                event->file.device_id != volume->device.device_id ||
                event->file.file_id == 0u || event->file.reserved != 0u ||
                server_drive_find_file(runtime, peer, event->file))
                terminal_status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            else
            {
                for (index = 0u;
                     index < runtime->config.max_open_files_per_peer;
                     index++)
                {
                    if (!peer->files[index].occupied)
                    {
                        file = &peer->files[index];
                        break;
                    }
                }
                if (!file)
                    terminal_status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            }
            if (terminal_status == LIBRDP_STATUS_OK)
            {
                file->volume_id = volume->volume_id;
                file->handle = event->file;
                file->occupied = 1;
                peer->open_files++;
                volume->open_files++;
            }
        }
        else if (event->operation == LIBRDP_SERVER_DRIVE_CLOSE)
        {
            server_drive_file* file =
                server_drive_find_file(runtime, peer, event->file);

            if (!file || file->volume_id != volume->volume_id)
                terminal_status = LIBRDP_STATUS_PROTOCOL_ERROR;
            else
            {
                memset(file, 0, sizeof(*file));
                if (peer->open_files > 0u)
                    peer->open_files--;
                if (volume->open_files > 0u)
                    volume->open_files--;
            }
        }
        if (terminal_status == LIBRDP_STATUS_OK)
            peer->transferred_bytes += event->transferred;
    }
    completion_status = server_drive_complete(runtime,
                                              peer,
                                              pending,
                                              event,
                                              terminal_status);
    server_drive_pending_clear(peer, pending);
    return terminal_status == LIBRDP_STATUS_OK ? completion_status
                                               : terminal_status;
}

static librdp_status server_drive_normalize_path(
    const server_drive_runtime* runtime,
    const char* source,
    char** normalized)
{
    size_t source_len = 0u;
    size_t source_index = 0u;
    size_t output_len = 0u;
    char* output = NULL;

    if (!runtime || !source || !normalized)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (source_len <= runtime->config.max_path_bytes &&
           source[source_len] != '\0')
        source_len++;
    if (source_len > runtime->config.max_path_bytes)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    output = (char*)malloc(source_len + 2u);
    if (!output)
        return LIBRDP_STATUS_NO_MEMORY;
    output[output_len++] = '\\';
    while (source_index < source_len)
    {
        size_t component_start = 0u;
        size_t component_len = 0u;

        while (source_index < source_len &&
               (source[source_index] == '/' ||
                source[source_index] == '\\'))
            source_index++;
        if (source_index == source_len)
            break;
        component_start = source_index;
        while (source_index < source_len &&
               source[source_index] != '/' &&
               source[source_index] != '\\')
        {
            if (source[source_index] == ':')
            {
                free(output);
                return LIBRDP_STATUS_STATE;
            }
            source_index++;
        }
        component_len = source_index - component_start;
        if (component_len == 0u)
            continue;
        if ((component_len == 1u &&
             source[component_start] == '.') ||
            (component_len == 2u &&
             source[component_start] == '.' &&
             source[component_start + 1u] == '.'))
        {
            free(output);
            return LIBRDP_STATUS_STATE;
        }
        if (output_len > 1u)
            output[output_len++] = '\\';
        memcpy(output + output_len,
               source + component_start,
               component_len);
        output_len += component_len;
    }
    output[output_len] = '\0';
    *normalized = output;
    return LIBRDP_STATUS_OK;
}

static int server_drive_operation_is_mutating(
    const librdp_server_drive_request* request)
{
    switch (request->operation)
    {
        case LIBRDP_SERVER_DRIVE_WRITE:
        case LIBRDP_SERVER_DRIVE_SET_INFORMATION:
        case LIBRDP_SERVER_DRIVE_SET_VOLUME:
        case LIBRDP_SERVER_DRIVE_CONTROL:
        case LIBRDP_SERVER_DRIVE_SET_SECURITY:
            return 1;
        case LIBRDP_SERVER_DRIVE_CREATE:
            return (request->desired_access &
                    SERVER_DRIVE_WRITE_ACCESS_MASK) != 0u ||
                   request->allocation_size != 0u ||
                   request->create_disposition !=
                       SERVER_DRIVE_CREATE_DISPOSITION_OPEN;
        default:
            return 0;
    }
}

static uint64_t server_drive_request_reservation(
    const librdp_server_drive_request* request)
{
    switch (request->operation)
    {
        case LIBRDP_SERVER_DRIVE_READ:
            return request->length;
        case LIBRDP_SERVER_DRIVE_WRITE:
        case LIBRDP_SERVER_DRIVE_SET_INFORMATION:
        case LIBRDP_SERVER_DRIVE_SET_VOLUME:
        case LIBRDP_SERVER_DRIVE_SET_SECURITY:
            return request->data_len;
        case LIBRDP_SERVER_DRIVE_CONTROL:
        case LIBRDP_SERVER_DRIVE_QUERY_SECURITY:
            return request->output_buffer_length > request->data_len
                       ? request->output_buffer_length
                       : request->data_len;
        default:
            return 0u;
    }
}

/*
 * Validation boundary for one borrowed native request: normalize its path,
 * verify the issued file token and volume scope, then reserve bounded quota.
 * No caller-owned field is modified; the optional path copy is returned
 * separately and must be freed after submit.
 */
static librdp_status server_drive_validate_request(
    const server_drive_runtime* runtime,
    server_drive_peer* peer,
    const server_drive_volume* volume,
    const server_platform_drive_request* request,
    librdp_server_drive_request* normalized,
    char** normalized_path,
    uint64_t* reservation)
{
    server_drive_file* file = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !peer || !volume || !request || !normalized ||
        !normalized_path || !reservation ||
        request->operation.version != LIBRDP_SERVER_DRIVE_REQUEST_VERSION ||
        request->operation.size < sizeof(request->operation) ||
        request->request_id == 0u ||
        (!request->operation.data && request->operation.data_len > 0u) ||
        request->operation.data_len > runtime->config.max_request_bytes ||
        request->operation.length > runtime->config.max_request_bytes ||
        request->operation.output_buffer_length >
            runtime->config.max_request_bytes)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *normalized = request->operation;
    if (normalized->operation < LIBRDP_SERVER_DRIVE_CREATE ||
        normalized->operation > LIBRDP_SERVER_DRIVE_SHUTDOWN ||
        (normalized->operation == LIBRDP_SERVER_DRIVE_READ &&
         normalized->offset > UINT64_MAX - normalized->length) ||
        (normalized->operation == LIBRDP_SERVER_DRIVE_WRITE &&
         normalized->offset != UINT64_MAX &&
         normalized->offset > UINT64_MAX - normalized->data_len) ||
        (normalized->operation == LIBRDP_SERVER_DRIVE_CREATE &&
         normalized->allocation_size >
             runtime->config.max_transfer_bytes_per_peer) ||
        (normalized->operation == LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY &&
         normalized->initial_query > 1u) ||
        (normalized->operation == LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY &&
         normalized->watch_tree > 1u) ||
        (normalized->operation == LIBRDP_SERVER_DRIVE_LOCK &&
         ((normalized->lock_count > 0u && !normalized->locks) ||
          normalized->lock_operation < LIBRDP_SERVER_DRIVE_LOCK_SHARED ||
          normalized->lock_operation >
              LIBRDP_SERVER_DRIVE_UNLOCK_MULTIPLE ||
          normalized->lock_count >
              runtime->config.max_request_bytes /
                  sizeof(*normalized->locks))))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (normalized->operation == LIBRDP_SERVER_DRIVE_LOCK)
    {
        uint32_t index = 0u;

        for (index = 0u; index < normalized->lock_count; index++)
        {
            if (normalized->locks[index].length == 0u ||
                normalized->locks[index].offset >
                    UINT64_MAX - normalized->locks[index].length)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
        }
    }
    if (normalized->operation == LIBRDP_SERVER_DRIVE_CREATE ||
        normalized->operation == LIBRDP_SERVER_DRIVE_SHUTDOWN)
    {
        if (normalized->device.reconnect_generation !=
                volume->device.reconnect_generation ||
            normalized->device.device_id != volume->device.device_id)
            return LIBRDP_STATUS_STATE;
    }
    else
    {
        file = server_drive_find_file(runtime, peer, normalized->file);
        if (!file || file->volume_id != volume->volume_id)
            return LIBRDP_STATUS_STATE;
    }
    if (runtime->config.read_only &&
        server_drive_operation_is_mutating(normalized))
        return LIBRDP_STATUS_STATE;
    if (normalized->path)
    {
        status = server_drive_normalize_path(runtime,
                                             normalized->path,
                                             normalized_path);
        if (status != LIBRDP_STATUS_OK)
            return status;
        normalized->path = *normalized_path;
    }
    else if (normalized->operation == LIBRDP_SERVER_DRIVE_CREATE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *reservation = server_drive_request_reservation(normalized);
    if (*reservation > runtime->config.max_request_bytes ||
        peer->transferred_bytes >
            runtime->config.max_transfer_bytes_per_peer ||
        peer->reserved_bytes >
            runtime->config.max_transfer_bytes_per_peer -
                peer->transferred_bytes ||
        *reservation >
            runtime->config.max_transfer_bytes_per_peer -
                peer->transferred_bytes - peer->reserved_bytes)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    return LIBRDP_STATUS_OK;
}

static librdp_status server_drive_complete_immediate(
    server_drive_runtime* runtime,
    const server_platform_drive_request* request,
    librdp_status status)
{
    server_platform_drive_completion completion;

    memset(&completion, 0, sizeof(completion));
    completion.request_id = request ? request->request_id : 0u;
    completion.volume_id = request ? request->volume_id : 0u;
    completion.peer_id = request ? request->peer_id : 0u;
    completion.generation = request ? request->generation : 0u;
    completion.type = LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED;
    completion.status = status;
    completion.operation =
        request ? request->operation.operation : (librdp_server_drive_operation)0;
    completion.information_class =
        request ? request->operation.information_class : 0u;
    return runtime->platform->complete(runtime->platform_context,
                                       &completion);
}

/*
 * Validate and submit one platform-originated operation. The public server API
 * consumes all borrowed fields synchronously, after which only identifiers,
 * quota reservations and a deadline are retained by the manager.
 */
librdp_status server_drive_runtime_platform_request(
    server_drive_runtime* runtime,
    const server_platform_drive_request* request,
    uint64_t now_ns)
{
    server_drive_peer* peer = NULL;
    server_drive_volume* volume = NULL;
    server_drive_pending* pending = NULL;
    librdp_server_drive_request normalized;
    uint64_t protocol_request_id = 0u;
    uint64_t reservation = 0u;
    char* normalized_path = NULL;
    uint32_t index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!runtime || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!runtime->enabled)
        status = LIBRDP_STATUS_STATE;
    peer = server_drive_find_peer(runtime,
                                  request->peer_id,
                                  request->generation);
    if (status == LIBRDP_STATUS_OK && !peer)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
        volume = server_drive_find_volume(runtime, peer, request->volume_id);
    if (status == LIBRDP_STATUS_OK && !volume)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK &&
        server_drive_find_pending_application(runtime,
                                              peer,
                                              request->request_id))
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK &&
        peer->pending_count >= runtime->config.max_pending_per_peer)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
    {
        status = server_drive_validate_request(runtime,
                                               peer,
                                               volume,
                                               request,
                                               &normalized,
                                               &normalized_path,
                                               &reservation);
    }
    if (status == LIBRDP_STATUS_OK &&
        normalized.operation == LIBRDP_SERVER_DRIVE_CREATE &&
        peer->open_files + peer->reserved_files >=
            runtime->config.max_open_files_per_peer)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK)
    {
        for (index = 0; index < runtime->config.max_pending_per_peer; index++)
        {
            if (!peer->pending[index].occupied)
            {
                pending = &peer->pending[index];
                break;
            }
        }
        if (!pending)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = peer->protocol->submit(peer->protocol_context,
                                        &normalized,
                                        &protocol_request_id);
    }
    free(normalized_path);
    if (status != LIBRDP_STATUS_OK)
    {
        (void)server_drive_complete_immediate(runtime, request, status);
        return status;
    }
    pending->application_request_id = request->request_id;
    pending->protocol_request_id = protocol_request_id;
    pending->volume_id = volume->volume_id;
    pending->operation = normalized.operation;
    pending->information_class = normalized.information_class;
    pending->reserved_bytes = reservation;
    pending->deadline_ns =
        now_ns + (uint64_t)runtime->config.request_timeout_ms *
                     SERVER_DRIVE_NS_PER_MS;
    if (pending->deadline_ns < now_ns)
        pending->deadline_ns = UINT64_MAX;
    pending->terminal_status = LIBRDP_STATUS_OK;
    pending->reserves_file =
        normalized.operation == LIBRDP_SERVER_DRIVE_CREATE;
    pending->occupied = 1;
    peer->pending_count++;
    peer->reserved_bytes += reservation;
    if (pending->reserves_file)
        peer->reserved_files++;
    return LIBRDP_STATUS_OK;
}

librdp_status server_drive_runtime_platform_cancel(
    server_drive_runtime* runtime,
    uint32_t peer_id,
    uint32_t generation,
    uint64_t request_id)
{
    server_drive_peer* peer =
        server_drive_find_peer(runtime, peer_id, generation);
    server_drive_pending* pending = NULL;

    if (!peer || request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    pending = server_drive_find_pending_application(runtime, peer, request_id);
    if (!pending)
        return LIBRDP_STATUS_STATE;
    return server_drive_cancel_pending(runtime,
                                       peer,
                                       pending,
                                       LIBRDP_STATUS_CANCELLED);
}

void server_drive_runtime_revoke(server_drive_runtime* runtime)
{
    uint32_t index = 0;

    if (!runtime || !runtime->enabled)
        return;
    runtime->enabled = 0;
    for (index = 0; index < runtime->config.max_peers; index++)
    {
        server_drive_peer* peer = &runtime->peers[index];

        if (!peer->occupied)
            continue;
        server_drive_cancel_all_pending(runtime,
                                        peer,
                                        LIBRDP_STATUS_STATE);
        server_drive_remove_all_volumes(runtime, peer);
        if (!peer->platform_released)
        {
            runtime->platform->remove_peer(runtime->platform_context,
                                           peer->peer_id,
                                           peer->generation);
            peer->platform_released = 1;
        }
    }
}

librdp_status server_drive_runtime_set_enabled(server_drive_runtime* runtime,
                                               int enabled)
{
    if (!runtime || (enabled != 0 && enabled != 1))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (runtime->enabled == enabled)
        return LIBRDP_STATUS_OK;
    if (!enabled)
        server_drive_runtime_revoke(runtime);
    else
    {
        uint32_t index = 0u;

        runtime->enabled = 1;
        for (index = 0u; index < runtime->config.max_peers; index++)
        {
            if (runtime->peers[index].occupied)
                runtime->peers[index].platform_released = 0;
        }
    }
    return LIBRDP_STATUS_OK;
}

int server_drive_runtime_is_enabled(const server_drive_runtime* runtime)
{
    return runtime && runtime->enabled;
}

librdp_status server_drive_runtime_dispatch_timeouts(
    server_drive_runtime* runtime,
    uint64_t now_ns)
{
    uint32_t peer_index = 0;
    librdp_status first_error = LIBRDP_STATUS_OK;

    if (!runtime)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (peer_index = 0;
         peer_index < runtime->config.max_peers;
         peer_index++)
    {
        server_drive_peer* peer = &runtime->peers[peer_index];
        uint32_t pending_index = 0;

        if (!peer->occupied)
            continue;
        for (pending_index = 0;
             pending_index < runtime->config.max_pending_per_peer;
             pending_index++)
        {
            server_drive_pending* pending = &peer->pending[pending_index];
            librdp_status status = LIBRDP_STATUS_OK;

            if (!pending->occupied || pending->deadline_ns > now_ns)
                continue;
            status = server_drive_cancel_pending(runtime,
                                                 peer,
                                                 pending,
                                                 LIBRDP_STATUS_TIMEOUT);
            if (status != LIBRDP_STATUS_OK &&
                first_error == LIBRDP_STATUS_OK)
                first_error = status;
        }
    }
    return first_error;
}

int server_drive_runtime_next_timeout(const server_drive_runtime* runtime,
                                      uint64_t now_ns)
{
    uint64_t earliest = UINT64_MAX;
    uint32_t peer_index = 0;

    if (!runtime)
        return -1;
    for (peer_index = 0;
         peer_index < runtime->config.max_peers;
         peer_index++)
    {
        const server_drive_peer* peer = &runtime->peers[peer_index];
        uint32_t pending_index = 0;

        if (!peer->occupied)
            continue;
        for (pending_index = 0;
             pending_index < runtime->config.max_pending_per_peer;
             pending_index++)
        {
            const server_drive_pending* pending =
                &peer->pending[pending_index];

            if (pending->occupied && pending->deadline_ns < earliest)
                earliest = pending->deadline_ns;
        }
    }
    if (earliest == UINT64_MAX)
        return -1;
    if (earliest <= now_ns)
        return 0;
    if ((earliest - now_ns) / SERVER_DRIVE_NS_PER_MS > (uint64_t)INT_MAX)
        return INT_MAX;
    return (int)(((earliest - now_ns) + SERVER_DRIVE_NS_PER_MS - 1u) /
                 SERVER_DRIVE_NS_PER_MS);
}

size_t server_drive_runtime_volume_count(const server_drive_runtime* runtime)
{
    size_t count = 0u;
    uint32_t peer_index = 0;

    if (!runtime)
        return 0u;
    for (peer_index = 0;
         peer_index < runtime->config.max_peers;
         peer_index++)
        count += runtime->peers[peer_index].volume_count;
    return count;
}

librdp_status server_drive_runtime_volume_at(
    const server_drive_runtime* runtime,
    size_t index,
    server_drive_volume_info* info)
{
    size_t current = 0u;
    uint32_t peer_index = 0;

    if (!runtime || !info ||
        info->version != SERVER_DRIVE_VOLUME_INFO_VERSION ||
        info->size < sizeof(*info))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (peer_index = 0;
         peer_index < runtime->config.max_peers;
         peer_index++)
    {
        const server_drive_peer* peer = &runtime->peers[peer_index];
        uint32_t volume_index = 0;

        if (!peer->occupied)
            continue;
        for (volume_index = 0;
             volume_index < runtime->config.max_volumes_per_peer;
             volume_index++)
        {
            const server_drive_volume* volume = &peer->volumes[volume_index];

            if (!volume->occupied)
                continue;
            if (current++ != index)
                continue;
            info->volume_id = volume->volume_id;
            info->peer_id = peer->peer_id;
            info->generation = peer->generation;
            info->device = volume->device;
            info->name = volume->name;
            info->read_only = runtime->config.read_only;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

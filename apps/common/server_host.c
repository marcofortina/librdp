/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared desktop-server listener, provider and peer ownership.
 * Invariants: accepted peers occupy one bounded slot, peer generations change
 * on reuse, and provider callbacks cannot outlive provider stop.
 * Ownership: the host owns every core server object and scheduler; provider
 * contexts remain frontend-owned and are never freed here.
 * Threading: all methods except later wakeup/cancel integration are confined
 * to the host owner thread.
 * Trust boundary: frame buffers and rectangles are validated before public
 * server surface APIs receive them.
 */

#include "server_host_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void server_host_config_init(server_host_config* config)
{
    if (!config)
        return;
    memset(config, 0, sizeof(*config));
    config->version = SERVER_HOST_CONFIG_VERSION;
    config->size = sizeof(*config);
    (void)librdp_server_config_init(&config->server);
    server_platform_init(&config->platform);
    server_dirty_config_init(&config->dirty);
    config->max_peers = 4u;
    config->max_work_per_iteration = 32u;
    config->input_policy = SERVER_HOST_INPUT_FIRST_ACTIVE;
}

void server_host_peer_info_init(server_host_peer_info* info)
{
    if (!info)
        return;
    memset(info, 0, sizeof(*info));
    info->version = SERVER_HOST_PEER_INFO_VERSION;
    info->size = sizeof(*info);
}

static int server_host_config_valid(const server_host_config* config)
{
    return config && config->version == SERVER_HOST_CONFIG_VERSION &&
           config->size >= sizeof(*config) && config->max_peers > 0u &&
           config->max_peers <= SERVER_HOST_MAX_PEERS &&
           config->max_work_per_iteration > 0u &&
           config->input_policy >= SERVER_HOST_INPUT_DISABLED &&
           config->input_policy <= SERVER_HOST_INPUT_EXPLICIT &&
           config->platform.capture.vtable &&
           config->platform.permission.vtable &&
           server_dirty_config_validate(&config->dirty) == LIBRDP_STATUS_OK &&
           server_platform_validate(&config->platform) == LIBRDP_STATUS_OK;
}

static int server_host_configure_wakeup_fd(int fd)
{
    int status_flags = fcntl(fd, F_GETFL, 0);
    int descriptor_flags = fcntl(fd, F_GETFD, 0);

    return status_flags >= 0 && descriptor_flags >= 0 &&
           fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) == 0 &&
           fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0;
}

server_host* server_host_new(const server_host_config* config)
{
    server_host* host = NULL;
    librdp_server_config listener_config;
    size_t index = 0;

    if (!server_host_config_valid(config))
        return NULL;
    listener_config = config->server;
    listener_config.max_peers = SERVER_HOST_MAX_PEERS;
    host = (server_host*)calloc(1u, sizeof(*host));
    if (!host)
        return NULL;
    host->peers = (server_host_peer_slot*)calloc(
        config->max_peers,
        sizeof(*host->peers));
    if (!host->peers)
    {
        free(host);
        return NULL;
    }
    host->listener = librdp_server_new(&listener_config);
    if (!host->listener)
    {
        free(host->peers);
        free(host);
        return NULL;
    }
    host->wakeup_read_fd = -1;
    host->wakeup_write_fd = -1;
    {
        int wakeup_fds[2] = {-1, -1};

        if (pipe(wakeup_fds) != 0)
        {
            librdp_server_free(host->listener);
            free(host->peers);
            free(host);
            return NULL;
        }
        if (!server_host_configure_wakeup_fd(wakeup_fds[0]) ||
            !server_host_configure_wakeup_fd(wakeup_fds[1]))
        {
            close(wakeup_fds[0]);
            close(wakeup_fds[1]);
            librdp_server_free(host->listener);
            free(host->peers);
            free(host);
            return NULL;
        }
        host->wakeup_read_fd = wakeup_fds[0];
        host->wakeup_write_fd = wakeup_fds[1];
    }
    host->platform = config->platform;
    host->dirty_config = config->dirty;
    host->peer_capacity = config->max_peers;
    host->max_work_per_iteration = config->max_work_per_iteration;
    host->input_policy = config->input_policy;
    host->state = SERVER_HOST_NEW;
    host->next_peer_id = 1u;
    atomic_init(&host->cancellation_requested, 0);
    for (index = 0; index < SERVER_PLATFORM_PROVIDER_COUNT; index++)
    {
        host->provider_states[index] =
            server_platform_provider_ready(&host->platform,
                                           (server_platform_provider_kind)index)
                ? SERVER_HOST_PROVIDER_STOPPED
                : SERVER_HOST_PROVIDER_UNAVAILABLE;
    }
    return host;
}

server_host_peer_slot* server_host_find_peer_slot(server_host* host,
                                                  uint32_t peer_id)
{
    size_t index = 0;

    if (!host || peer_id == 0u)
        return NULL;
    for (index = 0; index < host->peer_capacity; index++)
    {
        if (host->peers[index].occupied && host->peers[index].id == peer_id)
            return &host->peers[index];
    }
    return NULL;
}

static void server_host_release_input_owner(server_host* host)
{
    server_host_peer_slot* owner = NULL;

    if (!host || host->input_owner_id == 0u)
        return;
    owner = server_host_find_peer_slot(host, host->input_owner_id);
    if (owner)
        owner->input_owner = 0;
    if (host->platform.input.vtable &&
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] ==
            SERVER_HOST_PROVIDER_READY)
    {
        const server_platform_input_vtable* input =
            (const server_platform_input_vtable*)host->platform.input.vtable;

        input->release_all(host->platform.input.context);
    }
    host->input_owner_id = 0u;
}

/*
 * Cancel every peer-scoped request before platform generations are revoked.
 * Extension cancellation is metadata-only and remains safe for families that
 * never negotiated a channel.
 */
static void server_host_cancel_peer_protocol(librdp_server_peer* peer)
{
    librdp_server_extension_family family =
        LIBRDP_SERVER_EXTENSION_CLIPBOARD;

    if (!peer)
        return;
    (void)librdp_server_peer_cancel_clipboard_requests(peer);
    for (family = LIBRDP_SERVER_EXTENSION_CLIPBOARD;
         family <= LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING;
         family = (librdp_server_extension_family)((int)family + 1))
        (void)librdp_server_peer_cancel_extension(peer, family);
}

void server_host_release_peer_slot(server_host_peer_slot* slot)
{
    server_host* host = slot ? slot->host : NULL;

    if (!slot || !slot->occupied)
        return;
    if (host && host->input_owner_id == slot->id)
        server_host_release_input_owner(host);
    slot->state = SERVER_HOST_PEER_CLOSING;
    if (slot->protocol)
    {
        server_host_cancel_peer_protocol(slot->protocol);
        if (host &&
            host->provider_started[SERVER_PLATFORM_PROVIDER_CLIPBOARD])
        {
            const server_platform_clipboard_vtable* clipboard =
                (const server_platform_clipboard_vtable*)
                    host->platform.clipboard.vtable;

            clipboard->cancel_peer(host->platform.clipboard.context,
                                   slot->id,
                                   slot->clipboard_generation);
            clipboard->release_ownership(
                host->platform.clipboard.context,
                slot->clipboard_generation);
        }
        if (host && host->provider_started[SERVER_PLATFORM_PROVIDER_DRIVE])
        {
            const server_platform_drive_vtable* drive =
                (const server_platform_drive_vtable*)
                    host->platform.drive.vtable;

            drive->remove_peer(host->platform.drive.context,
                               slot->id,
                               slot->drive_generation);
        }
        (void)librdp_server_peer_close(slot->protocol);
        librdp_server_peer_free(slot->protocol);
    }
    server_dirty_scheduler_free(slot->dirty);
    slot->protocol = NULL;
    slot->dirty = NULL;
    slot->surface_width = 0u;
    slot->surface_height = 0u;
    slot->clipboard_generation++;
    if (slot->clipboard_generation == 0u)
        slot->clipboard_generation = 1u;
    slot->drive_generation++;
    if (slot->drive_generation == 0u)
        slot->drive_generation = 1u;
    slot->state = SERVER_HOST_PEER_CLOSED;
    slot->occupied = 0;
    slot->input_owner = 0;
    if (slot->host && slot->host->peer_count > 0u)
        slot->host->peer_count--;
}

static server_host_provider_state server_host_permission_state(
    server_host* host,
    server_platform_permission_kind kind)
{
    const server_platform_permission_vtable* table =
        (const server_platform_permission_vtable*)
            host->platform.permission.vtable;
    server_platform_permission_state state = SERVER_PLATFORM_PERMISSION_UNKNOWN;
    librdp_status status = table->query(host->platform.permission.context,
                                        kind,
                                        &state);

    if (status != LIBRDP_STATUS_OK)
        return SERVER_HOST_PROVIDER_FAILED;
    return state == SERVER_PLATFORM_PERMISSION_GRANTED
               ? SERVER_HOST_PROVIDER_READY
               : SERVER_HOST_PROVIDER_DENIED;
}

static int server_host_multiply_size(size_t left,
                                     size_t right,
                                     size_t* result)
{
    if (!result || (left != 0u && right > SIZE_MAX / left))
        return 0;
    *result = left * right;
    return 1;
}

/*
 * Validate one borrowed full-frame mapping and copy only its bounded dirty
 * rectangles into each peer-owned surface. Malformed provider geometry is
 * dropped without mutating peer scheduling state.
 */
static void server_host_capture_frame(const server_platform_frame* frame,
                                      void* user_data)
{
    server_host* host = (server_host*)user_data;
    size_t frame_bytes = 0;
    size_t row_bytes = 0;
    size_t index = 0;

    if (!host || host->state != SERVER_HOST_LISTENING || !frame ||
        !frame->pixels || frame->width == 0u || frame->height == 0u ||
        !server_host_multiply_size((size_t)frame->width, 4u, &row_bytes) ||
        frame->stride < row_bytes ||
        !server_host_multiply_size((size_t)frame->height,
                                   frame->stride,
                                   &frame_bytes))
        return;
    if (frame->pixels_len < frame_bytes ||
        (frame->dirty_count > 0u && !frame->dirty_rects))
        return;
    for (index = 0; index < host->peer_capacity; index++)
    {
        server_host_peer_slot* slot = &host->peers[index];
        size_t dirty_index = 0;
        server_platform_rect full;

        if (!slot->occupied || !slot->protocol)
            continue;
        if (slot->surface_width != frame->width ||
            slot->surface_height != frame->height)
        {
            if (librdp_server_peer_surface_resize(slot->protocol,
                                                  frame->width,
                                                  frame->height) !=
                LIBRDP_STATUS_OK ||
                server_dirty_scheduler_resize(slot->dirty,
                                               frame->width,
                                               frame->height,
                                               frame->timestamp_ns,
                                               1) != LIBRDP_STATUS_OK)
                continue;
            slot->surface_width = frame->width;
            slot->surface_height = frame->height;
        }
        full.x = 0u;
        full.y = 0u;
        full.width = frame->width;
        full.height = frame->height;
        for (dirty_index = 0;
             dirty_index < (frame->dirty_count ? frame->dirty_count : 1u);
             dirty_index++)
        {
            const server_platform_rect* rect =
                frame->dirty_count ? &frame->dirty_rects[dirty_index] : &full;
            size_t offset = 0;

            if (rect->width == 0u || rect->height == 0u ||
                rect->x >= frame->width || rect->y >= frame->height ||
                rect->width > frame->width - rect->x ||
                rect->height > frame->height - rect->y ||
                (size_t)rect->y > SIZE_MAX / frame->stride)
                continue;
            offset = (size_t)rect->y * frame->stride;
            if ((size_t)rect->x > (SIZE_MAX - offset) / 4u)
                continue;
            offset += (size_t)rect->x * 4u;
            if (offset >= frame->pixels_len)
                continue;
            if (librdp_server_peer_surface_blit_bgra32(
                    slot->protocol,
                    rect->x,
                    rect->y,
                    rect->width,
                    rect->height,
                    frame->stride,
                    frame->pixels + offset) == LIBRDP_STATUS_OK)
            {
                (void)server_dirty_scheduler_invalidate(
                    slot->dirty,
                    rect,
                    frame->timestamp_ns);
            }
        }
    }
}

static void server_host_capture_lost(librdp_status status, void* user_data)
{
    server_host* host = (server_host*)user_data;

    (void)status;
    if (!host)
        return;
    host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
        SERVER_HOST_PROVIDER_FAILED;
    host->state = SERVER_HOST_FAILED;
}

static void server_host_pointer_update(
    const server_platform_pointer* pointer,
    void* user_data)
{
    (void)pointer;
    (void)user_data;
}

static void server_host_clipboard_formats(
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation,
    void* user_data)
{
    (void)formats;
    (void)format_count;
    (void)generation;
    (void)user_data;
}

static void server_host_clipboard_data(
    const server_platform_clipboard_data* data,
    void* user_data)
{
    (void)data;
    (void)user_data;
}

static void server_host_drive_request(uint32_t peer_id,
                                      uint32_t generation,
                                      uint64_t request_id,
                                      void* user_data)
{
    (void)peer_id;
    (void)generation;
    (void)request_id;
    (void)user_data;
}

static void server_host_permission_changed(
    server_platform_permission_kind kind,
    server_platform_permission_state state,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    server_platform_provider_kind provider = SERVER_PLATFORM_PROVIDER_COUNT;

    if (!host)
        return;
    switch (kind)
    {
        case SERVER_PLATFORM_PERMISSION_CAPTURE:
            provider = SERVER_PLATFORM_PROVIDER_CAPTURE;
            break;
        case SERVER_PLATFORM_PERMISSION_INPUT:
            provider = SERVER_PLATFORM_PROVIDER_INPUT;
            break;
        case SERVER_PLATFORM_PERMISSION_CLIPBOARD:
            provider = SERVER_PLATFORM_PROVIDER_CLIPBOARD;
            break;
        case SERVER_PLATFORM_PERMISSION_DRIVE:
            provider = SERVER_PLATFORM_PROVIDER_DRIVE;
            break;
        default:
            break;
    }
    if (provider < SERVER_PLATFORM_PROVIDER_COUNT)
    {
        host->provider_states[provider] =
            state == SERVER_PLATFORM_PERMISSION_GRANTED
                ? SERVER_HOST_PROVIDER_READY
                : SERVER_HOST_PROVIDER_DENIED;
    }
}

/*
 * Start providers in dependency order after permission checks. The caller
 * owns rollback, so a failure leaves a precise FAILED/DENIED state and no
 * listener is exposed before every mandatory provider is usable.
 */
static librdp_status server_host_start_providers(server_host* host)
{
    const server_platform_permission_vtable* permission =
        (const server_platform_permission_vtable*)
            host->platform.permission.vtable;
    const server_platform_capture_vtable* capture =
        (const server_platform_capture_vtable*)host->platform.capture.vtable;
    const server_platform_pointer_vtable* pointer =
        (const server_platform_pointer_vtable*)host->platform.pointer.vtable;
    const server_platform_clipboard_vtable* clipboard =
        (const server_platform_clipboard_vtable*)host->platform.clipboard.vtable;
    const server_platform_drive_vtable* drive =
        (const server_platform_drive_vtable*)host->platform.drive.vtable;
    server_platform_permission_sink permission_sink;
    server_platform_capture_sink capture_sink;
    server_platform_pointer_sink pointer_sink;
    server_platform_clipboard_sink clipboard_sink;
    server_platform_drive_sink drive_sink;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&permission_sink, 0, sizeof(permission_sink));
    permission_sink.changed = server_host_permission_changed;
    permission_sink.user_data = host;
    host->provider_states[SERVER_PLATFORM_PROVIDER_PERMISSION] =
        SERVER_HOST_PROVIDER_STARTING;
    status = permission->start(host->platform.permission.context,
                               &permission_sink);
    if (status != LIBRDP_STATUS_OK)
    {
        host->provider_states[SERVER_PLATFORM_PROVIDER_PERMISSION] =
            SERVER_HOST_PROVIDER_FAILED;
        return status;
    }
    host->provider_started[SERVER_PLATFORM_PROVIDER_PERMISSION] = 1u;
    host->provider_states[SERVER_PLATFORM_PROVIDER_PERMISSION] =
        SERVER_HOST_PROVIDER_READY;

    host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
        server_host_permission_state(host, SERVER_PLATFORM_PERMISSION_CAPTURE);
    if (host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] !=
        SERVER_HOST_PROVIDER_READY)
        return LIBRDP_STATUS_STATE;
    memset(&capture_sink, 0, sizeof(capture_sink));
    capture_sink.frame = server_host_capture_frame;
    capture_sink.lost = server_host_capture_lost;
    capture_sink.user_data = host;
    host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
        SERVER_HOST_PROVIDER_STARTING;
    status = capture->start(host->platform.capture.context, &capture_sink);
    if (status != LIBRDP_STATUS_OK)
    {
        host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
            SERVER_HOST_PROVIDER_FAILED;
        return status;
    }
    host->provider_started[SERVER_PLATFORM_PROVIDER_CAPTURE] = 1u;
    host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
        SERVER_HOST_PROVIDER_READY;

    if (pointer)
    {
        memset(&pointer_sink, 0, sizeof(pointer_sink));
        pointer_sink.update = server_host_pointer_update;
        pointer_sink.user_data = host;
        host->provider_states[SERVER_PLATFORM_PROVIDER_POINTER] =
            SERVER_HOST_PROVIDER_STARTING;
        status = pointer->start(host->platform.pointer.context, &pointer_sink);
        if (status != LIBRDP_STATUS_OK)
        {
            host->provider_states[SERVER_PLATFORM_PROVIDER_POINTER] =
                SERVER_HOST_PROVIDER_FAILED;
            return status;
        }
        host->provider_started[SERVER_PLATFORM_PROVIDER_POINTER] = 1u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_POINTER] =
            SERVER_HOST_PROVIDER_READY;
    }

    if (host->platform.input.vtable)
    {
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] =
            server_host_permission_state(host, SERVER_PLATFORM_PERMISSION_INPUT);
    }
    if (clipboard)
    {
        host->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] =
            server_host_permission_state(host,
                                         SERVER_PLATFORM_PERMISSION_CLIPBOARD);
        if (host->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] ==
            SERVER_HOST_PROVIDER_READY)
        {
            memset(&clipboard_sink, 0, sizeof(clipboard_sink));
            clipboard_sink.formats = server_host_clipboard_formats;
            clipboard_sink.data = server_host_clipboard_data;
            clipboard_sink.user_data = host;
            host->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] =
                SERVER_HOST_PROVIDER_STARTING;
            status = clipboard->start(host->platform.clipboard.context,
                                      &clipboard_sink);
            if (status != LIBRDP_STATUS_OK)
            {
                host->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] =
                    SERVER_HOST_PROVIDER_FAILED;
                return status;
            }
            host->provider_started[SERVER_PLATFORM_PROVIDER_CLIPBOARD] = 1u;
            host->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] =
                SERVER_HOST_PROVIDER_READY;
        }
    }
    if (drive)
    {
        host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] =
            server_host_permission_state(host, SERVER_PLATFORM_PERMISSION_DRIVE);
        if (host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] ==
            SERVER_HOST_PROVIDER_READY)
        {
            memset(&drive_sink, 0, sizeof(drive_sink));
            drive_sink.request = server_host_drive_request;
            drive_sink.user_data = host;
            host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] =
                SERVER_HOST_PROVIDER_STARTING;
            status = drive->start(host->platform.drive.context, &drive_sink);
            if (status != LIBRDP_STATUS_OK)
            {
                host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] =
                    SERVER_HOST_PROVIDER_FAILED;
                return status;
            }
            host->provider_started[SERVER_PLATFORM_PROVIDER_DRIVE] = 1u;
            host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] =
                SERVER_HOST_PROVIDER_READY;
        }
    }
    return LIBRDP_STATUS_OK;
}

static void server_host_stop_providers(server_host* host)
{
    const server_platform_permission_vtable* permission = NULL;
    const server_platform_capture_vtable* capture = NULL;
    const server_platform_pointer_vtable* pointer = NULL;
    const server_platform_clipboard_vtable* clipboard = NULL;
    const server_platform_drive_vtable* drive = NULL;

    if (!host)
        return;
    permission = (const server_platform_permission_vtable*)
        host->platform.permission.vtable;
    capture =
        (const server_platform_capture_vtable*)host->platform.capture.vtable;
    pointer =
        (const server_platform_pointer_vtable*)host->platform.pointer.vtable;
    clipboard = (const server_platform_clipboard_vtable*)
        host->platform.clipboard.vtable;
    drive =
        (const server_platform_drive_vtable*)host->platform.drive.vtable;
    if (drive &&
        host->provider_started[SERVER_PLATFORM_PROVIDER_DRIVE])
    {
        drive->stop(host->platform.drive.context);
        host->provider_started[SERVER_PLATFORM_PROVIDER_DRIVE] = 0u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
    if (clipboard &&
        host->provider_started[SERVER_PLATFORM_PROVIDER_CLIPBOARD])
    {
        clipboard->stop(host->platform.clipboard.context);
        host->provider_started[SERVER_PLATFORM_PROVIDER_CLIPBOARD] = 0u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
    if (host->platform.input.vtable &&
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] ==
            SERVER_HOST_PROVIDER_READY)
    {
        const server_platform_input_vtable* input =
            (const server_platform_input_vtable*)host->platform.input.vtable;

        if (host->input_owner_id != 0u)
        {
            input->release_all(host->platform.input.context);
            host->input_owner_id = 0u;
        }
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
    if (pointer &&
        host->provider_started[SERVER_PLATFORM_PROVIDER_POINTER])
    {
        pointer->stop(host->platform.pointer.context);
        host->provider_started[SERVER_PLATFORM_PROVIDER_POINTER] = 0u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_POINTER] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
    if (capture &&
        host->provider_started[SERVER_PLATFORM_PROVIDER_CAPTURE])
    {
        capture->stop(host->platform.capture.context);
        host->provider_started[SERVER_PLATFORM_PROVIDER_CAPTURE] = 0u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
    if (permission &&
        host->provider_started[SERVER_PLATFORM_PROVIDER_PERMISSION])
    {
        permission->stop(host->platform.permission.context);
        host->provider_started[SERVER_PLATFORM_PROVIDER_PERMISSION] = 0u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_PERMISSION] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
}

/*
 * Provider startup is transactional: any failure closes the listener and
 * stops every provider that reached READY before exposing LISTENING state.
 */
librdp_status server_host_start(server_host* host)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t wakeup_bytes[64];
    ssize_t count = 0;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state != SERVER_HOST_NEW && host->state != SERVER_HOST_STOPPED)
        return LIBRDP_STATUS_STATE;
    atomic_store_explicit(&host->cancellation_requested,
                          0,
                          memory_order_release);
    do
    {
        count = read(host->wakeup_read_fd,
                     wakeup_bytes,
                     sizeof(wakeup_bytes));
    } while (count > 0 || (count < 0 && errno == EINTR));
    host->state = SERVER_HOST_STARTING;
    status = server_host_start_providers(host);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_listen(host->listener);
    if (status != LIBRDP_STATUS_OK)
    {
        librdp_server_close(host->listener);
        server_host_stop_providers(host);
        host->state = SERVER_HOST_FAILED;
        return status;
    }
    host->state = SERVER_HOST_LISTENING;
    return LIBRDP_STATUS_OK;
}

librdp_status server_host_stop(server_host* host)
{
    size_t index = 0;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state == SERVER_HOST_STOPPED)
        return LIBRDP_STATUS_OK;
    host->state = SERVER_HOST_STOPPING;
    librdp_server_close(host->listener);
    for (index = 0; index < host->peer_capacity; index++)
        server_host_release_peer_slot(&host->peers[index]);
    server_host_stop_providers(host);
    host->state = SERVER_HOST_STOPPED;
    return LIBRDP_STATUS_OK;
}

void server_host_free(server_host* host)
{
    if (!host)
        return;
    (void)server_host_stop(host);
    librdp_server_free(host->listener);
    if (host->wakeup_read_fd >= 0)
        close(host->wakeup_read_fd);
    if (host->wakeup_write_fd >= 0)
        close(host->wakeup_write_fd);
    free(host->pollfds);
    free(host->peers);
    memset(host, 0, sizeof(*host));
    free(host);
}

server_host_state server_host_get_state(const server_host* host)
{
    return host ? host->state : SERVER_HOST_FAILED;
}

server_host_provider_state server_host_get_provider_state(
    const server_host* host,
    server_platform_provider_kind kind)
{
    if (!host || kind < SERVER_PLATFORM_PROVIDER_CAPTURE ||
        kind >= SERVER_PLATFORM_PROVIDER_COUNT)
        return SERVER_HOST_PROVIDER_UNAVAILABLE;
    return host->provider_states[kind];
}

uint16_t server_host_local_port(const server_host* host)
{
    return host ? librdp_server_local_port(host->listener) : 0u;
}

static void server_host_peer_input(librdp_server_peer* peer,
                                   const librdp_server_input_event* event,
                                   void* user_data)
{
    (void)peer;
    (void)server_host_dispatch_peer_input(
        (server_host_peer_slot*)user_data,
        event);
}

static int server_host_event_is_native_input(
    librdp_server_input_type type)
{
    return type == LIBRDP_SERVER_INPUT_SYNCHRONIZE ||
           type == LIBRDP_SERVER_INPUT_SCANCODE_KEY ||
           type == LIBRDP_SERVER_INPUT_UNICODE_KEY ||
           type == LIBRDP_SERVER_INPUT_MOUSE ||
           type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE;
}

librdp_status server_host_dispatch_peer_input(
    server_host_peer_slot* slot,
    const librdp_server_input_event* event)
{
    server_host* host = slot ? slot->host : NULL;
    const server_platform_input_vtable* input = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !slot->occupied || !event ||
        event->version != LIBRDP_SERVER_INPUT_EVENT_VERSION ||
        event->size < sizeof(*event))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!server_host_event_is_native_input(event->type))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (slot->state != SERVER_HOST_PEER_ACTIVE || !slot->input_owner ||
        host->input_owner_id != slot->id ||
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] !=
            SERVER_HOST_PROVIDER_READY ||
        !host->platform.input.vtable)
        return LIBRDP_STATUS_STATE;
    input =
        (const server_platform_input_vtable*)host->platform.input.vtable;
    status = input->inject(host->platform.input.context, event);
    if (status != LIBRDP_STATUS_OK)
    {
        server_host_release_input_owner(host);
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] =
            SERVER_HOST_PROVIDER_FAILED;
    }
    return status;
}

static librdp_status server_host_assign_input_owner(server_host* host,
                                                    uint32_t peer_id)
{
    server_host_peer_slot* next = NULL;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer_id == host->input_owner_id)
        return LIBRDP_STATUS_OK;
    if (peer_id != 0u)
    {
        next = server_host_find_peer_slot(host, peer_id);
        if (!next || next->state == SERVER_HOST_PEER_CLOSED ||
            next->state == SERVER_HOST_PEER_FAILED)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        if (host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] !=
            SERVER_HOST_PROVIDER_READY)
            return LIBRDP_STATUS_STATE;
    }
    server_host_release_input_owner(host);
    if (next)
    {
        next->input_owner = 1;
        host->input_owner_id = next->id;
    }
    return LIBRDP_STATUS_OK;
}

static void server_host_peer_event(librdp_server_peer* peer,
                                   const librdp_server_event* event,
                                   void* user_data)
{
    server_host_peer_slot* slot = (server_host_peer_slot*)user_data;

    (void)peer;
    if (!slot || !event)
        return;
    if (event->type == LIBRDP_SERVER_EVENT_STATE_CHANGED)
    {
        if (event->new_state == LIBRDP_SERVER_PEER_ACTIVE)
        {
            slot->state = SERVER_HOST_PEER_ACTIVE;
            if (slot->host->input_policy ==
                    SERVER_HOST_INPUT_FIRST_ACTIVE &&
                slot->host->input_owner_id == 0u)
                (void)server_host_assign_input_owner(slot->host, slot->id);
        }
        else if (event->new_state == LIBRDP_SERVER_PEER_CLOSED)
        {
            slot->state = SERVER_HOST_PEER_CLOSED;
            if (slot->host->input_owner_id == slot->id)
                server_host_release_input_owner(slot->host);
        }
        else if (event->new_state == LIBRDP_SERVER_PEER_FAILED)
        {
            slot->state = SERVER_HOST_PEER_FAILED;
            if (slot->host->input_owner_id == slot->id)
                server_host_release_input_owner(slot->host);
        }
        else
            slot->state = SERVER_HOST_PEER_NEGOTIATING;
    }
    else if (event->type == LIBRDP_SERVER_EVENT_ERROR)
    {
        slot->state = SERVER_HOST_PEER_FAILED;
    }
}

static librdp_status server_host_prepare_peer_slot(
    server_host* host,
    server_host_peer_slot* slot,
    librdp_server_peer* peer)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t generation = 0;
    uint32_t clipboard_generation = 0;
    uint32_t drive_generation = 0;
    uint32_t candidate_id = 0;
    size_t attempts = 0;

    generation = slot->generation + 1u;
    if (generation == 0u)
        generation = 1u;
    clipboard_generation = slot->clipboard_generation;
    if (clipboard_generation == 0u)
        clipboard_generation = 1u;
    drive_generation = slot->drive_generation;
    if (drive_generation == 0u)
        drive_generation = 1u;
    do
    {
        candidate_id = host->next_peer_id++;
        if (candidate_id == 0u)
            continue;
        attempts++;
    } while (server_host_find_peer_slot(host, candidate_id) &&
             attempts <= host->peer_capacity);
    if (candidate_id == 0u ||
        server_host_find_peer_slot(host, candidate_id))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    memset(slot, 0, sizeof(*slot));
    slot->host = host;
    slot->protocol = peer;
    slot->dirty = server_dirty_scheduler_new(&host->dirty_config);
    if (!slot->dirty)
        return LIBRDP_STATUS_NO_MEMORY;
    slot->id = candidate_id;
    slot->generation = generation;
    slot->clipboard_generation = clipboard_generation;
    slot->drive_generation = drive_generation;
    slot->surface_width = librdp_server_peer_desktop_width(peer);
    slot->surface_height = librdp_server_peer_desktop_height(peer);
    status = server_dirty_scheduler_resize(slot->dirty,
                                           slot->surface_width,
                                           slot->surface_height,
                                           0u,
                                           0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_server_peer_set_input_callback(peer,
                                                   server_host_peer_input,
                                                   slot);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_set_event_callback(peer,
                                                       server_host_peer_event,
                                                       slot);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    slot->state = SERVER_HOST_PEER_ACCEPTED;
    slot->occupied = 1;
    host->peer_count++;
    return LIBRDP_STATUS_OK;
}

librdp_status server_host_accept_pending(server_host* host)
{
    server_host_peer_slot* slot = NULL;
    librdp_server_peer* peer = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t index = 0;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state != SERVER_HOST_LISTENING)
        return LIBRDP_STATUS_STATE;
    if (host->peer_count >= host->peer_capacity)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (index = 0; index < host->peer_capacity; index++)
    {
        if (!host->peers[index].occupied)
        {
            slot = &host->peers[index];
            break;
        }
    }
    if (!slot)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    status = librdp_server_accept(host->listener, 0, &peer);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = server_host_prepare_peer_slot(host, slot, peer);
    if (status == LIBRDP_STATUS_OK)
    {
        const server_platform_capture_vtable* capture =
            (const server_platform_capture_vtable*)
                host->platform.capture.vtable;

        status = capture->request_frame(host->platform.capture.context);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        if (slot->occupied)
            server_host_release_peer_slot(slot);
        else
        {
            server_dirty_scheduler_free(slot->dirty);
            slot->dirty = NULL;
            slot->protocol = NULL;
            librdp_server_peer_free(peer);
        }
    }
    return status;
}

size_t server_host_peer_count(const server_host* host)
{
    return host ? host->peer_count : 0u;
}

librdp_status server_host_peer_at(const server_host* host,
                                  size_t index,
                                  server_host_peer_info* info)
{
    size_t slot_index = 0;
    size_t found = 0;

    if (!host || !info || info->version != SERVER_HOST_PEER_INFO_VERSION ||
        info->size < sizeof(*info))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (slot_index = 0; slot_index < host->peer_capacity; slot_index++)
    {
        const server_host_peer_slot* slot = &host->peers[slot_index];

        if (!slot->occupied)
            continue;
        if (found++ != index)
            continue;
        info->id = slot->id;
        info->generation = slot->generation;
        info->state = slot->state;
        info->protocol_state =
            librdp_server_peer_get_state(slot->protocol);
        info->desktop_width = slot->surface_width;
        info->desktop_height = slot->surface_height;
        info->input_owner = slot->input_owner;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status server_host_close_peer(server_host* host, uint32_t peer_id)
{
    server_host_peer_slot* slot =
        server_host_find_peer_slot(host, peer_id);

    if (!slot)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    server_host_release_peer_slot(slot);
    return LIBRDP_STATUS_OK;
}

librdp_status server_host_set_input_owner(server_host* host,
                                          uint32_t peer_id)
{
    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->input_policy == SERVER_HOST_INPUT_DISABLED)
        return peer_id == 0u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_STATE;
    if (host->input_policy != SERVER_HOST_INPUT_EXPLICIT)
        return LIBRDP_STATUS_STATE;
    return server_host_assign_input_owner(host, peer_id);
}

uint32_t server_host_input_owner(const server_host* host)
{
    return host ? host->input_owner_id : 0u;
}

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

typedef struct server_host_provider_mapping
{
    librdp_server_extension_family family;
    server_platform_provider_kind provider;
} server_host_provider_mapping;

static const server_host_provider_mapping server_host_provider_mappings[] = {
    {LIBRDP_SERVER_EXTENSION_GRAPHICS, SERVER_PLATFORM_PROVIDER_CAPTURE},
    {LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR, SERVER_PLATFORM_PROVIDER_POINTER},
    {LIBRDP_SERVER_EXTENSION_CORE_INPUT, SERVER_PLATFORM_PROVIDER_INPUT},
    {LIBRDP_SERVER_EXTENSION_TOUCH_INPUT, SERVER_PLATFORM_PROVIDER_INPUT},
    {LIBRDP_SERVER_EXTENSION_CLIPBOARD, SERVER_PLATFORM_PROVIDER_CLIPBOARD},
    {LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION, SERVER_PLATFORM_PROVIDER_DRIVE},
    {LIBRDP_SERVER_EXTENSION_FILESYSTEM, SERVER_PLATFORM_PROVIDER_DRIVE},
};

static uint16_t server_host_peer_clipboard_channel(
    const librdp_server_peer* peer,
    uint16_t joined_channel_id);
static librdp_status server_host_start_peer_clipboard(
    server_host_peer_slot* slot,
    librdp_server_peer* peer);

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
    server_clipboard_config_init(&config->clipboard);
    server_drive_config_init(&config->drive);
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
           config->max_work_per_iteration <= SERVER_HOST_WORK_LIMIT &&
           config->input_policy >= SERVER_HOST_INPUT_DISABLED &&
           config->input_policy <= SERVER_HOST_INPUT_EXPLICIT &&
           config->platform.capture.vtable &&
           config->platform.permission.vtable &&
           server_clipboard_config_validate(&config->clipboard) ==
               LIBRDP_STATUS_OK &&
           server_drive_config_validate(&config->drive) ==
               LIBRDP_STATUS_OK &&
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

/*
 * Construct the listener and bounded peer/provider runtimes as one ownership
 * unit. Every allocation and descriptor created here is unwound on failure;
 * borrowed platform providers remain valid until server_host_free().
 */
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
    if (config->credentials_provider &&
        librdp_server_set_credentials_provider(
            host->listener,
            config->credentials_provider,
            config->credentials_provider_user_data) != LIBRDP_STATUS_OK)
    {
        librdp_server_free(host->listener);
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
    host->drive_configured = config->drive.enabled ? 1u : 0u;
    if (host->platform.clipboard.vtable)
    {
        server_clipboard_config clipboard_config = config->clipboard;

        clipboard_config.max_peers = config->max_peers;
        host->clipboard = server_clipboard_runtime_new(
            &clipboard_config,
            (const server_platform_clipboard_vtable*)
                host->platform.clipboard.vtable,
            host->platform.clipboard.context);
        if (!host->clipboard)
        {
            close(host->wakeup_read_fd);
            close(host->wakeup_write_fd);
            librdp_server_free(host->listener);
            free(host->peers);
            free(host);
            return NULL;
        }
    }
    if (host->platform.drive.vtable)
    {
        server_drive_config drive_config = config->drive;

        drive_config.max_peers = config->max_peers;
        host->drive = server_drive_runtime_new(
            &drive_config,
            (const server_platform_drive_vtable*)
                host->platform.drive.vtable,
            host->platform.drive.context);
        if (!host->drive)
        {
            server_clipboard_runtime_free(host->clipboard);
            close(host->wakeup_read_fd);
            close(host->wakeup_write_fd);
            librdp_server_free(host->listener);
            free(host->peers);
            free(host);
            return NULL;
        }
    }
    host->max_work_per_iteration = config->max_work_per_iteration;
    host->input_policy = config->input_policy;
    host->trace_callback = config->trace_callback;
    host->trace_user_data = config->trace_user_data;
    host->channel_callback = config->channel_callback;
    host->channel_user_data = config->channel_user_data;
    host->extension_callback = config->extension_callback;
    host->extension_user_data = config->extension_user_data;
    host->state = SERVER_HOST_NEW;
    host->next_peer_id = 1u;
    atomic_init(&host->cancellation_requested, 0);
    server_host_metrics_init(&host->metrics);
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
    if (host->platform.input.vtable)
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
    server_host_peer_state terminal_state =
        slot ? slot->state : SERVER_HOST_PEER_CLOSED;

    if (!slot || !slot->occupied)
        return;
    if (host && host->input_owner_id == slot->id)
        server_host_release_input_owner(host);
    slot->state = SERVER_HOST_PEER_CLOSING;
    if (slot->protocol)
    {
        server_host_cancel_peer_protocol(slot->protocol);
        (void)librdp_server_peer_close(slot->protocol);
        if (host && host->clipboard)
        {
            server_clipboard_runtime_remove_peer(host->clipboard,
                                                 slot->id,
                                                 slot->generation);
            server_host_metric_add(&host->metrics.clipboard_cleanups, 1u);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_CLIPBOARD_CLEANUP,
                                   slot,
                                   LIBRDP_STATUS_OK,
                                   slot->generation,
                                   1u);
        }
        if (host && host->drive)
        {
            server_drive_runtime_remove_peer(host->drive,
                                             slot->id,
                                             slot->generation);
            server_host_metric_add(&host->metrics.drive_cleanups, 1u);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_DRIVE_CLEANUP,
                                   slot,
                                   LIBRDP_STATUS_OK,
                                   slot->generation,
                                   1u);
        }
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
    slot->state = SERVER_HOST_PEER_CLOSED;
    slot->occupied = 0;
    slot->input_owner = 0;
    if (host)
    {
        if (terminal_state == SERVER_HOST_PEER_FAILED)
            server_host_metric_add(&host->metrics.peers_failed, 1u);
        else
            server_host_metric_add(&host->metrics.peers_closed, 1u);
        server_host_trace_emit(
            host,
            SERVER_HOST_TRACE_PEER_CLEANUP,
            slot,
            terminal_state == SERVER_HOST_PEER_FAILED
                ? LIBRDP_STATUS_IO_ERROR
                : LIBRDP_STATUS_OK,
            (uint64_t)terminal_state,
            1u);
        if (host->peer_count > 0u)
            host->peer_count--;
    }
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

static librdp_status server_host_sync_peer_surface(
    server_host_peer_slot* slot,
    uint64_t timestamp_ns,
    int invalidate)
{
    uint32_t width = 0u;
    uint32_t height = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!slot || !slot->protocol || !slot->dirty)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    width = librdp_server_peer_desktop_width(slot->protocol);
    height = librdp_server_peer_desktop_height(slot->protocol);
    if (width == 0u || height == 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (slot->surface_width == width && slot->surface_height == height &&
        !invalidate)
        return LIBRDP_STATUS_OK;
    status = server_dirty_scheduler_resize(slot->dirty,
                                           width,
                                           height,
                                           timestamp_ns,
                                           invalidate);
    if (status == LIBRDP_STATUS_OK)
    {
        slot->surface_width = width;
        slot->surface_height = height;
    }
    return status;
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

    if (!host || host->state != SERVER_HOST_LISTENING || !frame)
        return;
    if (host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] !=
        SERVER_HOST_PROVIDER_READY)
    {
        server_host_metric_add(&host->metrics.capture_frames_dropped, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_CAPTURE_DROPPED,
                               NULL,
                               LIBRDP_STATUS_STATE,
                               frame->sequence,
                               1u);
        return;
    }
    if (!frame->pixels || frame->width == 0u || frame->height == 0u ||
        !server_host_multiply_size((size_t)frame->width, 4u, &row_bytes) ||
        frame->stride < row_bytes ||
        !server_host_multiply_size((size_t)frame->height,
                                   frame->stride,
                                   &frame_bytes))
    {
        if (host)
        {
            server_host_metric_add(&host->metrics.capture_frames_dropped, 1u);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_CAPTURE_DROPPED,
                                   NULL,
                                   LIBRDP_STATUS_INVALID_ARGUMENT,
                                   0u,
                                   1u);
        }
        return;
    }
    if (frame->pixels_len < frame_bytes ||
        (frame->dirty_count > 0u && !frame->dirty_rects))
    {
        server_host_metric_add(&host->metrics.capture_frames_dropped, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_CAPTURE_DROPPED,
                               NULL,
                               LIBRDP_STATUS_INVALID_ARGUMENT,
                               frame->pixels_len,
                               1u);
        return;
    }
    server_host_metric_add(&host->metrics.capture_frames, 1u);
    server_host_metric_add(&host->metrics.dirty_regions,
                           frame->dirty_count ? (uint64_t)frame->dirty_count
                                              : 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CAPTURE_FRAME,
                           NULL,
                           LIBRDP_STATUS_OK,
                           ((uint64_t)frame->width << 32u) |
                               (uint64_t)frame->height,
                           frame->dirty_count ? (uint64_t)frame->dirty_count
                                              : 1u);
    for (index = 0; index < host->peer_capacity; index++)
    {
        server_host_peer_slot* slot = &host->peers[index];
        size_t dirty_index = 0;
        server_platform_rect full;

        if (!slot->occupied || !slot->protocol ||
            slot->state != SERVER_HOST_PEER_ACTIVE)
            continue;
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
            server_platform_rect clipped;
            size_t offset = 0;

            if (rect->width == 0u || rect->height == 0u ||
                rect->x >= frame->width || rect->y >= frame->height ||
                rect->width > frame->width - rect->x ||
                rect->height > frame->height - rect->y ||
                (size_t)rect->y > SIZE_MAX / frame->stride)
                continue;
            if (rect->x >= slot->surface_width ||
                rect->y >= slot->surface_height)
                continue;
            clipped = *rect;
            if (clipped.width > slot->surface_width - clipped.x)
                clipped.width = slot->surface_width - clipped.x;
            if (clipped.height > slot->surface_height - clipped.y)
                clipped.height = slot->surface_height - clipped.y;
            offset = (size_t)rect->y * frame->stride;
            if ((size_t)rect->x > (SIZE_MAX - offset) / 4u)
                continue;
            offset += (size_t)rect->x * 4u;
            if (offset >= frame->pixels_len)
                continue;
            if (librdp_server_peer_surface_blit_bgra32(
                    slot->protocol,
                    clipped.x,
                    clipped.y,
                    clipped.width,
                    clipped.height,
                    frame->stride,
                    frame->pixels + offset) == LIBRDP_STATUS_OK)
            {
                server_dirty_metrics before;
                server_dirty_metrics after;

                server_dirty_metrics_init(&before);
                server_dirty_metrics_init(&after);
                (void)server_dirty_scheduler_get_metrics(slot->dirty,
                                                         &before);
                (void)server_dirty_scheduler_invalidate(
                    slot->dirty,
                    &clipped,
                    frame->timestamp_ns);
                (void)server_dirty_scheduler_get_metrics(slot->dirty,
                                                         &after);
                if (after.queue_collapses > before.queue_collapses)
                {
                    uint64_t pressure =
                        after.queue_collapses - before.queue_collapses;

                    server_host_metric_add(&host->metrics.queue_pressure,
                                           pressure);
                    server_host_trace_emit(host,
                                           SERVER_HOST_TRACE_QUEUE_PRESSURE,
                                           slot,
                                           LIBRDP_STATUS_LIMIT_EXCEEDED,
                                           after.pending_regions,
                                           pressure);
                }
            }
        }
    }
}

static void server_host_capture_lost(librdp_status status, void* user_data)
{
    server_host* host = (server_host*)user_data;

    if (!host ||
        host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] ==
            SERVER_HOST_PROVIDER_DENIED)
        return;
    host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] =
        SERVER_HOST_PROVIDER_FAILED;
    server_host_metric_add(&host->metrics.capture_frames_dropped, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CAPTURE_LOST,
                           NULL,
                           status,
                           0u,
                           1u);
    host->state = SERVER_HOST_FAILED;
}

/*
 * Validate one borrowed native pointer snapshot, then emit only normalized
 * public server updates to active peers. Shape storage is never retained,
 * cache indices advance once per accepted shape, and one peer send failure is
 * isolated to its metrics rather than suppressing updates for other peers.
 */
static void server_host_pointer_update(
    const server_platform_pointer* pointer,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    librdp_server_pointer_update update;
    size_t index = 0;
    int position_valid = 0;

    if (!host || !pointer || host->state != SERVER_HOST_LISTENING ||
        host->provider_states[SERVER_PLATFORM_PROVIDER_CAPTURE] !=
            SERVER_HOST_PROVIDER_READY ||
        host->provider_states[SERVER_PLATFORM_PROVIDER_POINTER] !=
            SERVER_HOST_PROVIDER_READY)
        return;
    position_valid =
        pointer->x >= 0 && pointer->y >= 0 &&
        (uint32_t)pointer->x <= UINT16_MAX &&
        (uint32_t)pointer->y <= UINT16_MAX;
    if (pointer->visible && !position_valid)
        return;
    if (pointer->shape_valid &&
        (pointer->width == 0u || pointer->height == 0u ||
         pointer->width > UINT16_MAX || pointer->height > UINT16_MAX ||
         pointer->hotspot_x >= pointer->width ||
         pointer->hotspot_y >= pointer->height || !pointer->pixels))
        return;

    for (index = 0; index < host->peer_capacity; index++)
    {
        server_host_peer_slot* slot = &host->peers[index];
        librdp_status status = LIBRDP_STATUS_OK;

        if (!slot->occupied || !slot->protocol ||
            slot->state != SERVER_HOST_PEER_ACTIVE)
            continue;
        (void)librdp_server_pointer_update_init(&update);
        if (!pointer->visible)
        {
            update.type = LIBRDP_SERVER_POINTER_HIDDEN;
            status = librdp_server_peer_send_pointer_update(slot->protocol,
                                                            &update);
        }
        else
        {
            if (pointer->shape_valid)
            {
                update.type = LIBRDP_SERVER_POINTER_SHAPE;
                update.cache_index = host->next_pointer_cache_index;
                update.hotspot_x = (uint16_t)pointer->hotspot_x;
                update.hotspot_y = (uint16_t)pointer->hotspot_y;
                update.width = (uint16_t)pointer->width;
                update.height = (uint16_t)pointer->height;
                update.stride = pointer->stride;
                update.pixels = pointer->pixels;
                update.pixels_len = pointer->pixels_len;
                status = librdp_server_peer_send_pointer_update(slot->protocol,
                                                                &update);
            }
            else if (!host->pointer_visible)
            {
                update.type = LIBRDP_SERVER_POINTER_DEFAULT;
                status = librdp_server_peer_send_pointer_update(slot->protocol,
                                                                &update);
            }
            if (status == LIBRDP_STATUS_OK)
            {
                (void)librdp_server_pointer_update_init(&update);
                update.type = LIBRDP_SERVER_POINTER_POSITION;
                update.x = (uint16_t)pointer->x;
                update.y = (uint16_t)pointer->y;
                status = librdp_server_peer_send_pointer_update(slot->protocol,
                                                                &update);
            }
        }
        if (status == LIBRDP_STATUS_OK)
        {
            server_host_metric_add(&host->metrics.pointer_updates, 1u);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_POINTER_UPDATE,
                                   slot,
                                   status,
                                   pointer->sequence,
                                   1u);
        }
        else
        {
            server_host_metric_add(&host->metrics.pointer_failures, 1u);
            server_host_trace_emit(host,
                                   SERVER_HOST_TRACE_POINTER_FAILED,
                                   slot,
                                   status,
                                   pointer->sequence,
                                   1u);
        }
    }
    if (pointer->shape_valid)
    {
        host->next_pointer_cache_index++;
        if (host->next_pointer_cache_index == 0u)
            host->next_pointer_cache_index = 1u;
    }
    host->pointer_visible = pointer->visible ? 1u : 0u;
}

static void server_host_clipboard_formats(
    const server_platform_clipboard_format* formats,
    size_t format_count,
    uint64_t generation,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->clipboard)
        return;
    status = server_clipboard_runtime_platform_formats(host->clipboard,
                                                       formats,
                                                       format_count,
                                                       generation);
    server_host_metric_add(&host->metrics.clipboard_events, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                           NULL,
                           status,
                           generation,
                           (uint64_t)format_count);
}

static void server_host_clipboard_data(
    const server_platform_clipboard_data* data,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->clipboard || !data)
        return;
    status = server_clipboard_runtime_platform_data(host->clipboard, data);
    server_host_metric_add(&host->metrics.clipboard_events, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                           NULL,
                           status,
                           data->request_id,
                           data->data_len);
}

static librdp_status server_host_clipboard_request(
    const server_platform_clipboard_request* request,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->clipboard || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = server_clipboard_runtime_platform_request(host->clipboard,
                                                       request);
    server_host_metric_add(&host->metrics.clipboard_events, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                           server_host_find_peer_slot(host, request->peer_id),
                           status,
                           request->request_id,
                           1u);
    return status;
}

static librdp_status server_host_clipboard_file_request(
    const server_platform_clipboard_file_request* request,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->clipboard || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = server_clipboard_runtime_platform_file_request(host->clipboard,
                                                            request);
    server_host_metric_add(&host->metrics.clipboard_events, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                           server_host_find_peer_slot(host, request->peer_id),
                           status,
                           request->request_id,
                           request->requested_bytes);
    return status;
}

static librdp_status server_host_clipboard_cancel(
    uint32_t peer_id,
    uint32_t generation,
    uint64_t ownership_generation,
    uint64_t request_id,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->clipboard)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = server_clipboard_runtime_platform_cancel(
        host->clipboard,
        peer_id,
        generation,
        ownership_generation,
        request_id);
    server_host_metric_add(&host->metrics.clipboard_events, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                           server_host_find_peer_slot(host, peer_id),
                           status,
                           request_id,
                           0u);
    return status;
}

static void server_host_drive_request(
    const server_platform_drive_request* request,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    server_host_peer_slot* slot = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->drive || !request)
        return;
    slot = server_host_find_peer_slot(host, request->peer_id);
    status = server_drive_runtime_platform_request(host->drive,
                                                   request,
                                                   server_host_now_ns());
    server_host_metric_add(&host->metrics.drive_requests, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_DRIVE_REQUEST,
                           slot,
                           status,
                           request->request_id,
                           1u);
}

static void server_host_drive_cancel(uint32_t peer_id,
                                     uint32_t generation,
                                     uint64_t request_id,
                                     void* user_data)
{
    server_host* host = (server_host*)user_data;
    server_host_peer_slot* slot =
        host ? server_host_find_peer_slot(host, peer_id) : NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!host || !host->drive)
        return;
    status = server_drive_runtime_platform_cancel(host->drive,
                                                  peer_id,
                                                  generation,
                                                  request_id);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_DRIVE_REQUEST,
                           slot,
                           status,
                           request_id,
                           0u);
}

static int server_host_provider_mapping_ready(
    const server_host* host,
    const server_host_provider_mapping* mapping)
{
    if (!host || !mapping ||
        host->provider_states[mapping->provider] !=
            SERVER_HOST_PROVIDER_READY)
        return 0;
    if ((mapping->provider == SERVER_PLATFORM_PROVIDER_CAPTURE ||
         mapping->provider == SERVER_PLATFORM_PROVIDER_POINTER ||
         mapping->provider == SERVER_PLATFORM_PROVIDER_CLIPBOARD ||
         mapping->provider == SERVER_PLATFORM_PROVIDER_DRIVE) &&
        !host->provider_started[mapping->provider])
        return 0;
    if (mapping->provider == SERVER_PLATFORM_PROVIDER_DRIVE)
        return host->drive && server_drive_runtime_is_enabled(host->drive);
    return 1;
}

/*
 * Apply native permission changes to both listener bookkeeping and every live
 * peer provider gate. Revocation cancels domain state before disabling the
 * protocol path; regrant only reactivates clipboard transport when its static
 * channel was already joined, preserving negotiation and ownership ordering.
 */
static void server_host_permission_changed(
    server_platform_permission_kind kind,
    server_platform_permission_state state,
    void* user_data)
{
    server_host* host = (server_host*)user_data;
    server_platform_provider_kind provider = SERVER_PLATFORM_PROVIDER_COUNT;
    server_platform_provider_kind secondary =
        SERVER_PLATFORM_PROVIDER_COUNT;

    if (!host)
        return;
    switch (kind)
    {
        case SERVER_PLATFORM_PERMISSION_CAPTURE:
            provider = SERVER_PLATFORM_PROVIDER_CAPTURE;
            secondary = SERVER_PLATFORM_PROVIDER_POINTER;
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
        size_t index = 0;

        host->provider_states[provider] =
            state == SERVER_PLATFORM_PERMISSION_GRANTED
                ? (provider == SERVER_PLATFORM_PROVIDER_INPUT
                       ? (host->platform.input.vtable
                              ? SERVER_HOST_PROVIDER_READY
                              : SERVER_HOST_PROVIDER_UNAVAILABLE)
                       : (host->provider_started[provider]
                              ? SERVER_HOST_PROVIDER_READY
                              : SERVER_HOST_PROVIDER_STOPPED))
                : SERVER_HOST_PROVIDER_DENIED;
        if (secondary < SERVER_PLATFORM_PROVIDER_COUNT &&
            host->platform.pointer.vtable)
        {
            host->provider_states[secondary] =
                state == SERVER_PLATFORM_PERMISSION_GRANTED
                    ? (host->provider_started[secondary]
                           ? SERVER_HOST_PROVIDER_READY
                           : SERVER_HOST_PROVIDER_STOPPED)
                    : SERVER_HOST_PROVIDER_DENIED;
        }
        if (state != SERVER_PLATFORM_PERMISSION_GRANTED)
            server_host_metric_add(&host->metrics.permission_denials, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_PERMISSION_CHANGED,
                               NULL,
                               state == SERVER_PLATFORM_PERMISSION_GRANTED
                                   ? LIBRDP_STATUS_OK
                                   : LIBRDP_STATUS_STATE,
                               (uint64_t)kind,
                               (uint64_t)state);
        if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD &&
            state != SERVER_PLATFORM_PERMISSION_GRANTED &&
            host->clipboard)
            server_clipboard_runtime_revoke(host->clipboard);
        if (kind == SERVER_PLATFORM_PERMISSION_DRIVE && host->drive)
        {
            (void)server_drive_runtime_set_enabled(
                host->drive,
                state == SERVER_PLATFORM_PERMISSION_GRANTED &&
                    host->drive_configured);
        }
        if (kind == SERVER_PLATFORM_PERMISSION_CAPTURE &&
            state != SERVER_PLATFORM_PERMISSION_GRANTED)
        {
            for (index = 0; index < host->peer_capacity; index++)
            {
                server_host_peer_slot* slot = &host->peers[index];

                if (slot->occupied && slot->dirty)
                {
                    (void)server_dirty_scheduler_clear(
                        slot->dirty,
                        server_host_now_ns());
                }
            }
        }
        for (index = 0; index < host->peer_capacity; index++)
        {
            server_host_peer_slot* slot = &host->peers[index];
            size_t mapping_index = 0u;

            if (!slot->occupied || !slot->protocol)
                continue;
            for (mapping_index = 0;
                 mapping_index <
                     sizeof(server_host_provider_mappings) /
                         sizeof(server_host_provider_mappings[0]);
                 mapping_index++)
            {
                const server_host_provider_mapping* mapping =
                    &server_host_provider_mappings[mapping_index];

                if (mapping->provider != provider &&
                    mapping->provider != secondary)
                    continue;
                (void)librdp_server_peer_enable_extension_provider(
                    slot->protocol,
                    mapping->family,
                    server_host_provider_mapping_ready(host, mapping));
            }
            if (state == SERVER_PLATFORM_PERMISSION_GRANTED)
            {
                if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD &&
                    host->clipboard)
                {
                    (void)server_host_start_peer_clipboard(
                        slot,
                        slot->protocol);
                }
                continue;
            }
            if (kind == SERVER_PLATFORM_PERMISSION_CLIPBOARD)
            {
                (void)librdp_server_peer_cancel_clipboard_requests(
                    slot->protocol);
            }
        }
        if (state != SERVER_PLATFORM_PERMISSION_GRANTED &&
            kind == SERVER_PLATFORM_PERMISSION_INPUT)
            server_host_release_input_owner(host);
        if (state == SERVER_PLATFORM_PERMISSION_GRANTED &&
            kind == SERVER_PLATFORM_PERMISSION_CAPTURE &&
            host->provider_started[SERVER_PLATFORM_PROVIDER_CAPTURE])
            host->capture_pending = 1u;
    }
}

/*
 * Publish only providers that completed native startup and permission checks.
 * Listener state is copied into accepted peers, while later permission
 * revocation is applied through the peer-scoped provider API.
 */
static librdp_status server_host_configure_listener_providers(server_host* host)
{
    size_t index = 0;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0;
         index < sizeof(server_host_provider_mappings) /
                     sizeof(server_host_provider_mappings[0]);
         index++)
    {
        const server_host_provider_mapping* mapping =
            &server_host_provider_mappings[index];
        librdp_status status = librdp_server_enable_extension_provider(
            host->listener,
            mapping->family,
            server_host_provider_mapping_ready(host, mapping));

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status server_host_configure_peer_providers(
    server_host* host,
    librdp_server_peer* peer)
{
    size_t index = 0;

    if (!host || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0;
         index < sizeof(server_host_provider_mappings) /
                     sizeof(server_host_provider_mappings[0]);
         index++)
    {
        const server_host_provider_mapping* mapping =
            &server_host_provider_mappings[index];
        librdp_status status = librdp_server_peer_enable_extension_provider(
            peer,
            mapping->family,
            server_host_provider_mapping_ready(host, mapping));

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
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
            clipboard_sink.request = server_host_clipboard_request;
            clipboard_sink.file_request =
                server_host_clipboard_file_request;
            clipboard_sink.cancel = server_host_clipboard_cancel;
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
            drive_sink.cancel = server_host_drive_cancel;
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
        server_drive_runtime_revoke(host->drive);
        drive->stop(host->platform.drive.context);
        host->provider_started[SERVER_PLATFORM_PROVIDER_DRIVE] = 0u;
        host->provider_states[SERVER_PLATFORM_PROVIDER_DRIVE] =
            SERVER_HOST_PROVIDER_STOPPED;
    }
    if (clipboard &&
        host->provider_started[SERVER_PLATFORM_PROVIDER_CLIPBOARD])
    {
        server_clipboard_runtime_revoke(host->clipboard);
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
    host->provider_poll_traced = 0u;
    host->provider_dispatch_traced = 0u;
    do
    {
        count = read(host->wakeup_read_fd,
                     wakeup_bytes,
                     sizeof(wakeup_bytes));
    } while (count > 0 || (count < 0 && errno == EINTR));
    host->state = SERVER_HOST_STARTING;
    server_host_metric_add(&host->metrics.listener_starts, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_LISTENER_START,
                           NULL,
                           LIBRDP_STATUS_OK,
                           0u,
                           1u);
    status = server_host_start_providers(host);
    if (status == LIBRDP_STATUS_OK)
        status = server_host_configure_listener_providers(host);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_listen(host->listener);
    if (status != LIBRDP_STATUS_OK)
    {
        librdp_server_close(host->listener);
        server_host_stop_providers(host);
        host->state = SERVER_HOST_FAILED;
        server_host_metric_add(&host->metrics.listener_failures, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_LISTENER_FAILED,
                               NULL,
                               status,
                               0u,
                               1u);
        return status;
    }
    host->listener_running = 1;
    host->state = SERVER_HOST_LISTENING;
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_LISTENER_READY,
                           NULL,
                           LIBRDP_STATUS_OK,
                           librdp_server_local_port(host->listener),
                           1u);
    return LIBRDP_STATUS_OK;
}

librdp_status server_host_stop(server_host* host)
{
    size_t index = 0;
    int listener_was_running = 0;

    if (!host)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state == SERVER_HOST_STOPPED)
        return LIBRDP_STATUS_OK;
    if (host->state == SERVER_HOST_NEW)
    {
        host->state = SERVER_HOST_STOPPED;
        return LIBRDP_STATUS_OK;
    }
    listener_was_running = host->listener_running;
    host->state = SERVER_HOST_STOPPING;
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_SHUTDOWN_START,
                           NULL,
                           LIBRDP_STATUS_OK,
                           host->peer_count,
                           1u);
    librdp_server_close(host->listener);
    host->listener_running = 0;
    host->capture_pending = 0u;
    for (index = 0; index < host->peer_capacity; index++)
        server_host_release_peer_slot(&host->peers[index]);
    server_host_stop_providers(host);
    host->state = SERVER_HOST_STOPPED;
    if (listener_was_running)
    {
        server_host_metric_add(&host->metrics.listener_stops, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_LISTENER_STOP,
                               NULL,
                               LIBRDP_STATUS_OK,
                               0u,
                               1u);
    }
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_SHUTDOWN_DONE,
                           NULL,
                           LIBRDP_STATUS_OK,
                           0u,
                           1u);
    return LIBRDP_STATUS_OK;
}

void server_host_free(server_host* host)
{
    if (!host)
        return;
    (void)server_host_stop(host);
    librdp_server_free(host->listener);
    server_clipboard_runtime_free(host->clipboard);
    server_drive_runtime_free(host->drive);
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

librdp_status server_host_request_permission(
    server_host* host,
    server_platform_permission_kind kind)
{
    const server_platform_permission_vtable* permission = NULL;

    if (!host || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state != SERVER_HOST_LISTENING)
        return LIBRDP_STATUS_STATE;
    permission = (const server_platform_permission_vtable*)
        host->platform.permission.vtable;
    return permission->request(host->platform.permission.context, kind);
}

librdp_status server_host_revoke_permission(
    server_host* host,
    server_platform_permission_kind kind)
{
    const server_platform_permission_vtable* permission = NULL;

    if (!host || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (host->state != SERVER_HOST_LISTENING)
        return LIBRDP_STATUS_STATE;
    permission = (const server_platform_permission_vtable*)
        host->platform.permission.vtable;
    return permission->revoke(host->platform.permission.context, kind);
}

uint16_t server_host_local_port(const server_host* host)
{
    return host ? librdp_server_local_port(host->listener) : 0u;
}

static librdp_status server_host_clipboard_send_monitor_ready(
    void* context,
    uint16_t channel_id)
{
    return librdp_server_peer_send_clipboard_monitor_ready(
        (librdp_server_peer*)context,
        channel_id);
}

static librdp_status server_host_clipboard_send_capabilities(
    void* context,
    uint16_t channel_id,
    uint32_t flags)
{
    return librdp_server_peer_send_clipboard_capabilities(
        (librdp_server_peer*)context,
        channel_id,
        flags);
}

static librdp_status server_host_clipboard_send_format_list(
    void* context,
    uint16_t channel_id,
    const librdp_server_clipboard_format* formats,
    uint32_t format_count,
    int long_names)
{
    return librdp_server_peer_send_clipboard_format_list(
        (librdp_server_peer*)context,
        channel_id,
        formats,
        format_count,
        long_names);
}

static librdp_status server_host_clipboard_send_format_list_response(
    void* context,
    uint16_t channel_id,
    int ok)
{
    return librdp_server_peer_send_clipboard_format_list_response(
        (librdp_server_peer*)context,
        channel_id,
        ok);
}

static librdp_status server_host_clipboard_send_data_request(
    void* context,
    uint16_t channel_id,
    uint32_t format_id)
{
    return librdp_server_peer_send_clipboard_format_data_request(
        (librdp_server_peer*)context,
        channel_id,
        format_id);
}

static librdp_status server_host_clipboard_send_data_response(
    void* context,
    uint16_t channel_id,
    int ok,
    const void* data,
    size_t data_len)
{
    return librdp_server_peer_send_clipboard_format_data_response(
        (librdp_server_peer*)context,
        channel_id,
        ok,
        data,
        data_len);
}

static librdp_status server_host_clipboard_send_file_request(
    void* context,
    uint16_t channel_id,
    uint32_t stream_id,
    int32_t file_index,
    uint32_t flags,
    uint64_t position,
    uint32_t requested_bytes,
    const uint32_t* clip_data_id)
{
    return librdp_server_peer_send_clipboard_file_contents_request(
        (librdp_server_peer*)context,
        channel_id,
        stream_id,
        file_index,
        flags,
        position,
        requested_bytes,
        clip_data_id);
}

static librdp_status server_host_clipboard_send_file_response(
    void* context,
    uint16_t channel_id,
    int ok,
    uint32_t stream_id,
    const void* data,
    size_t data_len)
{
    return librdp_server_peer_send_clipboard_file_contents_response(
        (librdp_server_peer*)context,
        channel_id,
        ok,
        stream_id,
        data,
        data_len);
}

static librdp_status server_host_clipboard_cancel_requests(void* context)
{
    return librdp_server_peer_cancel_clipboard_requests(
        (librdp_server_peer*)context);
}

static const server_clipboard_protocol_vtable
    server_host_clipboard_protocol = {
        server_host_clipboard_send_monitor_ready,
        server_host_clipboard_send_capabilities,
        server_host_clipboard_send_format_list,
        server_host_clipboard_send_format_list_response,
        server_host_clipboard_send_data_request,
        server_host_clipboard_send_data_response,
        server_host_clipboard_send_file_request,
        server_host_clipboard_send_file_response,
        server_host_clipboard_cancel_requests,
    };

static librdp_status server_host_drive_submit(
    void* context,
    const librdp_server_drive_request* request,
    librdp_server_drive_request_id* request_id)
{
    return librdp_server_peer_submit_drive_request(
        (librdp_server_peer*)context,
        request,
        request_id);
}

static librdp_status server_host_drive_cancel_request(
    void* context,
    librdp_server_drive_request_id request_id)
{
    return librdp_server_peer_cancel_drive_request(
        (librdp_server_peer*)context,
        request_id);
}

static librdp_status server_host_drive_send_device_reply(
    void* context,
    uint32_t device_id,
    uint32_t io_status)
{
    librdp_server_peer* peer = (librdp_server_peer*)context;
    uint32_t count = librdp_server_peer_static_channel_count(peer);
    uint32_t index = 0;

    for (index = 0; index < count; index++)
    {
        librdp_server_static_channel_info info;

        if (librdp_server_static_channel_info_init(&info) !=
                LIBRDP_STATUS_OK ||
            librdp_server_peer_static_channel_at(peer, index, &info) !=
                LIBRDP_STATUS_OK)
            continue;
        if (info.joined && strcmp(info.name, "rdpdr") == 0)
        {
            return librdp_server_peer_send_device_reply(
                peer,
                info.channel_id,
                LIBRDP_SERVER_EXTENSION_FILESYSTEM,
                device_id,
                io_status);
        }
    }
    return LIBRDP_STATUS_STATE;
}

static const server_drive_protocol_vtable server_host_drive_protocol = {
    server_host_drive_submit,
    server_host_drive_cancel_request,
    server_host_drive_send_device_reply,
};

static void server_host_peer_input(librdp_server_peer* peer,
                                   const librdp_server_input_event* event,
                                   void* user_data)
{
    server_host_peer_slot* slot =
        (server_host_peer_slot*)user_data;

    (void)peer;
    if (!slot || !slot->host || !event)
        return;
    if (event->type == LIBRDP_SERVER_INPUT_REFRESH_RECT)
    {
        if (slot->host->provider_states[
                SERVER_PLATFORM_PROVIDER_CAPTURE] ==
            SERVER_HOST_PROVIDER_READY)
            slot->host->capture_pending = 1u;
        server_host_trace_emit(slot->host,
                               SERVER_HOST_TRACE_REFRESH_REQUEST,
                               slot,
                               LIBRDP_STATUS_OK,
                               ((uint64_t)event->x << 32) |
                                   event->y,
                               ((uint64_t)event->width << 32) |
                                   event->height);
        return;
    }
    if (event->type == LIBRDP_SERVER_INPUT_SUPPRESS_OUTPUT)
    {
        server_host_trace_emit(slot->host,
                               SERVER_HOST_TRACE_OUTPUT_SUPPRESSION,
                               slot,
                               LIBRDP_STATUS_OK,
                               event->flags ? 0u : 1u,
                               1u);
        return;
    }
    (void)server_host_dispatch_peer_input(slot, event);
}

static void server_host_peer_clipboard(
    librdp_server_peer* peer,
    const librdp_server_clipboard_event* event,
    void* user_data)
{
    server_host_peer_slot* slot = (server_host_peer_slot*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    (void)peer;
    if (!slot || !slot->host || !slot->host->clipboard || !event)
        return;
    status = server_clipboard_runtime_protocol_event(
        slot->host->clipboard,
        slot->id,
        slot->generation,
        event);
    server_host_metric_add(&slot->host->metrics.clipboard_events, 1u);
    server_host_trace_emit(slot->host,
                           SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                           slot,
                           status,
                           (uint64_t)event->type,
                           event->data_len);
}

static void server_host_peer_drive(
    librdp_server_peer* peer,
    const librdp_server_drive_event* event,
    void* user_data)
{
    server_host_peer_slot* slot = (server_host_peer_slot*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    (void)peer;
    if (!slot || !slot->host || !slot->host->drive || !event)
        return;
    status = server_drive_runtime_protocol_event(slot->host->drive,
                                                 slot->id,
                                                 slot->generation,
                                                 event);
    server_host_metric_add(&slot->host->metrics.drive_requests, 1u);
    server_host_trace_emit(slot->host,
                           SERVER_HOST_TRACE_DRIVE_REQUEST,
                           slot,
                           status,
                           event->request_id,
                           (uint64_t)event->type);
}

static uint16_t server_host_peer_clipboard_channel(
    const librdp_server_peer* peer,
    uint16_t joined_channel_id)
{
    uint32_t count = librdp_server_peer_static_channel_count(peer);
    uint32_t index = 0;

    for (index = 0; index < count; index++)
    {
        librdp_server_static_channel_info info;

        if (librdp_server_static_channel_info_init(&info) !=
                LIBRDP_STATUS_OK ||
            librdp_server_peer_static_channel_at(peer, index, &info) !=
                LIBRDP_STATUS_OK)
            continue;
        if (info.joined &&
            (joined_channel_id == 0u ||
             info.channel_id == joined_channel_id) &&
            strcmp(info.name, "cliprdr") == 0)
            return info.channel_id;
    }
    return 0u;
}

static librdp_status server_host_start_peer_clipboard(
    server_host_peer_slot* slot,
    librdp_server_peer* peer)
{
    uint16_t channel_id = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!slot || !slot->host || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!slot->host->clipboard ||
        slot->state != SERVER_HOST_PEER_ACTIVE ||
        slot->host
                ->provider_states[SERVER_PLATFORM_PROVIDER_CLIPBOARD] !=
            SERVER_HOST_PROVIDER_READY)
        return LIBRDP_STATUS_OK;
    channel_id = server_host_peer_clipboard_channel(peer, 0u);
    if (channel_id == 0u)
        return LIBRDP_STATUS_OK;
    status = server_clipboard_runtime_channel_ready(
        slot->host->clipboard,
        slot->id,
        slot->generation,
        channel_id);
    if (status != LIBRDP_STATUS_OK)
    {
        (void)librdp_server_peer_enable_extension_provider(
            peer,
            LIBRDP_SERVER_EXTENSION_CLIPBOARD,
            0);
        server_host_trace_emit(slot->host,
                               SERVER_HOST_TRACE_CLIPBOARD_EVENT,
                               slot,
                               status,
                               channel_id,
                               1u);
    }
    return status;
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
    /* Activation Synchronize controls protocol sequencing, not native key state. */
    if (event->type == LIBRDP_SERVER_INPUT_SYNCHRONIZE &&
        slot->state != SERVER_HOST_PEER_ACTIVE)
    {
        return LIBRDP_STATUS_OK;
    }
    if (slot->state != SERVER_HOST_PEER_ACTIVE || !slot->input_owner ||
        host->input_owner_id != slot->id ||
        host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] !=
            SERVER_HOST_PROVIDER_READY ||
        !host->platform.input.vtable)
    {
        server_host_metric_add(&host->metrics.input_rejections, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_INPUT_REJECTED,
                               slot,
                               LIBRDP_STATUS_STATE,
                               (uint64_t)event->type,
                               1u);
        return LIBRDP_STATUS_STATE;
    }
    input =
        (const server_platform_input_vtable*)host->platform.input.vtable;
    status = input->inject(host->platform.input.context, event);
    if (status != LIBRDP_STATUS_OK)
    {
        server_host_metric_add(&host->metrics.input_rejections, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_INPUT_REJECTED,
                               slot,
                               status,
                               (uint64_t)event->type,
                               1u);
        if (status == LIBRDP_STATUS_IO_ERROR)
        {
            server_host_release_input_owner(host);
            host->provider_states[SERVER_PLATFORM_PROVIDER_INPUT] =
                SERVER_HOST_PROVIDER_FAILED;
        }
    }
    else
    {
        server_host_metric_add(&host->metrics.input_events, 1u);
        server_host_trace_emit(host,
                               SERVER_HOST_TRACE_INPUT_ACCEPTED,
                               slot,
                               LIBRDP_STATUS_OK,
                               (uint64_t)event->type,
                               1u);
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

    if (!slot || !peer || !event)
        return;
    if (event->type == LIBRDP_SERVER_EVENT_STATE_CHANGED)
    {
        if (event->new_state == LIBRDP_SERVER_PEER_ACTIVE)
        {
            librdp_status status = server_host_sync_peer_surface(
                slot,
                server_host_now_ns(),
                0);

            if (status != LIBRDP_STATUS_OK)
            {
                slot->state = SERVER_HOST_PEER_FAILED;
                (void)librdp_server_peer_close(peer);
                return;
            }
            slot->state = SERVER_HOST_PEER_ACTIVE;
            if (slot->host->input_policy ==
                    SERVER_HOST_INPUT_FIRST_ACTIVE &&
                slot->host->input_owner_id == 0u)
                (void)server_host_assign_input_owner(slot->host, slot->id);
            (void)server_host_start_peer_clipboard(slot, peer);
            slot->host->capture_pending = 1u;
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
        server_host_trace_emit(slot->host,
                               SERVER_HOST_TRACE_PEER_STATE,
                               slot,
                               LIBRDP_STATUS_OK,
                               (uint64_t)event->new_state,
                               1u);
    }
    else if (event->type == LIBRDP_SERVER_EVENT_ERROR)
    {
        slot->state = SERVER_HOST_PEER_FAILED;
        server_host_trace_emit(slot->host,
                               SERVER_HOST_TRACE_PEER_ERROR,
                               slot,
                               event->status,
                               (uint64_t)event->component,
                               1u);
    }
    else if (event->type == LIBRDP_SERVER_EVENT_SURFACE)
    {
        if (server_host_sync_peer_surface(slot,
                                          server_host_now_ns(),
                                          0) != LIBRDP_STATUS_OK)
        {
            slot->state = SERVER_HOST_PEER_FAILED;
            (void)librdp_server_peer_close(peer);
        }
    }
}

/*
 * Prepare one accepted peer as a transaction across core callbacks and common
 * clipboard/drive runtimes. A failure unwinds every manager already attached;
 * no partially initialized slot becomes visible to the event loop.
 */
static librdp_status server_host_prepare_peer_slot(
    server_host* host,
    server_host_peer_slot* slot,
    librdp_server_peer* peer)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t generation = 0;
    uint32_t clipboard_generation = 0;
    uint32_t candidate_id = 0;
    size_t attempts = 0;
    int clipboard_added = 0;
    int drive_added = 0;

    generation = slot->generation + 1u;
    if (generation == 0u)
        generation = 1u;
    clipboard_generation = slot->clipboard_generation;
    if (clipboard_generation == 0u)
        clipboard_generation = 1u;
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
    slot->surface_width = librdp_server_peer_desktop_width(peer);
    slot->surface_height = librdp_server_peer_desktop_height(peer);
    status = server_dirty_scheduler_resize(slot->dirty,
                                           slot->surface_width,
                                           slot->surface_height,
                                           0u,
                                           0);
    if (status == LIBRDP_STATUS_OK)
        status = server_host_configure_peer_providers(host, peer);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = librdp_server_peer_set_input_callback(peer,
                                                   server_host_peer_input,
                                                   slot);
    if (status == LIBRDP_STATUS_OK && host->channel_callback)
    {
        status = librdp_server_peer_set_channel_callback(
            peer,
            host->channel_callback,
            host->channel_user_data);
    }
    if (status == LIBRDP_STATUS_OK && host->extension_callback)
    {
        status = librdp_server_peer_set_extension_callback(
            peer,
            host->extension_callback,
            host->extension_user_data);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_set_event_callback(peer,
                                                       server_host_peer_event,
                                                       slot);
    }
    if (status == LIBRDP_STATUS_OK && host->clipboard)
    {
        status = librdp_server_peer_set_clipboard_callback(
            peer,
            server_host_peer_clipboard,
            slot);
    }
    if (status == LIBRDP_STATUS_OK && host->clipboard)
    {
        status = server_clipboard_runtime_add_peer(
            host->clipboard,
            slot->id,
            slot->generation,
            &server_host_clipboard_protocol,
            peer);
        clipboard_added = status == LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK && host->drive)
    {
        status = librdp_server_peer_set_drive_callback(peer,
                                                       server_host_peer_drive,
                                                       slot);
    }
    if (status == LIBRDP_STATUS_OK && host->drive)
    {
        status = server_drive_runtime_add_peer(host->drive,
                                               slot->id,
                                               slot->generation,
                                               &server_host_drive_protocol,
                                               peer);
        drive_added = status == LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        if (drive_added)
        {
            server_drive_runtime_remove_peer(host->drive,
                                             slot->id,
                                             slot->generation);
        }
        if (clipboard_added)
        {
            server_clipboard_runtime_remove_peer(host->clipboard,
                                                 slot->id,
                                                 slot->generation);
        }
        return status;
    }
    slot->state = SERVER_HOST_PEER_ACCEPTED;
    slot->occupied = 1;
    host->peer_count++;
    server_host_metric_add(&host->metrics.peers_accepted, 1u);
    server_host_trace_emit(host,
                           SERVER_HOST_TRACE_PEER_ACCEPTED,
                           slot,
                           LIBRDP_STATUS_OK,
                           slot->surface_width,
                           slot->surface_height);
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

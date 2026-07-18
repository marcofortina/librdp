/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server-side client-drive registry and request lifecycle.
 * Invariants: wire completion identifiers are never exposed as standalone
 * application handles, and reconnect invalidates every device, file, and
 * request token before new client state is accepted.
 * Ownership: the peer owns normalized drive names and fixed-capacity state
 * tables; request and callback payload pointers are borrowed.
 * Threading: the peer owner thread serializes all entry points.
 * Trust boundary: client drive announcements, file identifiers, completion
 * status, and returned bytes are validated before callbacks run.
 */

#include "server/server_drive.h"

#include "channels/filesystem_redirection.h"
#include "common/charset.h"
#include "server/server_channels.h"

#include <stdlib.h>
#include <string.h>

#define RDP_SERVER_DRIVE_MAX_PATH_BYTES 32768u
#define RDP_SERVER_DRIVE_MAX_REQUEST_BYTES (16u * 1024u * 1024u)

static char* rdp_server_drive_copy_name(const char* value)
{
    char* copy = NULL;
    size_t length = value ? strlen(value) : 0u;

    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    if (length > 0u)
        memcpy(copy, value, length);
    copy[length] = '\0';
    return copy;
}

static rdp_server_redirected_device* rdp_server_find_redirected_device_mut(
    librdp_server_peer* peer,
    uint32_t device_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
    {
        if (peer->redirected_devices[i].present &&
            peer->redirected_devices[i].device_id == device_id)
            return &peer->redirected_devices[i];
    }
    return NULL;
}

const rdp_server_redirected_device* rdp_server_find_redirected_device_const(
    const librdp_server_peer* peer,
    uint32_t device_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
    {
        if (peer->redirected_devices[i].present &&
            peer->redirected_devices[i].device_id == device_id)
            return &peer->redirected_devices[i];
    }
    return NULL;
}

static rdp_server_drive_file* rdp_server_drive_find_file(
    librdp_server_peer* peer,
    uint32_t generation,
    uint32_t device_id,
    uint32_t file_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_FILES; i++)
    {
        rdp_server_drive_file* file = &peer->drive_files[i];

        if (file->present &&
            file->reconnect_generation == generation &&
            file->device_id == device_id &&
            file->file_id == file_id)
            return file;
    }
    return NULL;
}

static librdp_status rdp_server_drive_store_file(
    librdp_server_peer* peer,
    uint32_t device_id,
    uint32_t file_id)
{
    if (!peer || file_id == 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_server_drive_find_file(peer,
                                   peer->drive_reconnect_generation,
                                   device_id,
                                   file_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (peer->drive_file_count >= RDP_SERVER_MAX_DRIVE_FILES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_FILES; i++)
    {
        rdp_server_drive_file* file = &peer->drive_files[i];

        if (!file->present)
        {
            file->present = 1u;
            file->reconnect_generation =
                peer->drive_reconnect_generation;
            file->device_id = device_id;
            file->file_id = file_id;
            peer->drive_file_count++;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_LIMIT_EXCEEDED;
}

static void rdp_server_drive_remove_file(
    librdp_server_peer* peer,
    uint32_t generation,
    uint32_t device_id,
    uint32_t file_id)
{
    rdp_server_drive_file* file =
        rdp_server_drive_find_file(peer, generation, device_id, file_id);

    if (!file)
        return;
    memset(file, 0, sizeof(*file));
    if (peer->drive_file_count > 0u)
        peer->drive_file_count--;
}

static rdp_server_drive_pending* rdp_server_drive_find_pending(
    librdp_server_peer* peer,
    librdp_server_drive_request_id request_id)
{
    if (!peer || request_id == 0u)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_REQUESTS; i++)
    {
        if (peer->drive_pending[i].present &&
            peer->drive_pending[i].request_id == request_id)
            return &peer->drive_pending[i];
    }
    return NULL;
}

static rdp_server_drive_pending* rdp_server_drive_find_completion(
    librdp_server_peer* peer,
    uint32_t device_id,
    uint32_t completion_id)
{
    if (!peer || completion_id == 0u)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_REQUESTS; i++)
    {
        rdp_server_drive_pending* pending = &peer->drive_pending[i];

        if (pending->present &&
            pending->device_id == device_id &&
            pending->completion_id == completion_id)
            return pending;
    }
    return NULL;
}

static void rdp_server_drive_clear_pending(
    librdp_server_peer* peer,
    rdp_server_drive_pending* pending)
{
    if (!peer || !pending || !pending->present)
        return;
    memset(pending, 0, sizeof(*pending));
    if (peer->drive_pending_count > 0u)
        peer->drive_pending_count--;
}

static void rdp_server_drive_fill_device_handle(
    const rdp_server_redirected_device* device,
    librdp_server_drive_device_handle* handle)
{
    if (!handle)
        return;
    memset(handle, 0, sizeof(*handle));
    if (!device)
        return;
    handle->reconnect_generation = device->reconnect_generation;
    handle->device_id = device->device_id;
}

static void rdp_server_drive_fill_file_handle(
    uint32_t generation,
    uint32_t device_id,
    uint32_t file_id,
    librdp_server_drive_file_handle* handle)
{
    if (!handle)
        return;
    memset(handle, 0, sizeof(*handle));
    handle->reconnect_generation = generation;
    handle->device_id = device_id;
    handle->file_id = file_id;
}

static void rdp_server_drive_emit_device(
    librdp_server_peer* peer,
    const rdp_server_redirected_device* device,
    librdp_server_drive_event_type type)
{
    librdp_server_drive_event event;

    if (!peer || !device || !peer->drive_callback ||
        librdp_server_drive_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = type;
    event.status = LIBRDP_STATUS_OK;
    rdp_server_drive_fill_device_handle(device, &event.device);
    memcpy(event.preferred_name,
           device->preferred_name,
           sizeof(event.preferred_name));
    event.name = device->name;
    peer->drive_callback(peer, &event, peer->drive_callback_user_data);
}

static void rdp_server_drive_emit_cancel(
    librdp_server_peer* peer,
    const rdp_server_drive_pending* pending)
{
    librdp_server_drive_event event;
    const rdp_server_redirected_device* device = NULL;

    if (!peer || !pending || !peer->drive_callback ||
        librdp_server_drive_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    device = rdp_server_find_redirected_device_const(peer,
                                                     pending->device_id);
    event.type = LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED;
    event.status = LIBRDP_STATUS_CANCELLED;
    event.request_id = pending->request_id;
    event.operation = pending->operation;
    rdp_server_drive_fill_device_handle(device, &event.device);
    if (pending->file_id != 0u)
    {
        rdp_server_drive_fill_file_handle(
            pending->reconnect_generation,
            pending->device_id,
            pending->file_id,
            &event.file);
    }
    peer->drive_callback(peer, &event, peer->drive_callback_user_data);
}

static void rdp_server_drive_cancel_device_requests(
    librdp_server_peer* peer,
    uint32_t device_id)
{
    if (!peer)
        return;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_REQUESTS; i++)
    {
        rdp_server_drive_pending* pending = &peer->drive_pending[i];

        if (!pending->present || pending->device_id != device_id)
            continue;
        if (!pending->cancelled)
            rdp_server_drive_emit_cancel(peer, pending);
        rdp_server_drive_clear_pending(peer, pending);
    }
}

static void rdp_server_drive_remove_device_files(
    librdp_server_peer* peer,
    uint32_t device_id)
{
    if (!peer)
        return;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_FILES; i++)
    {
        rdp_server_drive_file* file = &peer->drive_files[i];

        if (!file->present || file->device_id != device_id)
            continue;
        memset(file, 0, sizeof(*file));
        if (peer->drive_file_count > 0u)
            peer->drive_file_count--;
    }
}

librdp_status librdp_server_drive_request_init(
    librdp_server_drive_request* request)
{
    if (!request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    request->version = LIBRDP_SERVER_DRIVE_REQUEST_VERSION;
    request->size = (uint32_t)sizeof(*request);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_drive_event_init(
    librdp_server_drive_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_DRIVE_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    event->status = LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_drive_callback(
    librdp_server_peer* peer,
    librdp_server_drive_callback callback,
    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (!callback && peer->drive_pending_count > 0u)
        return LIBRDP_STATUS_STATE;
    peer->drive_callback = callback;
    peer->drive_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

/*
 * Commit one validated device announcement atomically. Filesystem names are
 * converted before a registry slot becomes visible, duplicate IDs are rejected,
 * and allocation or conversion failure leaves peer state unchanged.
 */
librdp_status rdp_server_redirected_device_store(
    librdp_server_peer* peer,
    uint16_t channel_id,
    const rdp_device_redirection_device_announce* announce)
{
    rdp_server_redirected_device* slot = NULL;
    char* normalized_name = NULL;
    size_t normalized_name_len = 0u;

    if (!peer || !announce || announce->device_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_server_find_redirected_device_const(peer, announce->device_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (peer->redirected_device_count >= RDP_SERVER_MAX_REDIRECTED_DEVICES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (announce->device_type == RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM)
    {
        if (announce->data_len > 0u)
        {
            librdp_status status = rdp_charset_utf16le_to_utf8_alloc(
                announce->data,
                announce->data_len,
                1,
                &normalized_name,
                &normalized_name_len);

            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else
        {
            char preferred[9];

            memset(preferred, 0, sizeof(preferred));
            memcpy(preferred,
                   announce->preferred_dos_name,
                   sizeof(announce->preferred_dos_name));
            normalized_name = rdp_server_drive_copy_name(preferred);
            if (!normalized_name)
                return LIBRDP_STATUS_NO_MEMORY;
            normalized_name_len = strlen(normalized_name);
        }
        if (normalized_name_len == 0u)
        {
            free(normalized_name);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
    {
        if (!peer->redirected_devices[i].present)
        {
            slot = &peer->redirected_devices[i];
            break;
        }
    }
    if (!slot)
    {
        free(normalized_name);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    memset(slot, 0, sizeof(*slot));
    slot->present = 1u;
    slot->device_id = announce->device_id;
    slot->device_type = announce->device_type;
    slot->reconnect_generation = peer->drive_reconnect_generation;
    slot->channel_id = channel_id;
    memcpy(slot->preferred_name,
           announce->preferred_dos_name,
           sizeof(announce->preferred_dos_name));
    slot->preferred_name[sizeof(slot->preferred_name) - 1u] = '\0';
    slot->name = normalized_name;
    peer->redirected_device_count++;
    if (slot->device_type == RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM)
        rdp_server_drive_emit_device(
            peer,
            slot,
            LIBRDP_SERVER_DRIVE_DEVICE_ADDED);
    return LIBRDP_STATUS_OK;
}

void rdp_server_redirected_device_remove(
    librdp_server_peer* peer,
    uint32_t device_id)
{
    rdp_server_redirected_device* slot =
        rdp_server_find_redirected_device_mut(peer, device_id);

    if (!peer || !slot)
        return;
    if (slot->device_type == RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM)
    {
        rdp_server_drive_cancel_device_requests(peer, device_id);
        rdp_server_drive_remove_device_files(peer, device_id);
        rdp_server_drive_emit_device(
            peer,
            slot,
            LIBRDP_SERVER_DRIVE_DEVICE_REMOVED);
    }
    free(slot->name);
    memset(slot, 0, sizeof(*slot));
    if (peer->redirected_device_count > 0u)
        peer->redirected_device_count--;
}

void rdp_server_drive_state_reset(
    librdp_server_peer* peer,
    int reconnect)
{
    if (!peer)
        return;
    if (reconnect)
    {
        for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_REQUESTS; i++)
        {
            if (peer->drive_pending[i].present &&
                !peer->drive_pending[i].cancelled)
                rdp_server_drive_emit_cancel(
                    peer,
                    &peer->drive_pending[i]);
        }
        for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
        {
            if (peer->redirected_devices[i].present &&
                peer->redirected_devices[i].device_type ==
                    RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM)
            {
                rdp_server_drive_emit_device(
                    peer,
                    &peer->redirected_devices[i],
                    LIBRDP_SERVER_DRIVE_DEVICE_REMOVED);
            }
        }
    }
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
        free(peer->redirected_devices[i].name);
    memset(peer->redirected_devices, 0, sizeof(peer->redirected_devices));
    memset(peer->drive_files, 0, sizeof(peer->drive_files));
    memset(peer->drive_pending, 0, sizeof(peer->drive_pending));
    peer->redirected_device_count = 0u;
    peer->drive_file_count = 0u;
    peer->drive_pending_count = 0u;
    if (peer->drive_reconnect_generation == 0u)
        peer->drive_reconnect_generation = 1u;
    else if (reconnect)
    {
        peer->drive_reconnect_generation++;
        if (peer->drive_reconnect_generation == 0u)
            peer->drive_reconnect_generation = 1u;
    }
    peer->drive_next_completion_id = 0u;
}

static librdp_status rdp_server_drive_validate_device(
    librdp_server_peer* peer,
    librdp_server_drive_device_handle handle,
    const rdp_server_redirected_device** device)
{
    const rdp_server_redirected_device* found = NULL;

    if (!peer || !device || handle.reconnect_generation == 0u ||
        handle.device_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (handle.reconnect_generation != peer->drive_reconnect_generation)
        return LIBRDP_STATUS_STATE;
    found = rdp_server_find_redirected_device_const(peer, handle.device_id);
    if (!found || found->device_type != RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM ||
        found->reconnect_generation != handle.reconnect_generation)
        return LIBRDP_STATUS_STATE;
    *device = found;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_drive_validate_file(
    librdp_server_peer* peer,
    librdp_server_drive_file_handle handle,
    const rdp_server_redirected_device** device)
{
    librdp_server_drive_device_handle device_handle;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !device || handle.file_id == 0u || handle.reserved != 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    device_handle.reconnect_generation = handle.reconnect_generation;
    device_handle.device_id = handle.device_id;
    status = rdp_server_drive_validate_device(peer,
                                              device_handle,
                                              device);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_server_drive_find_file(peer,
                                    handle.reconnect_generation,
                                    handle.device_id,
                                    handle.file_id))
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_server_drive_next_completion_id(
    librdp_server_peer* peer)
{
    if (!peer)
        return 0u;
    for (uint32_t attempt = 0; attempt < RDP_SERVER_MAX_DRIVE_REQUESTS + 1u;
         attempt++)
    {
        uint32_t candidate = ++peer->drive_next_completion_id;
        int used = 0;

        if (candidate == 0u)
            candidate = ++peer->drive_next_completion_id;
        for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_REQUESTS; i++)
        {
            if (peer->drive_pending[i].present &&
                peer->drive_pending[i].completion_id == candidate)
            {
                used = 1;
                break;
            }
        }
        if (!used)
            return candidate;
    }
    return 0u;
}

static librdp_status rdp_server_drive_append_empty_request(
    rdp_buffer* packet,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t major_function)
{
    static const uint8_t padding[32] = {0};

    return rdp_device_redirection_write_io_request(
        packet,
        device_id,
        file_id,
        completion_id,
        major_function,
        0u,
        padding,
        sizeof(padding));
}

/*
 * Serialize exactly one normalized operation. The switch is the complete
 * operation-to-wire mapping: each branch validates its own pointer, range, and
 * encoding contract, while failure leaves the caller-owned packet disposable
 * and creates no pending request.
 */
static librdp_status rdp_server_drive_build_request(
    const librdp_server_drive_request* request,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    rdp_buffer* packet)
{
    rdp_buffer path;
    rdp_filesystem_redirection_lock_info lock_ranges[
        RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!request || !packet ||
        request->version != LIBRDP_SERVER_DRIVE_REQUEST_VERSION ||
        request->size < sizeof(*request) ||
        (!request->data && request->data_len > 0u) ||
        request->data_len > RDP_SERVER_DRIVE_MAX_REQUEST_BYTES ||
        request->data_len > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&path);
    memset(lock_ranges, 0, sizeof(lock_ranges));
    switch (request->operation)
    {
        case LIBRDP_SERVER_DRIVE_CREATE:
            if (!request->path ||
                strlen(request->path) > RDP_SERVER_DRIVE_MAX_PATH_BYTES)
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                status = rdp_charset_utf8_to_utf16le_buffer(
                    request->path,
                    1,
                    &path);
            if (status == LIBRDP_STATUS_OK && path.length <= UINT32_MAX)
            {
                status = rdp_filesystem_redirection_write_create_request(
                    packet,
                    device_id,
                    0u,
                    completion_id,
                    request->desired_access,
                    request->allocation_size,
                    request->file_attributes,
                    request->shared_access,
                    request->create_disposition,
                    request->create_options,
                    path.data,
                    (uint32_t)path.length);
            }
            else if (status == LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        case LIBRDP_SERVER_DRIVE_CLOSE:
            status = rdp_filesystem_redirection_write_close_request(
                packet, device_id, file_id, completion_id);
            break;
        case LIBRDP_SERVER_DRIVE_READ:
            status = rdp_filesystem_redirection_write_read_request(
                packet,
                device_id,
                file_id,
                completion_id,
                request->length,
                request->offset);
            break;
        case LIBRDP_SERVER_DRIVE_WRITE:
            status = rdp_filesystem_redirection_write_write_request(
                packet,
                device_id,
                file_id,
                completion_id,
                request->offset,
                request->data,
                (uint32_t)request->data_len);
            break;
        case LIBRDP_SERVER_DRIVE_QUERY_INFORMATION:
        case LIBRDP_SERVER_DRIVE_SET_INFORMATION:
        case LIBRDP_SERVER_DRIVE_QUERY_VOLUME:
        case LIBRDP_SERVER_DRIVE_SET_VOLUME:
        {
            uint32_t major = RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION;

            if (request->operation == LIBRDP_SERVER_DRIVE_SET_INFORMATION)
                major = RDP_DEVICE_REDIRECTION_IRP_SET_INFORMATION;
            else if (request->operation ==
                     LIBRDP_SERVER_DRIVE_QUERY_VOLUME)
                major = RDP_DEVICE_REDIRECTION_IRP_QUERY_VOLUME_INFORMATION;
            else if (request->operation == LIBRDP_SERVER_DRIVE_SET_VOLUME)
                major = RDP_DEVICE_REDIRECTION_IRP_SET_VOLUME_INFORMATION;
            status = rdp_filesystem_redirection_write_information_request(
                packet,
                device_id,
                file_id,
                completion_id,
                major,
                request->information_class,
                request->data,
                (uint32_t)request->data_len);
            break;
        }
        case LIBRDP_SERVER_DRIVE_FLUSH:
            status = rdp_server_drive_append_empty_request(
                packet,
                device_id,
                file_id,
                completion_id,
                RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS);
            break;
        case LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY:
            if (request->initial_query > 1u ||
                (request->path &&
                 strlen(request->path) > RDP_SERVER_DRIVE_MAX_PATH_BYTES))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else if (request->path)
                status = rdp_charset_utf8_to_utf16le_buffer(
                    request->path,
                    1,
                    &path);
            if (status == LIBRDP_STATUS_OK && path.length <= UINT32_MAX)
            {
                status =
                    rdp_filesystem_redirection_write_query_directory_request(
                        packet,
                        device_id,
                        file_id,
                        completion_id,
                        request->information_class,
                        request->initial_query,
                        path.data,
                        (uint32_t)path.length);
            }
            else if (status == LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_LIMIT_EXCEEDED;
            break;
        case LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY:
            status =
                rdp_filesystem_redirection_write_notify_change_request(
                    packet,
                    device_id,
                    file_id,
                    completion_id,
                    request->watch_tree,
                    request->completion_filter);
            break;
        case LIBRDP_SERVER_DRIVE_CONTROL:
            status = rdp_filesystem_redirection_write_control_request(
                packet,
                device_id,
                file_id,
                completion_id,
                request->output_buffer_length,
                request->control_code,
                request->data,
                (uint32_t)request->data_len);
            break;
        case LIBRDP_SERVER_DRIVE_LOCK:
        {
            uint32_t lock_operation = 0u;

            if (request->lock_count >
                    RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS ||
                (request->lock_count > 0u && !request->locks))
            {
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
                break;
            }
            for (uint32_t i = 0; i < request->lock_count; i++)
            {
                lock_ranges[i].offset = request->locks[i].offset;
                lock_ranges[i].length = request->locks[i].length;
            }
            switch (request->lock_operation)
            {
                case LIBRDP_SERVER_DRIVE_LOCK_SHARED:
                    lock_operation =
                        RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK;
                    break;
                case LIBRDP_SERVER_DRIVE_LOCK_EXCLUSIVE:
                    lock_operation =
                        RDP_FILESYSTEM_REDIRECTION_LOWIO_EXCLUSIVELOCK;
                    break;
                case LIBRDP_SERVER_DRIVE_UNLOCK:
                    lock_operation =
                        RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK;
                    break;
                case LIBRDP_SERVER_DRIVE_UNLOCK_MULTIPLE:
                    lock_operation =
                        RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK_MULTIPLE;
                    break;
                default:
                    status = LIBRDP_STATUS_INVALID_ARGUMENT;
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_filesystem_redirection_write_lock_request(
                packet,
                device_id,
                file_id,
                completion_id,
                lock_operation,
                request->lock_flags,
                lock_ranges,
                request->lock_count);
            break;
        }
        case LIBRDP_SERVER_DRIVE_QUERY_SECURITY:
        case LIBRDP_SERVER_DRIVE_SET_SECURITY:
            status = rdp_filesystem_redirection_write_security_request(
                packet,
                device_id,
                file_id,
                completion_id,
                request->operation == LIBRDP_SERVER_DRIVE_QUERY_SECURITY
                    ? RDP_DEVICE_REDIRECTION_IRP_QUERY_SECURITY
                    : RDP_DEVICE_REDIRECTION_IRP_SET_SECURITY,
                request->security_information,
                request->operation == LIBRDP_SERVER_DRIVE_QUERY_SECURITY
                    ? NULL
                    : request->data,
                request->operation == LIBRDP_SERVER_DRIVE_QUERY_SECURITY
                    ? request->output_buffer_length
                    : (uint32_t)request->data_len);
            break;
        case LIBRDP_SERVER_DRIVE_CLEANUP:
            status = rdp_server_drive_append_empty_request(
                packet,
                device_id,
                file_id,
                completion_id,
                RDP_DEVICE_REDIRECTION_IRP_CLEANUP);
            break;
        case LIBRDP_SERVER_DRIVE_SHUTDOWN:
            status = rdp_server_drive_append_empty_request(
                packet,
                device_id,
                file_id,
                completion_id,
                RDP_DEVICE_REDIRECTION_IRP_SHUTDOWN);
            break;
        default:
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            break;
    }
    rdp_buffer_free(&path);
    return status;
}

librdp_status librdp_server_peer_submit_drive_request(
    librdp_server_peer* peer,
    const librdp_server_drive_request* request,
    librdp_server_drive_request_id* request_id)
{
    const rdp_server_redirected_device* device = NULL;
    rdp_server_drive_pending* pending = NULL;
    rdp_buffer packet;
    uint32_t completion_id = 0u;
    uint32_t file_id = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !request || !request_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *request_id = 0u;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE ||
        !peer->drive_callback)
        return LIBRDP_STATUS_STATE;
    if (request->operation == LIBRDP_SERVER_DRIVE_CREATE ||
        request->operation == LIBRDP_SERVER_DRIVE_SHUTDOWN)
        status = rdp_server_drive_validate_device(
            peer,
            request->device,
            &device);
    else
    {
        status = rdp_server_drive_validate_file(peer,
                                                request->file,
                                                &device);
        file_id = request->file.file_id;
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (peer->drive_pending_count >= RDP_SERVER_MAX_DRIVE_REQUESTS)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DRIVE_REQUESTS; i++)
    {
        if (!peer->drive_pending[i].present)
        {
            pending = &peer->drive_pending[i];
            break;
        }
    }
    completion_id = rdp_server_drive_next_completion_id(peer);
    if (!pending || completion_id == 0u)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    rdp_buffer_init(&packet);
    status = rdp_server_drive_build_request(request,
                                            device->device_id,
                                            file_id,
                                            completion_id,
                                            &packet);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_static_extension_data(
            peer,
            LIBRDP_SERVER_EXTENSION_FILESYSTEM,
            device->channel_id,
            packet.data,
            packet.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        pending->present = 1u;
        pending->reconnect_generation =
            peer->drive_reconnect_generation;
        pending->completion_id = completion_id;
        pending->device_id = device->device_id;
        pending->file_id = file_id;
        pending->operation = request->operation;
        pending->request_id =
            ((uint64_t)peer->drive_reconnect_generation << 32u) |
            completion_id;
        peer->drive_pending_count++;
        *request_id = pending->request_id;
    }
    rdp_buffer_free(&packet);
    return status;
}

librdp_status librdp_server_peer_cancel_drive_request(
    librdp_server_peer* peer,
    librdp_server_drive_request_id request_id)
{
    rdp_server_drive_pending* pending = NULL;
    uint32_t generation = (uint32_t)(request_id >> 32u);

    if (!peer || request_id == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (generation != peer->drive_reconnect_generation)
        return LIBRDP_STATUS_STATE;
    pending = rdp_server_drive_find_pending(peer, request_id);
    if (!pending || pending->cancelled)
        return LIBRDP_STATUS_STATE;
    rdp_server_drive_emit_cancel(peer, pending);
    pending->cancelled = 1u;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_drive_parse_success(
    rdp_server_drive_pending* pending,
    const uint8_t* data,
    size_t data_len,
    librdp_server_drive_event* event)
{
    if (!pending || !data || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    switch (pending->operation)
    {
        case LIBRDP_SERVER_DRIVE_CREATE:
        {
            rdp_filesystem_redirection_create_response response;
            librdp_status status =
                rdp_filesystem_redirection_parse_create_response(
                    data,
                    data_len,
                    &response);

            if (status != LIBRDP_STATUS_OK)
                return status;
            event->information = response.information;
            event->file.file_id = response.file_id;
            return LIBRDP_STATUS_OK;
        }
        case LIBRDP_SERVER_DRIVE_CLOSE:
        {
            rdp_device_redirection_io_completion response;

            return rdp_filesystem_redirection_parse_close_response(
                data,
                data_len,
                &response);
        }
        case LIBRDP_SERVER_DRIVE_FLUSH:
        case LIBRDP_SERVER_DRIVE_CLEANUP:
        case LIBRDP_SERVER_DRIVE_SHUTDOWN:
            return LIBRDP_STATUS_OK;
        case LIBRDP_SERVER_DRIVE_LOCK:
        {
            rdp_device_redirection_io_completion response;

            return rdp_filesystem_redirection_parse_lock_response(
                data,
                data_len,
                &response);
        }
        default:
        {
            rdp_filesystem_redirection_length_response response;
            librdp_status status =
                rdp_filesystem_redirection_parse_length_response(
                    data,
                    data_len,
                    &response);

            if (status != LIBRDP_STATUS_OK)
                return status;
            event->transferred = response.length;
            event->data = response.buffer;
            event->data_len = response.buffer_len;
            return LIBRDP_STATUS_OK;
        }
    }
}

/*
 * Correlate and validate one untrusted completion before committing file-table
 * changes. Malformed, unknown, or stale completions produce no callback; a
 * cancelled request consumes one late completion without delivering it twice.
 */
librdp_status rdp_server_drive_handle_completion(
    librdp_server_peer* peer,
    const uint8_t* data,
    size_t data_len)
{
    rdp_device_redirection_io_completion completion;
    const rdp_server_redirected_device* device = NULL;
    rdp_server_drive_pending* pending = NULL;
    librdp_server_drive_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_completion(
        data,
        data_len,
        &completion);
    if (status != LIBRDP_STATUS_OK)
        return status;
    device = rdp_server_find_redirected_device_const(
        peer,
        completion.device_id);
    if (!device)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (device->device_type != RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM)
        return LIBRDP_STATUS_OK;
    pending = rdp_server_drive_find_completion(peer,
                                               completion.device_id,
                                               completion.completion_id);
    if (!pending ||
        pending->reconnect_generation !=
            peer->drive_reconnect_generation)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pending->cancelled)
    {
        rdp_server_drive_clear_pending(peer, pending);
        return LIBRDP_STATUS_OK;
    }
    status = librdp_server_drive_event_init(&event);
    if (status != LIBRDP_STATUS_OK)
        return status;
    event.type = LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED;
    event.request_id = pending->request_id;
    event.operation = pending->operation;
    event.io_status = completion.io_status;
    rdp_server_drive_fill_device_handle(device, &event.device);
    if (pending->file_id != 0u)
    {
        rdp_server_drive_fill_file_handle(
            pending->reconnect_generation,
            pending->device_id,
            pending->file_id,
            &event.file);
    }
    if (completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        status = rdp_server_drive_parse_success(pending,
                                                data,
                                                data_len,
                                                &event);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (pending->operation == LIBRDP_SERVER_DRIVE_CREATE &&
        completion.io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        status = rdp_server_drive_store_file(
            peer,
            completion.device_id,
            event.file.file_id);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_server_drive_fill_file_handle(
            pending->reconnect_generation,
            pending->device_id,
            event.file.file_id,
            &event.file);
    }
    else if (pending->operation == LIBRDP_SERVER_DRIVE_CLOSE &&
             completion.io_status ==
                 RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
    {
        rdp_server_drive_remove_file(
            peer,
            pending->reconnect_generation,
            pending->device_id,
            pending->file_id);
    }
    if (peer->drive_callback)
        peer->drive_callback(peer, &event, peer->drive_callback_user_data);
    rdp_server_drive_clear_pending(peer, pending);
    return LIBRDP_STATUS_OK;
}

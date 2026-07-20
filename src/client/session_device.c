/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client device redirection routing and common device state.
 * Invariants: device identifiers are mapped through configured settings before
 * a backend receives an IRP, and fragmented channel payloads are reassembled
 * before parser entry points run.
 * Ownership: redirected file handles, drive root descriptors, and PNP scratch
 * buffers remain owned by the session and are reset during disconnect/free.
 * Threading: all functions run on the session owner thread; slow backend work is
 * delegated by backend-specific modules.
 * Trust boundary: server-provided device, PNP, and printer packets are validated
 * before mutating session state or dispatching to backend-specific handlers.
 */

#include "client/session_internal.h"
#include "client/settings_internal.h"
#include "common/charset.h"
#include "common/trace.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

librdp_status rdp_session_send_device_redirection_packet(librdp_session* session,
                                                                const rdp_buffer* payload,
                                                                const char* event)
{
    if (!session || !payload || !event || session->device_redirection_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->device_redirection_channel_id, payload, event);
}

librdp_status rdp_session_send_pnp_redirection_packet(librdp_session* session,
                                                             const rdp_buffer* payload,
                                                             const char* event)
{
    if (!session || !payload || !event || session->pnp_redirection_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->pnp_redirection_channel_id, payload, event);
}

librdp_status rdp_session_send_remote_programs_packet(librdp_session* session,
                                                             const rdp_buffer* payload,
                                                             const char* event)
{
    if (!session || !payload || !event || session->remote_programs_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_write_channel_pdu(session, session->remote_programs_channel_id, payload, event);
}

uint32_t rdp_session_errno_to_device_status(int error)
{
    switch (error)
    {
        case 0:
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        case ENOENT:
        case ENOTDIR:
            return RDP_SESSION_DEVICE_NO_SUCH_FILE;
        case EEXIST:
            return RDP_SESSION_DEVICE_OBJECT_NAME_COLLISION;
        case EACCES:
        case EPERM:
        case EISDIR:
            return RDP_SESSION_DEVICE_ACCESS_DENIED;
        case EINVAL:
            return RDP_SESSION_DEVICE_INVALID_PARAMETER;
        case EMFILE:
        case ENFILE:
            return RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
        default:
            return RDP_SESSION_DEVICE_NOT_SUPPORTED;
    }
}

librdp_status rdp_session_pnp_send_version(librdp_session* session)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_pnp_redirection_write_version(&packet,
                                               1,
                                               0,
                                               RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session, &packet, "client.pnp.version");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.pnp.version",
                        "channel_id=%u capabilities=%u",
                        session->pnp_redirection_channel_id,
                        RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES);
    rdp_buffer_free(&packet);
    return status;
}

librdp_status rdp_session_pnp_send_authenticated(librdp_session* session)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_pnp_redirection_write_authenticated(&packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session, &packet, "client.pnp.authenticated");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.pnp.authenticated",
                        "channel_id=%u",
                        session->pnp_redirection_channel_id);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_session_pnp_multisz1(rdp_buffer* out, const char* text)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!out || !text)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_utf8_to_utf16le(text, out, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, 0);
    return status;
}

/*
 * Derive a stable, non-secret container identifier from the persistent client
 * device ID. The namespace bytes separate synthetic PNP containers from other
 * device classes, while the final UUID bits retain the normal variant shape.
 */
static void rdp_session_pnp_container_id(uint32_t device_id,
                                         uint8_t container_id[16])
{
    static const uint8_t namespace_bytes[12] = {
        0x6cu, 0x69u, 0x62u, 0x72u, 0x64u, 0x70u,
        0x2du, 0x70u, 0x6eu, 0x70u, 0x00u, 0x01u
    };

    memcpy(container_id, namespace_bytes, sizeof(namespace_bytes));
    container_id[12] = (uint8_t)device_id;
    container_id[13] = (uint8_t)(device_id >> 8u);
    container_id[14] = (uint8_t)(device_id >> 16u);
    container_id[15] = (uint8_t)(device_id >> 24u);
    container_id[6] = (uint8_t)((container_id[6] & 0x0fu) | 0x40u);
    container_id[8] = (uint8_t)((container_id[8] & 0x3fu) | 0x80u);
}

/*
 * Announce configured PNP devices to the server. The function snapshots
 * session-owned backend descriptors into protocol packets so later host-device
 * changes cannot alter an in-flight announcement or violate lifecycle state.
 */
librdp_status rdp_session_pnp_send_devices(librdp_session* session)
{
    rdp_pnp_redirection_device_description devices[LIBRDP_SETTINGS_MAX_PNP_DEVICES];
    rdp_buffer hardware[LIBRDP_SETTINGS_MAX_PNP_DEVICES];
    rdp_buffer compatibility[LIBRDP_SETTINGS_MAX_PNP_DEVICES];
    rdp_buffer descriptions[LIBRDP_SETTINGS_MAX_PNP_DEVICES];
    uint8_t container_ids[LIBRDP_SETTINGS_MAX_PNP_DEVICES][16];
    rdp_buffer packet;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->pnp_redirection_devices_sent)
        return LIBRDP_STATUS_OK;
    if (!rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_PNP))
        return LIBRDP_STATUS_OK;
    count = librdp_settings_pnp_device_count(session->settings);
    if (count == 0)
        return LIBRDP_STATUS_OK;
    if (count > RDP_PNP_REDIRECTION_MAX_DEVICES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(devices, 0, sizeof(devices));
    memset(container_ids, 0, sizeof(container_ids));
    for (i = 0; i < LIBRDP_SETTINGS_MAX_PNP_DEVICES; i++)
    {
        rdp_buffer_init(&hardware[i]);
        rdp_buffer_init(&compatibility[i]);
        rdp_buffer_init(&descriptions[i]);
    }
    rdp_buffer_init(&packet);

    for (i = 0; status == LIBRDP_STATUS_OK && i < count; i++)
    {
        status = rdp_session_pnp_multisz1(&hardware[i],
                                          librdp_settings_pnp_device_hardware_id(session->settings, i));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_pnp_multisz1(
                &compatibility[i],
                librdp_settings_pnp_device_compatibility_id(session->settings, i));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(
                librdp_settings_pnp_device_description(session->settings, i),
                &descriptions[i],
                1);
        if (status == LIBRDP_STATUS_OK)
        {
            devices[i].client_device_id = rdp_settings_pnp_device_id_internal(session->settings, i);
            rdp_session_pnp_container_id(devices[i].client_device_id,
                                         container_ids[i]);
            devices[i].hardware_id = hardware[i].data;
            devices[i].hardware_id_len = (uint32_t)hardware[i].length;
            devices[i].compatibility_id = compatibility[i].data;
            devices[i].compatibility_id_len = (uint32_t)compatibility[i].length;
            devices[i].device_description = descriptions[i].data;
            devices[i].device_description_len = (uint32_t)descriptions[i].length;
            devices[i].custom_flag = RDP_PNP_REDIRECTION_CUSTOM_FLAG_REDIRECTABLE;
            devices[i].container_id = container_ids[i];
            devices[i].container_id_len = sizeof(container_ids[i]);
            devices[i].has_container_id = 1;
            devices[i].device_caps = librdp_settings_pnp_device_caps(session->settings, i);
            devices[i].has_device_caps = 1;
        }
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_pnp_redirection_write_device_addition(&packet, devices, count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session,
                                                         &packet,
                                                         "client.pnp.device_addition");
    if (status == LIBRDP_STATUS_OK)
    {
        session->pnp_redirection_devices_sent = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.pnp.device_addition",
                        "channel_id=%u device_count=%u",
                        session->pnp_redirection_channel_id,
                        count);
    }
    rdp_buffer_free(&packet);
    for (i = 0; i < LIBRDP_SETTINGS_MAX_PNP_DEVICES; i++)
    {
        rdp_buffer_free(&hardware[i]);
        rdp_buffer_free(&compatibility[i]);
        rdp_buffer_free(&descriptions[i]);
    }
    return status;
}

static uint32_t rdp_session_pnp_device_index_from_id(const librdp_session* session,
                                                     uint32_t device_id,
                                                     uint32_t* index)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session || !index)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    count = librdp_settings_pnp_device_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_pnp_device_id_internal(session->settings, i) == device_id)
        {
            *index = i;
            return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
        }
    }
    return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
}

static uint32_t rdp_session_pnp_open_device_index(const librdp_session* session, uint32_t* index)
{
    if (!session || !index)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (!session->pnp_redirection_open_device_active)
        return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    return rdp_session_pnp_device_index_from_id(session,
                                                session->pnp_redirection_open_device_id,
                                                index);
}

static librdp_status rdp_session_pnp_build_read_data(const librdp_session* session,
                                                     uint32_t index,
                                                     rdp_buffer* out)
{
    const char* hardware = NULL;
    const char* compatibility = NULL;
    const char* description = NULL;

    if (!session || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    hardware = librdp_settings_pnp_device_hardware_id(session->settings, index);
    compatibility = librdp_settings_pnp_device_compatibility_id(session->settings, index);
    description = librdp_settings_pnp_device_description(session->settings, index);
    if (!hardware || !compatibility || !description)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_buffer_append(out, hardware, strlen(hardware)) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(out, '\n') != LIBRDP_STATUS_OK ||
        rdp_buffer_append(out, compatibility, strlen(compatibility)) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(out, '\n') != LIBRDP_STATUS_OK ||
        rdp_buffer_append(out, description, strlen(description)) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(out, '\n') != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    if (out->length > session->limits.device_io_bytes)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_pnp_prepare_storage(librdp_session* session,
                                                     uint32_t index,
                                                     uint32_t device_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->pnp_redirection_storage_active &&
        session->pnp_redirection_storage_device_id == device_id)
        return LIBRDP_STATUS_OK;
    rdp_buffer_free(&session->pnp_redirection_storage);
    rdp_buffer_init(&session->pnp_redirection_storage);
    status = rdp_session_pnp_build_read_data(session, index, &session->pnp_redirection_storage);
    if (status == LIBRDP_STATUS_OK)
    {
        session->pnp_redirection_storage_active = 1;
        session->pnp_redirection_storage_device_id = device_id;
    }
    return status;
}

static uint32_t rdp_session_pnp_read_storage(const librdp_session* session,
                                             uint64_t offset,
                                             uint32_t requested,
                                             const uint8_t** data)
{
    size_t available = 0;

    if (!session || !data || !session->pnp_redirection_storage_active)
        return 0;
    *data = NULL;
    if (offset >= session->pnp_redirection_storage.length)
        return 0;
    available = session->pnp_redirection_storage.length - (size_t)offset;
    if (requested > available)
        requested = (uint32_t)available;
    *data = session->pnp_redirection_storage.data + (size_t)offset;
    return requested;
}

static librdp_status rdp_session_pnp_write_storage(librdp_session* session,
                                                   uint64_t offset,
                                                   const uint8_t* data,
                                                   uint32_t data_len)
{
    size_t end = 0;
    size_t old_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !session->pnp_redirection_storage_active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (offset > session->limits.device_io_bytes ||
        data_len > session->limits.device_io_bytes ||
        data_len > session->limits.device_io_bytes - offset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    end = (size_t)offset + data_len;
    old_len = session->pnp_redirection_storage.length;
    if (end > old_len)
    {
        status = rdp_buffer_reserve(&session->pnp_redirection_storage, end);
        if (status != LIBRDP_STATUS_OK)
            return status;
        memset(session->pnp_redirection_storage.data + old_len, 0, end - old_len);
        session->pnp_redirection_storage.length = end;
    }
    if (data_len > 0)
        memcpy(session->pnp_redirection_storage.data + (size_t)offset, data, data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_pnp_send_status(librdp_session* session,
                                                 uint32_t request_id,
                                                 uint32_t io_status,
                                                 const char* event)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_pnp_redirection_write_status_reply(&packet, request_id, io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_pnp_redirection_packet(session, &packet, event);
    rdp_buffer_free(&packet);
    return status;
}

/*
 * PNP redirection multiplexes version/authentication announcements and server
 * I/O requests on one static channel. Keep all state transitions in this
 * dispatcher so partial storage writes, open-device lifetime, and completion
 * status mapping stay ordered exactly as the server expects.
 */
librdp_status rdp_session_handle_pnp_redirection_message(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_pnp_redirection_info_header info;
    rdp_pnp_redirection_server_io_header server_header;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&info, 0, sizeof(info));
    if (rdp_pnp_redirection_parse_info_header(data, data_len, &info) == LIBRDP_STATUS_OK)
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.pnp.info",
                              "packet_id=%u payload_len=%u",
                              info.packet_id,
                              (unsigned)info.payload_len);
        switch (info.packet_id)
        {
            case RDP_PNP_REDIRECTION_INFO_VERSION:
            {
                rdp_pnp_redirection_version version;
                status = rdp_pnp_redirection_parse_version(data, data_len, &version);
                if (status == LIBRDP_STATUS_OK)
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.server_version",
                                    "major=%u minor=%u capabilities=%u",
                                    version.major_version,
                                    version.minor_version,
                                    version.capabilities);
                }
                break;
            }
            case RDP_PNP_REDIRECTION_INFO_SERVER_LOGON:
                status = rdp_pnp_redirection_parse_authenticated(data, data_len, &info);
                if (status == LIBRDP_STATUS_OK)
                {
                    session->pnp_redirection_ready = 1;
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.server_logon",
                                    "channel_id=%u",
                                    session->pnp_redirection_channel_id);
                    status = rdp_session_pnp_send_devices(session);
                }
                break;
            case RDP_PNP_REDIRECTION_INFO_REDIRECT_DEVICES:
            {
                rdp_pnp_redirection_device_addition addition;
                status = rdp_pnp_redirection_parse_device_addition(data, data_len, &addition);
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.device_addition",
                                    "device_count=%u",
                                    addition.device_count);
                break;
            }
            case RDP_PNP_REDIRECTION_INFO_UNREDIRECT_DEVICE:
            {
                rdp_pnp_redirection_device_removal removal;
                status = rdp_pnp_redirection_parse_device_removal(data, data_len, &removal);
                if (status == LIBRDP_STATUS_OK)
                {
                    uint8_t open_cleared = 0;

                    if (session->pnp_redirection_open_device_active &&
                        session->pnp_redirection_open_device_id == removal.client_device_id)
                    {
                        session->pnp_redirection_open_device_active = 0;
                        session->pnp_redirection_open_device_id = 0;
                        session->pnp_redirection_storage_active = 0;
                        session->pnp_redirection_storage_device_id = 0;
                        rdp_buffer_free(&session->pnp_redirection_storage);
                        rdp_buffer_init(&session->pnp_redirection_storage);
                        open_cleared = 1;
                    }
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.device_removal",
                                    "device_id=%u open_cleared=%u",
                                    removal.client_device_id,
                                    open_cleared);
                }
                break;
            }
            default:
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
        }
        return status;
    }

    memset(&server_header, 0, sizeof(server_header));
    status = rdp_pnp_redirection_parse_server_io_header(data, data_len, &server_header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.pnp.io_request",
                    "request_id=%u function=%u payload_len=%u",
                    server_header.request_id,
                    server_header.function_id,
                    (unsigned)server_header.payload_len);
    rdp_buffer_init(&response);
    switch (server_header.function_id)
    {
        case RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST:
        {
            rdp_pnp_redirection_io_version request;
            uint16_t version = RDP_PNP_REDIRECTION_IO_VERSION_6;

            status = rdp_pnp_redirection_parse_capabilities_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                version = request.version == RDP_PNP_REDIRECTION_IO_VERSION_4 ?
                              RDP_PNP_REDIRECTION_IO_VERSION_4 :
                              RDP_PNP_REDIRECTION_IO_VERSION_6;
                session->pnp_redirection_io_version = version;
                status = rdp_pnp_redirection_write_capabilities_reply(&response,
                                                                      request.header.request_id,
                                                                      version);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_pnp_redirection_packet(session,
                                                                 &response,
                                                                 "client.pnp.capabilities_reply");
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pnp.capabilities_reply",
                                "request_id=%u version=%u",
                                server_header.request_id,
                                version);
            break;
        }
        case RDP_PNP_REDIRECTION_IO_CREATE_FILE_REQUEST:
        {
            rdp_pnp_redirection_create_request request;
            status = rdp_pnp_redirection_parse_create_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                uint32_t index = 0;
                uint32_t io_status =
                    rdp_session_pnp_device_index_from_id(session, request.device_id, &index);

                if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                {
                    status = rdp_session_pnp_prepare_storage(session, index, request.device_id);
                    if (status != LIBRDP_STATUS_OK)
                    {
                        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
                    }
                    else
                    {
                        session->pnp_redirection_open_device_active = 1;
                        session->pnp_redirection_open_device_id = request.device_id;
                    }
                }
                status = rdp_session_pnp_send_status(session,
                                                     request.header.request_id,
                                                     io_status,
                                                     "client.pnp.create_reply");
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.create_reply",
                                    "request_id=%u device_id=%u status=%u storage_len=%u",
                                    request.header.request_id,
                                    request.device_id,
                                    io_status,
                                    (unsigned)session->pnp_redirection_storage.length);
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_READ_REQUEST:
        {
            rdp_pnp_redirection_read_request request;
            status = rdp_pnp_redirection_parse_read_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                uint32_t index = 0;
                uint32_t io_status = rdp_session_pnp_open_device_index(session, &index);
                const uint8_t* payload = NULL;
                uint32_t payload_len = 0;

                if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                {
                    status = rdp_session_pnp_prepare_storage(session,
                                                             index,
                                                             session->pnp_redirection_open_device_id);
                    if (status != LIBRDP_STATUS_OK)
                        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
                    else
                    {
                        uint64_t offset = ((uint64_t)request.offset_high << 32) |
                                          (uint64_t)request.offset_low;
                        payload_len = rdp_session_pnp_read_storage(session,
                                                                   offset,
                                                                   request.bytes_to_read,
                                                                   &payload);
                    }
                }
                status = rdp_pnp_redirection_write_read_reply(&response,
                                                              request.header.request_id,
                                                              io_status,
                                                              payload,
                                                              payload_len);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_send_pnp_redirection_packet(session,
                                                                     &response,
                                                                     "client.pnp.read_reply");
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.read_reply",
                                    "request_id=%u status=%u offset=%u:%u requested=%u sent=%u",
                                    request.header.request_id,
                                    io_status,
                                    request.offset_high,
                                    request.offset_low,
                                    request.bytes_to_read,
                                    payload_len);
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_WRITE_REQUEST:
        {
            rdp_pnp_redirection_write_request request;
            status = rdp_pnp_redirection_parse_write_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                uint32_t index = 0;
                uint32_t io_status = rdp_session_pnp_open_device_index(session, &index);
                uint32_t bytes_written = 0;

                if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                {
                    uint64_t offset = ((uint64_t)request.offset_high << 32) |
                                      (uint64_t)request.offset_low;

                    status = rdp_session_pnp_prepare_storage(session,
                                                             index,
                                                             session->pnp_redirection_open_device_id);
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_pnp_write_storage(session,
                                                               offset,
                                                               request.data,
                                                               request.bytes_to_write);
                    if (status == LIBRDP_STATUS_OK)
                        bytes_written = request.bytes_to_write;
                    else
                    {
                        io_status = RDP_SESSION_DEVICE_ACCESS_DENIED;
                    }
                }
                status = rdp_pnp_redirection_write_write_reply(&response,
                                                               request.header.request_id,
                                                               io_status,
                                                               bytes_written);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_send_pnp_redirection_packet(session,
                                                                     &response,
                                                                     "client.pnp.write_reply");
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.write_reply",
                                    "request_id=%u status=%u requested=%u written=%u",
                                    request.header.request_id,
                                    io_status,
                                    request.bytes_to_write,
                                    bytes_written);
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_CONTROL_REQUEST:
        {
            rdp_pnp_redirection_control_request request;
            status = rdp_pnp_redirection_parse_control_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                uint32_t index = 0;
                uint32_t io_status = rdp_session_pnp_open_device_index(session, &index);
                const uint8_t* output = NULL;
                uint32_t output_len = 0;

                if (io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
                {
                    (void)index;
                    output = request.input;
                    output_len = request.input_len;
                    if (output_len > request.output_len)
                        output_len = request.output_len;
                    if (output_len > RDP_SESSION_MAX_PNP_READ_BYTES)
                        output_len = RDP_SESSION_MAX_PNP_READ_BYTES;
                }
                status = rdp_pnp_redirection_write_control_reply(&response,
                                                                 request.header.request_id,
                                                                 io_status,
                                                                 output,
                                                                 output_len);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_send_pnp_redirection_packet(session,
                                                                     &response,
                                                                     "client.pnp.control_reply");
                if (status == LIBRDP_STATUS_OK)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.pnp.control_reply",
                                    "request_id=%u status=%u io_code=%u input_len=%u output_len=%u returned=%u",
                                    request.header.request_id,
                                    io_status,
                                    request.io_code,
                                    request.input_len,
                                    request.output_len,
                                    output_len);
            }
            break;
        }
        case RDP_PNP_REDIRECTION_IO_SPECIFIC_CANCEL_REQUEST:
        {
            rdp_pnp_redirection_cancel_request request;
            status = rdp_pnp_redirection_parse_cancel_request(data, data_len, &request);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_pnp_send_status(session,
                                                     request.header.request_id,
                                                     RDP_DEVICE_REDIRECTION_STATUS_SUCCESS,
                                                     "client.pnp.cancel_reply");
            break;
        }
        default:
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
    }
    rdp_buffer_free(&response);
    return status;
}



void rdp_session_redirected_file_reset(rdp_session_redirected_file* file)
{
    if (!file)
        return;
    if (!file->active)
    {
        memset(file, 0, sizeof(*file));
        file->fd = -1;
        return;
    }
    if (file->directory)
        (void)closedir(file->directory);
    if (file->fd >= 0)
        (void)close(file->fd);
    rdp_session_directory_notify_clear(file);
    free(file->path);
    free(file->directory_path);
    free(file->directory_pattern);
    memset(file, 0, sizeof(*file));
    file->fd = -1;
}

void rdp_session_redirected_files_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < session->limits.file_handles; i++)
        rdp_session_redirected_file_reset(&session->redirected_files[i]);
    memset(session->redirected_files, 0, sizeof(session->redirected_files));
    session->next_redirected_file_id = 1;
}

void rdp_session_drive_roots_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < LIBRDP_SETTINGS_MAX_DRIVES; i++)
    {
        if (session->drive_roots[i].active && session->drive_roots[i].fd >= 0)
            (void)close(session->drive_roots[i].fd);
    }
    memset(session->drive_roots, 0, sizeof(session->drive_roots));
}

static uint32_t rdp_session_drive_open_root(librdp_session* session, uint32_t drive_index)
{
    const char* root = NULL;
    struct stat after;
    int fd = -1;

    if (!session || drive_index >= LIBRDP_SETTINGS_MAX_DRIVES)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (session->drive_roots[drive_index].active)
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    root = librdp_settings_drive_path(session->settings, drive_index);
    if (!root || root[0] == '\0')
        return RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    memset(&after, 0, sizeof(after));
    fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return rdp_session_errno_to_device_status(errno);
    if (fstat(fd, &after) != 0)
    {
        uint32_t io_status = rdp_session_errno_to_device_status(errno);
        (void)close(fd);
        return io_status;
    }
    if (!S_ISDIR(after.st_mode))
    {
        (void)close(fd);
        return RDP_SESSION_DEVICE_NOT_A_DIRECTORY;
    }
    session->drive_roots[drive_index].active = 1;
    session->drive_roots[drive_index].fd = fd;
    session->drive_roots[drive_index].dev = after.st_dev;
    session->drive_roots[drive_index].ino = after.st_ino;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

uint32_t rdp_session_drive_root_fd(librdp_session* session, uint32_t drive_index, int* fd)
{
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    struct stat st;

    if (!session || !fd || drive_index >= LIBRDP_SETTINGS_MAX_DRIVES)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    *fd = -1;
    io_status = rdp_session_drive_open_root(session, drive_index);
    if (io_status != RDP_DEVICE_REDIRECTION_STATUS_SUCCESS)
        return io_status;
    if (fstat(session->drive_roots[drive_index].fd, &st) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (st.st_dev != session->drive_roots[drive_index].dev ||
        st.st_ino != session->drive_roots[drive_index].ino ||
        !S_ISDIR(st.st_mode))
        return RDP_SESSION_DEVICE_ACCESS_DENIED;
    *fd = session->drive_roots[drive_index].fd;
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

rdp_session_redirected_file* rdp_session_redirected_file_find(librdp_session* session,
                                                                     uint32_t device_id,
                                                                     uint32_t file_id)
{
    size_t i = 0;

    if (!session || file_id == 0)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_REDIRECTED_FILES; i++)
    {
        if (session->redirected_files[i].active &&
            session->redirected_files[i].device_id == device_id &&
            session->redirected_files[i].file_id == file_id)
            return &session->redirected_files[i];
    }
    rdp_session_metric_add(&session->metrics.limits_rejected, 1);
    return NULL;
}

rdp_session_redirected_file* rdp_session_redirected_file_alloc(librdp_session* session,
                                                                      uint32_t device_id,
                                                                      uint32_t* file_id)
{
    size_t i = 0;
    uint32_t candidate = 0;

    if (!session || !file_id)
        return NULL;
    for (i = 0; i < session->limits.file_handles; i++)
    {
        if (!session->redirected_files[i].active)
        {
            candidate = session->next_redirected_file_id++;
            if (candidate == 0)
                candidate = session->next_redirected_file_id++;
            session->redirected_files[i].active = 1;
            session->redirected_files[i].device_id = device_id;
            session->redirected_files[i].file_id = candidate;
            session->redirected_files[i].fd = -1;
            session->redirected_files[i].directory = NULL;
            *file_id = candidate;
            return &session->redirected_files[i];
        }
    }
    rdp_session_metric_add(&session->metrics.limits_rejected, 1);
    return NULL;
}

uint32_t rdp_session_drive_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_drive_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_drive_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

uint32_t rdp_session_printer_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_printer_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_printer_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

uint32_t rdp_session_smartcard_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_smartcard_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_smartcard_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

uint32_t rdp_session_serial_port_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_serial_port_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_serial_port_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}

uint32_t rdp_session_parallel_port_index_from_device_id(const librdp_session* session, uint32_t device_id)
{
    uint32_t count = 0;
    uint32_t i = 0;

    if (!session)
        return UINT32_MAX;
    count = librdp_settings_parallel_port_count(session->settings);
    for (i = 0; i < count; i++)
    {
        if (rdp_settings_parallel_port_device_id_internal(session->settings, i) == device_id)
            return i;
    }
    return UINT32_MAX;
}



static librdp_status rdp_session_handle_device_io_request(librdp_session* session,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_device_redirection_io_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (rdp_session_drive_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_filesystem_io_request(session, data, data_len);
    if (rdp_session_serial_port_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_port_io_request(session,
                                                  data,
                                                  data_len,
                                                  RDP_SESSION_PORT_TYPE_SERIAL,
                                                  rdp_session_serial_port_index_from_device_id(session,
                                                                                              request.device_id));
    if (rdp_session_parallel_port_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_port_io_request(session,
                                                  data,
                                                  data_len,
                                                  RDP_SESSION_PORT_TYPE_PARALLEL,
                                                  rdp_session_parallel_port_index_from_device_id(session,
                                                                                                request.device_id));
    if (rdp_session_printer_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_printer_io_request(session, data, data_len);
    if (rdp_session_smartcard_index_from_device_id(session, request.device_id) != UINT32_MAX)
        return rdp_session_handle_smartcard_io_request(session, data, data_len);

    rdp_buffer_init(&response);
    status = rdp_device_redirection_write_io_completion(&response,
                                                        request.device_id,
                                                        request.completion_id,
                                                        RDP_SESSION_DEVICE_NO_SUCH_DEVICE,
                                                        NULL,
                                                        0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.io_completion.no_device");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_write_device_redirection_client_name(rdp_buffer* buffer)
{
    static const char name[] = "librdp";
    uint8_t utf16[(sizeof(name)) * 2u];
    size_t i = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(utf16, 0, sizeof(utf16));
    for (i = 0; i + 1u < sizeof(name); i++)
        utf16[i * 2u] = (uint8_t)name[i];
    return rdp_device_redirection_write_client_name_utf16le(buffer, utf16, (uint32_t)sizeof(utf16));
}

static librdp_status rdp_session_drive_name_to_utf16le(const char* name,
                                                       uint8_t* out,
                                                       size_t out_len,
                                                       uint32_t* written)
{
    rdp_buffer buffer;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!name || !out || out_len < 2u || !written)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(out, 0, out_len);
    rdp_buffer_init(&buffer);
    status = rdp_charset_utf8_to_utf16le_buffer(name, 1, &buffer);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&buffer);
        return status;
    }
    if (buffer.length > out_len || buffer.length > UINT32_MAX)
    {
        rdp_buffer_free(&buffer);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    memcpy(out, buffer.data, buffer.length);
    *written = (uint32_t)buffer.length;
    rdp_buffer_free(&buffer);
    return LIBRDP_STATUS_OK;
}

/*
 * Send the aggregate device redirection announcement. Each configured drive,
 * printer, port, smartcard, and optional backend is serialized from session-
 * owned settings into stable device IDs.
 */
static librdp_status rdp_session_send_device_redirection_device_list(librdp_session* session)
{
    rdp_device_redirection_device_announce
        devices[LIBRDP_SETTINGS_MAX_DRIVES + LIBRDP_SETTINGS_MAX_SERIAL_PORTS +
                LIBRDP_SETTINGS_MAX_PARALLEL_PORTS + LIBRDP_SETTINGS_MAX_PRINTERS +
                LIBRDP_SETTINGS_MAX_SMARTCARDS];
    uint8_t names[LIBRDP_SETTINGS_MAX_DRIVES][16];
    rdp_buffer printer_data[LIBRDP_SETTINGS_MAX_PRINTERS];
    rdp_buffer packet;
    uint32_t drive_count = 0;
    uint32_t serial_count = 0;
    uint32_t parallel_count = 0;
    uint32_t printer_count = 0;
    uint32_t smartcard_count = 0;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(devices, 0, sizeof(devices));
    memset(names, 0, sizeof(names));
    for (i = 0; i < LIBRDP_SETTINGS_MAX_PRINTERS; i++)
        rdp_buffer_init(&printer_data[i]);
    drive_count = librdp_settings_drive_count(session->settings);
    serial_count = librdp_settings_serial_port_count(session->settings);
    parallel_count = librdp_settings_parallel_port_count(session->settings);
    printer_count = librdp_settings_printer_count(session->settings);
    smartcard_count = librdp_settings_smartcard_count(session->settings);
    if (drive_count > LIBRDP_SETTINGS_MAX_DRIVES || printer_count > LIBRDP_SETTINGS_MAX_PRINTERS ||
        smartcard_count > LIBRDP_SETTINGS_MAX_SMARTCARDS ||
        serial_count > LIBRDP_SETTINGS_MAX_SERIAL_PORTS ||
        parallel_count > LIBRDP_SETTINGS_MAX_PARALLEL_PORTS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < drive_count; i++)
    {
        const char* name = librdp_settings_drive_name(session->settings, i);
        size_t name_len = name ? strlen(name) : 0;

        if (!name || name_len == 0 || name_len > 7u)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto out;
        }
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM;
        devices[count].device_id = rdp_settings_drive_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, name, name_len + 1u);
        status = rdp_session_drive_name_to_utf16le(name, names[i], sizeof(names[i]), &devices[count].data_len);
        if (status != LIBRDP_STATUS_OK)
            goto out;
        devices[count].data = names[i];
        count++;
    }
    for (i = 0; i < serial_count; i++)
    {
        const char* name = librdp_settings_serial_port_name(session->settings, i);
        size_t name_len = name ? strlen(name) : 0;

        if (!name || name_len == 0 || name_len > 7u)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto out;
        }
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_SERIAL;
        devices[count].device_id = rdp_settings_serial_port_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, name, name_len + 1u);
        devices[count].data = NULL;
        devices[count].data_len = 0;
        count++;
    }
    for (i = 0; i < parallel_count; i++)
    {
        const char* name = librdp_settings_parallel_port_name(session->settings, i);
        size_t name_len = name ? strlen(name) : 0;

        if (!name || name_len == 0 || name_len > 7u)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
            goto out;
        }
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_PARALLEL;
        devices[count].device_id = rdp_settings_parallel_port_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, name, name_len + 1u);
        devices[count].data = NULL;
        devices[count].data_len = 0;
        count++;
    }
    for (i = 0; i < printer_count; i++)
    {
        rdp_printer_redirection_announce announce;
        rdp_buffer driver;
        rdp_buffer printer;
        char port_name[8];
        const char* driver_name = librdp_settings_printer_driver(session->settings, i);
        const char* printer_name = librdp_settings_printer_name(session->settings, i);

        rdp_buffer_init(&driver);
        rdp_buffer_init(&printer);
        memset(&announce, 0, sizeof(announce));
        if (snprintf(port_name, sizeof(port_name), "PRN%u", (unsigned)i + 1u) <= 0)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(driver_name, &driver, 1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(printer_name, &printer, 1);
        if (status == LIBRDP_STATUS_OK)
        {
            announce.flags = 0;
            if (i == 0)
                announce.flags |= RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_DEFAULT;
            announce.driver_name = driver.data;
            announce.driver_name_len = (uint32_t)driver.length;
            announce.printer_name = printer.data;
            announce.printer_name_len = (uint32_t)printer.length;
            status = rdp_printer_redirection_write_announce_data(&printer_data[i], &announce);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_PRINTER;
            devices[count].device_id = rdp_settings_printer_device_id_internal(session->settings, i);
            memcpy(devices[count].preferred_dos_name, port_name, strlen(port_name) + 1u);
            devices[count].data = printer_data[i].data;
            devices[count].data_len = (uint32_t)printer_data[i].length;
            count++;
        }
        rdp_buffer_free(&driver);
        rdp_buffer_free(&printer);
        if (status != LIBRDP_STATUS_OK)
            goto out;
    }
    for (i = 0; i < smartcard_count; i++)
    {
        devices[count].device_type = RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD;
        devices[count].device_id = rdp_settings_smartcard_device_id_internal(session->settings, i);
        memcpy(devices[count].preferred_dos_name, "SCARD", 6u);
        devices[count].data = NULL;
        devices[count].data_len = 0;
        count++;
    }
    rdp_buffer_init(&packet);
    status = rdp_device_redirection_write_device_list_announce(&packet, devices, count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &packet,
                                                            "client.rdpdr.device_list");
    rdp_buffer_free(&packet);
    if (status == LIBRDP_STATUS_OK)
    {
        session->device_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.device_list",
                        "channel_id=%u drive_count=%u serial_count=%u parallel_count=%u printer_count=%u smartcard_count=%u device_count=%u",
                        session->device_redirection_channel_id,
                        drive_count,
                        serial_count,
                        parallel_count,
                        printer_count,
                        smartcard_count,
                        count);
    }
out:
    for (i = 0; i < LIBRDP_SETTINGS_MAX_PRINTERS; i++)
        rdp_buffer_free(&printer_data[i]);
    return status;
}

static librdp_status rdp_session_handle_printer_component_message(librdp_session* session,
                                                                  const uint8_t* data,
                                                                  size_t data_len,
                                                                  uint16_t packet_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (packet_id == RDP_DEVICE_REDIRECTION_PAKID_PRINTER_CACHE_DATA)
    {
        rdp_printer_redirection_cache_event event;
        uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;

        status = rdp_printer_redirection_parse_cache_event(data, data_len, &event);
        if (status == LIBRDP_STATUS_OK)
            io_status = rdp_session_store_printer_cache_event(session, &event);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.printer.cache",
                            "channel_id=%u event_id=%u printer_name_len=%u cached_len=%u status=%u",
                            session->device_redirection_channel_id,
                            event.event_id,
                            event.printer_name_len,
                            event.cached_fields_len,
                            io_status);
    }
    else if (packet_id == RDP_DEVICE_REDIRECTION_PAKID_PRINTER_USING_XPS)
    {
        rdp_printer_redirection_xps_mode mode;

        status = rdp_printer_redirection_parse_xps_mode(data, data_len, &mode);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.printer.xps_mode",
                            "channel_id=%u printer_id=%u flags=%u",
                            session->device_redirection_channel_id,
                            mode.printer_id,
                            mode.flags);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.rdpdr.printer.pdu.ignored",
                              "channel_id=%u packet_id=%u payload_len=%u",
                              session->device_redirection_channel_id,
                              packet_id,
                              (unsigned)data_len);
    }
    return status;
}

/*
 * Dispatch one device redirection message after static-channel framing.
 * Capability exchange, device announcements, and IRP routing stay centralized
 * so device IDs cannot target the wrong backend.
 */
librdp_status rdp_session_handle_device_redirection_message(librdp_session* session,
                                                                   const uint8_t* data,
                                                                   size_t data_len)
{
    rdp_device_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header.component == RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER)
        return rdp_session_handle_printer_component_message(session, data, data_len, header.packet_id);
    if (header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_ANNOUNCE)
    {
        rdp_device_redirection_announce announce;
        rdp_buffer client_announce;
        rdp_buffer client_name;

        rdp_buffer_init(&client_announce);
        rdp_buffer_init(&client_name);
        status = rdp_device_redirection_parse_server_announce(data, data_len, &announce);
        if (status == LIBRDP_STATUS_OK)
        {
            session->device_redirection_version_minor = announce.version_minor;
            session->device_redirection_client_id = announce.client_id;
            status = rdp_device_redirection_write_client_announce(&client_announce,
                                                                  announce.version_minor,
                                                                  announce.client_id);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_device_redirection_client_name(&client_name);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_packet(session,
                                                                &client_announce,
                                                                "client.rdpdr.client_announce");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_packet(session,
                                                                &client_name,
                                                                "client.rdpdr.client_name");
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.server_announce",
                            "channel_id=%u version_minor=%u client_id=%u",
                            session->device_redirection_channel_id,
                            announce.version_minor,
                            announce.client_id);
        rdp_buffer_free(&client_name);
        rdp_buffer_free(&client_announce);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_CLIENTID_CONFIRM)
    {
        rdp_device_redirection_announce confirm;

        status = rdp_device_redirection_parse_client_id_confirm(data, data_len, &confirm);
        if (status == LIBRDP_STATUS_OK)
        {
            session->device_redirection_version_minor = confirm.version_minor;
            session->device_redirection_client_id = confirm.client_id;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.client_id_confirm",
                            "channel_id=%u version_minor=%u client_id=%u",
                            session->device_redirection_channel_id,
                            confirm.version_minor,
                            confirm.client_id);
        }
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY)
    {
        rdp_device_redirection_capability_list server_caps;
        rdp_device_redirection_capability_config config;
        rdp_buffer response;

        rdp_buffer_init(&response);
        status = rdp_device_redirection_parse_capability_list(data,
                                                              data_len,
                                                              RDP_DEVICE_REDIRECTION_PAKID_CORE_SERVER_CAPABILITY,
                                                              &server_caps);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_device_redirection_make_default_capability_config(&config);
        if (status == LIBRDP_STATUS_OK && session->device_redirection_version_minor != 0)
            config.general.protocol_minor_version = session->device_redirection_version_minor;
        if (status == LIBRDP_STATUS_OK)
            config.include_drive = librdp_settings_drive_count(session->settings) > 0 ? 1u : 0u;
        if (status == LIBRDP_STATUS_OK)
            config.include_printer = librdp_settings_printer_count(session->settings) > 0 ? 1u : 0u;
        if (status == LIBRDP_STATUS_OK)
            config.include_port =
                librdp_settings_serial_port_count(session->settings) > 0 ||
                        librdp_settings_parallel_port_count(session->settings) > 0 ?
                    1u :
                    0u;
        if (status == LIBRDP_STATUS_OK)
            config.include_smartcard =
                librdp_settings_smartcard_count(session->settings) > 0 ? 1u : 0u;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_device_redirection_write_client_capability_response(&response, &config);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_packet(session,
                                                                &response,
                                                                "client.rdpdr.capability_response");
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.capability_response",
                            "channel_id=%u server_caps=%u drive=%u printer=%u port=%u smartcard=%u",
                            session->device_redirection_channel_id,
                            server_caps.count,
                            config.include_drive,
                            config.include_printer,
                            config.include_port,
                            config.include_smartcard);
        rdp_buffer_free(&response);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_USER_LOGGEDON)
    {
        status = rdp_device_redirection_parse_user_loggedon(data, data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_device_redirection_device_list(session);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.user_loggedon",
                            "channel_id=%u",
                            session->device_redirection_channel_id);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY)
    {
        rdp_device_redirection_device_reply reply;

        status = rdp_device_redirection_parse_device_reply(data, data_len, &reply);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.rdpdr.device_reply",
                            "channel_id=%u device_id=%u result=%u",
                            session->device_redirection_channel_id,
                            reply.device_id,
                            reply.result_code);
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST)
    {
        status = rdp_session_handle_device_io_request(session, data, data_len);
    }
    else
    {
        rdp_trace_event_level(RDP_TRACE_CLIENT,
                              RDP_TRACE_LEVEL_DEBUG,
                              "client.rdpdr.pdu.ignored",
                              "channel_id=%u packet_id=%u payload_len=%u",
                              session->device_redirection_channel_id,
                              header.packet_id,
                              (unsigned)data_len);
    }
    return status;
}

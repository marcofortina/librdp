/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: plug-and-play redirection device description and request helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/pnp_redirection.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

#define RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH 8u
#define RDP_PNP_REDIRECTION_SERVER_IO_HEADER_LENGTH 8u
#define RDP_PNP_REDIRECTION_CLIENT_IO_HEADER_LENGTH 4u
#define RDP_PNP_REDIRECTION_DEVICE_DESCRIPTION_FIXED_MIN 32u
#define RDP_PNP_REDIRECTION_REQUEST_ID_MAX 0x00ffffffu

static int rdp_pnp_redirection_valid_info_packet_id(uint32_t packet_id)
{
    return packet_id == RDP_PNP_REDIRECTION_INFO_VERSION ||
           packet_id == RDP_PNP_REDIRECTION_INFO_REDIRECT_DEVICES ||
           packet_id == RDP_PNP_REDIRECTION_INFO_SERVER_LOGON ||
           packet_id == RDP_PNP_REDIRECTION_INFO_UNREDIRECT_DEVICE;
}

static int rdp_pnp_redirection_valid_io_function(uint32_t function_id)
{
    return function_id == RDP_PNP_REDIRECTION_IO_READ_REQUEST ||
           function_id == RDP_PNP_REDIRECTION_IO_WRITE_REQUEST ||
           function_id == RDP_PNP_REDIRECTION_IO_CONTROL_REQUEST ||
           function_id == RDP_PNP_REDIRECTION_IO_CREATE_FILE_REQUEST ||
           function_id == RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST ||
           function_id == RDP_PNP_REDIRECTION_IO_SPECIFIC_CANCEL_REQUEST;
}

static int rdp_pnp_redirection_valid_io_version(uint16_t version)
{
    return version == RDP_PNP_REDIRECTION_IO_VERSION_4 ||
           version == RDP_PNP_REDIRECTION_IO_VERSION_6;
}

static int rdp_pnp_redirection_valid_custom_flag(uint32_t custom_flag)
{
    return custom_flag == RDP_PNP_REDIRECTION_CUSTOM_FLAG_REDIRECTABLE ||
           custom_flag == RDP_PNP_REDIRECTION_CUSTOM_FLAG_OPTIONAL_1 ||
           custom_flag == RDP_PNP_REDIRECTION_CUSTOM_FLAG_OPTIONAL_2;
}

static librdp_status rdp_pnp_redirection_write_info_header(rdp_buffer* buffer,
                                                           uint32_t packet_id,
                                                           uint32_t size)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_pnp_redirection_valid_info_packet_id(packet_id) ||
        size < RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, packet_id);
}

static librdp_status rdp_pnp_redirection_append_blob(rdp_buffer* buffer,
                                                     const uint8_t* data,
                                                     uint32_t length)
{
    if (!buffer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append(buffer, data, length);
}

static librdp_status rdp_pnp_redirection_read_blob(rdp_stream* stream,
                                                   uint32_t length,
                                                   const uint8_t** data)
{
    if (!stream || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *data = NULL;
    if (length > rdp_stream_remaining(stream) ||
        rdp_stream_read_bytes(stream, data, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_pnp_redirection_read_u24_le(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16);
}

static librdp_status rdp_pnp_redirection_append_u24_le(rdp_buffer* buffer, uint32_t value)
{
    uint8_t bytes[3];

    if (!buffer || value > RDP_PNP_REDIRECTION_REQUEST_ID_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    bytes[2] = (uint8_t)((value >> 16) & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

/*
 * Serialize one redirected PNP device description. Host-provided names and
 * identifiers are length-bounded and copied into the packet so backend memory
 * is not referenced after the write.
 */
static librdp_status rdp_pnp_redirection_write_device_description(
    rdp_buffer* buffer,
    const rdp_pnp_redirection_device_description* description)
{
    size_t data_size = RDP_PNP_REDIRECTION_DEVICE_DESCRIPTION_FIXED_MIN;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !description ||
        (!description->interface_guids && description->interface_guids_len > 0) ||
        (!description->hardware_id && description->hardware_id_len > 0) ||
        (!description->compatibility_id && description->compatibility_id_len > 0) ||
        (!description->device_description && description->device_description_len > 0) ||
        (!description->container_id && description->container_id_len > 0) ||
        (description->interface_guids_len % 16u) != 0 ||
        !rdp_pnp_redirection_valid_custom_flag(description->custom_flag))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    data_size += description->interface_guids_len;
    data_size += description->hardware_id_len;
    data_size += description->compatibility_id_len;
    data_size += description->device_description_len;
    if (description->has_container_id)
    {
        if (description->container_id_len != 16u)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        data_size += 20u;
    }
    if (description->has_device_caps)
        data_size += 8u;
    if (data_size > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, description->client_device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, (uint32_t)data_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, description->interface_guids_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_pnp_redirection_append_blob(buffer, description->interface_guids, description->interface_guids_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, description->hardware_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_pnp_redirection_append_blob(buffer, description->hardware_id, description->hardware_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, description->compatibility_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_pnp_redirection_append_blob(buffer, description->compatibility_id, description->compatibility_id_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, description->device_description_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_pnp_redirection_append_blob(buffer,
                                             description->device_description,
                                             description->device_description_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 4u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, description->custom_flag);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (description->has_container_id)
    {
        status = rdp_buffer_append_u32_le(buffer, 16u);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, description->container_id, 16u);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (description->has_device_caps)
    {
        status = rdp_buffer_append_u32_le(buffer, 4u);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append_u32_le(buffer, description->device_caps);
    }
    return status;
}

librdp_status rdp_pnp_redirection_parse_info_header(const void* data,
                                                    size_t length,
                                                    rdp_pnp_redirection_info_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH || length > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &header->size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->packet_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->size != length || !rdp_pnp_redirection_valid_info_packet_id(header->packet_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->payload = (const uint8_t*)data + RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH;
    header->payload_len = length - RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_version(rdp_buffer* buffer,
                                                uint32_t major_version,
                                                uint32_t minor_version,
                                                uint32_t capabilities)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (capabilities & ~RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES) != 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_info_header(buffer,
                                                   RDP_PNP_REDIRECTION_INFO_VERSION,
                                                   RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH + 12u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, major_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, minor_version);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, capabilities);
}

librdp_status rdp_pnp_redirection_parse_version(const void* data,
                                                size_t length,
                                                rdp_pnp_redirection_version* version)
{
    rdp_stream stream;

    if (!data || !version)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(version, 0, sizeof(*version));
    if (rdp_pnp_redirection_parse_info_header(data, length, &version->header) != LIBRDP_STATUS_OK ||
        version->header.packet_id != RDP_PNP_REDIRECTION_INFO_VERSION ||
        version->header.payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, version->header.payload, version->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &version->major_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &version->minor_version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &version->capabilities) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((version->capabilities & ~RDP_PNP_REDIRECTION_CAP_DYNAMIC_DEVICES) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_authenticated(const void* data,
                                                      size_t length,
                                                      rdp_pnp_redirection_info_header* header)
{
    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_pnp_redirection_parse_info_header(data, length, header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->packet_id != RDP_PNP_REDIRECTION_INFO_SERVER_LOGON ||
        header->payload_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_authenticated(rdp_buffer* buffer)
{
    return rdp_pnp_redirection_write_info_header(buffer,
                                                RDP_PNP_REDIRECTION_INFO_SERVER_LOGON,
                                                RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH);
}

librdp_status rdp_pnp_redirection_parse_device_description(
    const void* data,
    size_t length,
    rdp_pnp_redirection_device_description* description)
{
    rdp_stream stream;
    uint32_t custom_flag_len = 0;
    uint32_t optional_len = 0;

    if (!data || !description)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_PNP_REDIRECTION_DEVICE_DESCRIPTION_FIXED_MIN || length > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(description, 0, sizeof(*description));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &description->client_device_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &description->data_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (description->data_size < RDP_PNP_REDIRECTION_DEVICE_DESCRIPTION_FIXED_MIN ||
        description->data_size > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    stream.length = description->data_size;
    if (rdp_stream_read_u32_le(&stream, &description->interface_guids_len) != LIBRDP_STATUS_OK ||
        (description->interface_guids_len % 16u) != 0 ||
        rdp_pnp_redirection_read_blob(&stream,
                                      description->interface_guids_len,
                                      &description->interface_guids) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &description->hardware_id_len) != LIBRDP_STATUS_OK ||
        rdp_pnp_redirection_read_blob(&stream,
                                      description->hardware_id_len,
                                      &description->hardware_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &description->compatibility_id_len) != LIBRDP_STATUS_OK ||
        rdp_pnp_redirection_read_blob(&stream,
                                      description->compatibility_id_len,
                                      &description->compatibility_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &description->device_description_len) != LIBRDP_STATUS_OK ||
        rdp_pnp_redirection_read_blob(&stream,
                                      description->device_description_len,
                                      &description->device_description) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &custom_flag_len) != LIBRDP_STATUS_OK ||
        custom_flag_len != 4u ||
        rdp_stream_read_u32_le(&stream, &description->custom_flag) != LIBRDP_STATUS_OK ||
        !rdp_pnp_redirection_valid_custom_flag(description->custom_flag))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) == 0)
        return LIBRDP_STATUS_OK;
    if (rdp_stream_read_u32_le(&stream, &optional_len) != LIBRDP_STATUS_OK ||
        optional_len != 16u ||
        rdp_stream_read_bytes(&stream, &description->container_id, 16u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    description->container_id_len = 16u;
    description->has_container_id = 1;
    if (rdp_stream_remaining(&stream) == 0)
        return LIBRDP_STATUS_OK;
    if (rdp_stream_read_u32_le(&stream, &optional_len) != LIBRDP_STATUS_OK ||
        optional_len != 4u ||
        rdp_stream_read_u32_le(&stream, &description->device_caps) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    description->has_device_caps = 1;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_device_addition(
    rdp_buffer* buffer,
    const rdp_pnp_redirection_device_description* devices,
    uint32_t device_count)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;

    if (!buffer || (!devices && device_count > 0) ||
        device_count > RDP_PNP_REDIRECTION_MAX_DEVICES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_buffer_append_u32_le(&payload, device_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < device_count; i++)
        status = rdp_pnp_redirection_write_device_description(&payload, &devices[i]);
    if (status == LIBRDP_STATUS_OK && payload.length + RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH > UINT32_MAX)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_pnp_redirection_write_info_header(buffer,
                                                       RDP_PNP_REDIRECTION_INFO_REDIRECT_DEVICES,
                                                       (uint32_t)(payload.length +
                                                                  RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_pnp_redirection_parse_device_addition(
    const void* data,
    size_t length,
    rdp_pnp_redirection_device_addition* addition)
{
    rdp_stream stream;
    uint32_t i = 0;

    if (!data || !addition)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(addition, 0, sizeof(*addition));
    if (rdp_pnp_redirection_parse_info_header(data, length, &addition->header) != LIBRDP_STATUS_OK ||
        addition->header.packet_id != RDP_PNP_REDIRECTION_INFO_REDIRECT_DEVICES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, addition->header.payload, addition->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &addition->device_count) != LIBRDP_STATUS_OK ||
        addition->device_count > RDP_PNP_REDIRECTION_MAX_DEVICES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < addition->device_count; i++)
    {
        const uint8_t* position = addition->header.payload + stream.position;

        if (rdp_pnp_redirection_parse_device_description(position,
                                                         rdp_stream_remaining(&stream),
                                                         &addition->devices[i]) != LIBRDP_STATUS_OK ||
            rdp_stream_skip(&stream, addition->devices[i].data_size) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_pnp_redirection_write_device_removal(rdp_buffer* buffer,
                                                       uint32_t client_device_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_pnp_redirection_write_info_header(buffer,
                                                   RDP_PNP_REDIRECTION_INFO_UNREDIRECT_DEVICE,
                                                   RDP_PNP_REDIRECTION_INFO_HEADER_LENGTH + 4u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, client_device_id);
}

librdp_status rdp_pnp_redirection_parse_device_removal(
    const void* data,
    size_t length,
    rdp_pnp_redirection_device_removal* removal)
{
    rdp_stream stream;

    if (!data || !removal)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(removal, 0, sizeof(*removal));
    if (rdp_pnp_redirection_parse_info_header(data, length, &removal->header) != LIBRDP_STATUS_OK ||
        removal->header.packet_id != RDP_PNP_REDIRECTION_INFO_UNREDIRECT_DEVICE ||
        removal->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, removal->header.payload, removal->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &removal->client_device_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_server_io_header(
    const void* data,
    size_t length,
    rdp_pnp_redirection_server_io_header* header)
{
    rdp_stream stream;
    const uint8_t* request = NULL;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_PNP_REDIRECTION_SERVER_IO_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_bytes(&stream, &request, 3u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->unused) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &header->function_id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->request_id = rdp_pnp_redirection_read_u24_le(request);
    if (!rdp_pnp_redirection_valid_io_function(header->function_id))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->payload = (const uint8_t*)data + RDP_PNP_REDIRECTION_SERVER_IO_HEADER_LENGTH;
    header->payload_len = length - RDP_PNP_REDIRECTION_SERVER_IO_HEADER_LENGTH;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_client_io_header(
    const void* data,
    size_t length,
    rdp_pnp_redirection_client_io_header* header)
{
    rdp_stream stream;
    const uint8_t* request = NULL;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_PNP_REDIRECTION_CLIENT_IO_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_bytes(&stream, &request, 3u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &header->packet_type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header->packet_type != RDP_PNP_REDIRECTION_PACKET_RESPONSE &&
        header->packet_type != RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->request_id = rdp_pnp_redirection_read_u24_le(request);
    header->payload = (const uint8_t*)data + RDP_PNP_REDIRECTION_CLIENT_IO_HEADER_LENGTH;
    header->payload_len = length - RDP_PNP_REDIRECTION_CLIENT_IO_HEADER_LENGTH;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_server_io_header(rdp_buffer* buffer,
                                                        uint32_t request_id,
                                                        uint8_t unused,
                                                        uint32_t function_id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_pnp_redirection_valid_io_function(function_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_append_u24_le(buffer, request_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, unused);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, function_id);
}

librdp_status rdp_pnp_redirection_write_client_io_header(rdp_buffer* buffer,
                                                        uint32_t request_id,
                                                        uint8_t packet_type)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        (packet_type != RDP_PNP_REDIRECTION_PACKET_RESPONSE &&
         packet_type != RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_append_u24_le(buffer, request_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, packet_type);
}

librdp_status rdp_pnp_redirection_parse_capabilities_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_io_version* version)
{
    rdp_stream stream;

    if (!data || !version)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(version, 0, sizeof(*version));
    if (rdp_pnp_redirection_parse_server_io_header(data, length, &version->header) != LIBRDP_STATUS_OK ||
        version->header.function_id != RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST ||
        version->header.payload_len != 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, version->header.payload, version->header.payload_len);
    if (rdp_stream_read_u16_le(&stream, &version->version) != LIBRDP_STATUS_OK ||
        !rdp_pnp_redirection_valid_io_version(version->version))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_capabilities_request(rdp_buffer* buffer,
                                                             uint32_t request_id,
                                                             uint8_t unused,
                                                             uint16_t version)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_pnp_redirection_valid_io_version(version))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_server_io_header(buffer,
                                                        request_id,
                                                        unused,
                                                        RDP_PNP_REDIRECTION_IO_CAPABILITIES_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, version);
}

librdp_status rdp_pnp_redirection_write_capabilities_reply(rdp_buffer* buffer,
                                                           uint32_t request_id,
                                                           uint16_t version)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_pnp_redirection_valid_io_version(version))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_client_io_header(buffer,
                                                        request_id,
                                                        RDP_PNP_REDIRECTION_PACKET_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, version);
}

librdp_status rdp_pnp_redirection_parse_create_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_create_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_pnp_redirection_parse_server_io_header(data, length, &request->header) != LIBRDP_STATUS_OK ||
        request->header.function_id != RDP_PNP_REDIRECTION_IO_CREATE_FILE_REQUEST ||
        request->header.payload_len != 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->device_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->desired_access) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->share_mode) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->creation_disposition) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->flags_and_attributes) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_create_request(rdp_buffer* buffer,
                                                       uint32_t request_id,
                                                       uint8_t unused,
                                                       uint32_t device_id,
                                                       uint32_t desired_access,
                                                       uint32_t share_mode,
                                                       uint32_t creation_disposition,
                                                       uint32_t flags_and_attributes)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_pnp_redirection_write_server_io_header(buffer,
                                                        request_id,
                                                        unused,
                                                        RDP_PNP_REDIRECTION_IO_CREATE_FILE_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, device_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, desired_access);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, share_mode);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, creation_disposition);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, flags_and_attributes);
}

librdp_status rdp_pnp_redirection_write_status_reply(rdp_buffer* buffer,
                                                     uint32_t request_id,
                                                     uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_pnp_redirection_write_client_io_header(buffer,
                                                        request_id,
                                                        RDP_PNP_REDIRECTION_PACKET_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, result);
}

librdp_status rdp_pnp_redirection_parse_read_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_read_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_pnp_redirection_parse_server_io_header(data, length, &request->header) != LIBRDP_STATUS_OK ||
        request->header.function_id != RDP_PNP_REDIRECTION_IO_READ_REQUEST ||
        request->header.payload_len != 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->bytes_to_read) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->offset_high) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->offset_low) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_read_request(rdp_buffer* buffer,
                                                     uint32_t request_id,
                                                     uint8_t unused,
                                                     uint32_t bytes_to_read,
                                                     uint32_t offset_high,
                                                     uint32_t offset_low)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_pnp_redirection_write_server_io_header(buffer,
                                                        request_id,
                                                        unused,
                                                        RDP_PNP_REDIRECTION_IO_READ_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, bytes_to_read);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, offset_high);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, offset_low);
}

librdp_status rdp_pnp_redirection_write_read_reply(rdp_buffer* buffer,
                                                   uint32_t request_id,
                                                   uint32_t result,
                                                   const uint8_t* data,
                                                   uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_client_io_header(buffer,
                                                        request_id,
                                                        RDP_PNP_REDIRECTION_PACKET_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, result);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, 0);
}

librdp_status rdp_pnp_redirection_parse_write_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_write_request* request)
{
    rdp_stream stream;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_pnp_redirection_parse_server_io_header(data, length, &request->header) != LIBRDP_STATUS_OK ||
        request->header.function_id != RDP_PNP_REDIRECTION_IO_WRITE_REQUEST ||
        request->header.payload_len < 13u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->bytes_to_write) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->offset_high) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->offset_low) != LIBRDP_STATUS_OK ||
        request->bytes_to_write > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &request->data, request->bytes_to_write) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_write_request(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      uint8_t unused,
                                                      uint32_t offset_high,
                                                      uint32_t offset_low,
                                                      const uint8_t* data,
                                                      uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_server_io_header(buffer,
                                                        request_id,
                                                        unused,
                                                        RDP_PNP_REDIRECTION_IO_WRITE_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, offset_high);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, offset_low);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, 0);
}

librdp_status rdp_pnp_redirection_write_write_reply(rdp_buffer* buffer,
                                                    uint32_t request_id,
                                                    uint32_t result,
                                                    uint32_t bytes_written)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_pnp_redirection_write_status_reply(buffer, request_id, result);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, bytes_written);
}

librdp_status rdp_pnp_redirection_parse_control_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_control_request* request)
{
    rdp_stream stream;
    size_t output_remaining = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_pnp_redirection_parse_server_io_header(data, length, &request->header) != LIBRDP_STATUS_OK ||
        request->header.function_id != RDP_PNP_REDIRECTION_IO_CONTROL_REQUEST ||
        request->header.payload_len < 13u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &request->io_code) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->input_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &request->output_len) != LIBRDP_STATUS_OK ||
        request->input_len > rdp_stream_remaining(&stream) ||
        rdp_pnp_redirection_read_blob(&stream, request->input_len, &request->input) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&stream) < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    output_remaining = rdp_stream_remaining(&stream) - 1u;
    if (output_remaining > UINT32_MAX || output_remaining > request->output_len ||
        rdp_pnp_redirection_read_blob(&stream, (uint32_t)output_remaining, &request->output) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->actual_output_len = (uint32_t)output_remaining;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_control_request(rdp_buffer* buffer,
                                                        uint32_t request_id,
                                                        uint8_t unused,
                                                        uint32_t io_code,
                                                        const uint8_t* input,
                                                        uint32_t input_len,
                                                        uint32_t output_len,
                                                        const uint8_t* output,
                                                        uint32_t actual_output_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!input && input_len > 0) || (!output && actual_output_len > 0) ||
        actual_output_len > output_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_server_io_header(buffer,
                                                        request_id,
                                                        unused,
                                                        RDP_PNP_REDIRECTION_IO_CONTROL_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, io_code);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, output_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, input, input_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, output, actual_output_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, 0);
}

librdp_status rdp_pnp_redirection_write_control_reply(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      uint32_t result,
                                                      const uint8_t* data,
                                                      uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_client_io_header(buffer,
                                                        request_id,
                                                        RDP_PNP_REDIRECTION_PACKET_RESPONSE);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, result);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, 0);
}

librdp_status rdp_pnp_redirection_parse_cancel_request(
    const void* data,
    size_t length,
    rdp_pnp_redirection_cancel_request* request)
{
    rdp_stream stream;
    const uint8_t* id = NULL;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    if (rdp_pnp_redirection_parse_server_io_header(data, length, &request->header) != LIBRDP_STATUS_OK ||
        request->header.function_id != RDP_PNP_REDIRECTION_IO_SPECIFIC_CANCEL_REQUEST ||
        request->header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, request->header.payload, request->header.payload_len);
    if (rdp_stream_read_u8(&stream, &request->unused) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &id, 3u) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->id_to_cancel = rdp_pnp_redirection_read_u24_le(id);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_write_cancel_request(rdp_buffer* buffer,
                                                       uint32_t request_id,
                                                       uint8_t unused,
                                                       uint8_t cancel_unused,
                                                       uint32_t id_to_cancel)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (id_to_cancel > RDP_PNP_REDIRECTION_REQUEST_ID_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_server_io_header(buffer,
                                                        request_id,
                                                        unused,
                                                        RDP_PNP_REDIRECTION_IO_SPECIFIC_CANCEL_REQUEST);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, cancel_unused);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_pnp_redirection_append_u24_le(buffer, id_to_cancel);
}

librdp_status rdp_pnp_redirection_write_custom_event(rdp_buffer* buffer,
                                                     const uint8_t event_guid[16],
                                                     const uint8_t* data,
                                                     uint32_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !event_guid || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_pnp_redirection_write_client_io_header(buffer,
                                                        0,
                                                        RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, event_guid, 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, 0);
}

librdp_status rdp_pnp_redirection_parse_custom_event(const void* data,
                                                     size_t length,
                                                     rdp_pnp_redirection_custom_event* event)
{
    rdp_stream stream;
    const uint8_t* guid = NULL;

    if (!data || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    if (rdp_pnp_redirection_parse_client_io_header(data, length, &event->header) != LIBRDP_STATUS_OK ||
        event->header.packet_type != RDP_PNP_REDIRECTION_PACKET_CUSTOM_EVENT ||
        event->header.payload_len < 21u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, event->header.payload, event->header.payload_len);
    if (rdp_stream_read_bytes(&stream, &guid, 16u) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &event->data_len) != LIBRDP_STATUS_OK ||
        event->data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &event->data, event->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(event->event_guid, guid, sizeof(event->event_guid));
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_pnp_redirection_parse_response_payload(
    const void* data,
    size_t length,
    rdp_pnp_redirection_client_io_header* header,
    rdp_stream* stream)
{
    if (!data || !header || !stream)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_pnp_redirection_parse_client_io_header(data, length, header) != LIBRDP_STATUS_OK ||
        header->packet_type != RDP_PNP_REDIRECTION_PACKET_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(stream, header->payload, header->payload_len);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_status_reply(const void* data,
                                                     size_t length,
                                                     rdp_pnp_redirection_status_reply* reply)
{
    rdp_stream stream;

    if (!data || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(reply, 0, sizeof(*reply));
    if (rdp_pnp_redirection_parse_response_payload(data,
                                                   length,
                                                   &reply->header,
                                                   &stream) != LIBRDP_STATUS_OK ||
        reply->header.payload_len != 4u ||
        rdp_stream_read_u32_le(&stream, &reply->result) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_read_reply(const void* data,
                                                   size_t length,
                                                   rdp_pnp_redirection_read_reply* reply)
{
    rdp_stream stream;

    if (!data || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(reply, 0, sizeof(*reply));
    if (rdp_pnp_redirection_parse_response_payload(data,
                                                   length,
                                                   &reply->header,
                                                   &stream) != LIBRDP_STATUS_OK ||
        reply->header.payload_len < 9u ||
        rdp_stream_read_u32_le(&stream, &reply->result) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reply->data_len) != LIBRDP_STATUS_OK ||
        reply->data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &reply->data, reply->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_write_reply(const void* data,
                                                    size_t length,
                                                    rdp_pnp_redirection_write_reply* reply)
{
    rdp_stream stream;

    if (!data || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(reply, 0, sizeof(*reply));
    if (rdp_pnp_redirection_parse_response_payload(data,
                                                   length,
                                                   &reply->header,
                                                   &stream) != LIBRDP_STATUS_OK ||
        reply->header.payload_len != 8u ||
        rdp_stream_read_u32_le(&stream, &reply->result) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reply->bytes_written) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_pnp_redirection_parse_control_reply(const void* data,
                                                      size_t length,
                                                      rdp_pnp_redirection_control_reply* reply)
{
    rdp_stream stream;

    if (!data || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(reply, 0, sizeof(*reply));
    if (rdp_pnp_redirection_parse_response_payload(data,
                                                   length,
                                                   &reply->header,
                                                   &stream) != LIBRDP_STATUS_OK ||
        reply->header.payload_len < 9u ||
        rdp_stream_read_u32_le(&stream, &reply->result) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &reply->data_len) != LIBRDP_STATUS_OK ||
        reply->data_len > rdp_stream_remaining(&stream) ||
        rdp_stream_read_bytes(&stream, &reply->data, reply->data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

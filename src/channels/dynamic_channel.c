/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/dynamic_channel.h"

#include "common/stream.h"

#include <string.h>

static librdp_status rdp_dynamic_channel_read_channel_id(rdp_stream* stream,
                                                         uint8_t channel_id_bytes,
                                                         uint32_t* channel_id)
{
    uint8_t u8 = 0;
    uint16_t u16 = 0;

    if (!stream || !channel_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (channel_id_bytes == 1)
    {
        if (rdp_stream_read_u8(stream, &u8) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *channel_id = u8;
        return LIBRDP_STATUS_OK;
    }
    if (channel_id_bytes == 2)
    {
        if (rdp_stream_read_u16_le(stream, &u16) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *channel_id = u16;
        return LIBRDP_STATUS_OK;
    }
    if (channel_id_bytes == 4)
        return rdp_stream_read_u32_le(stream, channel_id);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_dynamic_channel_write_channel_id(rdp_buffer* buffer,
                                                          uint32_t channel_id,
                                                          uint8_t channel_id_bytes)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id_bytes == 1)
    {
        if (channel_id > 0xffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return rdp_buffer_append_u8(buffer, (uint8_t)channel_id);
    }
    if (channel_id_bytes == 2)
    {
        if (channel_id > 0xffffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return rdp_buffer_append_u16_le(buffer, (uint16_t)channel_id);
    }
    if (channel_id_bytes == 4)
        return rdp_buffer_append_u32_le(buffer, channel_id);
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_dynamic_channel_channel_id_code(uint32_t channel_id,
                                                         uint8_t channel_id_bytes,
                                                         uint8_t* cb_id)
{
    if (!cb_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id_bytes == 1)
    {
        if (channel_id > 0xffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        *cb_id = 0;
        return LIBRDP_STATUS_OK;
    }
    if (channel_id_bytes == 2)
    {
        if (channel_id > 0xffffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        *cb_id = 1;
        return LIBRDP_STATUS_OK;
    }
    if (channel_id_bytes == 4)
    {
        *cb_id = 2;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static librdp_status rdp_dynamic_channel_read_length(rdp_stream* stream,
                                                     uint8_t length_bytes,
                                                     uint32_t* length)
{
    uint8_t u8 = 0;
    uint16_t u16 = 0;

    if (!stream || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (length_bytes == 1)
    {
        if (rdp_stream_read_u8(stream, &u8) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *length = u8;
        return LIBRDP_STATUS_OK;
    }
    if (length_bytes == 2)
    {
        if (rdp_stream_read_u16_le(stream, &u16) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *length = u16;
        return LIBRDP_STATUS_OK;
    }
    if (length_bytes == 4)
        return rdp_stream_read_u32_le(stream, length);
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_dynamic_channel_write_length(rdp_buffer* buffer,
                                                      uint32_t length,
                                                      uint8_t length_bytes)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length_bytes == 1)
    {
        if (length > 0xffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return rdp_buffer_append_u8(buffer, (uint8_t)length);
    }
    if (length_bytes == 2)
    {
        if (length > 0xffffu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return rdp_buffer_append_u16_le(buffer, (uint16_t)length);
    }
    if (length_bytes == 4)
        return rdp_buffer_append_u32_le(buffer, length);
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

static uint8_t rdp_dynamic_channel_length_bytes(uint32_t length)
{
    if (length <= 0xffu)
        return 1;
    if (length <= 0xffffu)
        return 2;
    return 4;
}

static uint8_t rdp_dynamic_channel_length_code(uint8_t length_bytes)
{
    if (length_bytes == 1)
        return 0;
    if (length_bytes == 2)
        return 1;
    return 2;
}

uint16_t rdp_dynamic_channel_select_version(uint16_t server_version)
{
    if (server_version == 0)
        return 0;
    if (server_version > 2u)
        return 2;
    return server_version;
}

uint8_t rdp_dynamic_channel_select_channel_id_bytes(uint32_t channel_id)
{
    if (channel_id <= 0xffu)
        return 1;
    if (channel_id <= 0xffffu)
        return 2;
    return 4;
}

size_t rdp_dynamic_channel_data_pdu_header_size(uint8_t channel_id_bytes)
{
    if (channel_id_bytes != 1u && channel_id_bytes != 2u && channel_id_bytes != 4u)
        return 0;
    return 1u + channel_id_bytes;
}

size_t rdp_dynamic_channel_data_first_pdu_header_size(uint8_t channel_id_bytes, uint32_t total_length)
{
    if (channel_id_bytes != 1u && channel_id_bytes != 2u && channel_id_bytes != 4u)
        return 0;
    return 1u + channel_id_bytes + rdp_dynamic_channel_length_bytes(total_length);
}

librdp_status rdp_dynamic_channel_parse_header(const void* data,
                                               size_t length,
                                               rdp_dynamic_channel_header* header)
{
    const uint8_t* bytes = (const uint8_t*)data;
    rdp_dynamic_channel_header parsed;
    uint8_t cb_id = 0;

    if (!data || !header || length < 1)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    parsed.raw = bytes[0];
    parsed.command = (uint8_t)(bytes[0] >> 4);
    if (parsed.command == 0 || parsed.command > RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.priority = (uint8_t)((bytes[0] >> 2) & 0x03u);
    cb_id = (uint8_t)(bytes[0] & 0x03u);
    if (cb_id == 3)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.channel_id_bytes = cb_id == 0 ? 1u : (cb_id == 1 ? 2u : 4u);
    if (parsed.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST ||
        parsed.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST_COMPRESSED)
    {
        if (parsed.priority == 3)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.length_bytes = parsed.priority == 0 ? 1u : (parsed.priority == 1 ? 2u : 4u);
    }
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_parse_capabilities(const void* data,
                                                     size_t length,
                                                     rdp_dynamic_channel_capabilities* capabilities)
{
    rdp_dynamic_channel_capabilities parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;
    uint8_t pad = 0;

    if (!data || !capabilities)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES || length < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;
    if (parsed.version == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.version >= 2u)
    {
        if (rdp_stream_remaining(&stream) != 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_u16_le(&stream, &parsed.priority_charge[0]) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &parsed.priority_charge[1]) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &parsed.priority_charge[2]) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &parsed.priority_charge[3]) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed.has_priority_charges = 1;
    }
    else if (rdp_stream_remaining(&stream) != 0)
    {
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    *capabilities = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_capabilities_response(rdp_buffer* buffer, uint16_t version)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || version == 0 || version > 3)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES << 4));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, version);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_create_request(const void* data,
                                                       size_t length,
                                                       rdp_dynamic_channel_create_request* request)
{
    rdp_dynamic_channel_create_request parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;
    const uint8_t* name = NULL;
    size_t remaining = 0;
    size_t i = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_CREATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &parsed.channel_id) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    remaining = rdp_stream_remaining(&stream);
    if (remaining == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &name, remaining) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < remaining; i++)
    {
        if (name[i] == 0)
        {
            parsed.channel_id_bytes = header.channel_id_bytes;
            parsed.name = (const char*)name;
            parsed.name_len = i;
            *request = parsed;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_dynamic_channel_write_create_response(rdp_buffer* buffer,
                                                       uint32_t channel_id,
                                                       uint8_t channel_id_bytes,
                                                       uint32_t status_code)
{
    uint8_t cb_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_dynamic_channel_channel_id_code(channel_id, channel_id_bytes, &cb_id);
    if (status != LIBRDP_STATUS_OK)
        return status;

    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_CREATE << 4) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, status_code);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_data(const void* data,
                                             size_t length,
                                             rdp_dynamic_channel_data_pdu* pdu)
{
    rdp_dynamic_channel_data_pdu parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &parsed.channel_id) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.channel_id_bytes = header.channel_id_bytes;
    parsed.data_len = rdp_stream_remaining(&stream);
    if (parsed.data_len > 0 && rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_data(rdp_buffer* buffer,
                                             uint32_t channel_id,
                                             uint8_t channel_id_bytes,
                                             const void* data,
                                             size_t data_len)
{
    uint8_t cb_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_dynamic_channel_channel_id_code(channel_id, channel_id_bytes, &cb_id);
    if (status != LIBRDP_STATUS_OK)
        return status;

    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_DATA << 4) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_data_first(const void* data,
                                                   size_t length,
                                                   rdp_dynamic_channel_data_first_pdu* pdu)
{
    rdp_dynamic_channel_data_first_pdu parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &parsed.channel_id) !=
            LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_length(&stream, header.length_bytes, &parsed.total_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    parsed.channel_id_bytes = header.channel_id_bytes;
    parsed.data_len = rdp_stream_remaining(&stream);
    if (parsed.data_len > parsed.total_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.data_len > 0 && rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_data_first(rdp_buffer* buffer,
                                                  uint32_t channel_id,
                                                  uint8_t channel_id_bytes,
                                                  uint32_t total_length,
                                                  const void* data,
                                                  size_t data_len)
{
    uint8_t cb_id = 0;
    uint8_t length_bytes = 0;
    uint8_t length_code = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (!data && data_len > 0) || data_len > total_length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_dynamic_channel_channel_id_code(channel_id, channel_id_bytes, &cb_id);
    if (status != LIBRDP_STATUS_OK)
        return status;

    length_bytes = rdp_dynamic_channel_length_bytes(total_length);
    length_code = rdp_dynamic_channel_length_code(length_bytes);
    if (1u + channel_id_bytes + length_bytes + data_len > RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    start = buffer->length;
    status = rdp_buffer_append_u8(buffer,
                                  (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST << 4) |
                                            ((uint32_t)length_code << 2) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_length(buffer, total_length, length_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_close(const void* data,
                                              size_t length,
                                              rdp_dynamic_channel_close_pdu* pdu)
{
    rdp_dynamic_channel_close_pdu parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &parsed.channel_id) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.channel_id_bytes = header.channel_id_bytes;
    if (rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_close(rdp_buffer* buffer,
                                             uint32_t channel_id,
                                             uint8_t channel_id_bytes)
{
    uint8_t cb_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_dynamic_channel_channel_id_code(channel_id, channel_id_bytes, &cb_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_CLOSE << 4) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_compressed_data(
    const void* data,
    size_t length,
    rdp_dynamic_channel_compressed_data_pdu* pdu)
{
    rdp_dynamic_channel_compressed_data_pdu parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA_COMPRESSED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &parsed.channel_id) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.channel_id_bytes = header.channel_id_bytes;
    parsed.data_len = rdp_stream_remaining(&stream);
    if (parsed.data_len < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_compressed_data(rdp_buffer* buffer,
                                                        uint32_t channel_id,
                                                        uint8_t channel_id_bytes,
                                                        const void* data,
                                                        size_t data_len)
{
    uint8_t cb_id = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !data || data_len < 2u ||
        1u + channel_id_bytes + data_len > RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_dynamic_channel_channel_id_code(channel_id, channel_id_bytes, &cb_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_DATA_COMPRESSED << 4) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_compressed_data_first(
    const void* data,
    size_t length,
    rdp_dynamic_channel_compressed_data_first_pdu* pdu)
{
    rdp_dynamic_channel_compressed_data_first_pdu parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST_COMPRESSED)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &parsed.channel_id) !=
            LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_length(&stream, header.length_bytes, &parsed.total_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.total_length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    parsed.channel_id_bytes = header.channel_id_bytes;
    parsed.data_len = rdp_stream_remaining(&stream);
    if (parsed.data_len < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.data, parsed.data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_compressed_data_first(rdp_buffer* buffer,
                                                              uint32_t channel_id,
                                                              uint8_t channel_id_bytes,
                                                              uint32_t total_length,
                                                              const void* data,
                                                              size_t data_len)
{
    uint8_t cb_id = 0;
    uint8_t length_bytes = 0;
    uint8_t length_code = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !data || total_length == 0 || data_len < 2u || data_len > total_length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_dynamic_channel_channel_id_code(channel_id, channel_id_bytes, &cb_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    length_bytes = rdp_dynamic_channel_length_bytes(total_length);
    length_code = rdp_dynamic_channel_length_code(length_bytes);
    if (1u + channel_id_bytes + length_bytes + data_len > RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer,
                                  (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST_COMPRESSED << 4) |
                                            ((uint32_t)length_code << 2) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_length(buffer, total_length, length_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

static librdp_status rdp_dynamic_channel_validate_soft_sync_lists(const uint8_t* data,
                                                                  size_t length,
                                                                  uint16_t tunnel_count)
{
    rdp_stream stream;
    uint16_t i = 0;

    if (!data && length > 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, data, length);
    for (i = 0; i < tunnel_count; i++)
    {
        uint32_t tunnel_type = 0;
        uint16_t channel_count = 0;
        size_t ids_len = 0;

        if (rdp_stream_read_u32_le(&stream, &tunnel_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &channel_count) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (tunnel_type != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
            tunnel_type != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        ids_len = (size_t)channel_count * 4u;
        if (channel_count == 0 || ids_len / 4u != channel_count)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_skip(&stream, ids_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_dynamic_channel_parse_soft_sync_request(
    const void* data,
    size_t length,
    rdp_dynamic_channel_soft_sync_request* request)
{
    rdp_dynamic_channel_soft_sync_request parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;
    uint8_t pad = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST ||
        header.raw != (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST << 4) ||
        length < 10u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.tunnel_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pad != 0 || parsed.length != length - 2u ||
        (parsed.flags & RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED) == 0 ||
        (parsed.flags & ~(RDP_DYNAMIC_CHANNEL_SOFT_SYNC_TCP_FLUSHED |
                            RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT)) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.lists_len = rdp_stream_remaining(&stream);
    if ((parsed.flags & RDP_DYNAMIC_CHANNEL_SOFT_SYNC_CHANNEL_LIST_PRESENT) == 0)
    {
        if (parsed.tunnel_count != 0 || parsed.lists_len != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *request = parsed;
        return LIBRDP_STATUS_OK;
    }
    if (parsed.tunnel_count == 0 || parsed.lists_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.lists, parsed.lists_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_dynamic_channel_validate_soft_sync_lists(parsed.lists,
                                                          parsed.lists_len,
                                                          parsed.tunnel_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_soft_sync_request_get_list(
    const rdp_dynamic_channel_soft_sync_request* request,
    uint16_t index,
    rdp_dynamic_channel_soft_sync_channel_list* list)
{
    rdp_dynamic_channel_soft_sync_channel_list parsed;
    rdp_stream stream;
    uint16_t i = 0;

    if (!request || !list)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (index >= request->tunnel_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, request->lists, request->lists_len);
    for (i = 0; i <= index; i++)
    {
        uint32_t tunnel_type = 0;
        uint16_t channel_count = 0;
        const uint8_t* ids = NULL;
        size_t ids_len = 0;

        if (rdp_stream_read_u32_le(&stream, &tunnel_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &channel_count) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        ids_len = (size_t)channel_count * 4u;
        if (rdp_stream_read_bytes(&stream, &ids, ids_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (i == index)
        {
            parsed.tunnel_type = tunnel_type;
            parsed.channel_count = channel_count;
            parsed.channel_ids = ids;
            parsed.channel_ids_len = ids_len;
            *list = parsed;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status rdp_dynamic_channel_soft_sync_channel_list_get_id(
    const rdp_dynamic_channel_soft_sync_channel_list* list,
    uint16_t index,
    uint32_t* channel_id)
{
    const uint8_t* item = NULL;

    if (!list || !channel_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (index >= list->channel_count || list->channel_ids_len != (size_t)list->channel_count * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    item = list->channel_ids + (size_t)index * 4u;
    *channel_id = (uint32_t)item[0] | ((uint32_t)item[1] << 8) |
                  ((uint32_t)item[2] << 16) | ((uint32_t)item[3] << 24);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_soft_sync_response(rdp_buffer* buffer,
                                                          const uint32_t* tunnel_types,
                                                          uint32_t tunnel_count)
{
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (!tunnel_types && tunnel_count > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < tunnel_count; i++)
    {
        if (tunnel_types[i] != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
            tunnel_types[i] != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE << 4));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, tunnel_count);
    for (i = 0; status == LIBRDP_STATUS_OK && i < tunnel_count; i++)
        status = rdp_buffer_append_u32_le(buffer, tunnel_types[i]);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_dynamic_channel_parse_soft_sync_response(
    const void* data,
    size_t length,
    rdp_dynamic_channel_soft_sync_response* response)
{
    rdp_dynamic_channel_soft_sync_response parsed;
    rdp_stream stream;
    rdp_dynamic_channel_header header;
    uint8_t pad = 0;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE ||
        header.raw != (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_RESPONSE << 4) ||
        length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.tunnel_count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pad != 0 || rdp_stream_remaining(&stream) != (size_t)parsed.tunnel_count * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.tunnel_types_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &parsed.tunnel_types, parsed.tunnel_types_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_soft_sync_response_get_tunnel(
    const rdp_dynamic_channel_soft_sync_response* response,
    uint32_t index,
    uint32_t* tunnel_type)
{
    const uint8_t* item = NULL;
    uint32_t parsed = 0;

    if (!response || !tunnel_type)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (index >= response->tunnel_count || response->tunnel_types_len != (size_t)response->tunnel_count * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    item = response->tunnel_types + (size_t)index * 4u;
    parsed = (uint32_t)item[0] | ((uint32_t)item[1] << 8) |
             ((uint32_t)item[2] << 16) | ((uint32_t)item[3] << 24);
    if (parsed != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
        parsed != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *tunnel_type = parsed;
    return LIBRDP_STATUS_OK;
}

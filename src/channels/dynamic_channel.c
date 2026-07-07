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

librdp_status rdp_dynamic_channel_parse_header(const void* data,
                                               size_t length,
                                               rdp_dynamic_channel_header* header)
{
    const uint8_t* bytes = (const uint8_t*)data;
    uint8_t cb_id = 0;

    if (!data || !header || length < 1)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    header->raw = bytes[0];
    header->command = (uint8_t)(bytes[0] >> 4);
    header->priority = (uint8_t)((bytes[0] >> 2) & 0x03u);
    cb_id = (uint8_t)(bytes[0] & 0x03u);
    if (cb_id == 3)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->channel_id_bytes = cb_id == 0 ? 1u : (cb_id == 1 ? 2u : 4u);
    if (header->command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
    {
        if (header->priority == 3)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        header->length_bytes = header->priority == 0 ? 1u : (header->priority == 1 ? 2u : 4u);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_parse_capabilities(const void* data,
                                                     size_t length,
                                                     rdp_dynamic_channel_capabilities* capabilities)
{
    rdp_stream stream;
    rdp_dynamic_channel_header header;
    uint8_t pad = 0;

    if (!data || !capabilities)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(capabilities, 0, sizeof(*capabilities));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES || length < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pad) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &capabilities->version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    (void)pad;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_dynamic_channel_write_capabilities_response(rdp_buffer* buffer, uint16_t version)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || version == 0 || version > 3)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)(RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES << 4));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, version);
    return status;
}

librdp_status rdp_dynamic_channel_parse_create_request(const void* data,
                                                       size_t length,
                                                       rdp_dynamic_channel_create_request* request)
{
    rdp_stream stream;
    rdp_dynamic_channel_header header;
    const uint8_t* name = NULL;
    size_t remaining = 0;
    size_t i = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(request, 0, sizeof(*request));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_CREATE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &request->channel_id) !=
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
            request->channel_id_bytes = header.channel_id_bytes;
            request->name = (const char*)name;
            request->name_len = i;
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

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id_bytes == 1)
        cb_id = 0;
    else if (channel_id_bytes == 2)
        cb_id = 1;
    else if (channel_id_bytes == 4)
        cb_id = 2;
    else
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_CREATE << 4) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, status_code);
    return status;
}

librdp_status rdp_dynamic_channel_parse_data(const void* data,
                                             size_t length,
                                             rdp_dynamic_channel_data_pdu* pdu)
{
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pdu, 0, sizeof(*pdu));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &pdu->channel_id) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pdu->channel_id_bytes = header.channel_id_bytes;
    pdu->data_len = rdp_stream_remaining(&stream);
    if (pdu->data_len > 0 && rdp_stream_read_bytes(&stream, &pdu->data, pdu->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
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

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id_bytes == 1)
        cb_id = 0;
    else if (channel_id_bytes == 2)
        cb_id = 1;
    else if (channel_id_bytes == 4)
        cb_id = 2;
    else
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_DATA << 4) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    return status;
}

librdp_status rdp_dynamic_channel_parse_data_first(const void* data,
                                                   size_t length,
                                                   rdp_dynamic_channel_data_first_pdu* pdu)
{
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pdu, 0, sizeof(*pdu));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &pdu->channel_id) !=
            LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_length(&stream, header.length_bytes, &pdu->total_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    pdu->channel_id_bytes = header.channel_id_bytes;
    pdu->data_len = rdp_stream_remaining(&stream);
    if (pdu->data_len > pdu->total_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu->data_len > 0 && rdp_stream_read_bytes(&stream, &pdu->data, pdu->data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
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

    if (!buffer || (!data && data_len > 0) || data_len > total_length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (channel_id_bytes == 1)
        cb_id = 0;
    else if (channel_id_bytes == 2)
        cb_id = 1;
    else if (channel_id_bytes == 4)
        cb_id = 2;
    else
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    length_bytes = rdp_dynamic_channel_length_bytes(total_length);
    length_code = rdp_dynamic_channel_length_code(length_bytes);
    if (1u + channel_id_bytes + length_bytes + data_len > RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer,
                                  (uint8_t)((RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST << 4) |
                                            ((uint32_t)length_code << 2) | cb_id));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_channel_id(buffer, channel_id, channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_dynamic_channel_write_length(buffer, total_length, length_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    return status;
}

librdp_status rdp_dynamic_channel_parse_close(const void* data,
                                              size_t length,
                                              rdp_dynamic_channel_close_pdu* pdu)
{
    rdp_stream stream;
    rdp_dynamic_channel_header header;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pdu, 0, sizeof(*pdu));
    if (rdp_dynamic_channel_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.command != RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_skip(&stream, 1) != LIBRDP_STATUS_OK ||
        rdp_dynamic_channel_read_channel_id(&stream, header.channel_id_bytes, &pdu->channel_id) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pdu->channel_id_bytes = header.channel_id_bytes;
    return rdp_stream_remaining(&stream) == 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/audio_input.h"

#include "common/stream.h"

#include <stdint.h>
#include <string.h>

static int rdp_audio_input_valid_message(uint8_t message_id)
{
    return message_id >= RDP_AUDIO_INPUT_VERSION && message_id <= RDP_AUDIO_INPUT_FORMAT_CHANGE;
}

librdp_status rdp_audio_input_parse_header(const void* data, size_t length, rdp_audio_input_header* header)
{
    rdp_stream stream;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(header, 0, sizeof(*header));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &header->message_id) != LIBRDP_STATUS_OK ||
        !rdp_audio_input_valid_message(header->message_id) ||
        rdp_stream_read_bytes(&stream, &header->body, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header->body_len = length - 1u;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_parse_version(const void* data, size_t length, uint32_t* version)
{
    rdp_audio_input_header header;
    rdp_stream stream;

    if (!data || !version)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != RDP_AUDIO_INPUT_VERSION || header.body_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (*version != RDP_AUDIO_INPUT_VERSION_1 && *version != RDP_AUDIO_INPUT_VERSION_2)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_write_version(rdp_buffer* buffer, uint32_t version)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (version != RDP_AUDIO_INPUT_VERSION_1 && version != RDP_AUDIO_INPUT_VERSION_2))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_VERSION);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, version);
    return status;
}

librdp_status rdp_audio_input_parse_formats(const void* data,
                                            size_t length,
                                            rdp_audio_input_formats* formats)
{
    rdp_audio_input_header header;
    rdp_stream stream;
    size_t body_offset = 0;
    size_t consumed = 0;

    if (!data || !formats)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(formats, 0, sizeof(*formats));
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != RDP_AUDIO_INPUT_FORMATS || header.body_len < 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, &formats->format_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &formats->formats_packet_size) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    body_offset = 8u;
    if (rdp_audio_format_validate_list(header.body + body_offset,
                                       header.body_len - body_offset,
                                       formats->format_count,
                                       &consumed) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    formats->formats = header.body + body_offset;
    formats->formats_len = consumed;
    formats->extra_data = header.body + body_offset + consumed;
    formats->extra_data_len = header.body_len - body_offset - consumed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_parse_client_formats(const void* data,
                                                   size_t length,
                                                   rdp_audio_input_formats* formats)
{
    size_t useful_size = 0;
    librdp_status status = rdp_audio_input_parse_formats(data, length, formats);

    if (status != LIBRDP_STATUS_OK)
        return status;
    useful_size = length - formats->extra_data_len;
    if (formats->formats_packet_size != useful_size)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_write_formats_with_extra(rdp_buffer* buffer,
                                                       const rdp_audio_format* formats,
                                                       uint32_t format_count,
                                                       const void* extra_data,
                                                       size_t extra_data_len)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t i = 0;
    size_t useful_size = 0;

    if (!buffer || (!formats && format_count > 0) || (!extra_data && extra_data_len > 0) ||
        format_count > RDP_AUDIO_FORMAT_MAX_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&body);
    status = rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_FORMATS);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, format_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&body, 0);
    for (i = 0; status == LIBRDP_STATUS_OK && i < format_count; i++)
        status = rdp_audio_format_write(&body, &formats[i]);
    if (status == LIBRDP_STATUS_OK)
    {
        if (body.length > UINT32_MAX - 1u)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        else
            useful_size = 1u + body.length;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&body, extra_data, extra_data_len);
    if (status == LIBRDP_STATUS_OK)
    {
        if (body.length > UINT32_MAX)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        else
        {
            body.data[4] = (uint8_t)(useful_size & 0xffu);
            body.data[5] = (uint8_t)((useful_size >> 8) & 0xffu);
            body.data[6] = (uint8_t)((useful_size >> 16) & 0xffu);
            body.data[7] = (uint8_t)((useful_size >> 24) & 0xffu);
            status = rdp_buffer_append(buffer, body.data, body.length);
        }
    }
    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_audio_input_write_formats(rdp_buffer* buffer,
                                           const rdp_audio_format* formats,
                                           uint32_t format_count)
{
    return rdp_audio_input_write_formats_with_extra(buffer, formats, format_count, NULL, 0);
}

librdp_status rdp_audio_input_parse_open(const void* data, size_t length, rdp_audio_input_open* open)
{
    rdp_audio_input_header header;
    rdp_stream stream;
    const uint8_t* format_bytes = NULL;
    size_t consumed = 0;

    if (!data || !open)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(open, 0, sizeof(*open));
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != RDP_AUDIO_INPUT_OPEN || header.body_len < 8u + RDP_AUDIO_FORMAT_MIN_SIZE)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, &open->frames_per_packet) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &open->initial_format) != LIBRDP_STATUS_OK ||
        rdp_stream_read_bytes(&stream, &format_bytes, rdp_stream_remaining(&stream)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_audio_format_parse(format_bytes, header.body_len - 8u, &open->format, &consumed) !=
            LIBRDP_STATUS_OK ||
        consumed != header.body_len - 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_write_open(rdp_buffer* buffer,
                                         uint32_t frames_per_packet,
                                         uint32_t initial_format,
                                         const rdp_audio_format* format)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !format)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_OPEN);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, frames_per_packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, initial_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_audio_format_write(buffer, format);
    return status;
}

librdp_status rdp_audio_input_write_open_reply(rdp_buffer* buffer, uint32_t result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_OPEN_REPLY);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, result);
    return status;
}

librdp_status rdp_audio_input_parse_open_reply(const void* data, size_t length, uint32_t* result)
{
    rdp_audio_input_header header;
    rdp_stream stream;

    if (!data || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != RDP_AUDIO_INPUT_OPEN_REPLY || header.body_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, result) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_write_incoming_data(rdp_buffer* buffer)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_DATA_INCOMING);
}

librdp_status rdp_audio_input_parse_empty(const void* data, size_t length, uint8_t expected_message)
{
    rdp_audio_input_header header;

    if (!data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != expected_message || header.body_len != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_parse_data(const void* data, size_t length, rdp_audio_input_data* data_pdu)
{
    rdp_audio_input_header header;

    if (!data || !data_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(data_pdu, 0, sizeof(*data_pdu));
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != RDP_AUDIO_INPUT_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    data_pdu->data = header.body;
    data_pdu->data_len = header.body_len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_write_data(rdp_buffer* buffer, const void* data, size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_DATA);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    return status;
}

librdp_status rdp_audio_input_parse_format_change(const void* data, size_t length, uint32_t* new_format)
{
    rdp_audio_input_header header;
    rdp_stream stream;

    if (!data || !new_format)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_audio_input_parse_header(data, length, &header) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (header.message_id != RDP_AUDIO_INPUT_FORMAT_CHANGE || header.body_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, header.body, header.body_len);
    if (rdp_stream_read_u32_le(&stream, new_format) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_audio_input_write_format_change(rdp_buffer* buffer, uint32_t new_format)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(buffer, RDP_AUDIO_INPUT_FORMAT_CHANGE);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, new_format);
    return status;
}

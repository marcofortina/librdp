/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: multitransport negotiation and channel setup support.
 * Invariants: file descriptors, TLS state, and buffered bytes are updated only
 * after successful system calls.
 * Ownership: secondary transports are attached only after the primary session
 * state authorizes them.
 * Threading: not internally synchronized; callers must serialize access
 * through the owning session or transport.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include "transport/multitransport.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_multitransport_valid_action(uint8_t action)
{
    return action == RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST ||
           action == RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE ||
           action == RDP_MULTITRANSPORT_ACTION_DATA;
}

static int rdp_multitransport_valid_subheader_type(uint8_t type)
{
    return type == RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST ||
           type == RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_RESPONSE;
}

librdp_status rdp_multitransport_count_subheaders(const void* data,
                                                  size_t length,
                                                  uint16_t* subheader_count)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0;
    uint16_t count = 0;

    if ((!data && length > 0) || !subheader_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (offset < length)
    {
        rdp_multitransport_subheader subheader;

        if (rdp_multitransport_parse_subheader(bytes + offset, length - offset, &subheader) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (count == UINT16_MAX)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        count++;
        offset += subheader.length;
    }
    *subheader_count = count;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_parse_header(const void* data,
                                              size_t length,
                                              rdp_multitransport_header* header)
{
    rdp_multitransport_header parsed;
    rdp_stream stream;
    uint8_t action_flags = 0;

    if (!data || !header)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_MULTITRANSPORT_HEADER_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &action_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.payload_length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.header_length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.action = action_flags & 0x0fu;
    parsed.flags = (uint8_t)(action_flags >> 4);
    if (!rdp_multitransport_valid_action(parsed.action) ||
        parsed.flags != 0 ||
        parsed.header_length < RDP_MULTITRANSPORT_HEADER_LENGTH ||
        parsed.header_length > length ||
        (size_t)parsed.payload_length != length - parsed.header_length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.header_length > RDP_MULTITRANSPORT_HEADER_LENGTH)
    {
        uint16_t subheader_count = 0;

        parsed.subheaders_len = (size_t)parsed.header_length - RDP_MULTITRANSPORT_HEADER_LENGTH;
        if (rdp_stream_read_bytes(&stream, &parsed.subheaders, parsed.subheaders_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_multitransport_count_subheaders(parsed.subheaders,
                                                parsed.subheaders_len,
                                                &subheader_count) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    parsed.payload = (const uint8_t*)data + parsed.header_length;
    parsed.payload_len = parsed.payload_length;
    *header = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_header(rdp_buffer* buffer,
                                              uint8_t action,
                                              const void* subheaders,
                                              size_t subheaders_len,
                                              size_t payload_len)
{
    uint8_t action_flags = 0;
    size_t header_len = 0;
    size_t start = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_multitransport_valid_action(action) ||
        (!subheaders && subheaders_len > 0) ||
        subheaders_len > UINT8_MAX - RDP_MULTITRANSPORT_HEADER_LENGTH ||
        payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    header_len = RDP_MULTITRANSPORT_HEADER_LENGTH + subheaders_len;
    if (subheaders_len > 0)
    {
        uint16_t subheader_count = 0;

        if (rdp_multitransport_count_subheaders(subheaders, subheaders_len, &subheader_count) !=
            LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    start = buffer->length;
    action_flags = action;
    status = rdp_buffer_append_u8(buffer, action_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, (uint8_t)header_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, subheaders, subheaders_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_multitransport_parse_subheader(const void* data,
                                                 size_t length,
                                                 rdp_multitransport_subheader* subheader)
{
    rdp_multitransport_subheader parsed;
    rdp_stream stream;

    if (!data || !subheader)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.length < 2u ||
        parsed.length > length ||
        !rdp_multitransport_valid_subheader_type(parsed.type))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.data = (const uint8_t*)data + 2u;
    parsed.data_len = (size_t)parsed.length - 2u;
    *subheader = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_subheader(rdp_buffer* buffer,
                                                 uint8_t type,
                                                 const void* data,
                                                 size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !rdp_multitransport_valid_subheader_type(type) ||
        (!data && data_len > 0) || data_len > UINT8_MAX - 2u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, (uint8_t)(data_len + 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_multitransport_write_create_request(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      const uint8_t security_cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH])
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !security_cookie)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multitransport_write_header(buffer,
                                             RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST,
                                             NULL,
                                             0,
                                             24u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, request_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, security_cookie, RDP_MULTITRANSPORT_COOKIE_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_multitransport_parse_create_request(
    const void* data,
    size_t length,
    rdp_multitransport_create_request* request)
{
    rdp_multitransport_create_request parsed;
    rdp_stream stream;
    const uint8_t* cookie = NULL;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multitransport_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.action != RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST ||
        parsed.header.header_length != RDP_MULTITRANSPORT_HEADER_LENGTH ||
        parsed.header.payload_len != 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.request_id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.reserved) != LIBRDP_STATUS_OK ||
        parsed.reserved != 0 ||
        rdp_stream_read_bytes(&stream, &cookie, RDP_MULTITRANSPORT_COOKIE_LENGTH) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memcpy(parsed.security_cookie, cookie, RDP_MULTITRANSPORT_COOKIE_LENGTH);
    *request = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_create_response(rdp_buffer* buffer, uint32_t hresult)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multitransport_write_header(buffer,
                                             RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE,
                                             NULL,
                                             0,
                                             4u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, hresult);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_multitransport_parse_create_response(
    const void* data,
    size_t length,
    rdp_multitransport_create_response* response)
{
    rdp_multitransport_create_response parsed;
    rdp_stream stream;

    if (!data || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multitransport_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.action != RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE ||
        parsed.header.header_length != RDP_MULTITRANSPORT_HEADER_LENGTH ||
        parsed.header.payload_len != 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, parsed.header.payload, parsed.header.payload_len);
    if (rdp_stream_read_u32_le(&stream, &parsed.hresult) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *response = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_multitransport_write_data(rdp_buffer* buffer,
                                            const void* subheaders,
                                            size_t subheaders_len,
                                            const void* data,
                                            size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_multitransport_write_header(buffer,
                                             RDP_MULTITRANSPORT_ACTION_DATA,
                                             subheaders,
                                             subheaders_len,
                                             data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, data, data_len);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_multitransport_parse_data(const void* data,
                                            size_t length,
                                            rdp_multitransport_data* tunnel_data)
{
    rdp_multitransport_data parsed;

    if (!data || !tunnel_data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&parsed, 0, sizeof(parsed));
    if (rdp_multitransport_parse_header(data, length, &parsed.header) != LIBRDP_STATUS_OK ||
        parsed.header.action != RDP_MULTITRANSPORT_ACTION_DATA)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed.data = parsed.header.payload;
    parsed.data_len = parsed.header.payload_len;
    *tunnel_data = parsed;
    return LIBRDP_STATUS_OK;
}

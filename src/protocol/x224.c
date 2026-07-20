/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X.224 connection negotiation support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


#include "protocol/x224.h"

#include "common/stream.h"
#include "protocol/tpkt.h"

#include <string.h>

librdp_status rdp_x224_build_connection_request(rdp_buffer* buffer, const char* cookie_name, uint32_t protocols)
{
    return rdp_x224_build_connection_request_ex(
        buffer,
        cookie_name,
        NULL,
        0u,
        protocols);
}

/*
 * Build a connection request with either a bounded cookie or an opaque routing
 * token. Routing data takes precedence and suppresses the cookie during a
 * server-directed reconnect. Validation rejects combinations that exceed the
 * one-byte X.224 length boundary before mutating caller-owned storage.
 */
librdp_status rdp_x224_build_connection_request_ex(rdp_buffer* buffer,
                                                   const char* cookie_name,
                                                   const void* routing_data,
                                                   size_t routing_data_len,
                                                   uint32_t protocols)
{
    librdp_status status = LIBRDP_STATUS_OK;
    const char prefix[] = "Cookie: mstshash=";
    const char suffix[] = "\r\n";
    size_t cookie_len = 0;
    size_t connection_data_len = 0;
    size_t negotiation_len =
        protocols == RDP_X224_PROTOCOL_STANDARD ? 0u : 8u;
    size_t user_len = 0;
    uint8_t li = 0;

    if (!buffer || (!routing_data && routing_data_len > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (routing_data_len > 0u)
        connection_data_len = routing_data_len;
    else if (cookie_name && cookie_name[0] != '\0')
    {
        user_len = strlen(cookie_name);
        if (user_len > 64)
            user_len = 64;
        cookie_len = (sizeof(prefix) - 1u) + user_len + (sizeof(suffix) - 1u);
        connection_data_len = cookie_len;
    }

    if (connection_data_len > 255u - 6u ||
        negotiation_len > 255u - 6u - connection_data_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    li = (uint8_t)(6u + connection_data_len + negotiation_len);
    status = rdp_buffer_append_u8(buffer, li);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0xe0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_be(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_be(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (routing_data_len > 0u)
    {
        status = rdp_buffer_append(
            buffer,
            routing_data,
            routing_data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (cookie_len > 0)
    {
        status = rdp_buffer_append(buffer, prefix, sizeof(prefix) - 1u);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, cookie_name, user_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_buffer_append(buffer, suffix, sizeof(suffix) - 1u);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }

    if (protocols == RDP_X224_PROTOCOL_STANDARD)
        return LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u8(buffer, 1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, 8);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, protocols);
}

/*
 * Parse the server-facing X.224 connection request. The negotiation request,
 * when present, is the final 8-byte block after any cookie/routing data.
 */
librdp_status rdp_x224_parse_connection_request(const void* payload,
                                                size_t payload_len,
                                                rdp_x224_connection_request* request)
{
    rdp_stream stream;
    const uint8_t* bytes = (const uint8_t*)payload;
    size_t end = 0;
    uint8_t li = 0;
    uint8_t type = 0;

    if (!payload || !request || payload_len < 7u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(request, 0, sizeof(*request));
    request->requested_protocols = RDP_X224_PROTOCOL_STANDARD;
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u8(&stream, &li) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (type != 0xe0u || li < 6u || (size_t)li + 1u > payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u16_be(&stream, &request->destination_ref) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_be(&stream, &request->source_ref) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &request->class_option) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    end = (size_t)li + 1u;
    if (end >= 15u && bytes[end - 8u] == 1u)
    {
        rdp_stream negotiation;
        uint8_t neg_type = 0;

        rdp_stream_init(&negotiation, bytes + end - 8u, 8u);
        if (rdp_stream_read_u8(&negotiation, &neg_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&negotiation, &request->negotiation.flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&negotiation, &request->negotiation.length) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&negotiation, &request->requested_protocols) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (neg_type != 1u || request->negotiation.length != 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        request->negotiation.present = true;
        request->negotiation.type = neg_type;
        request->negotiation.selected_protocol = request->requested_protocols;
    }
    request->routing_data = bytes + 7u;
    request->routing_data_len =
        end - 7u - (request->negotiation.present ? 8u : 0u);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_x224_build_confirm_payload(rdp_buffer* payload,
                                                    uint8_t negotiation_type,
                                                    uint32_t negotiation_value)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t li = (uint8_t)(6u + (negotiation_type ? 8u : 0u));

    status = rdp_buffer_append_u8(payload, li);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(payload, 0xd0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_be(payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_be(payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(payload, 0u);
    if (status == LIBRDP_STATUS_OK && negotiation_type)
        status = rdp_buffer_append_u8(payload, negotiation_type);
    if (status == LIBRDP_STATUS_OK && negotiation_type)
        status = rdp_buffer_append_u8(payload, 0u);
    if (status == LIBRDP_STATUS_OK && negotiation_type)
        status = rdp_buffer_append_u16_le(payload, 8u);
    if (status == LIBRDP_STATUS_OK && negotiation_type)
        status = rdp_buffer_append_u32_le(payload, negotiation_value);
    return status;
}

librdp_status rdp_x224_build_connection_confirm(rdp_buffer* buffer, uint32_t selected_protocol)
{
    return rdp_x224_build_connection_confirm_ex(buffer, selected_protocol, selected_protocol != RDP_X224_PROTOCOL_STANDARD);
}

librdp_status rdp_x224_build_connection_confirm_ex(rdp_buffer* buffer,
                                                   uint32_t selected_protocol,
                                                   bool include_negotiation)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t type = include_negotiation ? 2u : 0u;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_x224_build_confirm_payload(&payload, type, selected_protocol);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(buffer, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_x224_build_negotiation_failure(rdp_buffer* buffer, uint32_t failure_code)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    status = rdp_x224_build_confirm_payload(&payload, 3u, failure_code);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(buffer, payload.data, payload.length);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status rdp_x224_parse_connection_confirm(const void* payload, size_t payload_len, rdp_x224_connection_confirm* confirm)
{
    rdp_stream stream;
    uint8_t li = 0;
    uint8_t type = 0;

    if (!payload || !confirm || payload_len < 7)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(confirm, 0, sizeof(*confirm));
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u8(&stream, &li) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &type) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (type != 0xd0 || li + 1u > payload_len || li < 6)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_stream_read_u16_be(&stream, &confirm->destination_ref) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_be(&stream, &confirm->source_ref) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &confirm->class_option) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_stream_remaining(&stream) >= 8)
    {
        uint8_t neg_type = 0;
        uint8_t flags = 0;
        uint16_t length = 0;
        uint32_t value = 0;

        if (rdp_stream_read_u8(&stream, &neg_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u8(&stream, &flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &length) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &value) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if ((neg_type != 2 && neg_type != 3) || length != 8)
            return LIBRDP_STATUS_PROTOCOL_ERROR;

        confirm->negotiation.present = true;
        confirm->negotiation.failure = neg_type == 3;
        confirm->negotiation.type = neg_type;
        confirm->negotiation.flags = flags;
        confirm->negotiation.length = length;
        if (neg_type == 2)
            confirm->negotiation.selected_protocol = value;
        else
            confirm->negotiation.failure_code = value;
    }

    return LIBRDP_STATUS_OK;
}

librdp_status rdp_x224_wrap_data(rdp_buffer* buffer, const void* payload, size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, 0x02);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0xf0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0x80);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_x224_parse_data(const void* payload, size_t payload_len, const uint8_t** data, size_t* data_len)
{
    const uint8_t* bytes = (const uint8_t*)payload;

    if (!payload || !data || !data_len || payload_len < 3)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (bytes[0] != 0x02 || bytes[1] != 0xf0 || bytes[2] != 0x80)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    *data = bytes + 3;
    *data_len = payload_len - 3u;
    return LIBRDP_STATUS_OK;
}

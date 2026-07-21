/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: network characteristics auto-detection codec.
 * Invariants: message direction selects the valid type set, fixed records have
 * no trailing bytes, and variable records match their declared payload size.
 * Ownership: no input bytes are copied by parsing; writers append
 * transactionally and restore the original buffer length on failure.
 * Threading: all state is local to each call.
 * Trust boundary: lengths and type-dependent fields are checked before any
 * output structure is published.
 */

#include "protocol/network_autodetect.h"

#include "common/stream.h"

#include <limits.h>
#include <string.h>

static int rdp_network_autodetect_is_rtt_request(uint16_t type)
{
    return type == RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONTINUOUS ||
           type == RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONNECT_TIME;
}

static int rdp_network_autodetect_is_bandwidth_start(uint16_t type)
{
    return type == RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS ||
           type == RDP_NETWORK_AUTODETECT_BANDWIDTH_START_TUNNEL ||
           type == RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME;
}

static int rdp_network_autodetect_is_bandwidth_stop(uint16_t type)
{
    return type == RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME ||
           type == RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONTINUOUS ||
           type == RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_TUNNEL;
}

static int rdp_network_autodetect_is_bandwidth_result(uint16_t type)
{
    return type == RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONNECT_TIME ||
           type == RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONTINUOUS;
}

static librdp_status rdp_network_autodetect_parse_variable_payload(
    rdp_stream* stream,
    rdp_network_autodetect_pdu* parsed,
    size_t length)
{
    const uint8_t* payload = NULL;

    if (parsed->header_length != 8u ||
        rdp_stream_read_u16_le(stream,
                               &parsed->declared_payload_length) !=
            LIBRDP_STATUS_OK ||
        (size_t)parsed->declared_payload_length != length - 8u ||
        rdp_stream_read_bytes(stream,
                              &payload,
                              parsed->declared_payload_length) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(stream) != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed->payload = payload;
    parsed->payload_len = parsed->declared_payload_length;
    return LIBRDP_STATUS_OK;
}

/*
 * Decode one complete auto-detect record. The type determines both its legal
 * direction and exact field layout, preventing a valid prefix from hiding
 * trailing or truncated data.
 */
librdp_status rdp_network_autodetect_parse(const void* data,
                                           size_t length,
                                           rdp_network_autodetect_pdu* pdu)
{
    rdp_network_autodetect_pdu parsed;
    rdp_stream stream;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 6u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &parsed.header_length) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &parsed.header_type) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.sequence_number) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &parsed.message_type) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (parsed.header_type == RDP_NETWORK_AUTODETECT_REQUEST)
    {
        if (rdp_network_autodetect_is_rtt_request(parsed.message_type) ||
            rdp_network_autodetect_is_bandwidth_start(parsed.message_type))
        {
            if (parsed.header_length != 6u || length != 6u)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_PAYLOAD ||
                 parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME)
        {
            status = rdp_network_autodetect_parse_variable_payload(
                &stream,
                &parsed,
                length);
        }
        else if (parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONTINUOUS ||
                 parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_TUNNEL)
        {
            if (parsed.header_length != 6u || length != 6u)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT ||
                 parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_NETWORK_RESULT_BANDWIDTH)
        {
            if (parsed.header_length != 14u || length != 14u)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            else if (parsed.message_type ==
                     RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT)
            {
                if (rdp_stream_read_u32_le(&stream,
                                           &parsed.base_rtt_ms) !=
                        LIBRDP_STATUS_OK ||
                    rdp_stream_read_u32_le(&stream,
                                           &parsed.average_rtt_ms) !=
                        LIBRDP_STATUS_OK)
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            else if (rdp_stream_read_u32_le(&stream,
                                            &parsed.bandwidth_kbps) !=
                         LIBRDP_STATUS_OK ||
                     rdp_stream_read_u32_le(&stream,
                                            &parsed.average_rtt_ms) !=
                         LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed.message_type ==
                 RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL)
        {
            if (parsed.header_length != 18u || length != 18u ||
                rdp_stream_read_u32_le(&stream, &parsed.base_rtt_ms) !=
                    LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &parsed.bandwidth_kbps) !=
                    LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &parsed.average_rtt_ms) !=
                    LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else if (parsed.header_type == RDP_NETWORK_AUTODETECT_RESPONSE)
    {
        if (parsed.message_type == RDP_NETWORK_AUTODETECT_RTT_RESPONSE)
        {
            if (parsed.header_length != 6u || length != 6u)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (rdp_network_autodetect_is_bandwidth_result(
                     parsed.message_type))
        {
            if (parsed.header_length != 14u || length != 14u ||
                rdp_stream_read_u32_le(&stream, &parsed.time_delta_ms) !=
                    LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &parsed.byte_count) !=
                    LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (parsed.message_type ==
                 RDP_NETWORK_AUTODETECT_NETWORK_SYNC)
        {
            if (parsed.header_length != 14u || length != 14u ||
                rdp_stream_read_u32_le(&stream, &parsed.bandwidth_kbps) !=
                    LIBRDP_STATUS_OK ||
                rdp_stream_read_u32_le(&stream, &parsed.average_rtt_ms) !=
                    LIBRDP_STATUS_OK)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    else
        status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (status != LIBRDP_STATUS_OK || rdp_stream_remaining(&stream) != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_network_autodetect_write_header(
    rdp_buffer* buffer,
    uint8_t header_length,
    uint8_t header_type,
    uint16_t sequence_number,
    uint16_t message_type)
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_buffer_append_u8(buffer, header_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, header_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, sequence_number);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, message_type);
    return status;
}

static librdp_status rdp_network_autodetect_finish_write(
    rdp_buffer* buffer,
    size_t start,
    librdp_status status)
{
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

librdp_status rdp_network_autodetect_write_rtt_request(rdp_buffer* buffer,
                                                       uint16_t sequence_number,
                                                       int connect_time)
{
    size_t start = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(
        buffer,
        6u,
        RDP_NETWORK_AUTODETECT_REQUEST,
        sequence_number,
        connect_time ? RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONNECT_TIME :
                       RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONTINUOUS);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_rtt_response(
    rdp_buffer* buffer,
    uint16_t sequence_number)
{
    size_t start = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(
        buffer,
        6u,
        RDP_NETWORK_AUTODETECT_RESPONSE,
        sequence_number,
        RDP_NETWORK_AUTODETECT_RTT_RESPONSE);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_bandwidth_start(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t request_type)
{
    size_t start = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_network_autodetect_is_bandwidth_start(request_type))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(buffer,
                                                  6u,
                                                  RDP_NETWORK_AUTODETECT_REQUEST,
                                                  sequence_number,
                                                  request_type);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_bandwidth_payload(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    const void* payload,
    size_t payload_len)
{
    size_t start = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0u) || payload_len > UINT16_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(
        buffer,
        8u,
        RDP_NETWORK_AUTODETECT_REQUEST,
        sequence_number,
        RDP_NETWORK_AUTODETECT_BANDWIDTH_PAYLOAD);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_bandwidth_stop(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t request_type,
    const void* payload,
    size_t payload_len)
{
    size_t start = 0u;
    uint8_t header_length = 6u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_network_autodetect_is_bandwidth_stop(request_type) ||
        (!payload && payload_len > 0u) || payload_len > UINT16_MAX ||
        (request_type != RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME &&
         payload_len != 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (request_type == RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME)
        header_length = 8u;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(buffer,
                                                  header_length,
                                                  RDP_NETWORK_AUTODETECT_REQUEST,
                                                  sequence_number,
                                                  request_type);
    if (status == LIBRDP_STATUS_OK && header_length == 8u)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_bandwidth_results(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t response_type,
    uint32_t time_delta_ms,
    uint32_t byte_count)
{
    size_t start = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !rdp_network_autodetect_is_bandwidth_result(response_type))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(buffer,
                                                  14u,
                                                  RDP_NETWORK_AUTODETECT_RESPONSE,
                                                  sequence_number,
                                                  response_type);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, time_delta_ms);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, byte_count);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_network_result(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t request_type,
    uint32_t base_rtt_ms,
    uint32_t bandwidth_kbps,
    uint32_t average_rtt_ms)
{
    size_t start = 0u;
    uint8_t header_length = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer ||
        (request_type != RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT &&
         request_type != RDP_NETWORK_AUTODETECT_NETWORK_RESULT_BANDWIDTH &&
         request_type != RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    header_length = request_type == RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL ?
                        18u :
                        14u;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(buffer,
                                                  header_length,
                                                  RDP_NETWORK_AUTODETECT_REQUEST,
                                                  sequence_number,
                                                  request_type);
    if (status == LIBRDP_STATUS_OK &&
        request_type != RDP_NETWORK_AUTODETECT_NETWORK_RESULT_BANDWIDTH)
        status = rdp_buffer_append_u32_le(buffer, base_rtt_ms);
    if (status == LIBRDP_STATUS_OK &&
        request_type != RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT)
        status = rdp_buffer_append_u32_le(buffer, bandwidth_kbps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, average_rtt_ms);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

librdp_status rdp_network_autodetect_write_network_sync(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint32_t bandwidth_kbps,
    uint32_t rtt_ms)
{
    size_t start = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_network_autodetect_write_header(
        buffer,
        14u,
        RDP_NETWORK_AUTODETECT_RESPONSE,
        sequence_number,
        RDP_NETWORK_AUTODETECT_NETWORK_SYNC);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, bandwidth_kbps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, rtt_ms);
    return rdp_network_autodetect_finish_write(buffer, start, status);
}

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: telemetry channel packet helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/telemetry.h"

#include "common/stream.h"

#include <string.h>

void rdp_telemetry_pdu_init(rdp_telemetry_pdu* pdu,
                            uint32_t prompt_for_credentials_ms,
                            uint32_t prompt_for_credentials_done_ms,
                            uint32_t graphics_channel_opened_ms,
                            uint32_t first_graphics_received_ms)
{
    if (!pdu)
        return;
    memset(pdu, 0, sizeof(*pdu));
    pdu->id = RDP_TELEMETRY_PDU_ID;
    pdu->length = RDP_TELEMETRY_PDU_LENGTH;
    pdu->prompt_for_credentials_ms = prompt_for_credentials_ms;
    pdu->prompt_for_credentials_done_ms = prompt_for_credentials_done_ms;
    pdu->graphics_channel_opened_ms = graphics_channel_opened_ms;
    pdu->first_graphics_received_ms = first_graphics_received_ms;
}

librdp_status rdp_telemetry_write_metrics(rdp_buffer* buffer,
                                          uint32_t prompt_for_credentials_ms,
                                          uint32_t prompt_for_credentials_done_ms,
                                          uint32_t graphics_channel_opened_ms,
                                          uint32_t first_graphics_received_ms)
{
    rdp_telemetry_pdu pdu;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_telemetry_pdu_init(&pdu,
                           prompt_for_credentials_ms,
                           prompt_for_credentials_done_ms,
                           graphics_channel_opened_ms,
                           first_graphics_received_ms);
    return rdp_telemetry_write_pdu(buffer, &pdu);
}

librdp_status rdp_telemetry_parse_pdu(const void* data, size_t length, rdp_telemetry_pdu* pdu)
{
    rdp_stream stream;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length != RDP_TELEMETRY_PDU_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(pdu, 0, sizeof(*pdu));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &pdu->id) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &pdu->length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->prompt_for_credentials_ms) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->prompt_for_credentials_done_ms) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->graphics_channel_opened_ms) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &pdu->first_graphics_received_ms) != LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (pdu->id != RDP_TELEMETRY_PDU_ID || pdu->length != RDP_TELEMETRY_PDU_LENGTH)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_telemetry_write_pdu(rdp_buffer* buffer, const rdp_telemetry_pdu* pdu)
{
    librdp_status status = LIBRDP_STATUS_OK;
    size_t start = 0;

    if (!buffer || !pdu ||
        (pdu->id != 0 && pdu->id != RDP_TELEMETRY_PDU_ID) ||
        (pdu->length != 0 && pdu->length != RDP_TELEMETRY_PDU_LENGTH))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    start = buffer->length;
    status = rdp_buffer_append_u8(buffer, RDP_TELEMETRY_PDU_ID);
    if (status != LIBRDP_STATUS_OK)
    {
        buffer->length = start;
        return status;
    }
    status = rdp_buffer_append_u8(buffer, RDP_TELEMETRY_PDU_LENGTH);
    if (status != LIBRDP_STATUS_OK)
    {
        buffer->length = start;
        return status;
    }
    status = rdp_buffer_append_u32_le(buffer, pdu->prompt_for_credentials_ms);
    if (status != LIBRDP_STATUS_OK)
    {
        buffer->length = start;
        return status;
    }
    status = rdp_buffer_append_u32_le(buffer, pdu->prompt_for_credentials_done_ms);
    if (status != LIBRDP_STATUS_OK)
    {
        buffer->length = start;
        return status;
    }
    status = rdp_buffer_append_u32_le(buffer, pdu->graphics_channel_opened_ms);
    if (status != LIBRDP_STATUS_OK)
    {
        buffer->length = start;
        return status;
    }
    status = rdp_buffer_append_u32_le(buffer, pdu->first_graphics_received_ms);
    if (status != LIBRDP_STATUS_OK)
        buffer->length = start;
    return status;
}

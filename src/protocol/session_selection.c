/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: session selection and routing-token helper support.
 * Invariants: wire lengths, tags, and stream offsets stay consistent across
 * every parse and write path.
 * Ownership: serialized buffers are caller-owned and parsed views never
 * outlive the input stream.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: all protocol bytes are untrusted network input until parsed
 * successfully.
 */


#include "protocol/session_selection.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_session_selection_parse_pdu(const void* data,
                                              size_t length,
                                              rdp_session_selection_pdu* pdu)
{
    rdp_session_selection_pdu parsed;
    rdp_stream stream;
    uint32_t expected = 0;

    if (!data || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < RDP_SESSION_SELECTION_V1_LENGTH || length > UINT32_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(&parsed, 0, sizeof(parsed));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &parsed.cb_size) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &parsed.id) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (parsed.cb_size != length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (parsed.cb_size == RDP_SESSION_SELECTION_V1_LENGTH)
    {
        if (parsed.version != RDP_SESSION_SELECTION_VERSION1 || rdp_stream_remaining(&stream) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        *pdu = parsed;
        return LIBRDP_STATUS_OK;
    }

    if (parsed.cb_size < RDP_SESSION_SELECTION_V2_HEADER_LENGTH ||
        parsed.version != RDP_SESSION_SELECTION_VERSION2 ||
        rdp_stream_read_u16_le(&stream, &parsed.text_chars) != LIBRDP_STATUS_OK ||
        parsed.text_chars > RDP_SESSION_SELECTION_MAX_TEXT_CHARS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    expected = RDP_SESSION_SELECTION_V2_HEADER_LENGTH + ((uint32_t)parsed.text_chars * 2u);
    if (parsed.cb_size != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&stream, &parsed.text_utf16le, (size_t)parsed.text_chars * 2u) !=
            LIBRDP_STATUS_OK ||
        rdp_stream_remaining(&stream) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *pdu = parsed;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_session_selection_write_v1(rdp_buffer* buffer, uint32_t id)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_V1_LENGTH);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_VERSION1);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u32_le(buffer, id);
}

librdp_status rdp_session_selection_write_v2(rdp_buffer* buffer,
                                             uint32_t id,
                                             const void* text_utf16le,
                                             uint16_t text_chars)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t byte_len = (uint32_t)text_chars * 2u;
    uint32_t cb_size = RDP_SESSION_SELECTION_V2_HEADER_LENGTH + byte_len;

    if (!buffer || (!text_utf16le && text_chars > 0) ||
        text_chars > RDP_SESSION_SELECTION_MAX_TEXT_CHARS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u32_le(buffer, cb_size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, RDP_SESSION_SELECTION_VERSION2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u32_le(buffer, id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_le(buffer, text_chars);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, text_utf16le, byte_len);
}

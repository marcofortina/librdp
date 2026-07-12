/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: static virtual-channel packet helpers.
 * Invariants: channel payload lengths and negotiated capabilities are checked
 * before state changes or callbacks.
 * Ownership: parsed channel objects are caller-owned unless the session stores
 * an explicit copy.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths remain local policy inputs.
 */


#include "channels/virtual_channel.h"

#include "common/stream.h"

#include <string.h>

librdp_status rdp_virtual_channel_parse_packet(const void* data, size_t length, rdp_virtual_channel_packet* packet)
{
    rdp_stream stream;
    size_t remaining = 0;

    if (!data || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(packet, 0, sizeof(*packet));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &packet->length) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &packet->flags) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    remaining = rdp_stream_remaining(&stream);
    if ((size_t)packet->length > remaining &&
        (packet->flags & (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST)) ==
            (RDP_VIRTUAL_CHANNEL_FLAG_FIRST | RDP_VIRTUAL_CHANNEL_FLAG_LAST))
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    packet->payload_len = (size_t)packet->length < remaining ? (size_t)packet->length : remaining;
    return rdp_stream_read_bytes(&stream, &packet->payload, packet->payload_len);
}

librdp_status rdp_virtual_channel_write_packet(rdp_buffer* buffer,
                                               const void* payload,
                                               size_t payload_len,
                                               uint32_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!payload && payload_len > 0) || payload_len > 0xffffffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u32_le(buffer, (uint32_t)payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}

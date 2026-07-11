/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "protocol/tpkt.h"

#include "common/stream.h"

librdp_status rdp_tpkt_write(rdp_buffer* buffer, const void* payload, size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    const size_t total = payload_len + 4u;

    if (!buffer || (!payload && payload_len > 0) || total > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, 3);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u8(buffer, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append_u16_be(buffer, (uint16_t)total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_tpkt_parse(const void* data, size_t length, rdp_tpkt* packet)
{
    rdp_stream stream;
    uint8_t version = 0;
    uint8_t reserved = 0;
    uint16_t total = 0;

    if (!data || !packet || length < 4)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u8(&stream, &version) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u8(&stream, &reserved) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_be(&stream, &total) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (version != 3 || reserved != 0 || total < 4 || total > length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    packet->payload = ((const uint8_t*)data) + 4;
    packet->payload_len = (size_t)total - 4u;
    packet->total_len = total;
    return LIBRDP_STATUS_OK;
}

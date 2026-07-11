/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "channels/echo_channel.h"

#include <string.h>

static librdp_status rdp_echo_channel_parse(const void* data, size_t length, rdp_echo_channel_pdu* pdu)
{
    if ((!data && length > 0) || !pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > RDP_ECHO_CHANNEL_MAX_PAYLOAD)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(pdu, 0, sizeof(*pdu));
    pdu->payload = (const uint8_t*)data;
    pdu->payload_len = length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_echo_channel_write(rdp_buffer* buffer, const void* payload, size_t payload_len)
{
    if (!buffer || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (payload_len > RDP_ECHO_CHANNEL_MAX_PAYLOAD)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append(buffer, payload, payload_len);
}

librdp_status rdp_echo_channel_parse_request(const void* data,
                                             size_t length,
                                             rdp_echo_channel_pdu* pdu)
{
    return rdp_echo_channel_parse(data, length, pdu);
}

librdp_status rdp_echo_channel_parse_response(const void* data,
                                              size_t length,
                                              rdp_echo_channel_pdu* pdu)
{
    return rdp_echo_channel_parse(data, length, pdu);
}

librdp_status rdp_echo_channel_write_request(rdp_buffer* buffer, const void* payload, size_t payload_len)
{
    return rdp_echo_channel_write(buffer, payload, payload_len);
}

librdp_status rdp_echo_channel_write_response(rdp_buffer* buffer, const void* payload, size_t payload_len)
{
    return rdp_echo_channel_write(buffer, payload, payload_len);
}

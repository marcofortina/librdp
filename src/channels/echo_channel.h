/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_CHANNELS_ECHO_CHANNEL_H
#define RDP_CHANNELS_ECHO_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_ECHO_CHANNEL_MAX_PAYLOAD 65536u

typedef struct rdp_echo_channel_pdu
{
    const uint8_t* payload;
    size_t payload_len;
} rdp_echo_channel_pdu;

librdp_status rdp_echo_channel_parse_request(const void* data,
                                             size_t length,
                                             rdp_echo_channel_pdu* pdu);
librdp_status rdp_echo_channel_parse_response(const void* data,
                                              size_t length,
                                              rdp_echo_channel_pdu* pdu);
librdp_status rdp_echo_channel_write_request(rdp_buffer* buffer, const void* payload, size_t payload_len);
librdp_status rdp_echo_channel_write_response(rdp_buffer* buffer, const void* payload, size_t payload_len);

#endif

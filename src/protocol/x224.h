/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_PROTOCOL_X224_H
#define RDP_PROTOCOL_X224_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_X224_PROTOCOL_STANDARD 0x00000000u
#define RDP_X224_PROTOCOL_TLS 0x00000001u
#define RDP_X224_PROTOCOL_NLA 0x00000002u

typedef struct rdp_x224_negotiation
{
    bool present;
    bool failure;
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t selected_protocol;
    uint32_t failure_code;
} rdp_x224_negotiation;

typedef struct rdp_x224_connection_confirm
{
    uint16_t destination_ref;
    uint16_t source_ref;
    uint8_t class_option;
    rdp_x224_negotiation negotiation;
} rdp_x224_connection_confirm;

librdp_status rdp_x224_build_connection_request(rdp_buffer* buffer, const char* cookie_name, uint32_t protocols);
librdp_status rdp_x224_parse_connection_confirm(const void* payload, size_t payload_len, rdp_x224_connection_confirm* confirm);
librdp_status rdp_x224_wrap_data(rdp_buffer* buffer, const void* payload, size_t payload_len);
librdp_status rdp_x224_parse_data(const void* payload,
                                  size_t payload_len,
                                  const uint8_t** data,
                                  size_t* data_len);

#endif

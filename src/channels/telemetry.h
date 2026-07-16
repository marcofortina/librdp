/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: telemetry channel parser and writer declarations.
 * Invariants: channel payload lengths, message identifiers, and negotiated
 * capabilities must be validated before state changes.
 * Ownership: parsed packet structs remain caller-owned unless a session
 * explicitly stores a copy.
 * Threading: internal APIs are not thread-safe unless explicitly stated;
 * callers serialize through the owning session or object.
 * Trust boundary: virtual-channel payloads are untrusted server data and host
 * backend paths are local policy inputs.
 */


#ifndef RDP_CHANNELS_TELEMETRY_H
#define RDP_CHANNELS_TELEMETRY_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_TELEMETRY_CHANNEL_NAME "telemetry"
#define RDP_TELEMETRY_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::Telemetry"
#define RDP_TELEMETRY_PDU_ID 0x01u
#define RDP_TELEMETRY_PDU_LENGTH 0x12u

typedef struct rdp_telemetry_pdu
{
    uint8_t id;
    uint8_t length;
    uint32_t prompt_for_credentials_ms;
    uint32_t prompt_for_credentials_done_ms;
    uint32_t graphics_channel_opened_ms;
    uint32_t first_graphics_received_ms;
} rdp_telemetry_pdu;

void rdp_telemetry_pdu_init(rdp_telemetry_pdu* pdu,
                            uint32_t prompt_for_credentials_ms,
                            uint32_t prompt_for_credentials_done_ms,
                            uint32_t graphics_channel_opened_ms,
                            uint32_t first_graphics_received_ms);
librdp_status rdp_telemetry_write_metrics(rdp_buffer* buffer,
                                          uint32_t prompt_for_credentials_ms,
                                          uint32_t prompt_for_credentials_done_ms,
                                          uint32_t graphics_channel_opened_ms,
                                          uint32_t first_graphics_received_ms);
librdp_status rdp_telemetry_parse_pdu(const void* data, size_t length, rdp_telemetry_pdu* pdu);
librdp_status rdp_telemetry_write_pdu(rdp_buffer* buffer, const rdp_telemetry_pdu* pdu);

#endif

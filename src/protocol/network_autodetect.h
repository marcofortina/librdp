/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: network characteristics auto-detection wire contract.
 * Invariants: header length, message direction, type-specific fields, and
 * variable payload lengths are validated before a parsed view is committed.
 * Ownership: parsed payload views borrow the caller's input buffer; serialized
 * bytes remain owned by the destination buffer.
 * Threading: the codec is stateless and may be used concurrently with
 * independent input, output, and result objects.
 * Trust boundary: every byte passed to a parser is untrusted wire data.
 */

#ifndef RDP_PROTOCOL_NETWORK_AUTODETECT_H
#define RDP_PROTOCOL_NETWORK_AUTODETECT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_NETWORK_AUTODETECT_REQUEST 0x00u
#define RDP_NETWORK_AUTODETECT_RESPONSE 0x01u

#define RDP_NETWORK_AUTODETECT_RTT_RESPONSE 0x0000u
#define RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONTINUOUS 0x0001u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_PAYLOAD 0x0002u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONNECT_TIME 0x0003u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONTINUOUS 0x000bu
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONTINUOUS 0x0014u
#define RDP_NETWORK_AUTODETECT_NETWORK_SYNC 0x0018u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME 0x002bu
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_START_TUNNEL 0x0114u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONTINUOUS 0x0429u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_TUNNEL 0x0629u
#define RDP_NETWORK_AUTODETECT_NETWORK_RESULT_RTT 0x0840u
#define RDP_NETWORK_AUTODETECT_NETWORK_RESULT_BANDWIDTH 0x0880u
#define RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL 0x08c0u
#define RDP_NETWORK_AUTODETECT_RTT_REQUEST_CONNECT_TIME 0x1001u
#define RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME 0x1014u

typedef struct rdp_network_autodetect_pdu
{
    uint8_t header_length;
    uint8_t header_type;
    uint16_t sequence_number;
    uint16_t message_type;
    uint16_t declared_payload_length;
    const uint8_t* payload;
    size_t payload_len;
    uint32_t base_rtt_ms;
    uint32_t average_rtt_ms;
    uint32_t bandwidth_kbps;
    uint32_t time_delta_ms;
    uint32_t byte_count;
} rdp_network_autodetect_pdu;

librdp_status rdp_network_autodetect_parse(const void* data,
                                           size_t length,
                                           rdp_network_autodetect_pdu* pdu);

librdp_status rdp_network_autodetect_write_rtt_request(rdp_buffer* buffer,
                                                       uint16_t sequence_number,
                                                       int connect_time);

librdp_status rdp_network_autodetect_write_rtt_response(rdp_buffer* buffer,
                                                        uint16_t sequence_number);

librdp_status rdp_network_autodetect_write_bandwidth_start(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t request_type);

librdp_status rdp_network_autodetect_write_bandwidth_payload(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    const void* payload,
    size_t payload_len);

librdp_status rdp_network_autodetect_write_bandwidth_stop(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t request_type,
    const void* payload,
    size_t payload_len);

librdp_status rdp_network_autodetect_write_bandwidth_results(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t response_type,
    uint32_t time_delta_ms,
    uint32_t byte_count);

librdp_status rdp_network_autodetect_write_network_result(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint16_t request_type,
    uint32_t base_rtt_ms,
    uint32_t bandwidth_kbps,
    uint32_t average_rtt_ms);

librdp_status rdp_network_autodetect_write_network_sync(
    rdp_buffer* buffer,
    uint16_t sequence_number,
    uint32_t bandwidth_kbps,
    uint32_t rtt_ms);

#endif

/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for Message Channel network auto-detection records.
 * Coverage: request/response parsing and every bounded writer family.
 * Bug classes: truncated headers, direction/type confusion, declared-length
 * mismatch, integer bounds, transactional rollback, and borrowed-view safety.
 * Determinism: no network, clock, filesystem, or backend state is used.
 */

#include "protocol/network_autodetect.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercise the complete stateless codec with one arbitrary
 * record. Writer payloads are capped so malformed length fields cannot
 * amplify allocation.
 * Bug classes: truncated records, type confusion, integer overflow and
 * inconsistent declared payload lengths.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_network_autodetect_pdu pdu;
    rdp_buffer buffer;
    uint16_t sequence_number = 0u;
    size_t payload_len = size < 64u ? size : 64u;

    if (size > 1u)
    {
        sequence_number = (uint16_t)((uint16_t)data[0] |
                                     ((uint16_t)data[1] << 8u));
    }
    (void)rdp_network_autodetect_parse(data, size, &pdu);
    rdp_buffer_init(&buffer);
    (void)rdp_network_autodetect_write_rtt_request(&buffer,
                                                    sequence_number,
                                                    0);
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_rtt_response(&buffer,
                                                     sequence_number);
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_bandwidth_start(
        &buffer,
        sequence_number,
        RDP_NETWORK_AUTODETECT_BANDWIDTH_START_CONNECT_TIME);
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_bandwidth_payload(&buffer,
                                                          sequence_number,
                                                          data,
                                                          payload_len);
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_bandwidth_stop(
        &buffer,
        sequence_number,
        RDP_NETWORK_AUTODETECT_BANDWIDTH_STOP_CONNECT_TIME,
        data,
        payload_len);
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_bandwidth_results(
        &buffer,
        sequence_number,
        RDP_NETWORK_AUTODETECT_BANDWIDTH_RESULTS_CONTINUOUS,
        (uint32_t)size,
        (uint32_t)payload_len);
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_network_result(
        &buffer,
        sequence_number,
        RDP_NETWORK_AUTODETECT_NETWORK_RESULT_ALL,
        (uint32_t)size,
        (uint32_t)payload_len,
        (uint32_t)(size ^ payload_len));
    buffer.length = 0u;
    (void)rdp_network_autodetect_write_network_sync(&buffer,
                                                     sequence_number,
                                                     (uint32_t)size,
                                                     (uint32_t)payload_len);
    rdp_buffer_free(&buffer);
    return 0;
}

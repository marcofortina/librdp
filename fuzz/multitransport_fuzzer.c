/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for multitransport request and response parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "transport/multitransport.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises multitransport request and response parser paths with
 * one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_multitransport_header header;
    rdp_multitransport_subheader subheader;
    rdp_multitransport_create_request request;
    rdp_multitransport_create_response response;
    rdp_multitransport_data tunnel_data;
    rdp_buffer buffer;
    rdp_buffer subheader_bytes;
    uint16_t subheader_count = 0;
    uint8_t cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH] = {0};

    (void)rdp_multitransport_parse_header(data, size, &header);
    (void)rdp_multitransport_parse_subheader(data, size, &subheader);
    (void)rdp_multitransport_count_subheaders(data, size, &subheader_count);
    (void)rdp_multitransport_parse_create_request(data, size, &request);
    (void)rdp_multitransport_parse_create_response(data, size, &response);
    (void)rdp_multitransport_parse_data(data, size, &tunnel_data);

    rdp_buffer_init(&buffer);
    rdp_buffer_init(&subheader_bytes);
    (void)rdp_multitransport_write_create_request(&buffer, 1, cookie);
    buffer.length = 0;
    (void)rdp_multitransport_write_create_response(&buffer, 0);
    buffer.length = 0;
    (void)rdp_multitransport_write_subheader(&subheader_bytes,
                                             RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST,
                                             data,
                                             size < 16u ? size : 16u);
    (void)rdp_multitransport_write_data(&buffer,
                                        subheader_bytes.data,
                                        subheader_bytes.length,
                                        data,
                                        size < 64u ? size : 64u);
    rdp_buffer_free(&subheader_bytes);
    rdp_buffer_free(&buffer);
    return 0;
}

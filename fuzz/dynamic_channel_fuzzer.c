/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for dynamic virtual-channel control parser and writer
 * paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/dynamic_channel.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises dynamic virtual-channel control parser and writer
 * paths with one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_dynamic_channel_header header;
    rdp_dynamic_channel_capabilities capabilities;
    rdp_dynamic_channel_create_request request;
    rdp_dynamic_channel_data_pdu data_pdu;
    rdp_dynamic_channel_data_first_pdu first_pdu;
    rdp_dynamic_channel_close_pdu close_pdu;
    rdp_dynamic_channel_compressed_data_pdu compressed_pdu;
    rdp_dynamic_channel_compressed_data_first_pdu compressed_first_pdu;
    rdp_dynamic_channel_soft_sync_request soft_sync;
    rdp_dynamic_channel_soft_sync_channel_list list;
    rdp_dynamic_channel_soft_sync_response soft_sync_response;
    rdp_buffer response;
    uint32_t tunnel = RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE;
    uint32_t channel_id = 0;

    rdp_buffer_init(&response);
    (void)rdp_dynamic_channel_parse_header(data, size, &header);
    (void)rdp_dynamic_channel_parse_capabilities(data, size, &capabilities);
    (void)rdp_dynamic_channel_parse_create_request(data, size, &request);
    (void)rdp_dynamic_channel_parse_data_first(data, size, &first_pdu);
    (void)rdp_dynamic_channel_parse_data(data, size, &data_pdu);
    (void)rdp_dynamic_channel_parse_close(data, size, &close_pdu);
    (void)rdp_dynamic_channel_parse_compressed_data(data, size, &compressed_pdu);
    (void)rdp_dynamic_channel_parse_compressed_data_first(data, size, &compressed_first_pdu);
    if (rdp_dynamic_channel_parse_soft_sync_request(data, size, &soft_sync) == LIBRDP_STATUS_OK)
    {
        if (rdp_dynamic_channel_soft_sync_request_get_list(&soft_sync, 0, &list) == LIBRDP_STATUS_OK)
            (void)rdp_dynamic_channel_soft_sync_channel_list_get_id(&list, 0, &channel_id);
    }
    if (rdp_dynamic_channel_parse_soft_sync_response(data, size, &soft_sync_response) == LIBRDP_STATUS_OK)
        (void)rdp_dynamic_channel_soft_sync_response_get_tunnel(&soft_sync_response, 0, &tunnel);
    (void)rdp_dynamic_channel_write_capabilities_response(&response, 1);
    response.length = 0;
    (void)rdp_dynamic_channel_write_close(&response, 1, 1);
    response.length = 0;
    if (size > 0)
        (void)rdp_dynamic_channel_write_data_first(&response, 1, 1, (uint32_t)size, data, size > 8u ? 8u : size);
    response.length = 0;
    (void)rdp_dynamic_channel_write_soft_sync_response(&response, &tunnel, 1);
    rdp_buffer_free(&response);
    return 0;
}

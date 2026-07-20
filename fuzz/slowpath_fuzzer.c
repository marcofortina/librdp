/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for slow-path share-control and update parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "protocol/slowpath.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises slow-path share-control and update parser paths with
 * one arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_slowpath_share_control_header header;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_deactivate_all deactivate;
    rdp_slowpath_data_pdu data_pdu;
    rdp_slowpath_font_map font_map;
    rdp_slowpath_save_session_info save_info;
    rdp_buffer output;
    uint32_t error_info = 0;

    rdp_buffer_init(&output);
    (void)rdp_slowpath_parse_share_control_header(data, size, &header);
    (void)rdp_slowpath_write_share_control_header(&output,
                                                  6,
                                                  (uint16_t)(RDP_SLOWPATH_PDU_VERSION |
                                                             RDP_SLOWPATH_PDU_TYPE_DATA),
                                                  1004);
    output.length = 0;
    (void)rdp_slowpath_write_share_data_header(&output,
                                               1,
                                               1,
                                               0,
                                               RDP_SLOWPATH_DATA_PDU_UPDATE,
                                               0,
                                               0);
    output.length = 0;
    (void)rdp_slowpath_parse_demand_active(data, size, &demand);
    (void)rdp_slowpath_parse_deactivate_all(data, size, &deactivate);
    if (rdp_slowpath_parse_data_pdu(data, size, &data_pdu) == LIBRDP_STATUS_OK)
    {
        if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP)
            (void)rdp_slowpath_parse_font_map(data_pdu.payload, data_pdu.payload_len, &font_map);
        else if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO)
            (void)rdp_slowpath_parse_set_error_info(data_pdu.payload, data_pdu.payload_len, &error_info);
        else if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO)
            (void)rdp_slowpath_parse_save_session_info(data_pdu.payload, data_pdu.payload_len, &save_info);
    }
    (void)rdp_slowpath_write_data_pdu(&output,
                                      1,
                                      1004,
                                      RDP_SLOWPATH_DATA_PDU_UPDATE,
                                      data,
                                      size < 64u ? size : 64u);
    rdp_buffer_free(&output);
    return 0;
}

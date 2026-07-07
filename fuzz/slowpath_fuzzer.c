#include "protocol/slowpath.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_slowpath_share_control_header header;
    rdp_slowpath_demand_active demand;
    rdp_slowpath_data_pdu data_pdu;
    rdp_slowpath_font_map font_map;
    rdp_slowpath_save_session_info save_info;
    uint32_t error_info = 0;

    (void)rdp_slowpath_parse_share_control_header(data, size, &header);
    (void)rdp_slowpath_parse_demand_active(data, size, &demand);
    if (rdp_slowpath_parse_data_pdu(data, size, &data_pdu) == LIBRDP_STATUS_OK)
    {
        if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP)
            (void)rdp_slowpath_parse_font_map(data_pdu.payload, data_pdu.payload_len, &font_map);
        else if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO)
            (void)rdp_slowpath_parse_set_error_info(data_pdu.payload, data_pdu.payload_len, &error_info);
        else if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO)
            (void)rdp_slowpath_parse_save_session_info(data_pdu.payload, data_pdu.payload_len, &save_info);
    }
    return 0;
}

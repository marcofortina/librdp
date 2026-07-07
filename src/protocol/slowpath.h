#ifndef RDP_PROTOCOL_SLOWPATH_H
#define RDP_PROTOCOL_SLOWPATH_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"
#include "protocol/capabilities.h"

#define RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE 0x0001u
#define RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE 0x0003u
#define RDP_SLOWPATH_PDU_VERSION 0x0010u

typedef struct rdp_slowpath_share_control_header
{
    uint16_t total_length;
    uint16_t pdu_type;
    uint16_t channel_id;
} rdp_slowpath_share_control_header;

typedef struct rdp_slowpath_demand_active
{
    rdp_slowpath_share_control_header header;
    uint32_t share_id;
    const uint8_t* source_descriptor;
    uint16_t source_descriptor_len;
    rdp_capability_list capabilities;
} rdp_slowpath_demand_active;

librdp_status rdp_slowpath_parse_share_control_header(const void* data,
                                                      size_t length,
                                                      rdp_slowpath_share_control_header* header);
librdp_status rdp_slowpath_parse_demand_active(const void* data,
                                               size_t length,
                                               rdp_slowpath_demand_active* demand);
librdp_status rdp_slowpath_write_confirm_active(rdp_buffer* buffer,
                                                uint32_t share_id,
                                                uint16_t channel_id,
                                                uint16_t width,
                                                uint16_t height,
                                                const char* source_descriptor);

#endif

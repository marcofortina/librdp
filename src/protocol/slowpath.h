#ifndef RDP_PROTOCOL_SLOWPATH_H
#define RDP_PROTOCOL_SLOWPATH_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_slowpath_share_control_header
{
    uint16_t total_length;
    uint16_t pdu_type;
    uint16_t channel_id;
} rdp_slowpath_share_control_header;

librdp_status rdp_slowpath_parse_share_control_header(const void* data,
                                                      size_t length,
                                                      rdp_slowpath_share_control_header* header);

#endif
